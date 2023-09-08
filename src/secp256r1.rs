use std::prelude::v1::*;

use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use serde_big_array::big_array;

#[cfg(feature = "sgx")]
use crate::Aes128Key;
use crate::to_buf;
#[cfg(feature = "sgx")]
use sgxlib::{
    sgx_types::{
        sgx_ec256_dh_shared_t, sgx_ec256_private_t, sgx_ec256_public_t, sgx_ec256_signature_t,
        sgx_ecc256_calculate_pub_from_priv, sgx_ecc256_close_context,
        sgx_ecc256_compute_shared_dhkey, sgx_ecc256_create_key_pair, sgx_ecc256_open_context,
        sgx_ecc_state_handle_t, sgx_ecdsa_sign,
    },
    to_result,
};

big_array! { BigArray; }

#[cfg(feature = "sgx")]
pub fn secp256r1_gen_keypair() -> (Secp256r1PrivateKey, Secp256r1PublicKey) {
    // generate secp256r1 keypair for communication with worker
    let mut sgx_pubkey = sgx_ec256_public_t::default();
    let mut sgx_prvkey = sgx_ec256_private_t::default();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    unsafe {
        to_result(sgx_ecc256_open_context(&mut ecc_handle)).unwrap();
        to_result(sgx_ecc256_create_key_pair(
            &mut sgx_prvkey,
            &mut sgx_pubkey,
            ecc_handle,
        ))
        .unwrap();
        sgxlib::to_result(sgx_ecc256_close_context(ecc_handle)).unwrap();
    }
    let prvkey = Secp256r1PrivateKey::from_sgx_ec256_private(&sgx_prvkey);
    let pubkey = Secp256r1PublicKey::from_sgx_ec256_public(&sgx_pubkey);
    (prvkey, pubkey)
}

#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Secp256r1PrivateKey {
    pub r: [u8; 32],
}

impl Secp256r1PrivateKey {
    #[cfg(feature = "sgx")]
    pub fn public(&self) -> Secp256r1PublicKey {
        let prv = self.to_sgx_ec256_private();
        let mut sgx_pubkey = sgx_ec256_public_t::default();
        unsafe {
            to_result(sgx_ecc256_calculate_pub_from_priv(&prv as _, &mut sgx_pubkey as _)).unwrap();
        }
        Secp256r1PublicKey::from_sgx_ec256_public(&sgx_pubkey)
    }

    #[cfg(feature = "sgx")]
    pub fn from_sgx_ec256_private(key: &sgx_ec256_private_t) -> Secp256r1PrivateKey {
        Secp256r1PrivateKey { r: key.r }
    }

    #[cfg(feature = "sgx")]
    pub fn to_sgx_ec256_private(&self) -> sgx_ec256_private_t {
        sgx_ec256_private_t { r: self.r }
    }

    #[cfg(feature = "sgx")]
    pub fn derive_kdk(&self, pubkey: &Secp256r1PublicKey) -> Result<Aes128Key, String> {
        let shared_dhkey = self
            .compute_shared_dhkey(pubkey)
            .map_err(|err| format!("compute_shared_dhkey: {:?}", err))?;
        let key0 = Aes128Key { key: [0; 16] };

        let mac = key0.mac(&shared_dhkey)?;
        Ok(Aes128Key { key: mac.mac })
    }

    #[cfg(feature = "sgx")]
    pub fn compute_shared_dhkey(&self, pubkey: &Secp256r1PublicKey) -> Result<[u8; 32], String> {
        let mut sgx_prvkey = self.to_sgx_ec256_private();
        let mut sgx_pubkey = pubkey.to_sgx_ec256_public();
        let mut gab_x = sgx_ec256_dh_shared_t::default();
        let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

        unsafe {
            to_result(sgx_ecc256_open_context(&mut ecc_handle))
                .map_err(|err| format!("sgx_ecc256_open_context: {:?}", err))?;
            println!("{:?}", ecc_handle);
            to_result(sgx_ecc256_compute_shared_dhkey(
                &mut sgx_prvkey,
                &mut sgx_pubkey,
                &mut gab_x,
                ecc_handle,
            ))
            .map_err(|err| format!("sgx_ecc256_compute_shared_dhkey: {:?}", err))?;
            to_result(sgx_ecc256_close_context(ecc_handle))
                .map_err(|err| format!("sgx_ecc256_close_context: {:?}", err))?;
        }
        Ok(gab_x.s)
    }

    #[cfg(feature = "sgx")]
    pub fn sign<T: Serialize>(&self, msg: T) -> Result<Secp256r1SignedMsg<T>, String> {
        let msg_bytes = serde_json::to_vec(&msg).unwrap();
        let signature = self.sign_bytes(&msg_bytes)?;

        Ok(Secp256r1SignedMsg::<T> {
            msg: msg,
            signature: signature,
        })
    }

    #[cfg(feature = "sgx")]
    pub fn sign_bytes(&self, msg: &[u8]) -> Result<Secp256r1Signature, String> {
        let mut sgx_prvkey = self.to_sgx_ec256_private();
        let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;
        let mut signature = sgx_ec256_signature_t::default();

        unsafe {
            to_result(sgx_ecc256_open_context(&mut ecc_handle))
                .map_err(|err| format!("{:?}", err))?;
            to_result(sgx_ecdsa_sign(
                msg.as_ptr(),
                msg.len() as u32,
                &mut sgx_prvkey,
                &mut signature,
                ecc_handle,
            ))
            .map_err(|err| format!("{:?}", err))?;
            to_result(sgx_ecc256_close_context(ecc_handle)).map_err(|err| format!("{:?}", err))?;
        }

        Ok(signature.into())
    }

    pub fn to_raw_bytes(&self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..32].copy_from_slice(&self.r);
        bytes
    }
}

#[derive(Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct Secp256r1PublicKey {
    pub gx: [u8; 32],
    pub gy: [u8; 32],
}

impl Secp256r1PublicKey {
    #[cfg(feature = "sgx")]
    pub fn from_sgx_ec256_public(key: &sgx_ec256_public_t) -> Secp256r1PublicKey {
        Secp256r1PublicKey {
            gx: key.gx,
            gy: key.gy,
        }
    }

    #[cfg(feature = "sgx")]
    pub fn to_sgx_ec256_public(&self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.gx);
        bytes[32..].copy_from_slice(&self.gy);
        bytes
    }

    pub fn from_raw_bytes(buf: &[u8; 64]) -> Self {
        let mut gx = [0_u8; 32];
        let mut gy = [0_u8; 32];
        gx.copy_from_slice(&buf[..32]);
        gy.copy_from_slice(&buf[32..]);
        Self { gx, gy }
    }
}

impl Serialize for Secp256r1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serialized_bytes = self.to_raw_bytes();
        let val = format!("0x{}", hex::encode(&serialized_bytes));
        serializer.serialize_str(&val)
    }
}

impl<'de> Deserialize<'de> for Secp256r1PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let result: Vec<u8> = if str.starts_with("0x") {
            hex::decode(&str[2..]).map_err(|e| D::Error::custom(format!("{}", e)))?
        } else {
            str.into()
        };
        let data = to_buf([0_u8; 64], result).map_err(|err| D::Error::custom(err))?;
        Ok(Self::from_raw_bytes(&data))
    }
}

#[derive(Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct Secp256r1Signature {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl Secp256r1Signature {
    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.x);
        bytes[32..].copy_from_slice(&self.y);
        bytes
    }

    pub fn from_raw_bytes(buf: &[u8; 64]) -> Self {
        let mut x = [0_u8; 32];
        let mut y = [0_u8; 32];
        x.copy_from_slice(&buf[..32]);
        y.copy_from_slice(&buf[32..]);
        Self { x, y }
    }
}

impl Serialize for Secp256r1Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serialized_bytes = self.to_raw_bytes();
        let val = format!("0x{}", hex::encode(&serialized_bytes));
        serializer.serialize_str(&val)
    }
}

impl<'de> Deserialize<'de> for Secp256r1Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let result: Vec<u8> = if str.starts_with("0x") {
            hex::decode(&str[2..]).map_err(|e| D::Error::custom(format!("{}", e)))?
        } else {
            str.into()
        };
        if result.len() != 64 {
            return Err(D::Error::custom(format!(
                "invalid buf length: {}",
                result.len()
            )));
        }
        let mut data = [0_u8; 64];
        data.copy_from_slice(&result);
        Ok(Self::from_raw_bytes(&data))
    }
}

impl Secp256r1Signature {
    #[cfg(feature = "sgx")]
    pub fn from_sgx_ec256_signature(sig: sgx_ec256_signature_t) -> Secp256r1Signature {
        Secp256r1Signature {
            x: unsafe { std::mem::transmute::<[u32; 8], [u8; 32]>(sig.x) },
            y: unsafe { std::mem::transmute::<[u32; 8], [u8; 32]>(sig.y) },
        }
    }

    #[cfg(feature = "sgx")]
    pub fn to_sgx_ec256_signature(&self) -> sgx_ec256_signature_t {
        sgx_ec256_signature_t {
            x: unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(self.x) },
            y: unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(self.y) },
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct Secp256r1SignedMsg<T: Serialize> {
    pub msg: T,
    pub signature: Secp256r1Signature,
}

#[cfg(feature = "sgx")]
impl From<sgx_ec256_signature_t> for Secp256r1Signature {
    fn from(item: sgx_ec256_signature_t) -> Self {
        Secp256r1Signature::from_sgx_ec256_signature(item)
    }
}

#[cfg(feature = "sgx")]
impl From<Secp256r1Signature> for sgx_ec256_signature_t {
    fn from(item: Secp256r1Signature) -> Self {
        item.to_sgx_ec256_signature()
    }
}

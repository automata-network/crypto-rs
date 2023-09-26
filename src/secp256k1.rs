use std::prelude::v1::*;

use crate::read_rand;
use primitive_types::H160;
use rust_secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use rust_secp256k1::ffi::types::AlignedType;
use rust_secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use tiny_keccak::{Hasher, Keccak};

#[cfg(feature = "sgx")]
use crate::Aes128Key;
#[cfg(feature = "sgx")]
use sgxlib::sgx_types::sgx_ec256_public_t;

pub fn secp256k1_gen_keypair() -> (Secp256k1PrivateKey, Secp256k1PublicKey) {
    let mut seed_bytes = [0_u8; 32];

    let secp_size = Secp256k1::preallocate_size();
    let mut buf = vec![AlignedType::zeroed(); secp_size];
    let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    secp.seeded_randomize(&seed_bytes);

    let prvkey = loop {
        read_rand(&mut seed_bytes);
        if let Ok(secret_key) = Secp256k1PrivateKey::new(&seed_bytes) {
            break secret_key;
        }
    };
    let pubkey = PublicKey::from_secret_key(&secp, &prvkey.origin);

    (prvkey, pubkey.into())
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct Secp256k1PrivateKey {
    pub r: [u8; 32],
    origin: SecretKey,
}

impl std::fmt::Debug for Secp256k1PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "0x{}...{}",
            hex::encode(&self.r[..2]),
            hex::encode(&self.r[30..])
        )
    }
}

impl Secp256k1PrivateKey {
    pub fn new(buf: &[u8]) -> Result<Self, String> {
        if buf.len() != 32 {
            return Err(format!("invalid sk length"));
        }
        let sk = SecretKey::from_slice(&buf).map_err(|err| format!("{:?}", err))?;

        let mut r = [0_u8; 32];
        r.copy_from_slice(&buf);
        Ok(Self { r, origin: sk })
    }

    pub fn sign(&self, msg: &[u8]) -> Secp256k1RecoverableSignature {
        secp256k1_rec_sign_bytes(self, msg)
    }

    pub fn public(&self) -> Secp256k1PublicKey {
        let mut seed_bytes = [0_u8; 32];
        read_rand(&mut seed_bytes);
        let secp_size = Secp256k1::preallocate_size();
        let mut buf = vec![AlignedType::zeroed(); secp_size];
        let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
        secp.seeded_randomize(&seed_bytes);
        let publickey = PublicKey::from_secret_key(&secp, &self.origin);
        publickey.into()
    }

    #[cfg(feature = "sgx")]
    pub fn derive_kdk(&self, pubkey: &Secp256k1PublicKey) -> Result<Aes128Key, String> {
        let point = pubkey.into();
        let secret = rust_secp256k1::ecdh::shared_secret_point(&point, &self.origin);
        let key0 = Aes128Key { key: [0; 16] };

        let mac = key0.mac(&secret)?;
        Ok(Aes128Key { key: mac.mac })
    }
}

impl<'de> Deserialize<'de> for Secp256k1PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let result: Vec<u8> = if str.starts_with("0x") {
            hex::decode(&str[2..]).map_err(|e| D::Error::custom(format!("{}", e)))?
        } else {
            str.into()
        };
        Self::new(&result).map_err(D::Error::custom)
    }
}

impl From<&[u8]> for Secp256k1PrivateKey {
    fn from(data: &[u8]) -> Self {
        Self::new(data).unwrap()
    }
}

impl From<&str> for Secp256k1PrivateKey {
    fn from(item: &str) -> Self {
        let prvkey_str = item.trim_start_matches("0x");
        let prvkey_bytes = hex::decode(prvkey_str).unwrap();
        (&prvkey_bytes[..]).into()
    }
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct Secp256k1PublicKey {
    pub gx: [u8; 32],
    pub gy: [u8; 32],
}

impl<'de> Deserialize<'de> for Secp256k1PublicKey {
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
        let pk = PublicKey::from_slice(&result).map_err(|e| D::Error::custom(format!("{}", e)))?;
        Ok(pk.into())
    }
}

impl Serialize for Secp256k1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let pk: PublicKey = self.into();
        let serialized_bytes = pk.serialize_uncompressed();
        let val = format!("0x{}", hex::encode(&serialized_bytes));
        serializer.serialize_str(&val)
    }
}

impl Secp256k1PublicKey {
    pub fn eth_accountid(&self) -> H160 {
        let mut data = [0_u8; 64];
        data[..32].copy_from_slice(&self.gx);
        data[32..].copy_from_slice(&self.gy);

        let mut keccak = Keccak::v256();
        let mut msg_hash = [0_u8; 32];
        keccak.update(&data);
        keccak.finalize(&mut msg_hash);
        let mut addr_bytes = [0_u8; 20];
        addr_bytes.copy_from_slice(&msg_hash[12..]);
        addr_bytes.into()
    }

    #[cfg(feature = "sgx")]
    pub fn from_sgx_ec256_public(key: &sgx_ec256_public_t) -> Self {
        Self {
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

    pub fn from_raw_bytes(bytes: &[u8; 64]) -> Self {
        let mut pubkey = Self {
            gx: [0_u8; 32],
            gy: [0_u8; 32],
        };
        pubkey.gx.copy_from_slice(&bytes[..32]);
        pubkey.gy.copy_from_slice(&bytes[32..]);
        pubkey
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.gx);
        bytes[32..].copy_from_slice(&self.gy);
        bytes
    }
}

#[derive(Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct Secp256k1RecoverableSignature {
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Secp256k1RecoverableSignature {
    pub fn new(sig: [u8; 65]) -> Self {
        let mut r = [0_u8; 32];
        let mut s = [0_u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        Self { v: sig[64], r, s }
    }

    pub fn to_array(&self) -> [u8; 65] {
        let mut result = [0_u8; 65];
        result[..32].copy_from_slice(&self.r);
        result[32..64].copy_from_slice(&self.s);
        result[64] = self.v;
        result
    }
}

pub fn secp256k1_recover_pubkey(
    signature: &Secp256k1RecoverableSignature,
    msg: &[u8],
) -> Secp256k1PublicKey {
    let mut seed_bytes = [0_u8; 32];
    read_rand(&mut seed_bytes);
    let secp_size = Secp256k1::preallocate_size();
    let mut buf = vec![AlignedType::zeroed(); secp_size];
    let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    secp.seeded_randomize(&seed_bytes);

    // hash the message with keccak-256
    let mut keccak = Keccak::v256();
    let mut msg_hash = [0_u8; 32];
    keccak.update(msg);
    keccak.finalize(&mut msg_hash);

    let message = Message::from_slice(&msg_hash).expect("32 bytes");
    secp.recover_ecdsa(&message, &signature.clone().into())
        .unwrap()
        .into()
}

pub fn secp256k1_rec_sign_bytes(
    prvkey: &Secp256k1PrivateKey,
    msg: &[u8],
) -> Secp256k1RecoverableSignature {
    let mut seed_bytes = [0_u8; 32];
    read_rand(&mut seed_bytes);
    let secp_size = Secp256k1::preallocate_size();
    let mut buf = vec![AlignedType::zeroed(); secp_size];
    let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    secp.seeded_randomize(&seed_bytes);

    // hash the message with keccak-256
    let mut keccak = Keccak::v256();
    let mut msg_hash = [0_u8; 32];
    keccak.update(msg);
    keccak.finalize(&mut msg_hash);

    let message = Message::from_slice(&msg_hash).expect("32 bytes");
    let signature = secp.sign_ecdsa_recoverable(&message, &(prvkey.clone().into()));

    signature.into()
}

impl From<Secp256k1PrivateKey> for rust_secp256k1::SecretKey {
    fn from(item: Secp256k1PrivateKey) -> Self {
        rust_secp256k1::SecretKey::from_slice(&item.r).unwrap()
    }
}

impl From<RecoverableSignature> for Secp256k1RecoverableSignature {
    fn from(item: RecoverableSignature) -> Self {
        let (recid, sig) = item.serialize_compact();
        let mut r = [0_u8; 32];
        let mut s = [0_u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        Secp256k1RecoverableSignature {
            v: recid.to_i32().try_into().unwrap(),
            r: r,
            s: s,
        }
    }
}

impl From<Secp256k1RecoverableSignature> for RecoverableSignature {
    fn from(item: Secp256k1RecoverableSignature) -> Self {
        let recid = RecoveryId::from_i32(item.v.into()).unwrap();
        let mut sig = [0_u8; 64];
        sig[..32].copy_from_slice(&item.r);
        sig[32..].copy_from_slice(&item.s);
        RecoverableSignature::from_compact(&sig, recid).unwrap()
    }
}

impl From<PublicKey> for Secp256k1PublicKey {
    fn from(item: PublicKey) -> Self {
        let mut x = [0_u8; 32];
        let mut y = [0_u8; 32];

        // libsecp256k1 - secp256k1_eckey_pubkey_serialize()
        // secp256k1_fe_get_b32(&pub[1], &elem->x);
        // secp256k1_fe_get_b32(&pub[33], &elem->y);
        // pub[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
        // #define SECP256K1_TAG_PUBKEY_UNCOMPRESSED 0x04
        let serialized_bytes = item.serialize_uncompressed();
        assert_eq!(serialized_bytes[0], 0x4);

        // values are in big-endian
        x.copy_from_slice(&serialized_bytes[1..=32]);
        y.copy_from_slice(&serialized_bytes[33..=64]);

        Secp256k1PublicKey { gx: x, gy: y }
    }
}

impl From<&Secp256k1PublicKey> for PublicKey {
    fn from(item: &Secp256k1PublicKey) -> Self {
        let mut buf = [0_u8; 65];
        buf[0] = 0x4;
        buf[1..=32].copy_from_slice(&item.gx);
        buf[33..=64].copy_from_slice(&item.gy);

        PublicKey::from_slice(&buf).unwrap()
    }
}

pub fn secp256k1_ecdsa_recover(sig: &[u8; 65], msg: &[u8; 32]) -> Option<[u8; 64]> {
    let mut seed_bytes = [0_u8; 32];
    read_rand(&mut seed_bytes);
    let secp_size = Secp256k1::preallocate_size();
    let mut buf = vec![AlignedType::zeroed(); secp_size];
    let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    secp.seeded_randomize(&seed_bytes);
    let rid =
        RecoveryId::from_i32(if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as i32).ok()?;
    let sig = RecoverableSignature::from_compact(&sig[..64], rid).ok()?;
    let msg = Message::from_slice(msg).expect("Message is 32 bytes; qed");

    let pubkey = secp.recover_ecdsa(&msg, &sig).ok()?;
    let mut res = [0u8; 64];
    res.copy_from_slice(&pubkey.serialize_uncompressed()[1..]);
    Some(res)
}

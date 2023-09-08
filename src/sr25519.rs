use std::prelude::v1::*;

use core::fmt;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey, PublicKey, SecretKey};
use schnorrkel::sign::Signature;

use thirdparty_rand::rngs::StdRng;
use thirdparty_rand::SeedableRng;

use serde_big_array::big_array;

use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::read_rand;

big_array! { BigArray; }

pub fn sr25519_gen_keypair() -> (Sr25519PrivateKey, Sr25519PublicKey) {
    let mut seed_bytes = [0_u8; 32];
    read_rand(&mut seed_bytes);
    let rng: StdRng = SeedableRng::from_seed(seed_bytes);
    let sr25519_keypair = schnorrkel::Keypair::generate_with(rng);
    let sr25519_pubkey = Sr25519PublicKey::from_schnorrkel_public(&sr25519_keypair.public);
    let sr25519_prvkey = Sr25519PrivateKey::from_schnorrkel_private(&sr25519_keypair.secret);
    (sr25519_prvkey, sr25519_pubkey)
}

#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Sr25519PrivateKey {
    pub secret: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct Sr25519PublicKey {
    // compressed Ristretto form byte array
    pub compressed_point: [u8; 32],
}

impl Serialize for Sr25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let val = format!("0x{}", hex::encode(&self.compressed_point));
        serializer.serialize_str(&val)
    }
}

impl<'de> Deserialize<'de> for Sr25519PublicKey {
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
        
        if result.len() != 32 {
            return Err(D::Error::custom(format!(
                "invalid PublicKey length: {}",
                result.len()
            )));
        }
        let mut compressed_point = [0_u8; 32];
        compressed_point.copy_from_slice(&result);
        Ok(Self { compressed_point })
    }
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct Sr25519Signature {
    #[serde(with = "BigArray")]
    pub signature_bytes: [u8; 64],
}

impl Default for Sr25519Signature {
    fn default() -> Self {
        Sr25519Signature {
            signature_bytes: [0; 64],
        }
    }
}

impl fmt::Debug for Sr25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.signature_bytes[..].fmt(f)
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Sr25519SignedMsg<T: Serialize> {
    pub msg: T,
    pub signature: Sr25519Signature,
}

impl Sr25519PublicKey {
    pub fn from_schnorrkel_public(key: &PublicKey) -> Sr25519PublicKey {
        Sr25519PublicKey {
            compressed_point: key.to_bytes(),
        }
    }

    pub fn to_schnorrkel_public(&self) -> PublicKey {
        PublicKey::from_bytes(&self.compressed_point).expect("bytes to pubkey ok")
    }

    pub fn to_raw_bytes(&self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..].copy_from_slice(&self.compressed_point);
        bytes
    }
}

impl Sr25519PrivateKey {
    pub fn from_schnorrkel_private(key: &SecretKey) -> Sr25519PrivateKey {
        let bytes = key.to_bytes();
        let mut secret_bytes = [0_u8; 32];
        let mut nonce_bytes = [0_u8; 32];
        secret_bytes.copy_from_slice(&bytes[..32]);
        nonce_bytes.copy_from_slice(&bytes[32..]);
        Sr25519PrivateKey {
            secret: secret_bytes,
            nonce: nonce_bytes,
        }
    }

    pub fn to_schnorrkel_private(&self) -> SecretKey {
        SecretKey::from_bytes(&self.to_raw_bytes()).expect("secret key bytes ok!")
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.secret);
        bytes[32..].copy_from_slice(&self.nonce);
        bytes
    }

    pub fn gen_public(&self) -> Sr25519PublicKey {
        let secret_key: SecretKey = self.clone().into();
        secret_key.to_public().into()
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        let minikey = MiniSecretKey::from_bytes(seed).unwrap();
        let secretkey = minikey.expand(ExpansionMode::Ed25519);
        secretkey.into()
    }

    pub fn sign_msg<T: Serialize>(&self, ctx: &[u8], msg: T) -> Sr25519SignedMsg<T> {
        let msg_bytes = serde_json::to_vec(&msg).unwrap();
        let signature = self.sign_bytes(ctx, &msg_bytes);
        Sr25519SignedMsg { msg, signature }
    }

    pub fn sign_bytes(&self, context: &[u8], msg: &[u8]) -> Sr25519Signature {
        let mut seed_bytes = [0_u8; 32];
        read_rand(&mut seed_bytes);
        let rng: StdRng = SeedableRng::from_seed(seed_bytes);
        let secretkey = self.to_schnorrkel_private();
        let context = schnorrkel::signing_context(context);
        let signature = secretkey.sign(
            schnorrkel::context::attach_rng(context.bytes(msg), rng),
            &secretkey.to_public(),
        );
        signature.into()
    }
}

impl From<Sr25519PrivateKey> for SecretKey {
    fn from(item: Sr25519PrivateKey) -> Self {
        item.to_schnorrkel_private()
    }
}

impl From<SecretKey> for Sr25519PrivateKey {
    fn from(item: SecretKey) -> Self {
        Sr25519PrivateKey::from_schnorrkel_private(&item)
    }
}

impl From<PublicKey> for Sr25519PublicKey {
    fn from(item: PublicKey) -> Self {
        Sr25519PublicKey::from_schnorrkel_public(&item)
    }
}

impl From<Sr25519Signature> for Signature {
    fn from(item: Sr25519Signature) -> Self {
        item.to_schnorrkel_signature()
    }
}

impl From<Signature> for Sr25519Signature {
    fn from(item: Signature) -> Self {
        Sr25519Signature::from_schnorrkel_signature(&item)
    }
}

impl Sr25519Signature {
    pub fn from_schnorrkel_signature(signature: &Signature) -> Sr25519Signature {
        Sr25519Signature {
            signature_bytes: signature.to_bytes(),
        }
    }

    pub fn to_schnorrkel_signature(&self) -> Signature {
        Signature::from_bytes(&self.signature_bytes).expect("Sr25519Signature bytes ok!")
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..].copy_from_slice(&self.signature_bytes);
        bytes
    }
}

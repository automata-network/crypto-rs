use std::prelude::v1::*;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct Aes128EncryptedMsg {
    pub iv: [u8; 12],
    pub mac: Aes128Mac,
    pub cipher: Vec<u8>,
}

#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Aes128Mac {
    pub mac: [u8; 16],
}

#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Aes128Key {
    pub key: [u8; 16],
}

impl Aes128Key {
    pub fn from_slice(byte_slice: &[u8]) -> Aes128Key {
        let mut buf = [0_u8; 16];
        buf.copy_from_slice(byte_slice);
        Aes128Key { key: buf }
    }

    pub fn to_raw_bytes(&self) -> [u8; 16] {
        self.key
    }

    #[cfg(feature = "sgx")]
    pub fn mac(&self, p_data: &[u8]) -> Result<Aes128Mac, String> {
        match sgxlib::crypto::rsgx_rijndael128_cmac_slice(&self.key, p_data) {
            Ok(mac) => Ok(Aes128Mac { mac }),
            Err(s) => Err(format!("{} {:?}", s.from_key(), s)),
        }
    }

    #[cfg(feature = "sgx")]
    pub fn encrypt(&self, p_data: &[u8]) -> Aes128EncryptedMsg {
        use crate::read_rand;

        let mut iv = [0_u8; 12];
        let mut mac = [0_u8; 16];
        let mut cipher = vec![0_u8; p_data.len()];
        read_rand(&mut iv);

        sgxlib::crypto::rsgx_rijndael128GCM_encrypt(
            &self.key,
            p_data,
            &iv,
            &[],
            &mut cipher[..],
            &mut mac,
        )
        .unwrap();

        let mac = Aes128Mac { mac };
        Aes128EncryptedMsg { iv, mac, cipher }
    }

    #[cfg(feature = "sgx")]
    pub fn decrypt(&self, p_encrypted_msg: &Aes128EncryptedMsg) -> Result<Vec<u8>, String> {
        let p_iv = &p_encrypted_msg.iv;
        let p_mac = &p_encrypted_msg.mac.mac;
        let p_cipher = &p_encrypted_msg.cipher[..];
        let mut plaintext = vec![0_u8; p_encrypted_msg.cipher.len()];

        if let Err(s) = sgxlib::crypto::rsgx_rijndael128GCM_decrypt(
            &self.key,
            p_cipher,
            p_iv,
            &[],
            p_mac,
            &mut plaintext[..],
        ) {
            return Err(format!("{} {:?}", s.from_key(), s));
        }

        Ok(plaintext)
    }

    #[cfg(feature = "sgx")]
    pub fn verify(&self, p_data: &[u8], p_orig_mac: &Aes128Mac) -> Result<bool, String> {
        let msg_mac = self.mac(p_data)?;
        Ok(msg_mac.mac == p_orig_mac.mac)
    }
}

impl Aes128Mac {
    pub fn to_raw_bytes(&self) -> [u8; 16] {
        self.mac
    }
}

impl From<[u8; 16]> for Aes128Key {
    fn from(item: [u8; 16]) -> Self {
        Aes128Key { key: item }
    }
}

impl From<Aes128Key> for [u8; 16] {
    fn from(item: Aes128Key) -> Self {
        item.key
    }
}

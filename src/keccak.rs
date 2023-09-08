use tiny_keccak::{Hasher, Keccak};

pub fn keccak_hash(msg: &[u8]) -> [u8; 32] {
    // hash the message with keccak-256
    let mut keccak = Keccak::v256();
    let mut msg_hash = [0_u8; 32];
    keccak.update(msg);
    keccak.finalize(&mut msg_hash);
    msg_hash
}

pub fn keccak_encode<F>(f: F) -> [u8; 32]
where
    F: FnOnce(&mut dyn FnMut(&[u8])),
{
    let mut keccak = Keccak::v256();
    let mut msg_hash = [0_u8; 32];
    f(&mut |data: &[u8]| keccak.update(data));
    keccak.finalize(&mut msg_hash);
    msg_hash
}
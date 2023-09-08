
pub fn sha256_sum(data: &[u8]) -> [u8; 32] {
    blst::sha256_sum(data)
}

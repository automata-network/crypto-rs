use std::prelude::v1::*;

#[cfg(feature = "std")]
pub fn read_rand(buf: &mut [u8]) {
    use rand_std::Rng;
    rand_std::thread_rng().fill(buf)
}

#[cfg(feature = "tstd")]
pub fn read_rand(buf: &mut [u8]) {
    use sgxlib::sgx_types::sgx_read_rand;
    unsafe {
        sgx_read_rand(buf.as_mut_ptr(), buf.len());
    }
}

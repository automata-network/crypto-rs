use std::prelude::v1::*;

pub fn vec_to_buf<T>(buf: Vec<u8>) -> Result<T, String>
where
    T: Default + AsMut<[u8]>,
{
    let mut ret = T::default();
    if buf.len() != std::mem::size_of::<T>() {
        return Err(format!(
            "unexpected buffer size: {}, want: {}",
            buf.len(),
            std::mem::size_of::<T>()
        ));
    }
    let ptr = ret.as_mut();
    ptr.copy_from_slice(&buf);
    Ok(ret)
}


pub fn to_buf<T>(mut ret: T, buf: Vec<u8>) -> Result<T, String>
where
    T: AsMut<[u8]>,
{
    if buf.len() != std::mem::size_of::<T>() {
        return Err(format!(
            "unexpected buffer size: {}, want: {}",
            buf.len(),
            std::mem::size_of::<T>()
        ));
    }
    let ptr = ret.as_mut();
    ptr.copy_from_slice(&buf);
    Ok(ret)
}

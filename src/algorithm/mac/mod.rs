use ring::hmac::Tag;

mod hmac_sha1;
mod hmac_sha2;
use crate::constant::algorithms as constant;
use hmac_sha1::HMacSha1;
use hmac_sha2::{HmacSha2_256, HmacSha2_512};

pub(crate) trait Mac: Send + Sync {
    fn sign(&self, ik: &[u8], sequence_num: u32, buf: &[u8]) -> Tag;
    fn new() -> Self
    where
        Self: Sized;
    fn bsize(&self) -> usize;
}

pub(crate) fn from(s: &str) -> Box<dyn Mac> {
    match s {
        constant::mac::HMAC_SHA1 => Box::new(HMacSha1::new()),
        constant::mac::HMAC_SHA2_256 => Box::new(HmacSha2_256::new()),
        constant::mac::HMAC_SHA2_512 => Box::new(HmacSha2_512::new()),
        _ => unreachable!("Currently dont support"),
    }
}

pub(crate) struct MacNone {}

impl Mac for MacNone {
    fn sign(&self, _ik: &[u8], _sequence_num: u32, _buf: &[u8]) -> Tag {
        unreachable!()
    }
    fn new() -> Self
    where
        Self: Sized,
    {
        Self {}
    }
    fn bsize(&self) -> usize {
        unreachable!()
    }
}

use ring::hmac::Tag;

mod hmac_sha1;
use crate::constant::algorithms as constant;
pub(crate) use hmac_sha1::HMacSha1;

pub(crate) trait Mac: Send + Sync {
    fn sign(&self, ik: &[u8], sequence_num: u32, buf: &[u8]) -> Tag;
    fn new() -> Self
    where
        Self: Sized;
    fn bsize(&self) -> usize;
}

pub(crate) fn from(s: &str) -> Box<dyn Mac> {
    match s {
        constant::mac::HMAC_SHA1 => Box::new(HMacSha1),
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

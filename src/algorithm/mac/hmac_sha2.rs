use crate::algorithm::mac::Mac;
use ring::hmac;
use ring::hmac::{Context, Tag};

const BSIZE: usize = 20;

pub(super) struct HmacSha2_256;
pub(super) struct HmacSha2_512;

impl Mac for HmacSha2_256 {
    fn sign(&self, ik: &[u8], sequence_num: u32, buf: &[u8]) -> Tag {
        let ik = &ik[..BSIZE];
        let key = hmac::Key::new(hmac::HMAC_SHA256, ik);
        let mut c = Context::with_key(&key);
        c.update(sequence_num.to_be_bytes().as_slice());
        c.update(buf);
        c.sign()
    }

    fn new() -> Self
    where
        Self: Sized,
    {
        HmacSha2_256
    }

    fn bsize(&self) -> usize {
        BSIZE
    }
}

impl Mac for HmacSha2_512 {
    fn sign(&self, ik: &[u8], sequence_num: u32, buf: &[u8]) -> Tag {
        let ik = &ik[..BSIZE];
        let key = hmac::Key::new(hmac::HMAC_SHA512, ik);
        let mut c = Context::with_key(&key);
        c.update(sequence_num.to_be_bytes().as_slice());
        c.update(buf);
        c.sign()
    }

    fn new() -> Self
    where
        Self: Sized,
    {
        HmacSha2_512
    }

    fn bsize(&self) -> usize {
        BSIZE
    }
}

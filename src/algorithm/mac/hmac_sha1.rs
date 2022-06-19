use std::borrow::BorrowMut;
use ring::hmac;
use ring::hmac::{Context, Tag};
use crate::algorithm::hash;
use crate::algorithm::mac::Mac;

const BSIZE: usize = 20;

pub(crate) struct HMacSha1;

impl Mac for HMacSha1 {

    fn sign(&self, ik: &[u8], sequence_num: u32, buf: &[u8]) -> Tag {
        let ik = &ik[..BSIZE];
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, ik);
        let mut c = Context::with_key(&key);
        c.update(sequence_num.to_be_bytes().as_slice());
        c.update(buf);
        c.sign()
    }

    fn new() -> Self where Self: Sized {
        HMacSha1
    }

    fn bsize(&self) -> usize {
        BSIZE
    }
}
use ring::hmac::Tag;

pub(crate) mod hmac_sha1;

pub trait Mac {
    fn sign(&self, ik: &[u8], sequence_num: u32, buf: &[u8]) -> Tag;
    fn new() -> Self where Self: Sized;
    fn bsize(&self) -> usize;
}
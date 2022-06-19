use ring::hmac::{Context, Tag};

pub(crate) mod hmac_sha1;


static mut MAC: Option<Box<dyn Mac>> = None;


pub(crate) fn put(m: Box<dyn Mac>) {
    unsafe {
        MAC = Some(m);
    }
}

pub(crate) fn get() -> &'static mut Box<dyn Mac> {
    unsafe {
        MAC.as_mut().unwrap()
    }
}


pub(crate) trait Mac {
    fn sign(&self, ik: &[u8], sequence_num: u32, buf: &[u8]) -> Tag;
    fn new() -> Self where Self: Sized;
    fn bsize(&self) -> usize;
}
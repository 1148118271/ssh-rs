mod hmac_sha1;


pub(crate) trait Mac {
    fn bsize() -> usize;
    fn new() -> Self where Self: Sized;
}
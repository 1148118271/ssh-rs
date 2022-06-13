use std::ptr;
use crate::SshError;

mod ed25519;
mod rsa;


static mut PUBLIC_KEY: *const Box<dyn PublicKey> = ptr::null();


pub(crate) trait PublicKey: Send + Sync {
    fn new() -> Self where Self: Sized;
    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError>;
}
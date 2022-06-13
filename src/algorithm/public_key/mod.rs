use crate::SshError;

mod ed25519;
mod rsa;


pub(crate) use ed25519::Ed25519;
pub(crate) use self::rsa::RSA;


/// # 公钥算法
/// 主要用于对服务端签名的验证

static mut PUBLIC_KEY: Option<Box<dyn PublicKey>> = None;

pub(crate) fn put(pk: Box<dyn PublicKey>) {
    unsafe {
        PUBLIC_KEY = Some(pk)
    }
}


pub(crate) fn get() -> &'static Box<dyn PublicKey> {
    unsafe {
        PUBLIC_KEY.as_ref().unwrap()
    }
}


pub(crate) trait PublicKey: Send + Sync {
    fn new() -> Self where Self: Sized;
    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError>;
}
use crate::SshError;

mod ed25519;
mod rsa;

#[cfg(feature = "dangerous-rsa-sha1")]
pub(crate) use self::rsa::RsaSha1;
pub(crate) use self::rsa::RsaSha256;
pub(crate) use ed25519::Ed25519;

/// # 公钥算法
/// 主要用于对服务端签名的验证

pub trait PublicKey: Send + Sync {
    fn new() -> Self
    where
        Self: Sized;
    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError>;
}

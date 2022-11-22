use crate::SshError;

mod ed25519;
mod rsa;

#[cfg(feature = "dangerous-rsa-sha1")]
use self::rsa::RsaSha1;
use self::rsa::RsaSha256;
use self::rsa::RsaSha512;
use super::PubKey;
use ed25519::Ed25519;

/// # 公钥算法
/// 主要用于对服务端签名的验证

pub(crate) trait PublicKey: Send + Sync {
    fn new() -> Self
    where
        Self: Sized;
    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError>;
}

pub(crate) fn from(s: &PubKey) -> Box<dyn PublicKey> {
    match s {
        PubKey::SshEd25519 => Box::new(Ed25519::new()),
        #[cfg(feature = "dangerous-rsa-sha1")]
        PubKey::SshRsa => Box::new(RsaSha1::new()),
        PubKey::RsaSha2_256 => Box::new(RsaSha256::new()),
        PubKey::RsaSha2_512 => Box::new(RsaSha512::new()),
    }
}

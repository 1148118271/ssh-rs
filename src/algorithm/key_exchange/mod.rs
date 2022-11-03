use crate::algorithm::hash::HashType;
use crate::{SshError, SshResult};
use ring::agreement;
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey};

/// # 密钥交换方法
///
/// 密钥交换方法规定如何生成用于加密和验证的一次性会话密钥，以及如何进行服务器验证。
///
pub(crate) mod curve25519;
pub(crate) mod ecdh_sha2_nistp256;

pub trait KeyExchange: Send + Sync {
    fn new() -> SshResult<Self>
    where
        Self: Sized;
    fn get_public_key(&self) -> &[u8];
    fn get_shared_secret(&self, puk: Vec<u8>) -> SshResult<Vec<u8>>;
    fn get_hash_type(&self) -> HashType;
}

pub(crate) fn agree_ephemeral<B: AsRef<[u8]>>(
    private_key: EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
) -> SshResult<Vec<u8>> {
    match agreement::agree_ephemeral(
        private_key,
        peer_public_key,
        ring::error::Unspecified,
        |_key_material| Ok(_key_material.to_vec()),
    ) {
        Ok(o) => Ok(o),
        Err(_) => Err(SshError::from("encryption error.")),
    }
}

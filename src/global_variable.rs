use std::sync::atomic::{AtomicBool, AtomicU32};
use crate::encryption::ChaCha20Poly1305;
use crate::error::SshErrorKind;
use crate::SshError;

// 客户端通道编号初始值
pub(crate) static CLIENT_CHANNEL: AtomicU32 = AtomicU32::new(0);
// 服务端通道编号初始值
// pub(crate) static SERVER_CHANNEL: AtomicU32 = AtomicU32::new(0);

// 密钥是否交换完成 true 是  false 否
pub(crate) static IS_ENCRYPT: AtomicBool = AtomicBool::new(false);

// 加密密钥
pub(crate) static mut ENCRYPTION_KEY: Option<ChaCha20Poly1305> = None;

pub(crate) fn encryption_key() -> Result<&'static mut ChaCha20Poly1305, SshError>  {
    unsafe {
        match &mut ENCRYPTION_KEY {
            None => Err(SshError::from(SshErrorKind::EncryptionError)),
            Some(v) => Ok(v)
        }
    }
}
pub(crate) fn update_encryption_key(v: Option<ChaCha20Poly1305>) {
    unsafe {
        ENCRYPTION_KEY = v
    }
}
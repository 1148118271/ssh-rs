use std::sync::atomic::AtomicU32;
use encryption::ChaCha20Poly1305;


// 客户端通道编号初始值
pub(crate) static CLIENT_CHANNEL: AtomicU32 = AtomicU32::new(0);

// 加密密钥
pub(crate) static mut ENCRYPTION_KEY: Option<ChaCha20Poly1305> = None;


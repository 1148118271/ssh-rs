use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::Mutex;
use encryption::ChaCha20Poly1305;
use crate::Config;


// 客户端通道编号初始值
pub(crate) static CLIENT_CHANNEL: AtomicU32 = AtomicU32::new(0);

pub(crate) static mut CONFIG: Option<Mutex<Config>> = None;

// 加密密钥
pub(crate) static mut ENCRYPTION_KEY: Option<ChaCha20Poly1305> = None;


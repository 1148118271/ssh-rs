use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Mutex, MutexGuard};
use crate::encryption::ChaCha20Poly1305;
use crate::error::SshErrorKind;
use crate::slog::Slog;
use crate::{Config, Client, SshError, SshResult};



// 客户端通道编号初始值
pub(crate) static CLIENT_CHANNEL: AtomicU32 = AtomicU32::new(0);

// 密钥是否交换完成 true 是  false 否
pub(crate) static IS_ENCRYPT: AtomicBool = AtomicBool::new(false);

pub(crate) static SLOG: Slog = Slog;

pub(crate) static mut CLIENT: Option<Mutex<Client>> = None;

pub(crate) static mut CONFIG: Option<Mutex<Config>> = None;

// 加密密钥
pub(crate) static mut ENCRYPTION_KEY: Option<ChaCha20Poly1305> = None;
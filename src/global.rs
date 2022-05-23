use std::sync::atomic::AtomicU32;


// 客户端通道编号初始值
pub(crate) static CLIENT_CHANNEL: AtomicU32 = AtomicU32::new(0);


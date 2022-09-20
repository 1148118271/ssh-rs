
mod chacha20_poly1305_openssh;
mod aes_ctr_128;

use std::rc::Rc;
use std::sync::atomic::AtomicBool;

pub(crate) use {
    chacha20_poly1305_openssh::ChaCha20Poly1305,
    aes_ctr_128::AesCtr128
};
use crate::algorithm::hash::hash::HASH;
use crate::algorithm::mac::Mac;
use crate::SshResult;


/// # 加密算法
/// 在密钥交互中将协商出一种加密算法和一个密钥。当加密生效时，每个数据包的数据包长度、填
/// 充长度、有效载荷和填充域必须使用给定的算法加密。
/// 所有从一个方向发送的数据包中的加密数据应被认为是一个数据流。例如，初始向量应从一个数
/// 据包的结束传递到下一个数据包的开始。所有加密器应使用有效密钥长度为 128 位或以上的密
/// 钥。
/// 两个方向上的加密器必须独立运行。如果本地策略允许多种算法，系统实现必须允许独立选择每
/// 个方向上的算法。但是，在实际使用中，推荐在两个方向上使用相同的算法。


pub trait Encryption {
    fn bsize(&self) -> usize;
    fn iv_size(&self) -> usize;
    fn new(hash: HASH, mac: Box<dyn Mac>) -> Self where Self: Sized;
    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>);
    fn decrypt(&mut self, sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>>;
    fn packet_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize;
    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize;
    fn is_cp(&self) -> bool;
}
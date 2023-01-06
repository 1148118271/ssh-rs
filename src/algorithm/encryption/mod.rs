mod aes_ctr;
mod chacha20_poly1305_openssh;

use crate::algorithm::hash::Hash;
use crate::algorithm::mac::Mac;
use crate::SshResult;

use super::{hash::HashCtx, mac::MacNone, Enc};

/// # 加密算法
/// 在密钥交互中将协商出一种加密算法和一个密钥。当加密生效时，每个数据包的数据包长度、填
/// 充长度、有效载荷和填充域必须使用给定的算法加密。
/// 所有从一个方向发送的数据包中的加密数据应被认为是一个数据流。例如，初始向量应从一个数
/// 据包的结束传递到下一个数据包的开始。所有加密器应使用有效密钥长度为 128 位或以上的密
/// 钥。
/// 两个方向上的加密器必须独立运行。如果本地策略允许多种算法，系统实现必须允许独立选择每
/// 个方向上的算法。但是，在实际使用中，推荐在两个方向上使用相同的算法。
pub(crate) trait Encryption: Send + Sync {
    fn bsize(&self) -> usize;
    fn iv_size(&self) -> usize;
    fn group_size(&self) -> usize;
    fn new(hash: Hash, mac: Box<dyn Mac>) -> Self
    where
        Self: Sized;
    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>);
    fn decrypt(&mut self, sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>>;
    fn packet_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize;
    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize;
    fn is_cp(&self) -> bool;
}

pub(crate) fn from(s: &Enc, hash: Hash, mac: Box<dyn Mac>) -> Box<dyn Encryption> {
    match s {
        Enc::Chacha20Poly1305Openssh => {
            Box::new(chacha20_poly1305_openssh::ChaCha20Poly1305::new(hash, mac))
        }
        Enc::Aes128Ctr => Box::new(aes_ctr::Ctr128::new(hash, mac)),
        Enc::Aes192Ctr => Box::new(aes_ctr::Ctr192::new(hash, mac)),
        Enc::Aes256Ctr => Box::new(aes_ctr::Ctr256::new(hash, mac)),
    }
}

pub(crate) struct EncryptionNone {}

impl Encryption for EncryptionNone {
    fn bsize(&self) -> usize {
        8
    }
    fn iv_size(&self) -> usize {
        8
    }

    fn group_size(&self) -> usize {
        8
    }

    fn new(_hash: Hash, _mac: Box<dyn Mac>) -> Self
    where
        Self: Sized,
    {
        Self {}
    }
    fn encrypt(&mut self, _client_sequence_num: u32, _buf: &mut Vec<u8>) {
        // do nothing
    }
    fn decrypt(&mut self, _sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        Ok(buf.to_vec())
    }
    fn packet_len(&mut self, _sequence_number: u32, buf: &[u8]) -> usize {
        u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize
    }
    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
        self.packet_len(sequence_number, buf) + 4
    }
    fn is_cp(&self) -> bool {
        false
    }
}

impl Default for EncryptionNone {
    fn default() -> Self {
        let hash = Hash::new(HashCtx::new(), &[], super::hash::HashType::None);
        let mac = Box::new(MacNone::new());
        Self::new(hash, mac)
    }
}

mod ed25519;
mod chacha20_poly1305_openssh;
mod rsa;
mod aes_ctr;

use std::sync::atomic::AtomicBool;
pub use ring::digest;

pub use {
    ed25519::Ed25519,
    chacha20_poly1305_openssh::ChaCha20Poly1305,
    self::rsa::RSA,
    aes_ctr::AesCtr
};
use crate::error::{SshError, SshErrorKind};
use crate::data::Data;


// 密钥是否交换完成 true 是  false 否
pub static IS_ENCRYPT: AtomicBool = AtomicBool::new(false);

// 加密密钥
pub(crate) static mut ENCRYPTION_KEY: Option<AesCtr> = None;




pub fn encryption_key() -> Result<&'static mut AesCtr, SshError>  {
    unsafe {
        match &mut ENCRYPTION_KEY {
            None => {
                Err(SshError::from(SshErrorKind::EncryptionNullError))
            },
            Some(v) => Ok(v)
        }
    }
}
pub fn update_encryption_key(v: Option<AesCtr>) {
    unsafe {
        ENCRYPTION_KEY = v
    }
}



// pub type DH = dyn KeyExchange;
//
// pub trait KeyExchange: Send + Sync {
//     fn new() -> Result<Self, SshError> where Self: Sized;
//     fn get_public_key(&self) -> &[u8];
//     fn get_shared_secret(&self, puk: Vec<u8>) -> Result<Vec<u8>, SshError>;
// }

pub type SIGN = dyn PublicKey;

pub trait PublicKey: Send + Sync {
    fn new() -> Self where Self: Sized;
    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError>;
}


// /// 交换哈希 H , 也被用作会话标识
// /// 它是一个对该连接的唯一标识。它是验证方法中
// /// 被签名（以证明拥有私钥）的数据的一部分
// #[derive(Clone)]
// pub struct H {
//     // 客户端的版本， u32数组长度 + 数组 不包含 /r/n
//     pub v_c: Vec<u8>,
//     // 服务端的版本， u32数组长度 + 数组， 不包含 /r/n
//     pub v_s: Vec<u8>,
//     // 客户端算法 不包含 PacketLength PaddingLength  PaddingString
//     // 客户端密钥交换信息数组，u32数组长度 + 数组
//     pub i_c: Vec<u8>,
//     // 服务端算法 同客户端
//     pub i_s: Vec<u8>,
//     // 主机密钥 服务端发过来的host key 整体数据
//     pub k_s: Vec<u8>,
//     // 客户端公钥 u32数组长度 + 数组
//     pub q_c: Vec<u8>,
//     // 服务端公钥 u32数组长度 + 数组
//     pub q_s: Vec<u8>,
//     // 共享密钥 u32数组长度 + 数组
//     pub k  : Vec<u8>,
// }
//
// impl H {
//     pub fn new() -> Self {
//         H {
//             v_c: vec![],
//             v_s: vec![],
//             i_c: vec![],
//             i_s: vec![],
//             k_s: vec![],
//             q_c: vec![],
//             q_s: vec![],
//             k: vec![]
//         }
//     }
//
//
//     pub fn set_v_c(&mut self, vc: &str) {
//         let mut data = Data::new();
//         data.put_str(vc);
//         self.v_c = data.to_vec();
//     }
//     pub fn set_v_s(&mut self, vs: &str) {
//         let mut data = Data::new();
//         data.put_str(vs);
//         self.v_s = data.to_vec();
//     }
//     pub fn set_i_c(&mut self, ic: &[u8]) {
//         let mut data = Data::new();
//         data.put_u8s(ic);
//         self.i_c = data.to_vec();
//     }
//     pub fn set_i_s(&mut self, is: &[u8]) {
//         let mut data = Data::new();
//         data.put_u8s(is);
//         self.i_s = data.to_vec();
//     }
//     pub fn set_q_c(&mut self, qc: &[u8]) {
//         let mut data = Data::new();
//         data.put_u8s(qc);
//         self.q_c = data.to_vec();
//     }
//     pub fn set_q_s(&mut self, qs: &[u8]) {
//         let mut data = Data::new();
//         data.put_u8s(qs);
//         self.q_s = data.to_vec();
//     }
//     pub fn set_k_s(&mut self, ks: &[u8]) {
//         let mut data = Data::new();
//         data.put_u8s(ks);
//         self.k_s = data.to_vec();
//     }
//     pub fn set_k(&mut self, k: &[u8]) {
//         let mut data = Data::new();
//         data.put_mpint(k);
//         self.k = data.to_vec();
//     }
//
//
//     pub fn as_bytes(&mut self) -> Vec<u8> {
//         let mut v = vec![];
//         v.extend(& self.v_c);
//         v.extend(& self.v_s);
//         v.extend(& self.i_c);
//         v.extend(& self.i_s);
//         v.extend(& self.k_s);
//         v.extend(& self.q_c);
//         v.extend(& self.q_s);
//         v.extend(& self.k);
//         v
//     }
//
// }
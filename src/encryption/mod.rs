mod curve25519;
pub mod ed25519;
mod chacha20_poly1305_openssh;
mod ecdh_sha2_nistp256;
pub mod rsa;

pub use curve25519::CURVE25519;
pub use ecdh_sha2_nistp256::EcdhP256;
pub use chacha20_poly1305_openssh::ChaCha20Poly1305;


use crate::packet::Data;
use crate::SshError;

pub type DH = dyn KeyExchange;

pub trait KeyExchange {
    fn new() -> Result<Self, SshError> where Self: Sized;
    fn get_public_key(&self) -> &[u8];
    fn get_shared_secret(&self, puk: Vec<u8>) -> Result<Vec<u8>, SshError>;
}

pub type SIGN = dyn PublicKey;

pub trait PublicKey {
    fn new() -> Self where Self: Sized;
    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError>;
}



#[derive(Clone)]
pub struct H {
    // 客户端的版本， u32数组长度 + 数组 不包含 /r/n
    pub v_c: Vec<u8>,
    // 服务端的版本， u32数组长度 + 数组， 不包含 /r/n
    pub v_s: Vec<u8>,
    // 客户端算法 不包含 PacketLength PaddingLength  PaddingString
    // 客户端密钥交换信息数组，u32数组长度 + 数组
    pub i_c: Vec<u8>,
    // 服务端算法 同客户端
    pub i_s: Vec<u8>,
    // 主机密钥 服务端发过来的host key 整体数据
    pub k_s: Vec<u8>,
    // 客户端公钥 u32数组长度 + 数组
    pub q_c: Vec<u8>,
    // 服务端公钥 u32数组长度 + 数组
    pub q_s: Vec<u8>,
    // 共享密钥 u32数组长度 + 数组
    pub k  : Vec<u8>,
}

impl H {
    pub fn new() -> Self {
        H {
            v_c: vec![],
            v_s: vec![],
            i_c: vec![],
            i_s: vec![],
            k_s: vec![],
            q_c: vec![],
            q_s: vec![],
            k: vec![]
        }
    }


    pub fn set_v_c(&mut self, vc: &str) {
        let mut data = Data::new();
        data.put_str(vc);
        self.v_c = data.to_vec();
    }
    pub fn set_v_s(&mut self, vs: &str) {
        let mut data = Data::new();
        data.put_str(vs);
        self.v_s = data.to_vec();
    }
    pub fn set_i_c(&mut self, ic: &[u8]) {
        let mut data = Data::new();
        data.put_bytes(ic);
        self.i_c = data.to_vec();
    }
    pub fn set_i_s(&mut self, is: &[u8]) {
        let mut data = Data::new();
        data.put_bytes(is);
        self.i_s = data.to_vec();
    }
    pub fn set_q_c(&mut self, qc: &[u8]) {
        let mut data = Data::new();
        data.put_bytes(qc);
        self.q_c = data.to_vec();
    }
    pub fn set_q_s(&mut self, qs: &[u8]) {
        let mut data = Data::new();
        data.put_bytes(qs);
        self.q_s = data.to_vec();
    }
    pub fn set_k_s(&mut self, ks: &[u8]) {
        let mut data = Data::new();
        data.put_bytes(ks);
        self.k_s = data.to_vec();
    }
    pub fn set_k(&mut self, k: &[u8]) {
        let mut data = Data::new();
        data.mpint(k);
        self.k = data.to_vec();
    }


    pub fn as_bytes(&mut self) -> Vec<u8> {
        let mut v = vec![];
        v.extend(& self.v_c);
        v.extend(& self.v_s);
        v.extend(& self.i_c);
        v.extend(& self.i_s);
        v.extend(& self.k_s);
        v.extend(& self.q_c);
        v.extend(& self.q_s);
        v.extend(& self.k);
        v
    }

}
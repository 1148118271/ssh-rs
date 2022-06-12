use std::borrow::BorrowMut;
use crate::data::Data;

/// 密钥交换产生两个值：一个共享秘密 K，以及一个交换哈希 H。加密和验证密钥来自它们。第一
/// 次密钥交换的交换哈希 H 也被用作会话标识，它是一个对该连接的唯一标识。它是验证方法中
/// 被签名（以证明拥有私钥）的数据的一部分。会话标识被计算出来后，即使后来重新交换了密钥，
/// 也不会改变。
///
///
/// H = hash algorithm(v_c | v_s | i_c | i_s | k_s | q_c | q_s | k)
///
///


static mut H_VAL: H = H::new();


pub(crate) fn get() -> &'static mut H {
    unsafe {
        H_VAL.borrow_mut()
    }
}



#[derive(Clone)]
pub(crate) struct H {

    /// 一下数据如果有从数据包解析的数据
    /// 统一不包含数据包里面的 PacketLength PaddingLength  PaddingString

    /// 数据统一转为 [bytes]

    /// 双方(客户端/服务端)的版本，
    /// 数据长度 + 数据， 不包含 /r/n
    /// 数据长度 [u32]
    /// 数据    [str]
    pub(crate) v_c: Vec<u8>,
    pub(crate) v_s: Vec<u8>,


    /// 双方(客户端/服务端)交换的算法，
    /// 数据长度 + 数据
    /// 数据长度 [u32]
    /// 数据(客户端密钥交换信息数组) [`[str, str ...]`]
    pub(crate) i_c: Vec<u8>,
    pub(crate) i_s: Vec<u8>,

    /// 主机密钥
    /// 服务端发过来的host key 整体数据
    pub(crate) k_s: Vec<u8>,

    /// 双方(客户端/服务端)的公钥，
    /// 数据长度 + 数据
    /// 数据长度 [u32]
    /// 数据(客户端密钥交换信息数组) [bytes]
    pub(crate) q_c: Vec<u8>,
    pub(crate) q_s: Vec<u8>,

    /// 共享密钥
    /// 二进制补码 + 数据
    pub(crate) k  : Vec<u8>,
}

impl H {
    pub(crate) const fn new() -> Self {
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


    pub(crate) fn set_v_c(&mut self, vc: &str) {
        let mut data = Data::new();
        data.put_str(vc);
        self.v_c = data.to_vec();
    }
    pub(crate) fn set_v_s(&mut self, vs: &str) {
        let mut data = Data::new();
        data.put_str(vs);
        self.v_s = data.to_vec();
    }
    pub(crate) fn set_i_c(&mut self, ic: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(ic);
        self.i_c = data.to_vec();
    }
    pub(crate) fn set_i_s(&mut self, is: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(is);
        self.i_s = data.to_vec();
    }
    pub(crate) fn set_k_s(&mut self, ks: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(ks);
        self.k_s = data.to_vec();
    }
    pub(crate) fn set_q_c(&mut self, qc: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(qc);
        self.q_c = data.to_vec();
    }
    pub(crate) fn set_q_s(&mut self, qs: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(qs);
        self.q_s = data.to_vec();
    }
    pub(crate) fn set_k(&mut self, k: &[u8]) {
        let mut data = Data::new();
        data.put_mpint(k);
        self.k = data.to_vec();
    }


    pub(crate) fn as_bytes(&mut self) -> Vec<u8> {
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
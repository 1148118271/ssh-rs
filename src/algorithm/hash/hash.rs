use super::hash_ctx::HashCtx;
use crate::algorithm::hash;
use crate::algorithm::hash::HashType;
use crate::constant;

/// 加密密钥必须是对一个已知值和 K 的 HASH 结果，方法如下：
/// ○ 客户端到服务器的初始 IV：HASH(K || H || "A" || session_id)（这里 K 为 mpint
/// 格式，"A"为 byte 格式，session_id 为原始数据（raw data）。"A"是单个字母 A，
/// ASCII 65）。
/// ○ 服务器到客户端的初始 IV：HASH(K || H || "B" || session_id)
/// ○ 客户端到服务器的加密密钥：HASH(K || H || "C" || session_id)
/// ○ 服务器到客户端的加密密钥：HASH(K || H || "D" || session_id)
/// ○ 客户端到服务器的完整性密钥：HASH(K || H || "E" || session_id)
/// ○ 服务器到客户端的完整性密钥：HASH(K || H || "F" || session_id)
/// 密钥数据必须从哈希输出的开头开始取。即从哈希值的开头开始，取所需数量的字节。如果需要
/// 的密钥长度超过 HASH 输出，则拼接 K、H 和当前的整个密钥并计算其 HASH，然后将 HASH 产
/// 生的字节附加到密钥尾部。重复该过程，直到获得了足够的密钥材料；密钥从该值的开头开始取
/// 换句话说：
/// K1 = HASH(K || H || X || session_id)（X 表示"A"等）
/// K2 = HASH(K || H || K1)
/// K3 = HASH(K || H || K1 || K2)
/// ...
/// key = K1 || K2 || K3 || ...
/// 如果 K 的熵比 HASH 的内状态（internal state）大小要大，则该过程将造成熵的丢失。

pub struct Hash {
    /// 数据加密时只使用一次的随机数  number used once
    pub iv_c_s: Vec<u8>,
    pub iv_s_c: Vec<u8>,

    /// 数据加密的 key
    pub ek_c_s: Vec<u8>,
    pub ek_s_c: Vec<u8>,

    /// Hmac时候用到的 key
    pub ik_c_s: Vec<u8>,
    pub ik_s_c: Vec<u8>,

    hash_type: HashType,
    hash_ctx: HashCtx,
}

impl Hash {
    pub fn new(hash_ctx: HashCtx, session_id: &[u8], hash_type: HashType) -> Self {
        let k = hash_ctx.k.as_slice();
        let h = hash::digest(&hash_ctx.as_bytes(), hash_type);
        let mut keys = vec![];
        for v in constant::ALPHABET {
            keys.push(Hash::mix(k, &h, v, session_id, hash_type));
        }
        Hash {
            iv_c_s: keys[0].clone(),
            iv_s_c: keys[1].clone(),

            ek_c_s: keys[2].clone(),
            ek_s_c: keys[3].clone(),

            ik_c_s: keys[4].clone(),
            ik_s_c: keys[5].clone(),

            hash_type,
            hash_ctx,
        }
    }

    fn mix(k: &[u8], h: &[u8], key_char: u8, session_id: &[u8], hash_type: HashType) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::new();
        key.extend(k);
        key.extend(h);
        key.push(key_char);
        key.extend(session_id);
        hash::digest(key.as_slice(), hash_type)
    }

    pub fn mix_ek(&self, key_size: usize) -> (Vec<u8>, Vec<u8>) {
        let mut ck = self.ek_c_s.to_vec();
        let mut sk = self.ek_s_c.to_vec();
        while key_size > ck.len() {
            ck.extend(self.extend(ck.as_slice()));
            sk.extend(self.extend(sk.as_slice()));
        }
        (ck, sk)
    }

    pub fn mix_ik(&self, key_size: usize) -> (Vec<u8>, Vec<u8>) {
        let mut ck = self.ik_c_s.to_vec();
        let mut sk = self.ik_s_c.to_vec();
        while key_size > ck.len() {
            ck.extend(self.extend(ck.as_slice()));
            sk.extend(self.extend(sk.as_slice()));
        }
        (ck, sk)
    }

    fn extend(&self, key: &[u8]) -> Vec<u8> {
        let k = self.hash_ctx.k.clone();
        let h = hash::digest(self.hash_ctx.as_bytes().as_slice(), self.hash_type);
        let mut hash: Vec<u8> = Vec::new();
        hash.extend(k);
        hash.extend(h);
        hash.extend(key);
        hash::digest(hash.as_slice(), self.hash_type)
    }
}

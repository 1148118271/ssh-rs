use crate::packet::Data;

pub fn init() -> Vec<u8> {
    let mut data = Data::new();
    for x in ALGORITHMS {
        data.put_str(x);
    }
    data.to_vec()
}

pub const ALGORITHMS: [&str; 8] = [
    KEY_EXCHANGE_ALGORITHMS,
    PUBLIC_KEY_ALGORITHMS,
    ENCRYPTION_ALGORITHMS,
    ENCRYPTION_ALGORITHMS,
    MAC_ALGORITHMS,
    MAC_ALGORITHMS,
    COMPRESSION_ALGORITHMS,
    COMPRESSION_ALGORITHMS,
];


// 密钥交换算法
pub const KEY_EXCHANGE_ALGORITHMS: &str = "curve25519-sha256";

// 公钥算法
pub const PUBLIC_KEY_ALGORITHMS: &str = "ssh-ed25519";

// 对称加密算法
pub const ENCRYPTION_ALGORITHMS: &str = "chacha20-poly1305@openssh.com";

// 哈希散列算法
pub const MAC_ALGORITHMS: &str = "none";

// 压缩算法
pub const COMPRESSION_ALGORITHMS: &str = "none";
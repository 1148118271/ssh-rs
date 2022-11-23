/// 密钥交换对应的hash算法
#[derive(Copy, Clone)]
pub enum HashType {
    None,
    SHA1,
    SHA256,
}

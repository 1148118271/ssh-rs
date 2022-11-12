use std::ops::{Deref, DerefMut};

use crate::error::SshResult;

use super::Packet;

/// **byte**
/// byte 标识任意一个 8 位值（8 位字节）。固定长度的数据有时被表示为一个字节数组，写
/// 作 byte[[n]]，其中 n 是数组中字节的数量。
///
/// **boolean**
/// 一个布尔值作为一个字节存储。0 表示 FALSE，1 表示 TRUE。所有非零的值必须被解释为
/// TRUE；但是，应用软件禁止储存除 0 和 1 以外的值。
///
/// **uint32**
/// 表示一个 32 位无符号整数。按重要性降序（网络字节顺序）储存为 4 个字节。
///
/// **uint64**
/// 表示一个 64 位无符号整数。按重要性降序（网络字节顺序）储存为 8 个字节。
///
/// **string**
/// 任意长度二进制字符串。字符串用于装载任意二进制数据，包括空字符和 8 位字符。字符
/// 串被储存为 1 个包含其长度（后续字节数量）的 uint32 以及 0（=空字符串）或作为字符
/// 串的值的更多的字节。不使用终结符（空字符）。
/// 字符串也被用来存储文本。在这种情况下，内部名称使用 US-ASCII，可能显示给用户的
/// 文本使用 ISO-10646 UTF-8。终结符（空字符）一般不应被保存在字符串中。例如，
/// US-ASCII 字符串”testing”被表示为 00 00 00 07 t e s t i n g。UTF-8 映射不
/// 改变 US-ASCII 字符的编码。
///
/// **mpint**
/// 表示二进制补码（two’s complement）格式的多精度整数，存储为一个字符串，每字节
/// 8 位，从高位到低位（MSB first）。负数的数据区的首字节的最高位（the most
/// significant bit）的值为 1。对于正数，如果最高位将被置为 1，则必须在前面加一个
/// 值为 0 的字节。禁止包含值为 0 或 255 的非必要的前导字节（leading bytes）。零必
/// 须被存储为具有 0 个字节的数据的字符串。
///
/// **name-list**
/// 一个包含逗号分隔的名称列表的字符串。名称列表表示为一个含有其长度（后续字节数量）
/// 的 uint32，加上一个包含 0 或多个逗号分隔的名称的列表。名称的长度禁止为 0，并且禁
/// 止包含逗号(",")。由于这是一个名称列表，所有被包含的元素都是名称并且必须使用
/// US-ASCII。上下文可能对名称有附加的限制。例如，名称列表中的名称可能必须是一系列
/// 有效的算法标识，或一系列[[RFC3066]]语言标识。名称列表中名称的顺序可能有也可能没
/// 有意义。这取决于使用列表时的上下文。对单个名称或整个列表都禁止使用终结字符（空
/// 字符）。
///
#[derive(Debug, Clone)]
pub(crate) struct Data(Vec<u8>);

impl Default for Data {
    fn default() -> Self {
        Self::new()
    }
}

impl Data {
    pub fn new() -> Data {
        Data(Vec::new())
    }

    #[allow(clippy::uninit_vec)]
    pub fn uninit_new(len: usize) -> Data {
        let mut v = Vec::with_capacity(len);
        unsafe { v.set_len(len) }
        Data(v)
    }

    // 无符号字节 8位
    pub fn put_u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    // 32位无符号整型
    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        let vec = v.to_be_bytes().to_vec();
        self.0.extend(&vec);
        self
    }

    // 字符串型数据
    // 需要计算字符串长度
    pub fn put_str(&mut self, str: &str) -> &mut Self {
        let v = str.as_bytes();
        self.put_u32(v.len() as u32);
        self.0.extend(v);
        self
    }

    // 字节数组
    // 需要计算数组长度
    pub fn put_u8s(&mut self, v: &[u8]) -> &mut Self {
        self.put_u32(v.len() as u32);
        self.0.extend(v);
        self
    }

    // 表示二进制补码（two’s complement）格式的多精度整数
    // 存储为一个字符串，每字节8 位，从高位到低位（MSB first）。
    // 负数的数据区的首字节的最高位（the most significant bit）的值为 1。
    // 对于正数，如果最高位将被置为 1，则必须在前面加一个值为 0 的字节。
    // 禁止包含值为 0 或 255 的非必要的前导字节（leading bytes）。
    // 零必须被存储为具有 0 个字节的数据的字符串。
    pub fn put_mpint(&mut self, v: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        // 0x80 = 128
        if v[0] & 0x80 != 0 {
            result.push(0);
        }
        result.extend(v);
        self.put_u8s(&result).to_vec()
    }

    // 跳过多少位数据
    pub fn skip(&mut self, size: usize) {
        self.0.drain(..size);
    }

    // 获取字节
    pub fn get_u8(&mut self) -> u8 {
        self.0.remove(0)
    }

    // 获取32位无符号整型
    pub fn get_u32(&mut self) -> u32 {
        let u32_buf = self.0.drain(..4).into_iter().collect::<Vec<u8>>();
        u32::from_be_bytes(u32_buf.try_into().unwrap())
    }

    // 获取字节数组
    pub fn get_u8s(&mut self) -> Vec<u8> {
        let len = self.get_u32() as usize;
        let bytes = self.0.drain(..len).into_iter().collect::<Vec<u8>>();
        bytes
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Data(v)
    }
}

impl From<&[u8]> for Data {
    fn from(v: &[u8]) -> Self {
        Data(v.into())
    }
}

impl From<Data> for Vec<u8> {
    fn from(data: Data) -> Self {
        data.0
    }
}

impl Deref for Data {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Data {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> Packet<'a> for Data {
    fn pack(self, client: &'a mut crate::client::Client) -> super::packet::SecPacket<'a> {
        (self, client).into()
    }
    fn unpack(pkt: super::packet::SecPacket) -> SshResult<Self>
    where
        Self: Sized,
    {
        Ok(pkt.into_inner())
    }
}

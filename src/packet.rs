use std::ops::{Deref, DerefMut};
use std::sync::atomic::Ordering::Relaxed;
use crate::global_variable;

#[derive(Debug)]
pub struct Packet(Data);


impl Packet {

    pub(crate) fn processing_data(d: Vec<u8>) -> Data {
        let padding_length = *(&d[4]);
        let vec = (&d[5..(d.len() - padding_length as usize)]).to_vec();
        Data(vec)
    }

    pub(crate) fn from(d: Data) -> Packet {
        Packet(d)
    }

    pub(crate) fn new() -> Packet {
        Packet(Data::new())
    }

    pub(crate) fn put_data(&mut self, d: Data) {
        self.0 = d;
    }

    pub(crate) fn refresh(&mut self) {
        self.0 = Data::new();
    }

    pub(crate) fn build(&mut self) {
        let data_len =  self.0.len() as u32;
        let mut padding_len =
            match global_variable::IS_ENCRYPT.load(Relaxed)  {
                true => 8 - (data_len + 1) % 8,
                false => 16 - (data_len + 5) % 16
            };
        if padding_len < 4 { padding_len += 8 }

        // 组装数据
        let mut buf = vec![];

        buf.push(padding_len as u8);

        buf.extend(&self.0.to_vec());

        buf.extend(vec![0; padding_len as usize]);

        let packet_len = buf.len() as u32;

        let packet_len_u8s= packet_len.to_be_bytes().to_vec();

        self.refresh();

        self.0.extend(packet_len_u8s);
        self.0.extend(buf);
    }


    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

}

// 数据
// 不包含数据包其他必须字段的数据
#[derive(Debug)]
pub(crate) struct Data(pub(crate) Vec<u8>);

impl Data {

    pub fn new() -> Data {
        Data { 0: vec![] }
    }

    pub(crate) fn refresh(&mut self) {
        self.0 = vec![]
    }

    // 字节数据
    pub(crate) fn put_u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    // u32 integer 类型数据
    pub(crate) fn put_u32(&mut self, v: u32) -> &mut Self {
        let vec = v.to_be_bytes().to_vec();
        self.0.extend(&vec);
        self
    }

    // 字符型数据 并且计算长度
    pub(crate) fn put_str(&mut self, str: &str) -> &mut Self {
        let v = str.as_bytes();
        self.put_u32(v.len() as u32);
        self.0.extend(v);
        self
    }

    // 字节数组数据 并且计算长度
    pub(crate) fn put_bytes(&mut self, v: &[u8]) -> &mut Self {
        self.put_u32(v.len() as u32);
        self.0.extend(v);
        self
    }

    pub(crate) fn mpint(&mut self, v: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        // 0x80 = 128
        if v[0] & 0x80 != 0 {
            result.push(0);
        }
        result.extend(v);
        self.put_bytes(&result).to_vec()
    }

    pub(crate) fn skip(&mut self, size: usize) {
        self.0 = (&self.0[size..]).to_vec();
    }

    pub(crate) fn get_u8(&mut self) -> u8 {
        self.0.remove(0)
    }

    pub(crate) fn get_u32(&mut self) -> u32 {
        let mut a = (&self.0[0..4]).to_vec();
        self.0 = (&self.0[4..]).to_vec();
        a.reverse();
        unsafe {
            *(a.as_ptr() as *const u32)
        }
    }

    pub(crate) fn get_u8s(&mut self) -> Vec<u8> {
        let len = self.get_u32() as usize;
        let u8s = (&self.0[0_usize..len]).to_vec();
        self.0 = (&self.0[len..]).to_vec();
        u8s
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

use crate::algorithm::encryption::Encryption;
use crate::data::Data;


/// ## 数据包整体结构
///
/// ### uint32 `packet_length`
///
/// ### byte `padding_length`
///
/// ### byte[[n1]] `payload`; n1 = packet_length - padding_length - 1
///
/// ### byte[[n2]] `random padding`; n2 = padding_length
///
/// ### byte[[m]] `mac` (Message Authentication Code - MAC); m = mac_length
///
/// ---
///
/// **packet_length**
/// 以字节为单位的`数据包长度`，不包括`mac`或`packet_length`域自身。
///
///
/// **padding_length**
/// `random padding`的长度（字节）。
///
///
/// **payload**
/// 数据包中有用的内容。如果已经协商了压缩，该域是压缩的。初始时，压缩必须为"none"。
///
///
/// **random padding**
/// 任意长度的填充，使(packet_length || padding_length || payload || random padding)的总长度是加密分组长度或 8 中较大者的倍数。
/// 最少必须有 4 字节的填充。
/// 填充应包含随机字节。填充的最大长度为 255 字节。
///
///
/// **mac**
/// 消息验证码。如果已经协商了消息验证，该域包含 MAC。初始时，MAC 算法必须是"none"。

#[derive(Debug)]
pub struct Packet {
    data: Data,
    value: Vec<u8>
}


impl Packet {

    pub fn unpacking(&mut self) -> Data {
        if self.value.is_empty() {
            return Data::new()
        }
        let padding_length = *(&self.value[4]);
        let vec = (&self.value[5..(self.value.len() - padding_length as usize)]).to_vec();
        let data = Data::from(vec);
        self.data = data.clone();
        data
    }

    #[allow(dead_code)]
    pub fn refresh(&mut self) {
        self.value.clear();
        self.data = Data::new()
    }

    // 封包
    pub fn build(&mut self, encryption: Option<&Box<dyn Encryption>>, is_encrypt: bool) {
        let data_len =  self.data.len() as u32;
        let bsize = match is_encrypt {
                true => encryption.unwrap().bsize() as i32,
                // 未加密的填充: 整个包的总长度是8的倍数，并且填充长度不能小于4
                false => 8,
        };
        let padding_len = {
            let mut pad = (-((data_len +
                if is_encrypt && encryption.unwrap().is_cp() { 1 }
                else { 5 }) as i32))
                & (bsize - 1) as i32;
            if pad < bsize {
                pad += bsize;
            }
            pad as u32
        };
        // 组装数据 []
        let mut buf = vec![];
        // [padding_length]
        buf.push(padding_len as u8);
        // [padding_length, payload]
        buf.extend(self.data.as_slice());
        // [padding_length, payload, randomPadding]
        // 默认 0
        buf.extend(vec![0; padding_len as usize]);
        // 获取总长度
        let packet_len = buf.len() as u32;
        let mut packet_len_u8s= packet_len.to_be_bytes().to_vec();
        // [packet_length, padding_length, payload, randomPadding]
        packet_len_u8s.extend(buf);
        self.value = packet_len_u8s;
    }

    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.value.to_vec()
    }

}

impl From<Vec<u8>> for Packet {
    fn from(v: Vec<u8>) -> Self {
        Packet {
            data: Data::from(v.as_slice()),
            value: v
        }
    }
}

impl From<&[u8]> for Packet {
    fn from(v: &[u8]) -> Self {
        Packet {
            data: Data::from(v),
            value: v.to_vec()
        }
    }
}

impl From<Data> for Packet {
    fn from(d: Data) -> Self {
        let vec = d.as_slice().to_vec();
        Packet {
            data: d,
            value: vec
        }
    }
}

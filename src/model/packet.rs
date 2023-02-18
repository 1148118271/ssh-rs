use std::io::{Read, Write};
use std::time::Duration;

use crate::error::SshResult;
use crate::{client::Client, model::Data};

use super::timeout::Timeout;

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

fn read_with_timeout<S>(stream: &mut S, tm: Option<Duration>, buf: &mut [u8]) -> SshResult<()>
where
    S: Read,
{
    let want_len = buf.len();
    let mut offset = 0;
    let mut timeout = Timeout::new(tm);

    loop {
        match stream.read(&mut buf[offset..]) {
            Ok(i) => {
                offset += i;
                if offset == want_len {
                    return Ok(());
                } else {
                    timeout.renew();
                    continue;
                }
            }
            Err(e) => {
                if let std::io::ErrorKind::WouldBlock = e.kind() {
                    timeout.test()?;
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };
    }
}

fn try_read<S>(stream: &mut S, _tm: Option<Duration>, buf: &mut [u8]) -> SshResult<usize>
where
    S: Read,
{
    match stream.read(buf) {
        Ok(i) => Ok(i),
        Err(e) => {
            if let std::io::ErrorKind::WouldBlock = e.kind() {
                Ok(0)
            } else {
                Err(e.into())
            }
        }
    }
}

fn write_with_timeout<S>(stream: &mut S, tm: Option<Duration>, buf: &[u8]) -> SshResult<()>
where
    S: Write,
{
    let want_len = buf.len();
    let mut offset = 0;
    let mut timeout = Timeout::new(tm);

    loop {
        match stream.write(&buf[offset..]) {
            Ok(i) => {
                offset += i;
                if offset == want_len {
                    return Ok(());
                } else {
                    timeout.renew();
                    continue;
                }
            }
            Err(e) => {
                if let std::io::ErrorKind::WouldBlock = e.kind() {
                    timeout.test()?;
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };
    }
}

pub(crate) trait Packet<'a> {
    fn pack(self, client: &'a mut Client) -> SecPacket<'a>;
    fn unpack(pkt: SecPacket) -> SshResult<Self>
    where
        Self: Sized;
}

pub(crate) struct SecPacket<'a> {
    payload: Data,
    client: &'a mut Client,
}

impl<'a> SecPacket<'a> {
    pub fn write_stream<S>(self, stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        let tm = self.client.get_timeout();
        let payload_len = self.payload.len() as u32;
        let group_size = self.client.get_encryptor().group_size() as i32;
        let pad_len = {
            let mut pad = payload_len as i32;
            if self.client.get_encryptor().is_cp() {
                pad += 1;
            } else {
                pad += 5
            }
            pad = (-pad) & (group_size - 1);
            if pad < group_size {
                pad += group_size;
            }
            pad as u32
        } as u8;
        let packet_len = 1 + pad_len as u32 + payload_len;
        let mut buf = vec![];
        buf.extend(packet_len.to_be_bytes());
        buf.extend([pad_len]);
        buf.extend(self.payload.iter());
        buf.extend(vec![0; pad_len as usize]);
        let seq = self.client.get_seq().get_client();
        self.client.get_encryptor().encrypt(seq, &mut buf);
        write_with_timeout(stream, tm, &buf)
    }

    pub fn from_stream<S>(stream: &mut S, client: &'a mut Client) -> SshResult<Self>
    where
        S: Read,
    {
        let tm = client.get_timeout();
        let bsize = {
            let bsize = client.get_encryptor().bsize();
            if bsize > 8 {
                bsize
            } else {
                8
            }
        };

        // read the first block
        let mut first_block = vec![0; bsize];
        read_with_timeout(stream, tm, &mut first_block)?;

        // detect the total len
        let seq = client.get_seq().get_server();
        let data_len = client.get_encryptor().data_len(seq, &first_block);

        // read remain
        let mut data = Data::uninit_new(data_len);
        data[0..bsize].clone_from_slice(&first_block);
        read_with_timeout(stream, tm, &mut data[bsize..])?;

        // decrypt all
        let data = client.get_encryptor().decrypt(seq, &mut data)?;

        // unpacking
        let pkt_len = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let pad_len = data[4];
        let payload_len = pkt_len - pad_len as u32 - 1;

        let payload = data[5..payload_len as usize + 5].into();

        Ok(Self { payload, client })
    }

    pub fn try_from_stream<S>(stream: &mut S, client: &'a mut Client) -> SshResult<Option<Self>>
    where
        S: Read,
    {
        let tm = client.get_timeout();
        let bsize = {
            let bsize = client.get_encryptor().bsize();
            if bsize > 8 {
                bsize
            } else {
                8
            }
        };

        // read the first block
        let mut first_block = vec![0; bsize];
        let read = try_read(stream, tm, &mut first_block)?;
        if read == 0 {
            return Ok(None);
        }

        // detect the total len
        let seq = client.get_seq().get_server();
        let data_len = client.get_encryptor().data_len(seq, &first_block);

        // read remain
        let mut data = Data::uninit_new(data_len);
        data[0..bsize].clone_from_slice(&first_block);
        read_with_timeout(stream, tm, &mut data[bsize..])?;

        // decrypt all
        let data = client.get_encryptor().decrypt(seq, &mut data)?;

        // unpacking
        let pkt_len = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let pad_len = data[4];
        let payload_len = pkt_len - pad_len as u32 - 1;

        let payload = data[5..payload_len as usize + 5].into();

        Ok(Some(Self { payload, client }))
    }

    pub fn get_inner(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_inner(self) -> Data {
        self.payload
    }
}

impl<'a> From<(Data, &'a mut Client)> for SecPacket<'a> {
    fn from((d, c): (Data, &'a mut Client)) -> Self {
        Self {
            payload: d,
            client: c,
        }
    }
}

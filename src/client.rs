use std::io;
use std::io::Read;
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::ops::{Deref, DerefMut};
use crate::algorithm::encryption::Encryption;
use crate::constant::size;
use crate::data::Data;
use crate::error::{SshError, SshResult};
use crate::packet::Packet;
use crate::timeout::Timeout;
use crate::window_size::WindowSize;


pub struct Client {
    pub(crate) stream: TcpStream,
    pub(crate) sequence: Sequence,
    pub(crate) timeout: Timeout
}

#[derive(Clone)]
pub(crate) struct Sequence {
    pub(crate) client_sequence_num: u32,
    pub(crate) server_sequence_num: u32
}

impl Sequence {

    pub(crate) fn client_auto_increment(&mut self) {
        if self.client_sequence_num == u32::MAX {
            self.client_sequence_num = 0;
        }
        self.client_sequence_num += 1;
    }

    pub(crate) fn server_auto_increment(&mut self) {
        if self.server_sequence_num == u32::MAX {
            self.server_sequence_num = 0;
        }
        self.server_sequence_num += 1;
    }
}

impl Client {
    pub(crate) fn connect<A: ToSocketAddrs>(addr: A) -> SshResult<Client> {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                // default nonblocking
                stream.set_nonblocking(true).unwrap();

                Ok(
                    Client{
                        stream,
                        sequence: Sequence {
                            client_sequence_num: 0,
                            server_sequence_num: 0
                        },
                        timeout: Timeout::new()
                    }
                )
            }
            Err(e) => Err(SshError::from(e))
        }
    }


    pub(crate) fn close(&mut self) -> Result<(), SshError> {
        match self.stream.shutdown(Shutdown::Both) {
            Ok(o) => Ok(o),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub(crate) fn is_would_block(e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::WouldBlock
    }

}


// read util
impl Client {

    pub fn process_data(&mut self, mut result: Vec<u8>, results: &mut Vec<Data>) {
        // 未加密
        self.sequence.server_auto_increment();
        let packet_len = &result[..4];
        let mut packet_len_slice = [0_u8; 4];
        packet_len_slice.copy_from_slice(packet_len);
        let packet_len = (u32::from_be_bytes(packet_len_slice) as usize) + 4;
        // 唯一处理 server Key Exchange Reply 和 New Keys 会一块发
        if result.len() > packet_len {
            let (v1, v2) = result.split_at_mut(packet_len);
            let data = Packet::from(v1.to_vec()).unpacking();
            results.push(data);
            result = v2.to_vec();
        }
        let data = Packet::from(result).unpacking();
        results.push(data);
    }


    pub fn process_data_encrypt(&mut self,
                                mut result: Vec<u8>,
                                results: &mut Vec<Data>,
                                mut lws: Option<&mut WindowSize>,
                                encryption: &mut Box<dyn Encryption>
    ) -> SshResult<()>
    {
        loop {
            self.sequence.server_auto_increment();
            if result.len() < 4 {
                self.check_result_len(&mut result)?;
            }
            let data_len = encryption.data_len(self.sequence.server_sequence_num, result.as_slice());
            if result.len() < data_len {
                self.get_encrypt_data(&mut result, data_len)?;
            }
            let (this, remaining) = result.split_at_mut(data_len);
            let decryption_result =
                encryption.decrypt(self.sequence.server_sequence_num, &mut this.to_vec())?;
            let data = Packet::from(decryption_result).unpacking();
            // 判断是否需要修改窗口大小
            if let Some(v) = &mut lws {
               //  v.process_local_window_size(data.as_slice(), self)?
            }
            results.push(data);
            if remaining.len() <= 0 {
                break;
            }
            result = remaining.to_vec();
        }
        Ok(())
    }

    fn get_encrypt_data(&mut self, result: &mut Vec<u8>, data_len: usize) -> SshResult<()> {
        loop {
            let mut buf = vec![0; size::BUF_SIZE as usize];
            match self.stream.read(&mut buf) {
                Ok(len) => {
                    if len > 0 {
                        buf.truncate(len);
                        result.extend(buf);
                    }
                    if result.len() >= data_len {
                        return Ok(())
                    }
                },
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(SshError::from(e))
                }
            };
        }
    }

    fn check_result_len(&mut self, result: &mut Vec<u8>) -> SshResult<usize> {
        loop {
            let mut buf = vec![0; size::BUF_SIZE as usize];
            match self.stream.read(&mut buf) {
                Ok(len) => {
                    buf.truncate(len);
                    result.extend(buf);
                    if result.len() >= 4 {
                        return Ok(len)
                    }
                },
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(SshError::from(e))
                }
            };
        }
    }
}


// write util
impl Client {
    pub(crate) fn get_encryption_data(&self,
                                      data: Data,
                                      encryption:
                                      &mut Box<dyn Encryption>
    ) -> SshResult<Vec<u8>>
    {
        let mut packet = Packet::from(data);
        packet.build(Some(encryption),true);
        let mut buf = packet.to_vec();
        encryption.encrypt(self.sequence.client_sequence_num, &mut buf);
        Ok(buf)
    }
}

impl Deref for Client {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

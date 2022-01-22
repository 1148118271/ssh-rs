use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering::Relaxed;
use crate::{global, size};
use crate::channel::ChannelWindowSize;
use crate::encryption::ChaCha20Poly1305;
use crate::error::{SshError, SshResult};
use crate::packet::{Data, Packet};
use crate::util::encryption_key;


pub struct Client {
    pub(crate) stream: TcpStream,
    sequence: Sequence,
}

#[derive(Clone)]
struct Sequence {
    client_sequence_num: u32,
    server_sequence_num: u32
}

impl Sequence {

    fn client_auto_increment(&mut self) {
        if self.client_sequence_num == u32::MAX {
            self.client_sequence_num = 0;
        }
        self.client_sequence_num += 1;
    }

    fn server_auto_increment(&mut self) {
        if self.server_sequence_num == u32::MAX {
            self.server_sequence_num = 0;
        }
        self.server_sequence_num += 1;
    }
}


impl Client {
    pub fn connect<A: ToSocketAddrs>(adder: A) -> Result<Client, SshError> {
        match TcpStream::connect(adder) {
            Ok(stream) =>
                Ok(
                    Client{
                        stream,
                        sequence: Sequence {
                            client_sequence_num: 0,
                            server_sequence_num: 0
                        },
                    }
                ),
            Err(e) => Err(SshError::from(e))
        }

    }

    pub fn read_version(&mut self) -> Vec<u8>  {
        let mut v = [0_u8; 128];
        loop {
            match self.stream.read(&mut v) {
                Ok(i) => { return (&v[..i]).to_vec() }
                Err(_) => continue
            };
        }
    }

    pub(crate) fn read(&mut self) -> Result<Vec<Data>, SshError> {
        let mut results = vec![];
        let mut result = vec![0; size::BUF_SIZE as usize];
        let len = match self.stream.read(&mut result) {
            Ok(len) => {
                if len <= 0 {
                    return Ok(results)
                }
                len
            },
            Err(e) => {
                if is_would_block(&e) {
                    return Ok(results)
                }
                return Err(SshError::from(e))
            }
        };
        result.truncate(len);
        self.process_data(result, &mut results)?;
        Ok(results)
    }

    pub fn write_version(&mut self, buf: &[u8]) -> Result<(), SshError> {
        match self.stream.write(&buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), SshError> {
        let mut buf = buf.to_vec();
        if global::IS_ENCRYPT.load(Relaxed) {
            let key = encryption_key()?;
            key.encryption(self.sequence.client_sequence_num, &mut buf);
        }
        self.sequence.client_auto_increment();
        match self.stream.write(&buf) {
            Ok(_) => {}
            Err(e) => return Err(SshError::from(e))
        };
        match self.stream.flush() {
            Ok(_) => {}
            Err(e) => return Err(SshError::from(e))
        };
        Ok(())
    }

    pub(crate) fn close(&mut self) -> Result<(), SshError> {
        match self.stream.shutdown(Shutdown::Both) {
            Ok(o) => Ok(o),
            Err(e) => Err(SshError::from(e))
        }
    }

    fn process_data(&mut self, mut result: Vec<u8>, results: &mut Vec<Data>) -> SshResult<()> {
        // 未加密
        if !global::IS_ENCRYPT.load(Relaxed) {
            self.sequence.server_auto_increment();
            let packet_len = &result[..4];
            let mut packet_len_slice = [0_u8; 4];
            packet_len_slice.copy_from_slice(packet_len);
            let packet_len = (u32::from_be_bytes(packet_len_slice) as usize) + 4;
            // 唯一处理 server Key Exchange Reply 和 New Keys 会一块发
            if result.len() > packet_len {
                let (v1, v2) = result.split_at_mut(packet_len);
                let data = Packet::processing_data(v1.to_vec());
                results.push(data);
                result = v2.to_vec();
            }
            let data = Packet::processing_data(result);
            results.push(data);
            return Ok(())
        }

        // 加密数据
        self.process_data_encrypt(result, results)

    }


    fn process_data_encrypt(&mut self, mut result: Vec<u8>, results: &mut Vec<Data>) -> SshResult<()> {
        self.sequence.server_auto_increment();
        if result.len() < 4 {
            self.check_result_len(&mut result)?;
        }
        let key = encryption_key()?;
        let packet_len = self.get_encrypt_packet_length(&result[..4], key);
        let data_len = (packet_len + 4 + 16) as usize;
        if result.len() < data_len {
            self.get_encrypt_data(&mut result, data_len)?;
        }
        let (this, remaining) = result.split_at_mut(data_len);
        let decryption_result =
            key.decryption(self.sequence.server_sequence_num, &mut this.to_vec())?;
        let data = Packet::processing_data(decryption_result);

        // change the channel window size
        ChannelWindowSize::process_window_size(data.clone(), self)?;

        results.push(data);
        if  remaining.len() > 0 {
            self.process_data_encrypt(remaining.to_vec(), results)?;
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

    fn get_encrypt_packet_length(&self, len: &[u8], key: &mut ChaCha20Poly1305) -> u32 {
        let mut packet_len_slice = [0_u8; 4];
        packet_len_slice.copy_from_slice(len);
        let packet_len_slice = key.server_key
            .decrypt_packet_length(
                self.sequence.server_sequence_num,
                packet_len_slice);
        u32::from_be_bytes(packet_len_slice)
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

fn is_would_block(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
}

use std::io;
use std::io::Read;
use std::sync::atomic::Ordering::Relaxed;
use crate::client::Client;
use crate::constant::size;
use crate::data::Data;
use crate::algorithm::encryption::{Encryption, IS_ENCRYPT};
use crate::{SshError, SshResult};
use crate::algorithm::encryption;
use crate::packet::Packet;
use crate::window_size::WindowSize;

impl Client {
    pub(crate) fn read_version(&mut self) -> Vec<u8> {
        let mut v = [0_u8; 128];
        loop {
            match self.stream.read(&mut v) {
                Ok(i) => { return (&v[..i]).to_vec() }
                Err(_) => continue
            };
        }
    }

    pub(crate) fn read(&mut self) -> Result<Vec<Data>, SshError> {
        self.read_data(None)
    }

    pub(crate) fn read_data(&mut self, lws: Option<&mut WindowSize>) -> SshResult<Vec<Data>> {
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
                if Client::is_would_block(&e) {
                    return Ok(results)
                }
                return Err(SshError::from(e))
            }
        };

        result.truncate(len);
        // 处理未加密数据
        if !IS_ENCRYPT.load(Relaxed) {
            self.process_data(result, &mut results);
        }
        // 处理加密数据
        else {
            self.process_data_encrypt(result, &mut results, lws)?
        }

        Ok(results)
    }

    fn process_data(&mut self, mut result: Vec<u8>, results: &mut Vec<Data>) {
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

    fn process_data_encrypt(&mut self,
                            mut result: Vec<u8>,
                            results: &mut Vec<Data>,
                            mut lws: Option<&mut WindowSize>)
        -> SshResult<()>
    {
        loop {
            self.sequence.server_auto_increment();
            if result.len() < 4 {
                self.check_result_len(&mut result)?;
            }
            let key = encryption::get();
            let data_len = key.data_len(self.sequence.server_sequence_num, result.as_slice());

            // let packet_len = self.get_encrypt_packet_length(&result[..4], key);
            // let data_len = (packet_len + 4 + 16) as usize;

            if result.len() < data_len {
                self.get_encrypt_data(&mut result, data_len)?;
            }
            let (this, remaining) = result.split_at_mut(data_len);
            let decryption_result =
                key.decrypt(self.sequence.server_sequence_num, &mut this.to_vec())?;
            let data = Packet::from(decryption_result).unpacking();
            // 判断是否需要修改窗口大小
            if let Some(v) = &mut lws {
                v.process_local_window_size(data.as_slice())?
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

    // fn get_encrypt_packet_length(&self, len: &[u8], key: &mut ChaCha20Poly1305) -> u32 {
    //     let mut packet_len_slice = [0_u8; 4];
    //     packet_len_slice.copy_from_slice(len);
    //     let packet_len_slice = key.server_key
    //         .decrypt_packet_length(
    //             self.sequence.server_sequence_num,
    //             packet_len_slice);
    //     u32::from_be_bytes(packet_len_slice)
    // }

    // fn get_encrypt_packet_length(&self, len: &[u8], key: &mut AesCtr) -> u32 {
    //     // let mut packet_len_slice = [0_u8; 4];
    //     // key.decryption()
    //     // packet_len_slice.copy_from_slice(len);
    //     // let packet_len_slice = key.server_key
    //     //     .decrypt_packet_length(
    //     //         self.sequence.server_sequence_num,
    //     //         packet_len_slice);
    //     // u32::from_be_bytes(packet_len_slice)
    // }

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
use crate::algorithm::{
    encryption, key_exchange, mac,
    public_key::{self, PublicKey},
};
use crate::client::Client;
use crate::constant::{size, ssh_msg_code};
use crate::h::H;
use crate::model::{Data, Packet};
use crate::window_size::WindowSize;
use crate::{algorithm::hash, config::version::SshVersion};
use crate::{algorithm::key_exchange::KeyExchange, config::algorithm::AlgList};
use crate::{kex, SshError, SshResult};
use std::io::{self, Read, Write};

impl<S> Client<S>
where
    S: Read + Write,
{
    pub fn read(&mut self) -> SshResult<Vec<Data>> {
        self.read_data(None)
    }

    pub fn read_data(&mut self, lws: Option<&mut WindowSize>) -> SshResult<Vec<Data>> {
        // 判断超时时间
        // 如果超时,即抛出异常
        self.timeout.is_timeout()?;

        let mut results = vec![];
        let mut result = vec![0; size::BUF_SIZE as usize];
        let len = match self.stream.read(&mut result) {
            Ok(len) => {
                if len == 0 {
                    return Ok(results);
                }

                // 从服务段正常读取到数据的话
                // 就刷新超时时间
                self.timeout.renew();

                len
            }
            Err(e) => {
                if Client::<S>::is_would_block(&e) {
                    return Ok(results);
                }
                return Err(SshError::from(e));
            }
        };

        result.truncate(len);
        // 处理未加密数据
        match self.is_encryption {
            true => self.process_data_encrypt(result, &mut results, lws)?,
            false => self.process_data(result, &mut results),
        }
        Ok(results)
    }

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

    pub fn process_data_encrypt(
        &mut self,
        mut result: Vec<u8>,
        results: &mut Vec<Data>,
        mut lws: Option<&mut WindowSize>,
    ) -> SshResult<()> {
        loop {
            self.sequence.server_auto_increment();
            if result.len() < 4 {
                self.check_result_len(&mut result)?;
            }
            let data_len = {
                self.encryption
                    .as_mut()
                    .unwrap()
                    .data_len(self.sequence.server_sequence_num, result.as_slice())
            };
            if result.len() < data_len {
                self.get_encrypt_data(&mut result, data_len)?;
            }
            let (this, remaining) = result.split_at_mut(data_len);
            let decryption_result = {
                self.encryption
                    .as_mut()
                    .unwrap()
                    .decrypt(self.sequence.server_sequence_num, &mut this.to_vec())
            }?;
            let data = Packet::from(decryption_result).unpacking();
            // 判断是否需要修改窗口大小
            if !self.window_adjust(data.clone(), &mut lws)?
                && self.r_size_one_gb(data.clone(), &mut lws)?
            {
                results.push(data);
            }
            if remaining.is_empty() {
                break;
            }
            result = remaining.to_vec();
        }
        Ok(())
    }

    fn get_encrypt_data(&mut self, result: &mut Vec<u8>, data_len: usize) -> SshResult<()> {
        loop {
            self.timeout.is_timeout()?;

            let mut buf = vec![0; data_len - result.len()];
            match self.stream.read(&mut buf) {
                Ok(len) => {
                    if len > 0 {
                        self.timeout.renew();
                        buf.truncate(len);
                        result.extend(buf);
                    }
                    if result.len() >= data_len {
                        return Ok(());
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(SshError::from(e));
                }
            };
        }
    }

    fn check_result_len(&mut self, result: &mut Vec<u8>) -> SshResult<usize> {
        loop {
            self.timeout.is_timeout()?;

            let mut buf = vec![0; size::BUF_SIZE as usize];
            match self.stream.read(&mut buf) {
                Ok(len) => {
                    if len > 0 {
                        self.timeout.renew();
                        buf.truncate(len);
                        result.extend(buf);
                    }

                    if result.len() >= 4 {
                        return Ok(len);
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(SshError::from(e));
                }
            };
        }
    }

    fn window_adjust(
        &mut self,
        mut data: Data,
        lws: &mut Option<&mut WindowSize>,
    ) -> SshResult<bool> {
        if let Some(v) = lws {
            v.process_local_window_size(data.as_slice(), self)?;
            let mc = data[0];
            if mc == ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST {
                data.get_u8();
                // 接收方通道号， 暂时不需要
                data.get_u32();
                let size = data.get_u32();
                v.add_remote_window_size(size);
                return Ok(true);
            }
        }
        Ok(false)
    }

    // 密钥重新交换
    fn r_size_one_gb(
        &mut self,
        mut data: Data,
        lws: &mut Option<&mut WindowSize>,
    ) -> SshResult<bool> {
        if self.is_w_1_gb {
            return Ok(true);
        }
        return match data[0] {
            ssh_msg_code::SSH_MSG_KEXINIT => {
                self.is_r_1_gb = true;
                log::info!("start for key negotiation.");
                let mut h = H::new();
                if let SshVersion::V2(ref our, ref their) = self.config.lock().unwrap().ver {
                    h.set_v_c(our);
                    h.set_v_s(their);
                };
                h.set_i_s(data.clone().as_slice());
                let algs = AlgList::from(data)?;
                let negotiated = self.config.lock().unwrap().algs.match_with(&algs)?;

                match lws {
                    None => kex::send_algorithm(&mut h, self, None)?,
                    Some(ws) => kex::send_algorithm(&mut h, self, Some(ws))?,
                }
                let key_exchange = key_exchange::from(negotiated.key_exchange.0[0].as_str())?;
                let public_key = public_key::from(negotiated.public_key.0[0].as_str());
                match lws {
                    None => kex::send_qc(self, key_exchange.get_public_key(), None)?,
                    Some(ws) => kex::send_qc(self, key_exchange.get_public_key(), Some(ws))?,
                }
                self.negotiated = negotiated;
                self.signature = Some(Signature {
                    h,
                    key_exchange,
                    public_key,
                });
                Ok(false)
            }
            ssh_msg_code::SSH_MSG_KEXDH_REPLY => {
                // 生成session_id并且获取signature
                let k = self.signature.as_mut().unwrap();
                // 去掉msg code
                data.get_u8();
                let sig = kex::generate_signature(data, &mut k.h, &mut k.key_exchange)?;
                // 验签
                let session_id = hash::digest(&k.h.as_bytes(), k.key_exchange.get_hash_type());
                let flag = k.public_key.verify_signature(&k.h.k_s, &session_id, &sig)?;
                if !flag {
                    log::error!("signature verification failure.");
                    return Err(SshError::from("signature verification failure."));
                }
                log::info!("signature verification success.");
                Ok(false)
            }
            ssh_msg_code::SSH_MSG_NEWKEYS => {
                match lws {
                    None => kex::new_keys(self, None)?,
                    Some(ws) => kex::new_keys(self, Some(ws))?,
                }
                let k = self.signature.as_mut().unwrap();
                let hash_type = k.key_exchange.get_hash_type();
                let hash = hash::hash::Hash::new(k.h.clone(), &self.session_id, hash_type);
                // mac 算法
                let mac = mac::from(self.negotiated.c_mac.0[0].as_str());
                // 加密算法
                let encryption =
                    encryption::from(self.negotiated.c_encryption.0[0].as_str(), hash, mac);
                self.encryption = Some(encryption);
                self.is_encryption = true;
                self.signature = None;
                self.is_r_1_gb = false;
                log::info!("key negotiation successful.");
                Ok(false)
            }
            _ => Ok(true),
        };
    }
}

pub(crate) struct Signature {
    h: H,
    key_exchange: Box<dyn KeyExchange>,
    public_key: Box<dyn PublicKey>,
}

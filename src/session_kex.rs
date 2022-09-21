use std::borrow::{Borrow, BorrowMut};
use crate::constant::ssh_msg_code;
use crate::error::{SshError, SshResult};
use crate::data::Data;
use crate::slog::log;
use crate::config::{
    CompressionAlgorithm,
    EncryptionAlgorithm,
    KeyExchangeAlgorithm,
    MacAlgorithm,
    PublicKeyAlgorithm
};
use crate::{Session, util};
use crate::algorithm::hash;


impl Session {

    /// 发送客户端的算法列表
    pub(crate) fn send_algorithm(&mut self) -> SshResult<()> {
        let config = self.config.as_ref().unwrap();
        log::info!("client algorithms: [{}]", config.algorithm.client_algorithm.to_string());
        // TODO 密钥从新交换的时候, 不确定是否修改加密状态
        // if self.is_encryption.get() {
        //     self.is_encryption.set(false);
        // }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_KEXINIT);
        data.extend(util::cookie());
        data.extend(config.algorithm.client_algorithm.as_i());
        data.put_str("")
            .put_str("")
            .put_u8(false as u8)
            .put_u32(0_u32);

        // h 加入客户端算法信息
        self.h.as_ref().borrow_mut().set_i_c(data.as_slice());
        self.write(data)
    }

    /// 获取服务端的算法列表
    pub(crate) fn receive_algorithm(&mut self) -> SshResult<()> {
        loop {
            let results = self.read()?;
            for result in results {
                if result.is_empty() { continue }
                let message_code = result[0];
                match message_code {
                    ssh_msg_code::SSH_MSG_KEXINIT => {
                        // h 加入服务端算法信息
                        self.h.as_ref().borrow_mut().set_i_s(result.as_slice());
                        return self.processing_server_algorithm(result)
                    }
                    _ => {}
                }
            }
        }
    }

    /// 发送客户端公钥
    pub(crate) fn send_qc(&mut self) -> SshResult<()> {
        match self.key_exchange.as_mut() {
            None => Err(SshError::from("key exchange algorithm is none.")),
            Some(key_exchange) => {
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_KEXDH_INIT);
                data.put_u8s(key_exchange.get_public_key());
                self.write(data)
            }
        }

    }


    /// 接收服务端公钥和签名，并验证签名的正确性
    pub(crate) fn verify_signature_and_new_keys(&mut self) -> SshResult<()> {
        loop {
            let results = self.read()?;
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_KEXDH_REPLY => {
                        // 生成session_id并且获取signature
                        let sig = self.generate_signature(result)?;
                        // 验签
                        let session_id = match self.key_exchange.as_ref() {
                            None => return Err(SshError::from("key exchange algorithm is none.")),
                            Some(key_exchange) => {
                                let hash_type = key_exchange.get_hash_type();
                                hash::digest( self.h.as_ref().borrow_mut().as_bytes().as_slice(), hash_type)
                            }
                        };
                        match self.public_key.as_ref() {
                            None => return Err(SshError::from("public key algorithm is none.")),
                            Some(public_key) => {
                                let flag = public_key.verify_signature(self.h.as_ref().borrow().k_s.as_ref(),
                                                      &session_id, &sig)?;
                                if !flag {
                                    log::error!("signature verification failure.");
                                    return Err(SshError::from("signature verification failure."))
                                }
                                log::info!("signature verification success.");
                            }
                        }
                    }
                    ssh_msg_code::SSH_MSG_NEWKEYS => return self.new_keys(),
                    _ => {}
                }
            }
        }
    }

    /// SSH_MSG_NEWKEYS 代表密钥交换完成
    pub(crate) fn new_keys(&mut self) -> Result<(), SshError> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_NEWKEYS);
        self.write(data)?;
        log::info!("send new keys");
        Ok(())
    }

    /// 生成签名
    pub(crate) fn generate_signature(&mut self, mut data: Data) -> SshResult<Vec<u8>> {
        let key_exchange = match self.key_exchange.as_mut() {
            None => return Err(SshError::from("key exchange algorithm is none.")),
            Some(key_exchange) => key_exchange,
        };
        let ks = data.get_u8s();
        let mut h_val = self.h.as_ref().borrow_mut();
        h_val.set_k_s(&ks);
        // TODO 未进行密钥指纹验证！！
        let qs = data.get_u8s();
        h_val.set_q_c(key_exchange.get_public_key());
        h_val.set_q_s(&qs);
        let vec = key_exchange.get_shared_secret(qs)?;
        h_val.set_k(&vec);
        let h = data.get_u8s();
        let mut hd = Data::from(h);
        hd.get_u8s();
        let signature = hd.get_u8s();
        Ok(signature)
    }

    /// 处理服务端的算法列表
    pub(crate) fn processing_server_algorithm(&mut self, mut data: Data) -> SshResult<()> {
        data.get_u8();
        // 跳过16位cookie
        data.skip(16);
        let config = self.config.as_mut().unwrap();
        let server_algorithm = &mut config.algorithm.server_algorithm;
        server_algorithm.key_exchange_algorithm     =   KeyExchangeAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.public_key_algorithm       =   PublicKeyAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.c_encryption_algorithm     =   EncryptionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.s_encryption_algorithm     =   EncryptionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.c_mac_algorithm            =   MacAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.s_mac_algorithm            =   MacAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.c_compression_algorithm    =   CompressionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.s_compression_algorithm    =   CompressionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
        log::info!("server algorithms: [{}]", server_algorithm.to_string());
        return Ok(())
    }
}


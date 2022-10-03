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
use crate::algorithm::key_exchange::KeyExchange;
use crate::algorithm::public_key::PublicKey;
use crate::h::H;


impl Session {

    /// 发送客户端的算法列表
    pub(crate) fn send_algorithm(&mut self, h: &mut H) -> SshResult<()> {
        let config = self.config.as_ref().unwrap();
        log::info!("client algorithms: [{}]", config.algorithm.client_algorithm.to_string());
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_KEXINIT);
        data.extend(util::cookie());
        data.extend(config.algorithm.client_algorithm.as_i());
        data.put_str("")
            .put_str("")
            .put_u8(false as u8)
            .put_u32(0_u32);
        h.set_i_c(data.clone().as_slice());
        self.client.as_mut().unwrap().write(data)?;
        Ok(())
    }

    /// 获取服务端的算法列表
    pub(crate) fn receive_algorithm(&mut self, h: &mut H) -> SshResult<()> {
        loop {
            let results = self.client.as_mut().unwrap().read()?;
            for result in results {
                if result.is_empty() { continue }
                let message_code = result[0];
                match message_code {
                    ssh_msg_code::SSH_MSG_KEXINIT => {
                        h.set_i_s(result.clone().as_slice());
                        self.processing_server_algorithm(result)?;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }

    /// 发送客户端公钥
    pub(crate) fn send_qc(&mut self, public_key: &[u8]) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_KEXDH_INIT);
        data.put_u8s(public_key);
        self.client.as_mut().unwrap().write(data)


    }


    /// 接收服务端公钥和签名，并验证签名的正确性
    pub(crate) fn verify_signature_and_new_keys(&mut self,
                                                public_key: &mut Box<dyn PublicKey>,
                                                key_exchange: &mut Box<dyn KeyExchange>,
                                                h: &mut H
    ) -> SshResult<()>
    {
        loop {
            let results = self.client.as_mut().unwrap().read()?;
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_KEXDH_REPLY => {
                        // 生成session_id并且获取signature
                        let sig = self.generate_signature(result, h, key_exchange)?;
                        // 验签
                        let session_id = hash::digest( &h.as_bytes(), key_exchange.get_hash_type());
                        let flag = public_key.verify_signature(&h.k_s, &session_id, &sig)?;
                        if !flag {
                            log::error!("signature verification failure.");
                            return Err(SshError::from("signature verification failure."))
                        }
                        log::info!("signature verification success.");
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
        self.client.as_mut().unwrap().write(data)?;
        log::info!("send new keys");
        Ok(())
    }

    /// 生成签名
    pub(crate) fn generate_signature(&mut self,
                                     mut data: Data,
                                     h: &mut H,
                                     key_exchange: &mut Box<dyn KeyExchange>
    ) -> SshResult<Vec<u8>>
    {
        let ks = data.get_u8s();
        h.set_k_s(&ks);
        // TODO 未进行密钥指纹验证！！
        let qs = data.get_u8s();
        h.set_q_c(key_exchange.get_public_key());
        h.set_q_s(&qs);
        let vec = key_exchange.get_shared_secret(qs)?;
        h.set_k(&vec);
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


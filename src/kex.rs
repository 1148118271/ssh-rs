use std::sync::{Arc, LockResult, Mutex};
use std::sync::atomic::Ordering;
use rand::Rng;
use rand::rngs::OsRng;
use ring::digest;
use crate::{algorithms, message, global, SshResult, util};
use crate::config::{CompressionAlgorithm, EncryptionAlgorithm, KeyExchangeAlgorithm, MacAlgorithm, PublicKeyAlgorithm};
use crate::encryption::{ChaCha20Poly1305, CURVE25519, DH, EcdhP256, H, KeyExchange, PublicKey, SIGN};
use crate::encryption::ed25519::Ed25519;
use crate::encryption::rsa::RSA;
use crate::error::{SshError, SshErrorKind};
use crate::hash::HASH;
use crate::packet::{Data, Packet};
use crate::tcp::Client;



pub(crate) struct Kex {
    pub(crate) session_id: Vec<u8>,
    pub(crate) h: H,
    pub(crate) dh: Box<DH>,
    pub(crate) signature: Box<SIGN>
}

impl Kex {

    pub(crate) fn new() -> SshResult<Kex> {
        Ok(Kex {
            session_id: vec![],
            h: H::new(),
            dh: Box::new(CURVE25519::new()?),
            signature: Box::new(RSA::new())
        })
    }


    pub(crate) fn send_algorithm(&mut self) -> SshResult<()> {
        let config = util::config()?;
        log::info!("client algorithms => {}", config.algorithm.client_algorithm.to_string());
        if global::IS_ENCRYPT.load(Ordering::Relaxed) {
            global::IS_ENCRYPT.store(false, Ordering::Relaxed);
            util::update_encryption_key(None);
        }
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_KEXINIT);
        data.extend(util::cookie());
        data.extend(config.algorithm.client_algorithm.as_i());
        data.put_str("")
            .put_str("")
            .put_u8(false as u8)
            .put_u32(0_u32);

        self.h.set_i_c(data.as_slice());

        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }


    pub(crate) fn receive_algorithm(&mut self) -> SshResult<()> {
        let mut client = util::client()?;
        loop {
            let results = client.read()?;
            for result in results {
                if result.is_empty() { continue }
                let message_code = result[5];
                match message_code {
                    message::SSH_MSG_KEXINIT => {
                        let mut data = Packet::processing_data(result);
                        self.h.set_i_s(data.as_slice());
                        return processing_server_algorithm(data)
                    }
                    _ => { }
                }
            }
        }
    }


    pub(crate) fn send_qc(&self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_KEX_ECDH_INIT);
        data.put_bytes(self.dh.get_public_key());
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }


    pub(crate) fn verify_signature(&mut self) -> SshResult<()> {
        let mut client = util::client()?;
        loop {
            let results = client.read()?;
            for result in results {
                if result.is_empty() { continue }
                let message_code = result[5];
                match message_code {
                    message::SSH_MSG_KEX_ECDH_REPLY => {
                        // 生成session_id并且获取signature
                        let sig = self.generate_session_id_and_get_signature(result)?;
                        // 验签
                        let r = self
                            .signature
                            .verify_signature(&self.h.k_s, &self.session_id, &sig)?;
                        log::info!("Signature Verification Result => {}", r);
                        if !r {
                            return Err(SshError::from(SshErrorKind::SignatureError))
                        }
                        return Ok(())
                    }
                    _ => {}
                }
            }
        }
    }

    pub(crate) fn new_keys(&mut self) -> Result<(), SshError> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_NEWKEYS);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())?;

        let hash = HASH::new(&self.h.k, &self.session_id, &self.session_id);
        let poly1305 = ChaCha20Poly1305::new(hash);
        global::IS_ENCRYPT.store(true, Ordering::Relaxed);
        util::update_encryption_key(Some(poly1305));
        Ok(())
    }

    pub(crate) fn generate_session_id_and_get_signature(&mut self, buff: Vec<u8>) -> Result<Vec<u8>, SshError> {
        let mut data = Data(buff);
        let ke_n_l = data.get_u8s();
        data.refresh();
        let ke_y_l = data.put_bytes(&ke_n_l);
        let mut ke = Packet::processing_data(ke_y_l.to_vec());
        ke.get_u8();
        let ks = ke.get_u8s();
        self.h.set_k_s(&ks);
        // TODO 未进行密钥指纹验证！！
        let qs = ke.get_u8s();
        self.h.set_q_c(self.dh.get_public_key());
        self.h.set_q_s(&qs);
        let vec = self.dh.get_shared_secret(qs)?;
        self.h.set_k(&vec);
        let hb = self.h.as_bytes();
        self.session_id = digest::digest(&digest::SHA256, &hb).as_ref().to_vec();
        let h = ke.get_u8s();
        let mut hd = Data(h);
        hd.get_u8s();
        let signature = hd.get_u8s();
        Ok(signature)
    }
}

pub(crate) fn processing_server_algorithm(mut data: Data) -> SshResult<()> {
    data.get_u8();
    // 跳过16位cookie
    data.skip(16);
    let mut config = util::config()?;
    let server_algorithm = &mut config.algorithm.server_algorithm;
    server_algorithm.key_exchange_algorithm     =   KeyExchangeAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.public_key_algorithm       =   PublicKeyAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.c_encryption_algorithm     =   EncryptionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.s_encryption_algorithm     =   EncryptionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.c_mac_algorithm            =   MacAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.s_mac_algorithm            =   MacAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.c_compression_algorithm    =   CompressionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.s_compression_algorithm    =   CompressionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    log::info!("server algorithms => {}", server_algorithm.to_string());
    return Ok(())
}
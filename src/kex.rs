use std::sync::atomic::Ordering;
use constant::ssh_msg_code;
use encryption::{
    ChaCha20Poly1305,
    CURVE25519,
    DH,
    H,
    KeyExchange,
    PublicKey,
    SIGN,
    RSA,
    HASH,
    digest,
    IS_ENCRYPT
};
use error::{SshError, SshErrorKind, SshResult};
use packet::Data;
use slog::log;
use crate::config::{
    CompressionAlgorithm,
    EncryptionAlgorithm,
    KeyExchangeAlgorithm,
    MacAlgorithm,
    PublicKeyAlgorithm}
;
use crate::{client, util};


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
        log::info!("client algorithms: [{}]", config.algorithm.client_algorithm.to_string());
        if IS_ENCRYPT.load(Ordering::Relaxed) {
            IS_ENCRYPT.store(false, Ordering::Relaxed);
            util::update_encryption_key(None);
        }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_KEXINIT);
        data.extend(util::cookie());
        data.extend(config.algorithm.client_algorithm.as_i());
        data.put_str("")
            .put_str("")
            .put_u8(false as u8)
            .put_u32(0_u32);

        self.h.set_i_c(data.as_slice());

        let mut client = client::locking()?;
        client.write(data)
    }


    pub(crate) fn receive_algorithm(&mut self) -> SshResult<()> {
        let mut client = client::locking()?;
        loop {
            let results = client.read()?;
            for result in results {
                if result.is_empty() { continue }
                let message_code = result[0];
                match message_code {
                    ssh_msg_code::SSH_MSG_KEXINIT => {
                        self.h.set_i_s(result.as_slice());
                        return processing_server_algorithm(result)
                    }
                    _ => { }
                }
            }
        }
    }


    pub(crate) fn send_qc(&self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_KEX_ECDH_INIT);
        data.put_u8s(self.dh.get_public_key());
        let mut client = client::locking()?;
        client.write(data)
    }


    pub(crate) fn verify_signature_and_new_keys(&mut self) -> SshResult<()> {
        loop {
            let mut client = client::locking()?;
            let results = client.read()?;
            client::unlock(client);
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_KEX_ECDH_REPLY => {
                        // 生成session_id并且获取signature
                        let sig = self.generate_session_id_and_get_signature(result)?;
                        // 验签
                        let r = self
                            .signature
                            .verify_signature(&self.h.k_s, &self.session_id, &sig)?;
                        log::info!("signature verification result: [{}]", r);
                        if !r {
                            return Err(SshError::from(SshErrorKind::SignatureError))
                        }
                    }
                    ssh_msg_code::SSH_MSG_NEWKEYS => {
                        self.new_keys()?;
                        return Ok(())
                    }
                    _ => {}
                }
            }
        }
    }

    pub(crate) fn new_keys(&mut self) -> Result<(), SshError> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_NEWKEYS);
        let mut client = client::locking()?;
        client.write(data)?;

        let hash: HASH = HASH::new(&self.h.k, &self.session_id, &self.session_id);
        let poly1305 = ChaCha20Poly1305::new(hash);
        IS_ENCRYPT.store(true, Ordering::Relaxed);
        util::update_encryption_key(Some(poly1305));
        Ok(())
    }

    pub(crate) fn generate_session_id_and_get_signature(&mut self, mut data: Data) -> Result<Vec<u8>, SshError> {
        let ks = data.get_u8s();
        self.h.set_k_s(&ks);
        // TODO 未进行密钥指纹验证！！
        let qs = data.get_u8s();
        self.h.set_q_c(self.dh.get_public_key());
        self.h.set_q_s(&qs);
        let vec = self.dh.get_shared_secret(qs)?;
        self.h.set_k(&vec);
        let hb = self.h.as_bytes();
        self.session_id = digest::digest(&digest::SHA256, &hb).as_ref().to_vec();
        let h = data.get_u8s();
        let mut hd = Data::from(h);
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
    log::info!("server algorithms: [{}]", server_algorithm.to_string());
    return Ok(())
}

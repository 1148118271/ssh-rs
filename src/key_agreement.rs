use std::sync::atomic::Ordering;
use rand::Rng;
use rand::rngs::OsRng;
use ring::agreement::ECDH_P256;
use ring::digest;
use crate::{algorithms, encryption, message, global_variable};
use crate::encryption::{ChaCha20Poly1305, CURVE25519, DH, EcdhP256, H, KeyExchange};
use crate::error::{SshError, SshErrorKind};
use crate::hash::HASH;
use crate::packet::{Data, Packet};
use crate::tcp::Client;

pub(crate) struct KeyAgreement {
    pub(crate) session_id: Vec<u8>,
    pub(crate) h: H,
    pub(crate) encryption_algorithm: Option<Box<DH>>,

}

impl KeyAgreement {
    pub(crate) fn new() -> Self {
        KeyAgreement {
            session_id: vec![],
            h: H::new(),
            encryption_algorithm: None,
        }
    }


    pub(crate) fn key_agreement(&mut self, stream: &mut Client) -> Result<(), SshError> {
        loop {
            let results = stream.read()?;
            for buf in results {
                let message_code = buf[5];
                match message_code {
                    message::SSH_MSG_KEXINIT => {
                        let data = Packet::processing_data(buf);
                        // 重置加密算法
                        if global_variable::IS_ENCRYPT.load(Ordering::Relaxed) {
                            global_variable::IS_ENCRYPT.store(false, Ordering::Relaxed);
                            global_variable::update_encryption_key(None);
                        }
                        // 密钥协商
                        self.algorithm_negotiation(data, stream)?;
                        // 发送公钥
                        match self.send_public_key(stream) {
                            Ok(_) => {}
                            Err(e) => return Err(SshError::from(e))
                        };
                    }

                    message::SSH_MSG_KEX_ECDH_REPLY => {
                        // 生成session_id并且获取signature
                        let sig = match self.generate_session_id_and_get_signature(buf) {
                            Ok(sig) => sig,
                            Err(_) => return Err(SshError::from(SshErrorKind::EncryptionError))
                        };
                        // 验签
                        self.verify_signature(&sig)?;
                        // 新的密钥
                        self.new_keys(stream)?;

                        // 修改加密算法
                        let hash = HASH::new(&self.h.k, &self.session_id, &self.session_id);
                        let poly1305 = ChaCha20Poly1305::new(hash);
                        global_variable::IS_ENCRYPT.store(true, Ordering::Relaxed);
                        global_variable::update_encryption_key(Some(poly1305));
                        return Ok(())
                    }
                    _ => { return Ok(()) }
                }
            }
        }
    }

    pub(crate) fn algorithm_negotiation(&mut self, mut buff: Data, stream: &mut Client) -> Result<(), SshError> {
        self.h.set_i_s(buff.as_slice());
        buff.get_u8();
        buff.skip(16);
        let mut server_algorithm = vec![];
        for _ in 0..8 {
            let vec = buff.get_u8s();
            server_algorithm.push(
                match String::from_utf8(vec) {
                    Ok(v) => v,
                    Err(_) => return Err(SshError::from(SshErrorKind::FromUtf8Error))
                }
            );
        }

        println!(">> server algorithm: {:?}", server_algorithm);
        let alv = algorithms::init();
        println!(">> client algorithm: {:?}", algorithms::ALGORITHMS);
        let dh: Box<DH> = dn_matching_algorithm(server_algorithm[0].clone(), algorithms::ALGORITHMS[0].to_string())?;
        // 生成DH
        self.encryption_algorithm = Some(dh);

        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_KEXINIT);
        data.extend(&cookie());
        data.extend(alv);
        data.put_str("")
            .put_str("")
            .put_u8(false as u8)
            .put_u32(0_u32);
        self.h.set_i_c(data.as_slice());
        let mut packet = Packet::from(data);
        packet.build();
        match stream.write(packet.as_slice()) {
            Ok(_) => {}
            Err(e) => return Err(SshError::from(e))
        };
        Ok(())
    }

    pub(crate) fn send_public_key(&mut self, stream: &mut Client) -> Result<(), SshError> {
        let o = &self.encryption_algorithm;
        let dh = match o {
            None => return Err(SshError::from(SshErrorKind::EncryptionError)),
            Some(v) => v
        };
        self.h.set_q_c(dh.get_public_key());
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_KEX_ECDH_INIT);
        data.put_bytes(dh.get_public_key());
        let mut packet = Packet::from(data);
        packet.build();
        stream.write(packet.as_slice())?;
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
        self.h.set_q_s(&qs);
        let o = &self.encryption_algorithm;
        let dh = match o {
            None => return Err(SshError::from(SshErrorKind::EncryptionError)),
            Some(v) => v
        };
        let vec = dh.get_shared_secret(qs)?;
        self.h.set_k(&vec);
        let hb = self.h.as_bytes();
        self.session_id = digest::digest(&digest::SHA256, &hb).as_ref().to_vec();
        let h = ke.get_u8s();
        let mut hd = Data(h);
        hd.get_u8s();
        let signature = hd.get_u8s();
        Ok(signature)
    }

    pub(crate) fn new_keys(&mut self, stream: &mut Client) -> Result<(), SshError> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_NEWKEYS);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(stream.write(packet.as_slice())?)
    }

    pub(crate) fn verify_signature(&mut self, sig: &[u8]) -> Result<(), SshError>{
        let mut data = Data((&self.h.k_s[4..]).to_vec());
        data.get_u8s();
        let host_key = data.get_u8s();
        let signature = encryption::ed25519::verify_signature(&host_key, &self.session_id, &sig);
        println!(">> verify signature result: {}", signature);
        if !signature {
            return Err(SshError::from(SshErrorKind::SignatureError))
        }
        Ok(())
    }
}

fn dn_matching_algorithm(sdh: String, cdh: String) -> Result<Box<DH>, SshError> {
    let sda: Vec<&str> = sdh.split(",").collect();
    let cda: Vec<&str> = cdh.split(",").collect();
    for algorithm in cda {
        if sda.contains(&algorithm) {
            if algorithm.eq(algorithms::KEY_EXCHANGE_CURVE25519_SHA256) {
                return Ok(Box::new(CURVE25519::new()?))
            }
            if algorithm.eq(algorithms::KEY_EXCHANGE_ECDH_SHA2_NISTP256) {
                return Ok(Box::new(EcdhP256::new()?))
            }
        }
    }
    Err(SshError::from(SshErrorKind::KeyExchangeError))
}

// 十六位随机数
fn cookie() -> Vec<u8> {
    let cookie: [u8; 16] = OsRng.gen();
    cookie.to_vec()
}
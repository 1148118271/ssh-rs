use crate::{
    algorithm::{
        encryption,
        hash::{self, HashCtx},
        key_exchange::{self, KeyExchange},
        mac,
        public_key::{self, PublicKey},
        Digest,
    },
    client::Client,
    config::{algorithm::AlgList, version::SshVersion},
    constant::ssh_msg_code,
    error::{SshError, SshResult},
    model::{Data, Packet, SecPacket},
};
use std::io::{Read, Write};

impl Client {
    pub fn key_agreement<S>(
        &mut self,
        stream: &mut S,
        server_algs: AlgList,
        digest: &mut Digest,
    ) -> SshResult<()>
    where
        S: Read + Write,
    {
        // initialize the hash context
        if let SshVersion::V2(ref our, ref their) = self.config.ver {
            digest.hash_ctx.set_v_c(our);
            digest.hash_ctx.set_v_s(their);
        }

        log::info!("start for key negotiation.");
        log::info!("send client algorithm list.");

        let algs = self.config.algs.clone();
        let client_algs = algs.pack(self);
        digest.hash_ctx.set_i_c(client_algs.get_inner());
        client_algs.write_stream(stream, 0)?;

        let negotiated = self.config.algs.match_with(&server_algs)?;

        // key exchange algorithm
        let mut key_exchange = key_exchange::from(negotiated.key_exchange.0[0].as_str())?;
        self.send_qc(stream, key_exchange.get_public_key())?;

        // host key algorithm
        let mut public_key = public_key::from(negotiated.public_key.0[0].as_str());

        // generate session id
        let session_id = {
            let session_id = self.verify_signature_and_new_keys(
                stream,
                &mut public_key,
                &mut key_exchange,
                &mut digest.hash_ctx,
            )?;

            if self.session_id.is_empty() {
                session_id
            } else {
                self.session_id.clone()
            }
        };

        let hash = hash::Hash::new(
            digest.hash_ctx.clone(),
            &session_id,
            key_exchange.get_hash_type(),
        );

        // mac algorithm
        let mac = mac::from(negotiated.c_mac.0[0].as_str());

        // encryption algorithm
        let encryption = encryption::from(negotiated.c_encryption.0[0].as_str(), hash, mac);

        self.session_id = session_id;
        self.negotiated = negotiated;
        self.encryptor = encryption;
        digest.key_exchange = Some(key_exchange);

        log::info!("key negotiation successful.");

        Ok(())
    }

    /// Send the public key
    fn send_qc<S>(&mut self, stream: &mut S, public_key: &[u8]) -> SshResult<()>
    where
        S: Read + Write,
    {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_KEXDH_INIT)
            .put_u8s(public_key);
        data.pack(self).write_stream(stream, 0)
    }

    fn verify_signature_and_new_keys<S>(
        &mut self,
        stream: &mut S,
        public_key: &mut Box<dyn PublicKey>,
        key_exchange: &mut Box<dyn KeyExchange>,
        h: &mut HashCtx,
    ) -> SshResult<Vec<u8>>
    where
        S: Read + Write,
    {
        let mut session_id = vec![];
        loop {
            let mut data = Data::unpack(SecPacket::from_stream(stream, 0, self)?)?;
            let message_code = data.get_u8();
            match message_code {
                ssh_msg_code::SSH_MSG_KEXDH_REPLY => {
                    // 生成session_id并且获取signature
                    let sig = self.generate_signature(data, h, key_exchange)?;
                    // 验签
                    session_id = hash::digest(&h.as_bytes(), key_exchange.get_hash_type());
                    let flag = public_key.verify_signature(&h.k_s, &session_id, &sig)?;
                    if !flag {
                        log::error!("signature verification failure.");
                        return Err(SshError::from("signature verification failure."));
                    }
                    log::info!("signature verification success.");
                }
                ssh_msg_code::SSH_MSG_NEWKEYS => {
                    self.new_keys(stream)?;
                    return Ok(session_id);
                }
                _ => unreachable!(),
            }
        }
    }

    /// 生成签名
    fn generate_signature(
        &mut self,
        mut data: Data,
        h: &mut HashCtx,
        key_exchange: &mut Box<dyn KeyExchange>,
    ) -> SshResult<Vec<u8>> {
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

    /// SSH_MSG_NEWKEYS 代表密钥交换完成
    fn new_keys<S>(&mut self, stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_NEWKEYS);
        log::info!("send new keys");
        data.pack(self).write_stream(stream, 0)
    }
}

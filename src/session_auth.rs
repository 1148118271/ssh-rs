use rsa::pkcs1::FromRsaPrivateKey;
use rsa::PublicKeyParts;
use crate::{client, config, Session, SshError, SshResult};
use crate::algorithm::hash::h;
use crate::config_auth::AuthType;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::error::SshErrorKind;
use crate::user_info::UserInfo;

impl Session {



    pub fn auth_user_info(&self, user_info: UserInfo) {
        let config = config::config();
        config.auth = user_info
    }

    pub(crate) fn password_authentication(&self) -> SshResult<()> {
        log::info!("password authentication.");
        let config = config::config();
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PASSWORD)
            .put_u8(false as u8)
            .put_str(config.auth.password.as_str());
        let client = client::default()?;
        client.write(data)
    }

    pub(crate) fn public_key_authentication(&self) -> SshResult<()> {
        log::info!("public key authentication.");

        let config = config::config();
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(false as u8)
            .put_str(config.auth.key_pair.key_type.as_str())
            .put_u8s(config.auth.key_pair.blob.as_slice());
        let client = client::default()?;
        client.write(data)
    }

    pub(crate) fn public_key_signature(&self) -> SshResult<()> {
        let config = config::config();
        let rprk = rsa::RsaPrivateKey::from_pkcs1_pem(config.auth.private_key.as_str()).unwrap();
        let rpuk = rprk.to_public_key();
        let es = rpuk.e().to_bytes_be();
        let ns = rpuk.n().to_bytes_be();

        let mut blob = Data::new();
        blob.put_str("ssh-rsa");
        blob.put_mpint(&es);
        blob.put_mpint(&ns);
        let blob = blob.as_slice();
        println!("blob length : {}", blob.len());
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(true as u8)
            .put_str(config.auth.key_pair.key_type.as_str())
            .put_u8s(config.auth.key_pair.blob.as_slice());

        let session_id = h::get().digest();
        let mut sd = Data::new();
        sd.put_u8s(session_id.as_slice());
        let s = data.clone();
        sd.extend_from_slice(s.as_slice());
        let scheme = rsa::PaddingScheme::PKCS1v15Sign {
            hash: Some(rsa::Hash::SHA1)
        };
        println!("sd len {}", sd.len());
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, sd.as_slice());
        let msg = digest.as_ref();

        //let vec = rprk.decrypt(scheme, msg).unwrap();
        // rprk.decrypt()
        // rprk.s
        let sign = rprk.sign(scheme, msg).unwrap();
        println!("sign length => {}", sign.len());
        let mut ss = Data::new();
        ss.put_str("ssh-rsa");
        ss.put_u8s(sign.as_slice());
        println!("ss len {}", ss.len());
        data.put_u8s(ss.as_slice());
        let client = client::default()?;
        client.write(data)
    }
}
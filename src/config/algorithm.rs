use crate::{
    client::Client,
    constant::{algorithms as constant, ssh_msg_code},
    error::{SshError, SshResult},
    model::{Data, Packet, SecPacket},
    util,
};

#[derive(Debug, Clone)]
pub(crate) struct AlgList {
    pub key_exchange: KeyExchange,
    pub public_key: PublicKey,
    pub c_encryption: Encryption,
    pub s_encryption: Encryption,
    pub c_mac: Mac,
    pub s_mac: Mac,
    pub c_compression: Compression,
    pub s_compression: Compression,
}

impl Default for AlgList {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgList {
    pub fn new() -> Self {
        AlgList {
            key_exchange: KeyExchange(vec![]),
            public_key: PublicKey(vec![]),
            c_encryption: Encryption(vec![]),
            s_encryption: Encryption(vec![]),
            c_mac: Mac(vec![]),
            s_mac: Mac(vec![]),
            c_compression: Compression(vec![]),
            s_compression: Compression(vec![]),
        }
    }

    pub fn client_default() -> Self {
        AlgList {
            key_exchange: KeyExchange::client_default(),
            public_key: PublicKey::client_default(),
            c_encryption: Encryption::client_default(),
            s_encryption: Encryption::client_default(),
            c_mac: Mac::client_default(),
            s_mac: Mac::client_default(),
            c_compression: Compression::client_default(),
            s_compression: Compression::client_default(),
        }
    }

    fn from(mut data: Data) -> SshResult<Self> {
        data.get_u8();
        // 跳过16位cookie
        data.skip(16);
        let mut server_algorithm = Self::new();
        server_algorithm.key_exchange = KeyExchange(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.public_key = PublicKey(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.c_encryption = Encryption(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.s_encryption = Encryption(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.c_mac = Mac(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.s_mac = Mac(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.c_compression = Compression(util::vec_u8_to_string(data.get_u8s(), ",")?);
        server_algorithm.s_compression = Compression(util::vec_u8_to_string(data.get_u8s(), ",")?);
        log::info!("server algorithms: [{:?}]", server_algorithm);
        Ok(server_algorithm)
    }

    pub fn match_with(&self, other: &Self) -> SshResult<Self> {
        macro_rules! match_field {
            ($our: expr,  $their:expr, $field: ident, $err_hint: expr) => {
                $our.$field
                    .0
                    .iter()
                    .find_map(|k| {
                        if $their.$field.0.contains(k) {
                            Some(k)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        log::error!(
                            "description the {} fails to match, \
                    algorithms supported by the server: {},\
                    algorithms supported by the client: {}",
                            $err_hint,
                            $their.$field.to_string(),
                            $our.$field.to_string()
                        );
                        SshError::from("key exchange error.")
                    })
            };
        }

        // kex
        let kex = match_field!(self, other, key_exchange, "DH algorithm")?;
        // pubkey
        let pubkey = match_field!(self, other, public_key, "signature algorithm")?;
        // encryption
        let c_enc = match_field!(self, other, c_encryption, "client encryption algorithm")?;
        let s_enc = match_field!(self, other, s_encryption, "server encryption algorithm")?;

        // mac
        let c_mac = match_field!(self, other, c_mac, "client mac algorithm")?;
        let s_mac = match_field!(self, other, s_mac, "server mac algorithm")?;

        // compress
        let c_compress = match_field!(self, other, c_compression, "client compression algorithm")?;
        let s_compress = match_field!(self, other, s_compression, "server compression algorithm")?;

        let negotiated = Self {
            key_exchange: KeyExchange(vec![kex.to_string()]),
            public_key: PublicKey(vec![pubkey.to_string()]),
            c_encryption: Encryption(vec![c_enc.to_string()]),
            s_encryption: Encryption(vec![s_enc.to_string()]),
            c_mac: Mac(vec![c_mac.to_string()]),
            s_mac: Mac(vec![s_mac.to_string()]),
            c_compression: Compression(vec![c_compress.to_string()]),
            s_compression: Compression(vec![s_compress.to_string()]),
        };

        log::info!("matched algorithms [{:?}]", negotiated);

        Ok(negotiated)
    }

    fn as_i(&self) -> Vec<u8> {
        let mut data = Data::new();
        data.put_str(self.key_exchange.to_string().as_str());
        data.put_str(self.public_key.to_string().as_str());
        data.put_str(self.c_encryption.to_string().as_str());
        data.put_str(self.s_encryption.to_string().as_str());
        data.put_str(self.c_mac.to_string().as_str());
        data.put_str(self.s_mac.to_string().as_str());
        data.put_str(self.c_compression.to_string().as_str());
        data.put_str(self.s_compression.to_string().as_str());
        data.to_vec()
    }
}

impl<'a> Packet<'a> for AlgList {
    fn pack(self, client: &'a mut Client) -> crate::model::SecPacket<'a> {
        log::info!("client algorithms: [{:?}]", self);
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_KEXINIT);
        data.extend(util::cookie());
        data.extend(self.as_i());
        data.put_str("")
            .put_str("")
            .put_u8(false as u8)
            .put_u32(0_u32);

        (data, client).into()
    }

    fn unpack(pkt: SecPacket) -> SshResult<Self>
    where
        Self: Sized,
    {
        let data = pkt.into_inner();
        assert_eq!(data[0], ssh_msg_code::SSH_MSG_KEXINIT);
        AlgList::from(data)
    }
}

#[derive(Clone, Debug)]
pub struct KeyExchange(pub Vec<String>);
impl KeyExchange {
    pub fn client_default() -> Self {
        KeyExchange(vec![
            constant::kex::CURVE25519_SHA256.to_string(),
            constant::kex::ECDH_SHA2_NISTP256.to_string(),
        ])
    }
}

impl ToString for KeyExchange {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey(pub Vec<String>);
impl PublicKey {
    pub fn client_default() -> Self {
        PublicKey(vec![
            constant::pubkey::SSH_ED25519.to_string(),
            constant::pubkey::RSA_SHA2_512.to_string(),
            constant::pubkey::RSA_SHA2_256.to_string(),
        ])
    }
}

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct Encryption(pub Vec<String>);
impl Encryption {
    pub fn client_default() -> Self {
        Encryption(vec![
            constant::enc::CHACHA20_POLY1305_OPENSSH.to_string(),
            constant::enc::AES128_CTR.to_string(),
        ])
    }
}
impl ToString for Encryption {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct Mac(pub Vec<String>);
impl Mac {
    pub fn client_default() -> Self {
        Mac(vec![constant::mac::HMAC_SHA1.to_string()])
    }
}
impl ToString for Mac {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct Compression(pub Vec<String>);
impl Compression {
    pub fn client_default() -> Self {
        Compression(vec![constant::compress::NONE.to_string()])
    }
}
impl ToString for Compression {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}

fn to_string(v: &[String]) -> String {
    let mut s = String::new();
    if v.is_empty() {
        return s;
    }
    for (i, val) in v.iter().enumerate() {
        if i == 0 {
            s.push_str(val);
            continue;
        }
        s.push_str(format!(",{}", val).as_str());
    }
    s
}

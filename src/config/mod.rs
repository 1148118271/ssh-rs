pub(crate) mod algorithm;
pub(crate) mod auth;
pub(crate) mod version;
use crate::algorithm::PubKey as PubKeyAlgs;

#[derive(Clone)]
pub(crate) struct Config {
    pub ver: version::SshVersion,
    pub auth: auth::AuthInfo,
    pub algs: algorithm::AlgList,
    pub timeout: u128, // in milliseconds
}

impl Default for Config {
    fn default() -> Self {
        Self {
            algs: algorithm::AlgList::client_default(),
            auth: auth::AuthInfo::default(),
            ver: version::SshVersion::default(),
            timeout: 30 * 1000,
        }
    }
}

impl Config {
    // use an empty client algorithm list
    pub fn disable_default() -> Self {
        Self {
            algs: algorithm::AlgList::default(),
            auth: auth::AuthInfo::default(),
            ver: version::SshVersion::default(),
            timeout: 30 * 1000,
        }
    }

    pub(crate) fn tune_alglist_on_private_key(&mut self) {
        if let Some(ref key_pair) = self.auth.key_pair {
            match key_pair.key_type {
                auth::KeyType::PemRsa | auth::KeyType::SshRsa => {
                    self.algs
                        .public_key
                        .0
                        .insert(0, PubKeyAlgs::RsaSha2_256.as_str().to_owned());
                }
                auth::KeyType::SshEd25519 => {
                    self.algs
                        .public_key
                        .0
                        .insert(0, PubKeyAlgs::SshEd25519.as_str().to_owned());
                }
            }
        }
    }
}

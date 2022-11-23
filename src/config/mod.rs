pub(crate) mod algorithm;
pub(crate) mod auth;
pub(crate) mod version;
use crate::algorithm::PubKey as PubKeyAlgs;

fn insert_or_move_first(v: &mut Vec<String>, alg: &str) {
    if let Some(i) = v.iter().position(|each| *each == alg) {
        v.swap(0, i)
    } else {
        v.insert(0, alg.to_owned())
    }
}

#[derive(Clone)]
pub(crate) struct Config {
    pub ver: version::SshVersion,
    pub auth: auth::AuthInfo,
    pub algs: algorithm::AlgList,
    pub timeout: u128, // in milliseconds
    auto_tune: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            algs: algorithm::AlgList::client_default(),
            auth: auth::AuthInfo::default(),
            ver: version::SshVersion::default(),
            timeout: 30 * 1000,
            auto_tune: true,
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
            auto_tune: false,
        }
    }

    pub(crate) fn tune_alglist_on_private_key(&mut self) {
        if !self.auto_tune {
            return;
        }

        if let Some(ref key_pair) = self.auth.key_pair {
            match key_pair.key_type {
                auth::KeyType::PemRsa | auth::KeyType::SshRsa => {
                    let pubkeys = &mut self.algs.public_key.0;
                    insert_or_move_first(pubkeys, PubKeyAlgs::RsaSha2_256.as_str());
                    insert_or_move_first(pubkeys, PubKeyAlgs::RsaSha2_512.as_str());
                }
                auth::KeyType::SshEd25519 => {
                    let pubkeys = &mut self.algs.public_key.0;
                    insert_or_move_first(pubkeys, PubKeyAlgs::SshEd25519.as_str());
                }
            }
        }
    }
}

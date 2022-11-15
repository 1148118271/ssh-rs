pub(crate) mod algorithm;
pub(crate) mod auth;
pub(crate) mod version;

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
}

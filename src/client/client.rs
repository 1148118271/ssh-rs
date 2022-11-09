use crate::{algorithm::encryption::Encryption, config::Config};

use crate::config::algorithm::AlgList;
use crate::{algorithm::encryption::EncryptionNone, model::Sequence};

// the underlay connection
pub(crate) struct Client {
    pub(super) sequence: Sequence,
    pub(super) config: Config,
    pub(super) negotiated: AlgList,
    pub(super) encryptor: Box<dyn Encryption>,
    pub(super) session_id: Vec<u8>,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            encryptor: Box::new(EncryptionNone::default()),
            negotiated: AlgList::new(),
            session_id: vec![],
            sequence: Sequence::new(),
        }
    }

    pub fn get_encryptor(&mut self) -> &mut dyn Encryption {
        self.encryptor.as_mut()
    }

    pub fn get_seq(&mut self) -> &mut Sequence {
        &mut self.sequence
    }
}

use std::io::Write;
use crate::client::Client;
use crate::data::Data;
use crate::packet::Packet;
use crate::{Session, SshError};
use crate::window_size::WindowSize;

impl Session {

    /// 发送客户端版本
    pub(crate) fn write_version(&mut self, buf: &[u8]) -> Result<(), SshError> {
        let client = self.client.as_mut().unwrap();
        match client.stream.write(&buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub fn write(&mut self, data: Data) -> Result<(), SshError> {
        self.write_data(data, None)
    }

    pub fn write_data(&mut self, data: Data, rws: Option<&mut WindowSize>) -> Result<(), SshError> {
        let client = self.client.as_mut().unwrap();
        let buf = if self.is_encryption {
            match self.encryption.as_mut() {
                None => return Err(SshError::from("encryption algorithm is none.")),
                Some(encryption) => {
                    if let Some(rws) = rws {
                        // rws.process_remote_window_size(data.as_slice(), client, encryption)?;
                    }
                    client.get_encryption_data(data, encryption)?
                }
            }
        } else {
            let mut packet = Packet::from(data);
            packet.build(None, false);
            packet.to_vec()
        };
        client.sequence.client_auto_increment();
        loop {
            if let Err(e) = client.stream.write(&buf) {
                if Client::is_would_block(&e) {
                    continue
                }
                return Err(SshError::from(e))
            } else {
                break
            }
        }
        if let Err(e) = client.stream.flush() {
            return Err(SshError::from(e))
        }
        Ok(())
    }

}

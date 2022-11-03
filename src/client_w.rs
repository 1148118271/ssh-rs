use crate::client::Client;
use crate::data::Data;
use crate::packet::Packet;
use crate::window_size::WindowSize;
use crate::{SshError, SshResult};
use std::io::Write;


impl Client {
    /// 发送客户端版本
    pub(crate) fn write_version(&mut self, buf: &[u8]) -> SshResult<()> {
        match self.stream.write(buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(SshError::from(e)),
        }
    }

    pub fn write(&mut self, data: Data) -> Result<(), SshError> {
        self.write_data(data, None)
    }

    pub fn write_data(&mut self, data: Data, rws: Option<&mut WindowSize>) -> Result<(), SshError> {
        let buf = if self.is_encryption {
            if let Some(rws) = rws {
                rws.process_remote_window_size(data.as_slice(), self)?;
            }
            self.get_encryption_data(data)?
        } else {
            let mut packet = Packet::from(data);
            packet.build(None, false);
            packet.to_vec()
        };
        self.sequence.client_auto_increment();
        while let Err(e) = self.stream.write(&buf) {
            if Client::is_would_block(&e) {
                continue;
            }
            return Err(SshError::from(e));
        }
        if let Err(e) = self.stream.flush() {
            return Err(SshError::from(e));
        }
        Ok(())
    }

    pub(crate) fn get_encryption_data(&mut self, data: Data) -> SshResult<Vec<u8>> {
        let encryption = self.encryption.as_mut().unwrap();
        let mut packet = Packet::from(data);
        packet.build(Some(encryption.as_ref()), true);
        let mut buf = packet.to_vec();
        encryption.encrypt(self.sequence.client_sequence_num, &mut buf);
        Ok(buf)
    }
}

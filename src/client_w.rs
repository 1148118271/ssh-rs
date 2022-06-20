use std::io::Write;
use std::sync::atomic::Ordering::Relaxed;
use crate::client::Client;
use crate::data::Data;
use crate::algorithm::encryption::IS_ENCRYPT;
use crate::packet::Packet;
use crate::{SshError, SshResult};
use crate::algorithm::encryption;
use crate::window_size::WindowSize;

impl Client {

    /// 发送客户端版本
    pub fn write_version(&mut self, buf: &[u8]) -> Result<(), SshError> {
        match self.stream.write(&buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub fn write(&mut self, data: Data) -> Result<(), SshError> {
        self.write_data(data, None)
    }

    pub fn write_data(&mut self, data: Data, rws: Option<&mut WindowSize>) -> Result<(), SshError> {
        let buf = if IS_ENCRYPT.load(Relaxed) {
            if let Some(rws) = rws {
                rws.process_remote_window_size(data.as_slice())?;
            }
            self.get_encryption_data(data)?
        } else {
            let mut packet = Packet::from(data);
            packet.build(false);
            packet.to_vec()
        };
        self.sequence.client_auto_increment();
        loop {
            if let Err(e) = self.stream.write(&buf) {
                if Client::is_would_block(&e) {
                    continue
                }
                return Err(SshError::from(e))
            } else {
                break
            }
        }
        if let Err(e) = self.stream.flush() {
            return Err(SshError::from(e))
        }
        Ok(())
    }


    fn get_encryption_data(&self, data: Data) -> SshResult<Vec<u8>> {
        let mut packet = Packet::from(data);
        packet.build(true);
        let mut buf = packet.to_vec();
        encryption::get().encrypt(self.sequence.client_sequence_num, &mut buf);
        Ok(buf)
    }
}
use std::io::Write;
use std::ops::Deref;
use std::thread::sleep_ms;
use crate::client::Client;
use crate::{
    SshError,
    SshResult,
    constant,
    h::H,
    kex,
    slog::log
};
use crate::data::Data;
use crate::packet::Packet;
use crate::window_size::WindowSize;

impl Client {
    /// 发送客户端版本
    pub(crate) fn write_version(&mut self, buf: &[u8]) -> SshResult<()> {
        match self.stream.write(&buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub fn write(&mut self, data: Data) -> Result<(), SshError> {
        self.write_data(data, None)
    }

    pub fn write_data(&mut self, data: Data, rws: Option<&mut WindowSize>) -> Result<(), SshError> {
        self.w_size_one_gb()?;
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
        self.w_size += buf.len();
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
        self.timeout.renew();
        if let Err(e) = self.stream.flush() {
            return Err(SshError::from(e))
        }
        Ok(())
    }

    pub(crate) fn get_encryption_data(&mut self, data: Data) -> SshResult<Vec<u8>> {
        let encryption = self.encryption.as_mut().unwrap();
        let mut packet = Packet::from(data);
        packet.build(Some(encryption.deref()),true);
        let mut buf = packet.to_vec();
        encryption.encrypt(self.sequence.client_sequence_num, &mut buf);
        Ok(buf)
    }

    pub(crate) fn w_size_one_gb(&mut self) -> SshResult<()> {
        if self.w_size < constant::size::ONE_GB {
            return Ok(())
        }
        log::info!("————————————————————————————");
        self.w_size = 0;

        let mut h = H::new();
        let cv = self.config.version.client_version.as_str();
        let sv = self.config.version.server_version.as_str();
        h.set_v_c(cv);
        h.set_v_s(sv);
        kex::key_agreement(&mut h, self)?;
        self.w_size = 0;
        log::info!("————————————————————————————");
        Ok(())
    }
}
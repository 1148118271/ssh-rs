use crate::model::Data;
use crate::model::Packet;
use crate::model::WindowSize;
use crate::{client::Client, config::version::SshVersion};
use crate::{constant, h::H, kex, SshError, SshResult};
use std::io::{Read, Write};

impl<S> Client<S>
where
    S: Read + Write,
{
    pub(crate) fn write(&mut self, data: Data) -> Result<(), SshError> {
        self.write_data(data, None)
    }

    pub(crate) fn write_data(
        &mut self,
        data: Data,
        mut rws: Option<&mut WindowSize>,
    ) -> Result<(), SshError> {
        let buf = if self.is_encryption {
            if let Some(rws) = &mut rws {
                rws.process_remote_window_size(data.as_slice(), self)?;
            }
            self.w_size_one_gb(&mut rws)?;
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
                if Client::<S>::is_would_block(&e) {
                    self.timeout.is_timeout()?;
                    continue;
                }
                return Err(SshError::from(e));
            } else {
                self.timeout.renew();
                break;
            }
        }
        if let Err(e) = self.stream.flush() {
            return Err(SshError::from(e));
        }
        self.timeout.renew();
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

    // 数据超过1GB密钥重新交换
    fn w_size_one_gb(&mut self, rws: &mut Option<&mut WindowSize>) -> SshResult<()> {
        if self.w_size < constant::size::ONE_GB {
            return Ok(());
        }
        if self.is_r_1_gb {
            return Ok(());
        }
        self.w_size = 0;
        self.is_w_1_gb = true;
        let mut h = H::new();
        if let SshVersion::V2(ref our, ref their) = self.config.lock().unwrap().ver {
            h.set_v_c(our);
            h.set_v_s(their);
        };
        match rws {
            None => kex::key_agreement(&mut h, self, None)?,
            Some(ws) => kex::key_agreement(&mut h, self, Some(ws))?,
        };
        self.is_w_1_gb = false;
        Ok(())
    }
}

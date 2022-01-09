use crate::channel::Channel;
use crate::{message, SshError, strings};
use crate::error::{SshErrorKind, SshResult};
use crate::packet::{Data, Packet};

pub struct ChannelExec(pub(crate) Channel);

impl ChannelExec {
    pub fn set_command(mut self, command: &str) -> SshResult<Vec<u8>> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.0.server_channel)
            .put_str(strings::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        let mut packet = Packet::from(data);
        packet.build();
        match self.0.stream.lock() {
            Ok(mut v) => v.write(packet.as_slice())?,
            Err(_) => return Err(SshError::from(SshErrorKind::MutexError))
        }
        let mut r = vec![];
        loop {
            let results = match self.0.stream.lock() {
                Ok(mut v) => v.read()?,
                Err(_) =>
                    return Err(SshError::from(SshErrorKind::MutexError))
            };
            for buf in results {
                let message_code = buf[5];
                match message_code {
                    message::SSH_MSG_CHANNEL_DATA => {
                        let mut data = Packet::processing_data(buf);
                        data.get_u8();
                        let cc = data.get_u32();
                        if cc == self.0.client_channel {
                            r.append(&mut data.get_u8s());
                        }
                    }
                    message::SSH_MSG_CHANNEL_CLOSE => {
                        let mut data = Packet::processing_data(buf);
                        data.get_u8();
                        let cc = data.get_u32();
                        if cc == self.0.client_channel {
                            self.0.close()?;
                            return Ok(r)
                        }
                    }
                    _ => self.0.other_info(message_code, buf)?
                }

            }
        }
    }
}
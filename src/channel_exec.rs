use crate::channel::Channel;
use crate::{message, SshError, strings};
use crate::packet::{Data, Packet};

pub struct ChannelExec(pub(crate) Channel);

impl ChannelExec {
    pub fn set_command(&mut self, command: &str) -> Result<Vec<u8>, SshError> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.0.server_channel)
            .put_str(strings::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        let mut packet = Packet::from(data);
        packet.build();
        self.0.stream.write(packet.as_slice())?;
        let mut r = vec![];
        loop {
            let results = self.0.stream.read()?;
            for buf in results {
                let message_code = buf[5];
                match message_code {
                    message::SSH_MSG_CHANNEL_DATA => {
                        let mut data = Packet::processing_data(buf);
                        data.get_u8();
                        data.get_u32();
                        r.append(&mut data.get_u8s());
                    }
                    message::SSH_MSG_CHANNEL_CLOSE => {
                        return Ok(r)
                    }
                    _ => self.0.other_info(message_code, buf)?
                }

            }
        }
    }
}
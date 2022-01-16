use crate::channel::Channel;
use crate::{message, strings, util};
use crate::error::SshResult;
use crate::packet::{Data, Packet};

pub struct ChannelExec(pub(crate) Channel);

impl ChannelExec {

    fn exec_command(&self, command: &str) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.0.server_channel)
            .put_str(strings::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

    fn get_data(&mut self, v: &mut Vec<u8>) -> SshResult<()> {
        let mut client = util::client()?;
        let results = client.read()?;
        util::unlock(client);
        for result in results {
            if result.is_empty() { continue }
            let message_code = result[5];
            match message_code {
                message::SSH_MSG_CHANNEL_DATA => {
                    let mut data = Packet::processing_data(result);
                    data.get_u8();
                    let cc = data.get_u32();
                    if cc == self.0.client_channel {
                        v.append(&mut data.get_u8s());
                    }
                }
                message::SSH_MSG_CHANNEL_CLOSE => {
                    let mut data = Packet::processing_data(result);
                    data.get_u8();
                    let cc = data.get_u32();
                    if cc == self.0.client_channel {
                        self.0.remote_close = true;
                        self.0.close()?;
                    }
                }
                _ => self.0.other(message_code, result)?
            }
        }
        Ok(())
    }

    pub fn send_command(mut self, command: &str) -> SshResult<Vec<u8>> {
        self.exec_command(command)?;
        let mut r = vec![];
        loop {
            self.get_data(&mut r)?;
            if self.0.remote_close
                && self.0.local_close
            {
                break
            }
        }
        Ok(r)
    }
}
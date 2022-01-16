use crate::channel::Channel;
use crate::{message, util};
use crate::error::SshResult;
use crate::packet::{Data, Packet};

pub struct ChannelShell(pub(crate) Channel);

impl ChannelShell {
    pub fn read(&mut self) -> SshResult<Vec<u8>> {
        let mut buf = vec![];
        self.0.window_adjust()?;
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
                        let mut vec = data.get_u8s();
                        buf.append(&mut vec);
                    }
                }
                _ => self.0.other(message_code, result)?
            }
        }
        Ok(buf)
    }

    pub fn write(&self, buf: &[u8]) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.0.server_channel)
            .put_bytes(buf);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

    pub fn close(mut self) -> SshResult<()> {
        self.0.close()
    }

}
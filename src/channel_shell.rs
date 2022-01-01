use std::sync::atomic::Ordering::Relaxed;
use crate::channel::Channel;
use crate::{global_variable, message, SshError};
use crate::encryption::ChaCha20Poly1305;
use crate::hash::HASH;
use crate::packet::{Data, Packet};

pub struct ChannelShell(pub(crate) Channel);

impl ChannelShell {
    pub fn read(&mut self) -> Result<Vec<u8>, SshError> {
        let mut buf = vec![];
        self.0.window_adjust();
        let results = self.0.stream.read()?;
        for result in results {
            let message_code = result[5];
            match message_code {
                message::SSH_MSG_CHANNEL_DATA => {
                    let mut data = Packet::processing_data(result);
                    data.get_u8();
                    data.get_u32();
                    let vec = data.get_u8s();
                    buf.extend(vec);
                }
                _ => self.0.other_info(message_code, result)?
            }
        }
        Ok(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), SshError> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.0.server_channel)
            .put_bytes(buf);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.0.stream.write(packet.as_slice())?)
    }

    pub fn close(self) -> Result<(), SshError> {
        self.0.close()
    }

}
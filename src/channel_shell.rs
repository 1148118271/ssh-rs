use crate::channel::Channel;
use crate::{message, SshError};
use crate::error::{SshErrorKind, SshResult};
use crate::packet::{Data, Packet};

pub struct ChannelShell(pub(crate) Channel);

impl ChannelShell {
    pub fn read(&mut self) -> SshResult<Vec<u8>> {
        let mut buf = vec![];
        self.0.window_adjust()?;
        let results = match self.0.stream.lock() {
            Ok(ref mut v) => v.read()?,
            Err(_) =>
                return Err(SshError::from(SshErrorKind::MutexError))
        };
        for result in results {
            let message_code = result[5];
            match message_code {
                message::SSH_MSG_CHANNEL_DATA => {
                    let mut data = Packet::processing_data(result);
                    data.get_u8();
                    let cc = data.get_u32();
                    if cc == self.0.client_channel {
                        let vec = data.get_u8s();
                        buf.extend(vec);
                    }
                }
                _ => self.0.other_info(message_code, result)?
            }
        }
        Ok(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.0.server_channel)
            .put_bytes(buf);
        let mut packet = Packet::from(data);
        packet.build();
        match self.0.stream.lock() {
            Ok(ref mut v) =>
                Ok(v.write(packet.as_slice())?),
            Err(_) =>
                Err(SshError::from(SshErrorKind::MutexError))
        }
    }

    pub fn close(mut self) -> SshResult<()> {
        self.0.close()?;
        loop {
            let results = match self.0.stream.lock() {
                Ok(mut v) => v.read()?,
                Err(_) =>
                    return Err(SshError::from(SshErrorKind::MutexError))
            };
            for result in results {
                let message_code = result[5];
                match message_code {
                    message::SSH_MSG_CHANNEL_CLOSE => return Ok(()),
                    _ => self.0.other_info(message_code, result)?
                }
            }
        }
    }

}
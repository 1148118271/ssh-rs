use super::channel::Channel;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::error::SshResult;
use crate::model::Data;
use std::ops::{Deref, DerefMut};
use async_std::io::{Read, Write};
pub struct ChannelExec<S: Read + Write>(Channel<S>);

impl<S> ChannelExec<S>
where
    S: Read + Write + Unpin,
{
    pub(crate) fn open(channel: Channel<S>) -> Self {
        ChannelExec(channel)
    }

    async fn exec_command(&mut self, command: &str) -> SshResult<()> {
        log::debug!("Send command {}", command);
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel_no)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        self.send(data).await
    }

    /// Send an executable command to the server
    /// and get the result
    ///
    /// This method also implicitly consume the channel object,
    /// since the exec channel can only execute one command
    ///
    pub async fn send_command(mut self, command: &str) -> SshResult<Vec<u8>> {
        self.exec_command(command).await?;

        let r = self.recv_to_end().await?;
        Ok(r)
    }
}

impl<S> Deref for ChannelExec<S>
where
    S: Read + Write,
{
    type Target = Channel<S>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> DerefMut for ChannelExec<S>
where
    S: Read + Write,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

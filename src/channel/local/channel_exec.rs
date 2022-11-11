use super::channel::Channel;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::error::SshResult;
use crate::model::Data;
use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub struct ChannelExec<S: Read + Write + Send + 'static>(Channel<S>);

impl<S> ChannelExec<S>
where
    S: Read + Write + Send + 'static,
{
    pub(crate) fn open(channel: Channel<S>) -> Self {
        ChannelExec(channel)
    }

    fn exec_command(&mut self, command: &str) -> SshResult<()> {
        log::debug!("Send command {}", command);
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel_no)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        self.send(data)
    }

    pub fn send_command(mut self, command: &str) -> SshResult<Vec<u8>> {
        self.exec_command(command)?;

        let r = self.recv(true)?;
        Ok(r)
    }
}

impl<S> Deref for ChannelExec<S>
where
    S: Read + Write + Send + 'static,
{
    type Target = Channel<S>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> DerefMut for ChannelExec<S>
where
    S: Read + Write + Send + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

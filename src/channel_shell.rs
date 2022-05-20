use error::SshResult;
use packet::Data;
use constant::{ssh_msg_code, ssh_str};
use crate::channel::Channel;
use crate::{client, util};


pub struct ChannelShell(pub(crate) Channel);

impl ChannelShell {

    pub(crate) fn open(mut channel: Channel) -> SshResult<Self> {
        // shell 形式需要一个伪终端
        ChannelShell::request_pty(&channel)?;
        ChannelShell::get_shell(&channel)?;
        loop {
            let mut client = client::locking()?;
            let results = client.read()?;
            client::unlock(client);
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {
                        return Ok(ChannelShell(channel))
                    }
                    _ => channel.other(message_code, result)?
                }
            }
        }
    }

    fn request_pty(channel: &Channel) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(channel.server_channel)
            .put_str(ssh_str::PTY_REQ)
            .put_u8(false as u8)
            .put_str(ssh_str::XTERM_VAR)
            .put_u32(80)
            .put_u32(24)
            .put_u32(640)
            .put_u32(480);
        let model = [
            128,                  // TTY_OP_ISPEED
            0, 1, 0xc2, 0,        // 115200
            129,                  // TTY_OP_OSPEED
            0, 1, 0xc2, 0,        // 115200 again
            0_u8,                 // TTY_OP_END
        ];
        data.put_u8s(&model);
        let mut client = client::locking()?;
        client.write(data)
    }

    fn get_shell(channel: &Channel) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(channel.server_channel)
            .put_str(ssh_str::SHELL)
            .put_u8(true as u8);
        let mut client = client::locking()?;
        client.write(data)
    }

    pub fn read(&mut self) -> SshResult<Vec<u8>> {
        let mut buf = vec![];
        let mut client = client::locking()?;
        let results = client.read()?;
        client::unlock(client);
        for mut result in results {
            if result.is_empty() { continue }
            let message_code = result.get_u8();
            match message_code {
                ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                    let cc = result.get_u32();
                    if cc == self.0.client_channel {
                        let mut vec = result.get_u8s();
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
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.0.server_channel)
            .put_u8s(buf);
        let mut client = client::locking()?;
        client.write(data)
    }

    pub fn close(mut self) -> SshResult<()> {
        self.0.close()
    }

}

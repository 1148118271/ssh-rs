use crate::channel::Channel;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::error::SshResult;
use std::io::{Read, Write};

pub struct ChannelShell<S: Read + Write>(pub(crate) Channel<S>);

impl<S> ChannelShell<S>
where
    S: Read + Write,
{
    pub(crate) fn open(mut channel: Channel<S>) -> SshResult<Self> {
        // shell 形式需要一个伪终端
        ChannelShell::request_pty(&mut channel)?;
        ChannelShell::get_shell(&mut channel)?;
        loop {
            let results = channel.client.as_ref().borrow_mut().read()?;
            for mut result in results {
                if result.is_empty() {
                    continue;
                }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => return Ok(ChannelShell(channel)),
                    _ => channel.other(message_code, result)?,
                }
            }
        }
    }

    fn request_pty(channel: &mut Channel<S>) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(channel.server_channel_no)
            .put_str(ssh_str::PTY_REQ)
            .put_u8(false as u8)
            .put_str(ssh_str::XTERM_VAR)
            .put_u32(80)
            .put_u32(24)
            .put_u32(640)
            .put_u32(480);
        let model = [
            128, // TTY_OP_ISPEED
            0, 1, 0xc2, 0,   // 115200
            129, // TTY_OP_OSPEED
            0, 1, 0xc2, 0,    // 115200 again
            0_u8, // TTY_OP_END
        ];
        data.put_u8s(&model);
        channel.client.as_ref().borrow_mut().write(data)
    }

    fn get_shell(channel: &mut Channel<S>) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(channel.server_channel_no)
            .put_str(ssh_str::SHELL)
            .put_u8(true as u8);
        channel.client.as_ref().borrow_mut().write(data)
    }

    pub fn read(&mut self) -> SshResult<Vec<u8>> {
        let mut buf = vec![];
        let results = self
            .0
            .client
            .as_ref()
            .borrow_mut()
            .read_data(Some(&mut self.0.window_size))?;
        for mut result in results {
            if result.is_empty() {
                continue;
            }
            let message_code = result.get_u8();
            match message_code {
                ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                    let cc = result.get_u32();
                    if cc == self.0.client_channel_no {
                        let mut vec = result.get_u8s();
                        buf.append(&mut vec);
                    }
                }
                _ => self.0.other(message_code, result)?,
            }
        }
        Ok(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.0.server_channel_no)
            .put_u8s(buf);
        self.0
            .client
            .as_ref()
            .borrow_mut()
            .write_data(data, Some(&mut self.0.window_size))
    }

    pub fn close(mut self) -> SshResult<()> {
        self.0.close()
    }
}

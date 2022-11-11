use super::channel::Channel;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::error::SshResult;
use crate::model::Data;
use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub struct ChannelShell(Channel, Vec<u8>);

// impl ChannelShell
//
//
// {
//     pub(crate) fn open(channel: Channel) -> SshResult<Self> {
//         // shell 形式需要一个伪终端
//         let mut channel_shell = ChannelShell(channel, vec![]);
//         channel_shell.request_pty()?;
//         channel_shell.get_shell()?;
//         while !channel_shell.is_close() {
//             let maybe_recv = channel_shell.try_recv()?;
//             if let ChannelTryRead::Code(ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS) = maybe_recv {
//                 break;
//             }
//         }
//         Ok(channel_shell)
//     }

//     fn request_pty(&mut self) -> SshResult<()> {
//         let mut data = Data::new();
//         data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
//             .put_u32(self.server_channel_no)
//             .put_str(ssh_str::PTY_REQ)
//             .put_u8(false as u8)
//             .put_str(ssh_str::XTERM_VAR)
//             .put_u32(80)
//             .put_u32(24)
//             .put_u32(640)
//             .put_u32(480);
//         let model = [
//             128, // TTY_OP_ISPEED
//             0, 1, 0xc2, 0,   // 115200
//             129, // TTY_OP_OSPEED
//             0, 1, 0xc2, 0,    // 115200 again
//             0_u8, // TTY_OP_END
//         ];
//         data.put_u8s(&model);
//         self.send(data)
//     }

//     fn get_shell(&mut self) -> SshResult<()> {
//         let mut data = Data::new();
//         data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
//             .put_u32(self.server_channel_no)
//             .put_str(ssh_str::SHELL)
//             .put_u8(true as u8);
//         self.send(data)
//     }

//     pub fn read(&mut self) -> SshResult<Vec<u8>> {
//         let mut recv = self.recv(false)?;
//         let mut current = self.1.clone();
//         self.1.clear();
//         current.append(&mut recv);
//         Ok(current)
//     }

//     pub fn write(&mut self, buf: &[u8]) -> SshResult<()> {
//         let mut maybe_response = self.send_data(buf.to_vec())?;
//         self.1.append(&mut maybe_response);
//         Ok(())
//     }
// }

impl Deref for ChannelShell {
    type Target = Channel;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ChannelShell {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

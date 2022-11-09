use super::channel_exec::ChannelExec;
use super::channel_scp::ChannelScp;
use super::channel_shell::ChannelShell;
use crate::client::Client;
use crate::constant::ssh_msg_code;
use crate::error::{SshError, SshResult};
use crate::model::Data;
use crate::slog::log;
use crate::model::WindowSize;
use std::cell::RefCell;
use std::rc::Rc;
use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub struct Channel<S>
where
    S: Read + Write,
{
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) window_size: WindowSize,
    pub(crate) client: Rc<RefCell<Client<S>>>,
}

impl<S> Deref for Channel<S>
where
    S: Read + Write,
{
    type Target = WindowSize;

    fn deref(&self) -> &Self::Target {
        &self.window_size
    }
}

impl<S> DerefMut for Channel<S>
where
    S: Read + Write,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.window_size
    }
}

impl<S> Channel<S>
where
    S: Read + Write,
{
    pub(crate) fn other(&mut self, message_code: u8, mut result: Data) -> SshResult<()> {
        match message_code {
            ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                self.client.as_ref().borrow_mut().write(data)?;
            }
            // 通道大小
            ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                // 接收方通道号， 暂时不需要
                result.get_u32();
                // 需要调整增加的窗口大小
                let rws = result.get_u32();
                self.window_size.add_remote_window_size(rws);
            }
            ssh_msg_code::SSH_MSG_CHANNEL_EOF => {}
            ssh_msg_code::SSH_MSG_CHANNEL_REQUEST => {}
            ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {}
            ssh_msg_code::SSH_MSG_CHANNEL_FAILURE => {
                return Err(SshError::from("channel failure."))
            }
            ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                let cc = result.get_u32();
                if cc == self.client_channel_no {
                    self.remote_close = true;
                    self.close()?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub fn open_shell(self) -> SshResult<ChannelShell<S>> {
        log::info!("shell opened.");
        ChannelShell::open(self)
    }



    pub fn open_scp(self) -> SshResult<ChannelScp<S>> {
        log::info!("scp opened.");
        Ok(ChannelScp::open(self))
    }

    pub fn close(&mut self) -> SshResult<()> {
        log::info!("channel close.");
        self.send_close()?;
        self.receive_close()
    }

    fn send_close(&mut self) -> SshResult<()> {
        if self.local_close {
            return Ok(());
        }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_CLOSE)
            .put_u32(self.server_channel_no);
        self.client.as_ref().borrow_mut().write(data)?;
        self.local_close = true;
        Ok(())
    }

    fn receive_close(&mut self) -> SshResult<()> {
        if self.remote_close {
            return Ok(());
        }
        loop {
            // close 时不消耗窗口空间
            let results = self.client.as_ref().borrow_mut().read()?;
            for mut result in results {
                if result.is_empty() {
                    continue;
                }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                        let cc = result.get_u32();
                        if cc == self.client_channel_no {
                            self.remote_close = true;
                            return Ok(());
                        }
                    }
                    _ => self.other(message_code, result)?,
                }
            }
        }
    }

    pub(crate) fn is_close(&self) -> bool {
        self.local_close && self.remote_close
    }
}

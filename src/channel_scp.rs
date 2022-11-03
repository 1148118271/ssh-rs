use crate::constant::{scp, ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::error::{SshError, SshResult};
use crate::Channel;
use std::borrow::BorrowMut;
use std::path::{Path, PathBuf};

pub struct ChannelScp {
    pub(crate) channel: Channel,
    pub(crate) local_path: PathBuf,
}

impl ChannelScp {
    pub(crate) fn open(channel: Channel) -> Self {
        ChannelScp {
            channel,
            local_path: Default::default(),
        }
    }

    pub(crate) fn send_str(&mut self, cmd: &str) -> SshResult<()> {
        self.send_bytes(cmd.as_bytes())
    }

    pub(crate) fn send_end(&mut self) -> SshResult<()> {
        self.send_bytes(&[scp::END])
    }

    pub(crate) fn send_bytes(&mut self, bytes: &[u8]) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.channel.server_channel_no)
            .put_u8s(bytes);
        let session = unsafe { &mut *self.channel.session };
        session
            .client
            .as_mut()
            .unwrap()
            .write_data(data, Some(self.channel.window_size.borrow_mut()))
    }

    pub(crate) fn read_data(&mut self) -> SshResult<Vec<u8>> {
        let mut vec = vec![];
        loop {
            if !vec.is_empty() {
                break;
            }
            let session = unsafe { &mut *self.channel.session };
            let results = session
                .client
                .as_mut()
                .unwrap()
                .read_data(Some(self.channel.window_size.borrow_mut()))?;
            for mut result in results {
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                        let cc = result.get_u32();
                        if cc == self.channel.client_channel_no {
                            vec.extend(result.get_u8s())
                        }
                    }
                    ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                        let cc = result.get_u32();
                        if cc == self.channel.client_channel_no {
                            self.channel.remote_close = true;
                            self.channel.close()?;
                            return Ok(vec);
                        }
                    }
                    _ => self.channel.other(message_code, result)?,
                }
            }
        }
        Ok(vec)
    }

    pub(crate) fn exec_scp(&mut self, command: &str) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.channel.server_channel_no)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        self.channel
            .get_session_mut()
            .client
            .as_mut()
            .unwrap()
            .write(data)
    }

    pub(crate) fn command_init(&self, remote_path: &str, arg: &str) -> String {
        format!(
            "{} {} {} {} {} {}",
            ssh_str::SCP,
            arg,
            scp::QUIET,
            scp::RECURSIVE,
            scp::PRESERVE_TIMES,
            remote_path
        )
    }
}

pub(crate) fn check_path(path: &Path) -> SshResult<()> {
    if path.to_str().is_none() {
        return Err(SshError::from("path is null."));
    }
    Ok(())
}

pub struct ScpFile {
    pub(crate) modify_time: i64,
    pub(crate) access_time: i64,
    pub(crate) size: u64,
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    pub(crate) local_path: PathBuf,
}

impl ScpFile {
    pub(crate) fn new() -> Self {
        ScpFile {
            modify_time: 0,
            access_time: 0,
            size: 0,
            name: String::new(),
            is_dir: false,
            local_path: Default::default(),
        }
    }
}

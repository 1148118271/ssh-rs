use constant::size::LOCAL_WINDOW_SIZE;
use constant::{size, ssh_msg_code};
use error::SshResult;
use packet::Data;
use crate::{client, util};

pub struct WindowSize {
    pub(crate) server_channel: u32,
    pub(crate) client_channel: u32,
    /// 本地窗口大小
    local_window_size: u32,
    /// 远程窗口大小
    remote_window_size : u32
}

impl WindowSize {
    pub(crate) fn new() -> Self {
        WindowSize {
            server_channel: 0,
            client_channel: 0,
            local_window_size: LOCAL_WINDOW_SIZE,
            remote_window_size: 0
        }
    }

    pub fn add_remote_window_size(&mut self, ws: u32) {
        self.remote_window_size = self.remote_window_size + ws;
    }

    pub fn process_local_window_size(&mut self, data: &[u8]) -> SshResult<()> {
        let mc = &data[0];
        let size = match *mc {
            ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                let mut data = Data::from(data);
                data.get_u8(); // msg code
                data.get_u32(); // channel serial no    4 len
                let vec = data.get_u8s(); // string data len
                let size = vec.len() as u32;
                size
            }
            ssh_msg_code::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let mut data = Data::from(data);
                data.get_u8(); // msg code
                data.get_u32(); // channel serial no    4 len
                data.get_u32(); // data type code        4 len
                let vec = data.get_u8s();  // string data len
                let size = vec.len() as u32;
                size
            }
            _ => return Ok(())
        };
        self.sub_local_window_size(size)
    }

    pub fn sub_local_window_size(&mut self, ws: u32) -> SshResult<()> {
        self.local_window_size = self.local_window_size - ws;
        let used = LOCAL_WINDOW_SIZE - self.local_window_size;
        if (LOCAL_WINDOW_SIZE / used) > 20 {
            return Ok(());
        }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
            .put_u32(self.server_channel)
            .put_u32(used);
        let mut client = client::locking()?;
        client.write(data)?;
        self.local_window_size = LOCAL_WINDOW_SIZE;
        return Ok(());
    }
}

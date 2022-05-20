use constant::size::LOCAL_WINDOW_SIZE;
use constant::{size, ssh_msg_code};
use error::SshResult;
use packet::Data;
use crate::{client, util};

pub(crate) struct WindowSize {
    /// 本地窗口大小
    local_window_size: u32,
    /// 远程窗口大小
    remote_window_size : u32
}

impl WindowSize {
    pub(crate) fn new() -> Self {
        WindowSize {
            local_window_size: LOCAL_WINDOW_SIZE,
            remote_window_size: 0
        }
    }

    pub fn add_remote_window_size(&mut self, ws: u32) {
        self.remote_window_size = self.remote_window_size + ws;
    }

    pub fn sub_local_window_size(&mut self, ws: u32, server_channel: u32) -> SshResult<()> {
        self.local_window_size = self.local_window_size - ws;
        let used = LOCAL_WINDOW_SIZE - self.local_window_size;
        if (LOCAL_WINDOW_SIZE / used) > 20 {
            return Ok(());
        }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
            .put_u32(server_channel)
            .put_u32(used);
        let mut client = client::locking()?;
        client.write(data)?;
        self.local_window_size = LOCAL_WINDOW_SIZE;
        return Ok(());
    }
}

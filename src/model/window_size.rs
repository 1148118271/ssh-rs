use std::io::{Read, Write};

use crate::client::Client;
use crate::constant::size::LOCAL_WINDOW_SIZE;
use crate::constant::ssh_msg_code;
use crate::error::SshResult;
use crate::model::Data;

pub struct WindowSize {
    pub(crate) server_channel_no: u32,
    pub(crate) client_channel_no: u32,
    /// 本地窗口大小
    local_window_size: u32,
    /// 远程窗口大小
    remote_window_size: u32,
}

impl WindowSize {
    pub(crate) fn new() -> Self {
        WindowSize {
            server_channel_no: 0,
            client_channel_no: 0,
            local_window_size: LOCAL_WINDOW_SIZE,
            remote_window_size: 0,
        }
    }

    pub(crate) fn get_size(&self, data: &[u8]) -> Option<u32> {
        let mc = &data[0];
        match *mc {
            ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                let mut data = Data::from(data);
                data.get_u8(); // msg code
                data.get_u32(); // channel serial no    4 len
                let vec = data.get_u8s(); // string data len
                let size = vec.len() as u32;
                Some(size)
            }
            ssh_msg_code::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let mut data = Data::from(data);
                data.get_u8(); // msg code
                data.get_u32(); // channel serial no    4 len
                data.get_u32(); // data type code        4 len
                let vec = data.get_u8s(); // string data len
                let size = vec.len() as u32;
                Some(size)
            }
            _ => None,
        }
    }
}

impl WindowSize {
    pub(crate) fn process_remote_window_size<S>(
        &mut self,
        data: &[u8],
        client: &mut Client<S>,
    ) -> SshResult<()>
    where
        S: Read + Write,
    {
        let size = match self.get_size(data) {
            None => return Ok(()),
            Some(size) => size,
        };

        if size > self.remote_window_size {
            return self.read_window_size(client);
        }

        self.remote_window_size -= size;

        Ok(())
    }

    pub(crate) fn add_remote_window_size(&mut self, rws: u32) {
        self.remote_window_size += rws;
    }

    pub(crate) fn read_window_size<S>(&mut self, client: &mut Client<S>) -> SshResult<()>
    where
        S: Read + Write,
    {
        let results = client.read()?;
        if results.is_empty() {
            return Ok(());
        }
        for mut data in results {
            let mc = data.get_u8();
            if ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST == mc {
                // 接收方 通道编号 暂不处理
                data.get_u32();
                // 远程客户端调整的窗口大小
                let size = data.get_u32();
                self.remote_window_size += size;
            }
        }
        Ok(())
    }
}

impl WindowSize {
    pub(crate) fn process_local_window_size<S>(
        &mut self,
        data: &[u8],
        client: &mut Client<S>,
    ) -> SshResult<()>
    where
        S: Read + Write,
    {
        let size = match self.get_size(data) {
            None => return Ok(()),
            Some(size) => size,
        };
        if self.local_window_size <= size {
            let used = LOCAL_WINDOW_SIZE - self.local_window_size;
            let mut data = Data::new();
            data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
                .put_u32(self.server_channel_no)
                .put_u32(used);
            client.write(data)?;
            self.local_window_size += used;
        }
        self.local_window_size -= size;
        Ok(())
    }
}

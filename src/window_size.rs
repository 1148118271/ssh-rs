use std::io::{Read};
use crate::algorithm::encryption::Encryption;
use crate::client::Client;
use crate::constant::size::LOCAL_WINDOW_SIZE;
use crate::constant::{size, ssh_msg_code};
use crate::error::SshResult;
use crate::data::Data;
use crate::packet::Packet;
use crate::SshError;

pub struct WindowSize {
    pub(crate) server_channel_no: u32,
    pub(crate) client_channel_no: u32,
    /// 本地窗口最大大小
    local_max_window_size: u32,
    /// 本地窗口大小
    local_window_size: u32,
    /// 远程最大窗口大小
    remote_max_window_size : u32,
    /// 远程窗口大小
    remote_window_size : u32
}

impl WindowSize {

    pub(crate) fn new() -> Self {
        WindowSize {
            server_channel_no: 0,
            client_channel_no: 0,
            local_max_window_size: LOCAL_WINDOW_SIZE,
            local_window_size: LOCAL_WINDOW_SIZE,
            remote_max_window_size: 0,
            remote_window_size: 0
        }
    }

    fn get_size(&self, data: &[u8]) -> Option<u32> {
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
                let vec = data.get_u8s();  // string data len
                let size = vec.len() as u32;
                Some(size)
            }
            _ => None
        }

    }
}

impl WindowSize {

    pub fn process_remote_window_size(&mut self,
                                      data: &[u8],
                                      client: &mut Client,
                                      encryption: &mut Box<dyn Encryption>
    ) -> SshResult<()>
    {
        if self.remote_window_size == 0 {
            return Ok(());
        }
        let used = self.remote_max_window_size - self.remote_window_size;
        let size = match self.get_size(data) {
            None => return Ok(()),
            Some(size) => size
        };
        self.sub_remote_window_size(size);

        if used > 0 && self.remote_max_window_size / used <= 20 {
            let mut result = vec![0; size::BUF_SIZE as usize];
            loop {
                match client.stream.read(&mut result) {
                    Ok(len) => {
                        result.truncate(len);
                        break
                    }
                    Err(e) => {
                        if Client::is_would_block(&e) {
                           continue
                        }
                        return Err(SshError::from(e))
                    }
                };
            }

            client.sequence.server_auto_increment();

            let result = encryption.decrypt(client.sequence.server_sequence_num, &mut result)?;
            let mut data = Packet::from(result).unpacking();
            let mc = data.get_u8();
            if ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST == mc {
                // 接收方 通道编号 暂不处理
                data.get_u32();
                // 远程客户端调整的窗口大小
                let size = data.get_u32();
                self.add_remote_window_size(size);
                return Ok(())
            }
        }
        return Ok(())
    }

    pub fn sub_remote_window_size(&mut self, rws: u32) {
        self.remote_window_size = self.remote_window_size - rws;
    }

    pub fn add_remote_window_size(&mut self, rws: u32) {
        self.remote_window_size = self.remote_window_size + rws;
    }

    pub fn add_remote_max_window_size(&mut self, rws: u32) {
        self.remote_max_window_size = self.remote_max_window_size + rws;
    }
}

impl WindowSize {

    pub fn process_local_window_size(&mut self, data: &[u8], client: &mut Client) -> SshResult<()> {
        // let size = match self.get_size(data) {
        //     None => return Ok(()),
        //     Some(size) => size
        // };
        // self.sub_local_window_size(size);
        // let used = self.local_max_window_size - self.local_window_size;
        // if used <= 0 {
        //     return Ok(())
        // }
        // if (self.local_max_window_size / used) > 20 {
        //     return Ok(());
        // }
        //
        // let mut data = Data::new();
        // data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
        //     .put_u32(self.server_channel)
        //     .put_u32(used);
        //
        // let buf = client.get_encryption_data(data)?;
        //
        // client.sequence.client_auto_increment();
        //
        // if let Err(e) = client.stream.write(&buf) {
        //     return Err(SshError::from(e))
        // }
        // if let Err(e) = client.stream.flush() {
        //     return Err(SshError::from(e))
        // }
        // self.add_local_window_size(used);
        return Ok(());
    }

    pub fn sub_local_window_size(&mut self, lws: u32) {
        self.local_window_size = self.local_window_size - lws;
    }

    pub fn add_local_window_size(&mut self, lws: u32) {
        self.local_window_size = self.local_window_size + lws;
    }

}

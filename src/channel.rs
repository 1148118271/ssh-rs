use std::borrow::BorrowMut;
use constant::{ssh_msg_code, size, ssh_str};
use error::{SshError, SshErrorKind, SshResult};
use packet::{Data, Packet};
use crate::channel_exec::ChannelExec;
use crate::channel_scp::ChannelScp;
use crate::channel_shell::ChannelShell;
use crate::kex::{Kex, processing_server_algorithm};
use crate::{Client, util};

pub struct Channel {
    pub(crate) kex: Kex,
    pub(crate) server_channel: u32,
    pub(crate) client_channel: u32,
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
}



impl Channel {

    pub(crate) fn other(&mut self, message_code: u8, mut result: Data) -> SshResult<()> {
        match message_code {
            ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                let mut packet = Packet::from(data);
                packet.build();
                let mut client = util::client()?;
                client.write(packet.as_slice())?;
                util::unlock(client)
            }
            ssh_msg_code::SSH_MSG_KEXINIT => {
                //let data = Packet::processing_data(result);
                let vec = result.to_vec();
                let mut data = Data::from(vec![message_code]);
                data.extend(vec);
                self.kex.h.set_i_s(data.as_slice());
                processing_server_algorithm(data)?;
                self.kex.send_algorithm()?;
                let config = util::config()?;

                let (dh, sign) = config.algorithm.matching_algorithm()?;
                self.kex.dh = dh;
                self.kex.signature = sign;

                self.kex.h.set_v_c(config.version.client_version.as_str());
                self.kex.h.set_v_s(config.version.server_version.as_str());

                util::unlock(config);

                self.kex.send_qc()?;
            }
            ssh_msg_code::SSH_MSG_KEX_ECDH_REPLY => {
                // 生成session_id并且获取signature
                let sig = self
                    .kex
                    .generate_session_id_and_get_signature(result)?;
                // 验签
                let r = self
                    .kex
                    .signature
                    .verify_signature(&self.kex.h.k_s, &self.kex.session_id, &sig)?;
                log::info!("signature Verification Result => {}", r);
                if !r {
                    return Err(SshError::from(SshErrorKind::SignatureError))
                }
            }
            ssh_msg_code::SSH_MSG_NEWKEYS => self.kex.new_keys()?,
            // 通道大小 暂不处理
            ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                println!("通道大小");
                // let mut d = Data::from(result.clone().into());
                // println!("{}", d.get_u32());
                // println!("{}", d.get_u32());
                // CHANNEL_WINDOW
                let option = util::get_channel_window(result.get_u32()).unwrap();
                if let Some(mut v) = option {
                    let i = result.get_u32();
                    println!("远程客户端大小: {}", i);
                    v.borrow_mut().add_remote_window_size(i)
                }
            }
            ssh_msg_code::SSH_MSG_CHANNEL_EOF => {}
            ssh_msg_code::SSH_MSG_CHANNEL_REQUEST => {}
            ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {}
            ssh_msg_code::SSH_MSG_CHANNEL_FAILURE => return Err(SshError::from(SshErrorKind::ChannelFailureError)),
            ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                let cc = result.get_u32();
                if cc == self.client_channel {
                    self.remote_close = true;
                    self.close()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn open_shell(mut self) -> SshResult<ChannelShell> {
        log::info!("shell opened.");
        loop {
            let mut client = util::client()?;
            let results = client.read()?;
            util::unlock(client);
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        result.get_u32();
                        self.server_channel = result.get_u32();
                        // 请求伪终端
                        self.request_pty()?;
                        // 打开shell通道
                        self.get_shell()?;
                    }
                    ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {
                        util::set_channel_window(
                            self.client_channel,
                            ChannelWindowSize::new(self.client_channel, self.server_channel));

                        return Ok(ChannelShell(self))
                    }
                    _ => self.other(message_code, result)?
                }
            }
        }
    }

    pub fn open_exec(mut self) -> SshResult<ChannelExec> {
        log::info!("exec opened.");
        loop {
            let mut client = util::client()?;
            let results = client.read()?;
            util::unlock(client);
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        result.get_u32();
                        self.server_channel = result.get_u32();
                        util::set_channel_window(
                            self.client_channel,
                            ChannelWindowSize::new(self.client_channel, self.server_channel));
                        return Ok(ChannelExec(self))
                    }
                    _ => self.other(message_code, result)?
                }
            }
        }
    }
    
    pub fn open_scp(mut self) -> SshResult<ChannelScp> {
        log::info!("scp opened.");
        loop {
            let mut client = util::client()?;
            let results = client.read()?;
            util::unlock(client);
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        result.get_u32();
                        self.server_channel = result.get_u32();
                        println!("服务端window size {}",  result.get_u32());
                        println!("服务端buf size {}",  result.get_u32());
                        util::set_channel_window(
                            self.client_channel,
                            ChannelWindowSize::new(self.client_channel, self.server_channel));
                        return Ok(ChannelScp {
                            channel: self,
                            local_path: Default::default(),
                            is_sync_permissions: false
                        })
                    }
                    _ => self.other(message_code, result)?
                }
            }
        }
    }

    pub fn close(&mut self) -> SshResult<()> {
        log::info!("channel close.");
        self.send_close()?;
        self.receive_close()
    }

    fn send_close(&mut self) -> SshResult<()> {
        if self.local_close { return Ok(()); }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_CLOSE)
            .put_u32(self.server_channel);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())?;
        self.local_close = true;
        Ok(())
    }

    fn receive_close(&mut self) -> SshResult<()> {
        if self.remote_close { return Ok(()); }
        loop {
            let mut client = util::client()?;
            let results = client.read()?;
            util::unlock(client);
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                        let cc = result.get_u32();
                        if cc == self.client_channel {
                            self.remote_close = true;
                            return Ok(())
                        }
                    }
                    _ => self.other(message_code, result)?
                }
            }
        }
    }

    fn get_shell(&self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel)
            .put_str(ssh_str::SHELL)
            .put_u8(true as u8);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

    fn request_pty(&self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(0)
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
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

}


pub(crate) struct ChannelWindowSize {
    pub(crate) client_channel: u32,
    pub(crate) server_channel: u32,
    /// 本地窗口大小
    pub(crate) window_size   : u32,
    /// 远程窗口大小
    pub(crate) r_window_size : u32
}

impl ChannelWindowSize {
    pub(crate) fn new(client_channel: u32, server_channel: u32) -> ChannelWindowSize {
        ChannelWindowSize{
            client_channel,
            server_channel,
            window_size: 0,
            r_window_size: 0
        }
    }
    pub(crate) fn process_window_size(mut data: Data, client: &mut Client) -> SshResult<()> {

        if data.is_empty() { return Ok(()) }

        let msg_code = data.get_u8();

        let (client_channel_no, size) = match msg_code {
            ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                let client_channel_no = data.get_u32(); // channel serial no    4 len
                let vec = data.get_u8s(); // string data len
                let size = vec.len() as u32;
                (client_channel_no, size)
            }
            ssh_msg_code::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let client_channel_no = data.get_u32(); // channel serial no    4 len
                data.get_u32(); // data type code        4 len
                let vec = data.get_u8s();  // string data len
                let size = vec.len() as u32;
                (client_channel_no, size)
            }
            _ => return Ok(())
        };

        if size <= 0 { return Ok(()) }

        if let Some(mut map) = util::get_channel_window(client_channel_no)?
        {

            *map += size;

            if map.window_size >= (size::LOCAL_WINDOW_SIZE / 2) {
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
                    .put_u32(map.server_channel)
                    .put_u32(size::LOCAL_WINDOW_SIZE - map.window_size);
                let mut packet = Packet::from(data);
                packet.build();
                client.write(packet.as_slice())?;
                map.window_size = 0;
            }
        }

        Ok(())
    }

    pub(crate) fn add_remote_window_size(&mut self, rws: u32) {
        self.r_window_size = self.r_window_size + rws;
    }
}

impl std::ops::AddAssign<u32> for ChannelWindowSize {
    fn add_assign(&mut self, rhs: u32) {
        self.window_size += rhs;
    }
}

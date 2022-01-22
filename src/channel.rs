use crate::{message, strings, size, util};
use crate::channel_exec::ChannelExec;
use crate::channel_scp::ChannelScp;
use crate::channel_shell::ChannelShell;
use crate::error::{SshError, SshErrorKind, SshResult};
use crate::kex::{Kex, processing_server_algorithm};
use crate::packet::{Data, Packet};

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
            message::SSH_MSG_GLOBAL_REQUEST => {
                let mut data = Data::new();
                data.put_u8(message::SSH_MSG_REQUEST_FAILURE);
                let mut packet = Packet::from(data);
                packet.build();
                let mut client = util::client()?;
                client.write(packet.as_slice())?;
                util::unlock(client)
            }
            message::SSH_MSG_KEXINIT => {
                //let data = Packet::processing_data(result);
                let vec = result.to_vec();
                let mut data = Data(vec![message_code]);
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
            message::SSH_MSG_KEX_ECDH_REPLY => {
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
            message::SSH_MSG_NEWKEYS => self.kex.new_keys()?,
            // 通道大小 暂不处理
            message::SSH_MSG_CHANNEL_WINDOW_ADJUST => {}
            message::SSH_MSG_CHANNEL_EOF => {}
            message::SSH_MSG_CHANNEL_REQUEST => {}
            message::SSH_MSG_CHANNEL_SUCCESS => {}
            message::SSH_MSG_CHANNEL_FAILURE => return Err(SshError::from(SshErrorKind::ChannelFailureError)),
            message::SSH_MSG_CHANNEL_CLOSE => {
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

    pub fn window_adjust(&mut self) -> SshResult<()> {
        let mut client = util::client()?;
        if client.sender_window_size >= (size::LOCAL_WINDOW_SIZE / 2) {
            let mut data = Data::new();
            data.put_u8(message::SSH_MSG_CHANNEL_WINDOW_ADJUST)
                .put_u32(self.server_channel)
                .put_u32(size::LOCAL_WINDOW_SIZE - client.sender_window_size);
            let mut packet = Packet::from(data);
            packet.build();
            client.write(packet.as_slice())?;
            client.sender_window_size = 0;
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
                    message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        result.get_u32();
                        self.server_channel = result.get_u32();
                        // 请求伪终端
                        self.request_pty()?;
                        // 打开shell通道
                        self.get_shell()?;
                    }
                    message::SSH_MSG_CHANNEL_SUCCESS => {
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
                    message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        result.get_u32();
                        self.server_channel = result.get_u32();
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
                    message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        result.get_u32();
                        self.server_channel = result.get_u32();
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
        data.put_u8(message::SSH_MSG_CHANNEL_CLOSE)
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
                    message::SSH_MSG_CHANNEL_CLOSE => {
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
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel)
            .put_str(strings::SHELL)
            .put_u8(true as u8);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

    fn request_pty(&self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(0)
            .put_str(strings::PTY_REQ)
            .put_u8(false as u8)
            .put_str(strings::XTERM_VAR)
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
        data.put_bytes(&model);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

}

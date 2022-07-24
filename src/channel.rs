use std::ops::{Deref, DerefMut};
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::Relaxed;
use crate::constant::{ssh_msg_code};
use crate::error::{SshError, SshResult};
use crate::data::Data;
use crate::slog::log;
use crate::channel_exec::ChannelExec;
use crate::channel_scp::ChannelScp;
use crate::channel_shell::ChannelShell;
use crate::{client, config, kex};
use crate::algorithm::hash::h;
use crate::algorithm::{key_exchange, public_key};
use crate::window_size::WindowSize;


// 客户端通道编号初始值
pub(crate) static CLIENT_CHANNEL_NO: AtomicU32 = AtomicU32::new(0);


pub fn current_client_channel_no() -> u32 {
    let client_channel_no = CLIENT_CHANNEL_NO.load(Relaxed);
    CLIENT_CHANNEL_NO.fetch_add(1, Relaxed);
    client_channel_no
}



pub struct Channel {
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) window_size: WindowSize
}

impl Deref for Channel {
    type Target = WindowSize;

    fn deref(&self) -> &Self::Target {
        &self.window_size
    }
}

impl DerefMut for Channel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.window_size
    }
}

impl Channel {
    pub(crate) fn other(&mut self, message_code: u8, mut result: Data) -> SshResult<()> {
        match message_code {
            ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                let client = client::default()?;
                client.write(data)?;
            }
            ssh_msg_code::SSH_MSG_KEXINIT => {
                let vec = result.to_vec();
                let mut data = Data::from(vec![message_code]);
                data.extend(vec);
                let h = h::get();
                h.set_i_s(data.as_slice());
                kex::processing_server_algorithm(data)?;
                kex::send_algorithm()?;
                let config = config::config();

                // 缓存密钥交换算法
                key_exchange::put(config.algorithm.matching_key_exchange_algorithm()?);
                // 公钥算法
                public_key::put(config.algorithm.matching_public_key_algorithm()?);

                h.set_v_c(config.version.client_version.as_str());
                h.set_v_s(config.version.server_version.as_str());

                kex::send_qc()?;

                kex::verify_signature_and_new_keys()?
            }
            ssh_msg_code::SSH_MSG_KEXDH_REPLY => {
                // 生成session_id并且获取signature
                let sig = kex::generate_signature(result)?;
                // 验签
                let session_id = h::get().digest();
                let flag = public_key::get()
                    .verify_signature(h::get().k_s.as_ref(),
                                      &session_id, &sig)?;
                if !flag {
                    log::error!("signature verification failure.");
                    return Err(SshError::from("signature verification failure."))
                }
                log::info!("signature verification success.");
            }
            ssh_msg_code::SSH_MSG_NEWKEYS => kex::new_keys()?,
            // 通道大小 暂不处理
            ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                // 接收方通道号， 暂时不需要
                result.get_u32();
                // 需要调整增加的窗口大小
                let rws = result.get_u32();
                self.window_size.add_remote_window_size(rws);
                self.window_size.add_remote_max_window_size(rws);
            },
            ssh_msg_code::SSH_MSG_CHANNEL_EOF => {}
            ssh_msg_code::SSH_MSG_CHANNEL_REQUEST => {}
            ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {}
            ssh_msg_code::SSH_MSG_CHANNEL_FAILURE => return Err(SshError::from("channel failure.")),
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

    pub fn open_shell(self) -> SshResult<ChannelShell> {
        log::info!("shell opened.");
        return ChannelShell::open(self)
    }

    pub fn open_exec(self) -> SshResult<ChannelExec> {
        log::info!("exec opened.");
        return Ok(ChannelExec::open(self))
    }

    pub fn open_scp(self) -> SshResult<ChannelScp> {
        log::info!("scp opened.");
        return Ok(ChannelScp::open(self))
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
        let client = client::default()?;
        client.write(data)?;
        self.local_close = true;
        Ok(())
    }

    fn receive_close(&mut self) -> SshResult<()> {
        if self.remote_close { return Ok(()); }
        loop {
            let client = client::default()?;
            let results = client.read()?; // close 时不消耗窗口空间
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
}

use std::fmt::Debug;
use std::{
    cell::RefCell,
    rc::Rc,
};
#[cfg(not(target_family="wasm"))]
use std::time::Duration;
#[cfg(target_family="wasm")]
use crate::model::time_wasm::Duration;

use crate::model::TerminalSize;
use crate::{
    channel::{AsyncChannel, AsyncExec, AsyncShell},
    client::Client,
    constant::{size, ssh_msg_code, ssh_str},
    error::{SshError, SshResult},
    model::{Data, Packet, RcMut, SecPacket, U32Iter},
};

use async_std::io::{Read, Write};

pub struct AsyncSession<S>
where
    S: Read + Write + Unpin,
{
    client: RcMut<Client>,
    stream: RcMut<S>,
    channel_num: U32Iter,
}

impl<S> Debug for AsyncSession<S>
where
    S: Read + Write + Unpin,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncSession").finish()
    }
}

impl<S> AsyncSession<S>
where
    S: Read + Write + Unpin,
{
    pub(crate) fn new(client: Client, stream: S) -> Self {
        Self {
            client: Rc::new(RefCell::new(client)),
            stream: Rc::new(RefCell::new(stream)),
            channel_num: U32Iter::default(),
        }
    }

    /// close the local session and consume it
    ///
    pub fn close(self) {
        log::info!("Client close");
        drop(self)
    }

    /// Modify the timeout setting
    /// in case the user wants to change the timeout during ssh operations.
    ///
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.client.borrow_mut().set_timeout(timeout)
    }

    /// open a [AsyncExec] channel which can excute commands
    ///
    pub async fn open_exec(&mut self) -> SshResult<AsyncExec<S>> {
        let channel = self.open_channel().await?;
        channel.exec()
    }

    /// open a [AsyncScp] channel which can download/upload files/directories
    ///
    // pub async fn open_scp(&mut self) -> SshResult<AsyncScp<S>> {
    //     let channel = self.open_channel().await?;
    //     channel.scp()
    // }

    /// open a [AsyncShell] channel which can download/upload files/directories
    ///
    pub async fn open_shell(&mut self) -> SshResult<AsyncShell<S>> {
        self.open_shell_terminal(TerminalSize::from(80, 24)).await
    }

    /// open a [AsyncShell] channel
    ///
    /// custom terminal dimensions
    ///
    pub async fn open_shell_terminal(&mut self, tv: TerminalSize) -> SshResult<AsyncShell<S>> {
        let channel = self.open_channel().await?;
        channel.shell(tv).await
    }

    pub fn get_raw_io(&mut self) -> RcMut<S> {
        self.stream.clone()
    }

    /// open a raw channel
    ///
    /// need call `.exec()`, `.shell()`, `.scp()` and so on to convert it to a specific channel
    ///
    pub async fn open_channel(&mut self) -> SshResult<AsyncChannel<S>> {
        log::info!("channel opened.");

        let client_channel_no = self.channel_num.next().unwrap();
        self.send_open_channel(client_channel_no).await?;
        let (server_channel_no, remote_window_size) = self.receive_open_channel().await?;

        Ok(AsyncChannel::new(
            server_channel_no,
            client_channel_no,
            remote_window_size,
            self.client.clone(),
            self.stream.clone(),
        ))
    }

    // 本地请求远程打开通道
    async fn send_open_channel(&mut self, client_channel_no: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_channel_no)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        data.pack(&mut self.client.borrow_mut())
            .write_stream_async(&mut *self.stream.borrow_mut()).await
    }

    // 远程回应是否可以打开通道
    async fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let mut data = Data::unpack(SecPacket::from_stream_async(
                &mut *self.stream.borrow_mut(),
                &mut self.client.borrow_mut(),
            ).await?)?;

            let message_code = data.get_u8();
            match message_code {
                // 打开请求通过
                ssh_msg_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                    // 接收方通道号
                    data.get_u32();
                    // 发送方通道号
                    let server_channel_no = data.get_u32();
                    // 远程初始窗口大小
                    let remote_window_size = data.get_u32();
                    // 远程的最大数据包大小， 暂时不需要
                    data.get_u32();
                    return Ok((server_channel_no, remote_window_size));
                }
                /*
                    byte SSH_MSG_CHANNEL_OPEN_FAILURE
                    uint32 recipient channel
                    uint32 reason code
                    string description，ISO-10646 UTF-8 编码[RFC3629]
                    string language tag，[RFC3066]
                */
                // 打开请求拒绝
                ssh_msg_code::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                    data.get_u32();
                    // 失败原因码
                    let code = data.get_u32();
                    // 消息详情 默认utf-8编码
                    let description =
                        String::from_utf8(data.get_u8s()).unwrap_or_else(|_| String::from("error"));
                    // language tag 暂不处理， 应该是 en-US
                    data.get_u8s();

                    let err_msg = match code {
                        ssh_msg_code::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED => {
                            format!("SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: {}", description)
                        }
                        ssh_msg_code::SSH_OPEN_CONNECT_FAILED => {
                            format!("SSH_OPEN_CONNECT_FAILED: {}", description)
                        }
                        ssh_msg_code::SSH_OPEN_UNKNOWN_CHANNEL_TYPE => {
                            format!("SSH_OPEN_UNKNOWN_CHANNEL_TYPE: {}", description)
                        }
                        ssh_msg_code::SSH_OPEN_RESOURCE_SHORTAGE => {
                            format!("SSH_OPEN_RESOURCE_SHORTAGE: {}", description)
                        }
                        _ => description,
                    };
                    return Err(SshError::from(err_msg));
                }
                ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                    let mut data = Data::new();
                    data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                    data.pack(&mut self.client.borrow_mut())
                        .write_stream_async(&mut *self.stream.borrow_mut()).await?;
                    continue;
                }
                x => {
                    log::debug!("Ignore ssh msg {}", x);
                    continue;
                }
            }
        }
    }
}

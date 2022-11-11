use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{
        mpsc::{self, Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    thread::spawn,
};

use log::info;

use crate::{
    algorithm::Digest,
    channel::{BackendChannel, BackendExec, BackendScp, BackendShell},
    client::Client,
    config::algorithm::AlgList,
    constant::{size, ssh_msg_code, ssh_str},
    error::{SshError, SshResult},
    model::{ArcMut, Data, Packet, SecPacket, U32Iter},
};

pub(crate) enum BackendRqst {
    OpenChannel(u32),
}

pub(crate) enum BackendResp {
    OpenChannel(Receiver<Self>),
    Buf(Vec<u8>),
}

fn client_loop<S>(mut client: Client, mut stream: S, rcv: Receiver<BackendRqst>) -> SshResult<()>
where
    S: Read + Write + Send + 'static,
{
    let mut channels = HashMap::<u32, BackendChannel>::new();
    loop {
        let try_recv = rcv.try_recv();
        if try_recv.is_err() {
            if let Err(TryRecvError::Disconnected) = try_recv {
                info!("Session backend Closed");
                return Ok(());
            }
        } else {
            match try_recv.unwrap() {
                BackendRqst::OpenChannel(id) => {
                    log::info!("try open channel {}.", id);

                    let mut data = Data::new();
                    data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_OPEN)
                        .put_str(ssh_str::SESSION)
                        .put_u32(id)
                        .put_u32(size::LOCAL_WINDOW_SIZE)
                        .put_u32(size::BUF_SIZE as u32);
                    data.pack(&mut client).write_stream(&mut stream, 0)?;

                    // Ok(BackendChannel::new(
                    //     server_channel_no,
                    //     client_channel_no,
                    //     remote_window_size,
                    //     self.client.clone(),
                    //     self.stream.clone(),
                    // ))
                }
            }
        }

        if let Some(pkt) = SecPacket::try_from_stream(&mut stream, 0, &mut client)? {
            let mut data = Data::unpack(pkt)?;
            let message_code = data.get_u8();

            match message_code {
                ssh_msg_code::SSH_MSG_KEXINIT => {
                    data.insert(0, message_code);
                    let mut digest = Digest::new();
                    digest.hash_ctx.set_i_s(&data);
                    let server_algs = AlgList::unpack((data, &mut client).into())?;
                    client.key_agreement(&mut stream, server_algs, &mut digest)?;
                    unimplemented!()
                }
                ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                    let cc = data.get_u32();
                    unimplemented!()
                }
                // 通道大小
                ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                    // 接收方通道号， 暂时不需要
                    data.get_u32();
                    // 需要调整增加的窗口大小
                    let rws = data.get_u32();
                    unimplemented!()
                }
                ssh_msg_code::SSH_MSG_CHANNEL_EOF => {
                    unimplemented!()
                }
                ssh_msg_code::SSH_MSG_CHANNEL_REQUEST => {
                    unimplemented!()
                }
                ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {
                    unimplemented!()
                }
                ssh_msg_code::SSH_MSG_CHANNEL_FAILURE => {
                    log::error!("channel error");
                }
                ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                    let cc = data.get_u32();
                    // if cc == self.client_channel_no {
                    //     self.remote_close = true;
                    //     self.send_close()?;
                    // }
                    unimplemented!()
                }
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
                    // return Ok((server_channel_no, remote_window_size));
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
                    data.pack(&mut client).write_stream(&mut stream, 0)?;
                    continue;
                }
                x => {
                    log::debug!("Currently ignore message {}", x);
                }
            }
        }
    }
}

pub struct BackendSession {
    channel_num: ArcMut<U32Iter>,
    snd: Sender<BackendRqst>,
}

impl BackendSession {
    pub(crate) fn new<S>(client: Client, stream: S) -> Self
    where
        S: Read + Write + Send + 'static,
    {
        let (rqst_snd, rqst_rcv) = mpsc::channel();
        spawn(move || client_loop(client, stream, rqst_rcv));
        Self {
            channel_num: Arc::new(Mutex::new(U32Iter::default())),
            snd: rqst_snd,
        }
    }

    /// close the local session and consume it
    ///
    pub fn close(self) {
        log::info!("Client close");
        drop(self)
    }

    // /// open a [BackendExec] channel which can excute commands
    // ///
    // pub fn open_exec(&mut self) -> SshResult<BackendExec<S>> {
    //     let channel = self.open_channel()?;
    //     channel.exec()
    // }

    // /// open a [BackendScp] channel which can download/upload files/directories
    // ///
    // pub fn open_scp(&mut self) -> SshResult<BackendScp<S>> {
    //     let channel = self.open_channel()?;
    //     channel.scp()
    // }

    //     /// open a [LocalShell] channel which  can be used as a pseudo terminal (AKA PTY)
    // ///
    // pub fn open_shell(&mut self) -> SshResult<BackendShell<S>> {
    //     let channel = self.open_channel()?;
    //     channel.shell()
    // }

    /// open a raw channel
    ///
    /// need call `.exec()`, `.shell()`, `.scp()` and so on to convert it to a specific channel
    ///
    pub fn open_channel(&mut self) -> SshResult<BackendChannel> {
        // let (resp_snd, resp_rcv) = mpsc::channel();
        // let client_channel_no = self.channel_num.next().unwrap();
        // self.send_open_channel(client_channel_no)?;
        // let (server_channel_no, remote_window_size) = self.receive_open_channel()?;

        // Ok(BackendChannel::new(
        //     server_channel_no,
        //     client_channel_no,
        //     remote_window_size,
        //     self.client.clone(),
        //     self.stream.clone(),
        // ))
        unimplemented!()
    }
}

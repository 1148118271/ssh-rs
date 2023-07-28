use async_std::io::{Read, Write};

use crate::model::TerminalSize;
use crate::{
    algorithm::Digest,
    client::Client,
    config::algorithm::AlgList,
    constant::ssh_msg_code,
    error::{SshError, SshResult},
    model::{Data, FlowControl, Packet, RcMut, SecPacket},
};

use super::{ChannelExec, ChannelShell};

pub(super) enum ChannelRead {
    Data(Vec<u8>),
    Code(u8),
}

pub struct Channel<S>
where
    S: Read + Write,
{
    pub(crate) server_channel_no: u32,
    pub(crate) client_channel_no: u32,
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) flow_control: FlowControl,
    pub(crate) client: RcMut<Client>,
    pub(crate) stream: RcMut<S>,
}

impl<S> Channel<S>
where
    S: Read + Write + Unpin,
{
    pub(crate) fn new(
        server_channel_no: u32,
        client_channel_no: u32,
        remote_window: u32,
        client: RcMut<Client>,
        stream: RcMut<S>,
    ) -> Self {
        Self {
            server_channel_no,
            client_channel_no,
            remote_close: false,
            local_close: false,
            flow_control: FlowControl::new(remote_window),
            client,
            stream,
        }
    }

    /// convert the raw channel to an [self::ChannelExec]
    ///
    pub fn exec(self) -> SshResult<ChannelExec<S>> {
        log::info!("exec opened.");
        Ok(ChannelExec::open(self))
    }

    /// convert the raw channel to an [self::ChannelScp]
    ///
    // pub fn scp(self) -> SshResult<ChannelScp<S>> {
    //     log::info!("scp opened.");
    //     Ok(ChannelScp::open(self))
    // }

    /// convert the raw channel to an [self::ChannelShell]
    ///
    /// with `row` lines & `column` characters per one line
    ///
    pub async fn shell(self, tv: TerminalSize) -> SshResult<ChannelShell<S>> {
        log::info!("shell opened.");
        ChannelShell::open(self, tv).await
    }

    /// close the channel gracefully, but donnot consume it
    ///
    pub async fn close(&mut self) -> SshResult<()> {
        log::info!("channel close.");
        self.send_close().await?;
        self.receive_close().await
    }

    async fn send_close(&mut self) -> SshResult<()> {
        if self.local_close {
            return Ok(());
        }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_CLOSE)
            .put_u32(self.server_channel_no);
        self.local_close = true;
        self.send(data).await
    }

    async fn receive_close(&mut self) -> SshResult<()> {
        if self.remote_close {
            return Ok(());
        }
        let _ = self.recv_to_end().await?;
        Ok(())
    }

    pub(super) async fn send(&mut self, data: Data) -> SshResult<()> {
        data.pack(&mut self.client.borrow_mut())
            .write_stream_async(&mut *self.stream.borrow_mut()).await
    }

    // only send SSH_MSG_CHANNEL_DATA will call this,
    // for auto adjust the window size
    pub(super) async fn send_data(&mut self, mut buf: Vec<u8>) -> SshResult<Vec<u8>> {
        let mut maybe_response = vec![];

        loop {
            // first adjust the data to the max size we can send
            let maybe_remain = self.flow_control.tune_on_send(&mut buf);

            // send it
            let mut data = Data::new();
            data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_DATA)
                .put_u32(self.server_channel_no)
                .put_u8s(&buf);
            self.send(data).await?;

            if maybe_remain.is_empty() {
                // if all send, return
                break;
            } else {
                buf = maybe_remain
            }

            // otherwise wait the server to adjust its window
            while !self.flow_control.can_send() {
                let buf = self.recv_once().await?;

                if let ChannelRead::Data(mut data) = buf {
                    maybe_response.append(&mut data);
                }
            }
        }

        Ok(maybe_response)
    }

    /// this method will receive at least one data packet
    ///
    pub(super) async fn recv(&mut self) -> SshResult<Vec<u8>> {
        while !self.is_close() {
            let maybe_recv = self.recv_once().await?;

            if let ChannelRead::Data(data) = maybe_recv {
                return Ok(data);
            }
        }
        Ok(vec![])
    }

    pub(super) async fn recv_to_end(&mut self) -> SshResult<Vec<u8>> {
        let mut resp = vec![];
        while !self.is_close() {
            let mut read_this_time = self.recv().await?;
            resp.append(&mut read_this_time);
        }
        Ok(resp)
    }

    pub(super) async fn try_recv(&mut self) -> SshResult<Option<Vec<u8>>> {
        let data = {
            match SecPacket::try_from_stream_async(
                &mut *self.stream.borrow_mut(),
                &mut self.client.borrow_mut(),
            ).await? {
                Some(pkt) => Data::unpack(pkt)?,
                None => return Ok(None),
            }
        };
        if let ChannelRead::Data(d) = self.handle_msg(data).await? {
            Ok(Some(d))
        } else {
            Ok(None)
        }
    }

    async fn recv_once(&mut self) -> SshResult<ChannelRead> {
        let data = Data::unpack(SecPacket::from_stream_async(
            &mut *self.stream.borrow_mut(),
            &mut self.client.borrow_mut(),
        ).await?)?;
        self.handle_msg(data).await
    }

    async fn handle_msg(&mut self, mut data: Data) -> SshResult<ChannelRead> {
        let message_code = data.get_u8();
        match message_code {
            x @ ssh_msg_code::SSH_MSG_KEXINIT => {
                data.insert(0, message_code);
                let mut digest = Digest::new();
                digest.hash_ctx.set_i_s(&data);
                let server_algs = AlgList::unpack((data, &mut *self.client.borrow_mut()).into())?;
                self.client.borrow_mut().key_agreement_async(
                    &mut *self.stream.borrow_mut(),
                    server_algs,
                    &mut digest,
                ).await?;
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    let mut data = data.get_u8s();

                    // flow_control
                    self.flow_control.tune_on_recv(&mut data);
                    self.send_window_adjust(data.len() as u32).await?;

                    return Ok(ChannelRead::Data(data));
                }
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    let data_type_code = data.get_u32();
                    let mut data = data.get_u8s();

                    log::debug!("Recv extended data with type {data_type_code}");

                    // flow_contrl
                    self.flow_control.tune_on_recv(&mut data);
                    self.send_window_adjust(data.len() as u32).await?;

                    return Ok(ChannelRead::Data(data));
                }
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                self.send(data).await?;
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                data.get_u32();
                // to add
                let rws = data.get_u32();
                self.recv_window_adjust(rws)?;
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_EOF => {
                log::debug!("Currently ignore message {}", x);
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_REQUEST => {
                log::debug!("Currently ignore message {}", x);
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {
                log::debug!("Currently ignore message {}", x);
                Ok(ChannelRead::Code(x))
            }
            ssh_msg_code::SSH_MSG_CHANNEL_FAILURE => Err(SshError::from("channel failure.")),
            x @ ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    self.remote_close = true;
                    self.send_close().await?;
                }
                Ok(ChannelRead::Code(x))
            }
            x => {
                log::debug!("Currently ignore message {}", x);
                Ok(ChannelRead::Code(x))
            }
        }
    }

    async fn send_window_adjust(&mut self, to_add: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
            .put_u32(self.server_channel_no)
            .put_u32(to_add);
        self.flow_control.on_send(to_add);
        self.send(data).await
    }

    fn recv_window_adjust(&mut self, to_add: u32) -> SshResult<()> {
        self.flow_control.on_recv(to_add);
        Ok(())
    }

    pub(crate) fn is_close(&self) -> bool {
        self.local_close && self.remote_close
    }
}

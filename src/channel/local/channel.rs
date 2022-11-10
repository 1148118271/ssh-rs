use std::{
    cell::RefCell,
    io::{Read, Write},
    rc::Rc,
};

use crate::{
    client::Client,
    constant::ssh_msg_code,
    error::{SshError, SshResult},
    model::{Data, FlowControl, Packet, RcMut, SecPacket},
};

use super::ChannelExec;

pub struct Channel<S>
where
    S: Read + Write,
{
    pub(crate) server_channel_no: u32,
    pub(crate) client_channel_no: u32,
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) flow_control: FlowControl,
    pub(crate) client: Rc<RefCell<Client>>,
    pub(crate) stream: Rc<RefCell<S>>,
}

impl<S> Channel<S>
where
    S: Read + Write,
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

    /// convert the raw channel to an [ChannelExec]
    ///
    pub fn exec(self) -> SshResult<ChannelExec<S>> {
        log::info!("exec opened.");
        Ok(ChannelExec::open(self))
    }

    /// close the channel gracefully, but donnot consume it
    ///
    pub fn close(&mut self) -> SshResult<()> {
        log::info!("channel close.");
        self.send_close()?;
        self.receive_close()
    }

    fn send_close(&mut self) -> SshResult<()> {
        if self.local_close {
            return Ok(());
        }
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_CLOSE)
            .put_u32(self.server_channel_no);
        self.local_close = true;
        self.send(data)
    }

    fn receive_close(&mut self) -> SshResult<()> {
        if self.remote_close {
            return Ok(());
        }
        let _ = self.recv(true)?;
        Ok(())
    }

    pub(crate) fn send(&mut self, data: Data) -> SshResult<()> {
        data.pack(&mut self.client.borrow_mut())
            .write_stream(&mut *self.stream.borrow_mut(), 0)
    }

    // only send SSH_MSG_CHANNEL_DATA will call this,
    // for auto adjust the window size
    pub(crate) fn send_data(&mut self, mut buf: Vec<u8>) -> SshResult<Vec<u8>> {
        let mut maybe_response = vec![];

        loop {
            // first adjust the data to the max size we can send
            let (to_send, maybe_remain) = self.flow_control.tune_local(buf);

            // send it
            let mut data = Data::new();
            data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_DATA)
                .put_u32(self.server_channel_no)
                .put_u8s(&to_send);
            self.send(data)?;

            if maybe_remain.is_empty() {
                // if all send, return
                break;
            } else {
                buf = maybe_remain
            }

            // otherwise wait the server to adjust its window
            while !self.flow_control.can_send() {
                let buf = self.try_recv()?;

                if let Some(mut data) = buf {
                    maybe_response.append(&mut data);
                }
            }
        }

        Ok(maybe_response)
    }

    pub(crate) fn recv(&mut self, wait_peer_close: bool) -> SshResult<Vec<u8>> {
        let mut buf = vec![];
        while !self.is_close() {
            let maybe_recv = self.try_recv()?;

            if let Some(mut data) = maybe_recv {
                buf.append(&mut data);
                if !wait_peer_close {
                    break;
                }
            }
        }
        Ok(buf)
    }

    fn try_recv(&mut self) -> SshResult<Option<Vec<u8>>> {
        let mut data = Data::unpack(SecPacket::from_stream(
            &mut *self.stream.borrow_mut(),
            0,
            &mut self.client.borrow_mut(),
        )?)?;

        let message_code = data.get_u8();
        match message_code {
            ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    let mut data = data.get_u8s();

                    // flow_control
                    self.flow_control.tune_remote(&mut data);
                    self.send_window_adjust(data.len() as u32)?;

                    return Ok(Some(data));
                }
            }
            ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                self.send(data)?;
            }
            // 通道大小
            ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                // 接收方通道号， 暂时不需要
                data.get_u32();
                // 需要调整增加的窗口大小
                let rws = data.get_u32();
                self.recv_window_adjust(rws)?;
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_EOF => {
                log::debug!("Currently ignore message {}", x)
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_REQUEST => {
                log::debug!("Currently ignore message {}", x)
            }
            x @ ssh_msg_code::SSH_MSG_CHANNEL_SUCCESS => {
                log::debug!("Currently ignore message {}", x)
            }
            ssh_msg_code::SSH_MSG_CHANNEL_FAILURE => {
                return Err(SshError::from("channel failure."))
            }
            ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    self.remote_close = true;
                    self.send_close()?;
                }
            }
            x => log::debug!("Currently ignore message {}", x),
        }
        Ok(None)
    }
    fn send_window_adjust(&mut self, to_add: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
            .put_u32(self.server_channel_no)
            .put_u32(to_add);
        self.flow_control.add_local(to_add);
        self.send(data)
    }

    fn recv_window_adjust(&mut self, to_add: u32) -> SshResult<()> {
        self.flow_control.add_remote(to_add);
        Ok(())
    }

    pub(crate) fn is_close(&self) -> bool {
        self.local_close && self.remote_close
    }
}

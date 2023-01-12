use std::{
    io::{Read, Write},
    sync::mpsc::{Receiver, Sender},
    vec,
};

use crate::{client::Client, constant::ssh_msg_code, error::{SshError, SshResult}, model::{BackendResp, BackendRqst, Data, FlowControl, Packet}, TerminalSize};

use super::{channel_exec::ExecBroker, channel_scp::ScpBroker, channel_shell::ShellBrocker};

pub(crate) struct Channel {
    snd: Sender<BackendResp>,
    server_channel_no: u32,
    client_channel_no: u32,
    remote_close: bool,
    local_close: bool,
    flow_control: FlowControl,
    pending_send: Vec<u8>,
}

impl Channel {
    pub fn new(
        server_channel_no: u32,
        client_channel_no: u32,
        remote_window: u32,
        snd: Sender<BackendResp>,
    ) -> SshResult<Self> {
        snd.send(BackendResp::Ok(server_channel_no))?;

        Ok(Self {
            snd,
            server_channel_no,
            client_channel_no,
            remote_close: false,
            local_close: false,
            flow_control: FlowControl::new(remote_window),
            pending_send: vec![],
        })
    }

    pub fn send_data<S>(&mut self, data: Data, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        self.pending_send.append(&mut data.into_inner());
        self.try_send_data(client, stream)
    }

    fn try_send_data<S>(&mut self, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        // try to send as much as we can
        while !self.pending_send.is_empty() {
            if self.flow_control.can_send() {
                let maybe_remain = self.flow_control.tune_on_send(&mut self.pending_send);

                // send it
                let mut data = Data::new();
                data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_DATA)
                    .put_u32(self.server_channel_no)
                    .put_u8s(&self.pending_send);

                // update remain
                self.pending_send = maybe_remain;

                self.send(data, client, stream)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn send<S>(&mut self, data: Data, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        if !self.is_close() {
            data.pack(client).write_stream(stream)
        } else {
            Err(SshError::from("Send data on a closed channel"))
        }
    }

    pub fn recv<S>(&mut self, mut data: Data, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        let mut buf = data.get_u8s();
        // flow_control
        self.flow_control.tune_on_recv(&mut buf);
        self.send_window_adjust(buf.len() as u32, client, stream)?;
        self.snd.send(BackendResp::Data(buf.into()))?;
        Ok(())
    }

    fn send_window_adjust<S>(
        &mut self,
        to_add: u32,
        client: &mut Client,
        stream: &mut S,
    ) -> SshResult<()>
    where
        S: Read + Write,
    {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_WINDOW_ADJUST)
            .put_u32(self.server_channel_no)
            .put_u32(to_add);
        self.flow_control.on_send(to_add);
        self.send(data, client, stream)
    }

    pub fn recv_window_adjust<S>(
        &mut self,
        to_add: u32,
        client: &mut Client,
        stream: &mut S,
    ) -> SshResult<()>
    where
        S: Read + Write,
    {
        self.flow_control.on_recv(to_add);
        if !self.pending_send.is_empty() {
            self.try_send_data(client, stream)
        } else {
            Ok(())
        }
    }

    pub fn local_close(&mut self) -> SshResult<()> {
        log::trace!("Channel {} send local close", self.client_channel_no);
        self.local_close = true;
        Ok(())
    }

    pub fn remote_close(&mut self) -> SshResult<()> {
        log::trace!("Channel {} recv remote close", self.client_channel_no);
        self.remote_close = true;
        if !self.local_close {
            self.snd.send(BackendResp::Close)?;
        }
        Ok(())
    }

    pub fn success(&mut self) -> SshResult<()> {
        self.snd.send(BackendResp::Ok(self.client_channel_no))?;
        Ok(())
    }

    pub fn failed(&mut self) -> SshResult<()> {
        self.snd.send(BackendResp::Fail("".to_owned()))?;
        Ok(())
    }

    pub fn is_close(&self) -> bool {
        self.local_close && self.remote_close
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        log::info!("Channel {} closed", self.client_channel_no);
    }
}

pub struct ChannelBroker {
    pub(crate) client_channel_no: u32,
    pub(crate) server_channel_no: u32,
    pub(crate) rcv: Receiver<BackendResp>,
    pub(crate) snd: Sender<BackendRqst>,
    pub(crate) close: bool,
}

impl ChannelBroker {
    pub(crate) fn new(
        client_id: u32,
        server_id: u32,
        rcv: Receiver<BackendResp>,
        snd: Sender<BackendRqst>,
    ) -> Self {
        Self {
            client_channel_no: client_id,
            server_channel_no: server_id,
            rcv,
            snd,
            close: false,
        }
    }

    /// open a [ExecBroker] channel which can excute commands
    ///
    pub fn exec(self) -> SshResult<ExecBroker> {
        Ok(ExecBroker::open(self))
    }

    /// open a [ScpBroker] channel which can download/upload files/directories
    ///
    pub fn scp(self) -> SshResult<ScpBroker> {
        Ok(ScpBroker::open(self))
    }

    /// open a [ShellBrocker] channel which  can be used as a pseudo terminal (AKA PTY)
    ///
    pub fn shell(self, tv: TerminalSize) -> SshResult<ShellBrocker> {
        ShellBrocker::open(self, tv)
    }

    /// close the backend channel and consume the channel broker itself
    ///
    pub fn close(mut self) -> SshResult<()> {
        self.close_no_consue()
    }

    fn close_no_consue(&mut self) -> SshResult<()> {
        if !self.close {
            let mut data = Data::new();
            data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_CLOSE)
                .put_u32(self.server_channel_no);
            self.close = true;
            self.snd
                .send(BackendRqst::CloseChannel(self.client_channel_no, data))?;
        }
        Ok(())
    }

    pub(super) fn send_data(&self, data: Data) -> SshResult<()> {
        self.snd
            .send(BackendRqst::Data(self.client_channel_no, data))?;
        Ok(())
    }

    pub(super) fn send(&self, data: Data) -> SshResult<()> {
        self.snd
            .send(BackendRqst::Command(self.client_channel_no, data))?;
        if !self.close {
            match self.rcv.recv().unwrap() {
                BackendResp::Ok(_) => log::trace!("{}: control command ok", self.client_channel_no),
                BackendResp::Fail(msg) => log::error!(
                    "{}: channel error with reason {}",
                    self.client_channel_no,
                    msg
                ),
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    pub(super) fn recv(&mut self) -> SshResult<Vec<u8>> {
        if self.close {
            Ok(vec![])
        } else {
            match self.rcv.recv().unwrap() {
                BackendResp::Close => {
                    // the remote actively close their end
                    // but we can send close later when the broker get dropped
                    // just set a flag here
                    self.close = true;
                    Ok(vec![])
                }
                BackendResp::Data(data) => Ok(data.into_inner()),
                _ => unreachable!(),
            }
        }
    }

    pub(super) fn try_recv(&mut self) -> SshResult<Option<Vec<u8>>> {
        if !self.close {
            if let Ok(rqst) = self.rcv.try_recv() {
                match rqst {
                    BackendResp::Close => {
                        // the remote actively close their end
                        // but we can send close later when the broker get dropped
                        // just set a flag here
                        self.close = true;
                        Ok(None)
                    }
                    BackendResp::Data(data) => Ok(Some(data.into_inner())),
                    _ => unreachable!(),
                }
            } else {
                Ok(None)
            }
        } else {
            Err(SshError::from("Read data on a closed channel"))
        }
    }

    pub(super) fn recv_to_end(&mut self) -> SshResult<Vec<u8>> {
        let mut buf = vec![];
        while !self.close {
            buf.append(&mut self.recv()?);
        }
        Ok(buf)
    }
}

impl Drop for ChannelBroker {
    fn drop(&mut self) {
        let _ = self.close_no_consue();
    }
}

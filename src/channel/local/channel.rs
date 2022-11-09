use std::{
    cell::RefCell,
    io::{Read, Write},
    rc::Rc,
};

use crate::{client::Client, error::SshResult, model::WindowSize};

use super::ChannelExec;

pub(crate) struct Channel<S>
where
    S: Read + Write,
{
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) window_size: WindowSize,
    pub(crate) client: Rc<RefCell<Client>>,
    pub(crate) stream: Rc<RefCell<S>>,
}

impl<S> Channel<S>
where
    S: Read + Write,
{
    pub fn open_exec(self) -> SshResult<ChannelExec<S>> {
        log::info!("exec opened.");
        Ok(ChannelExec::open(self))
    }
}

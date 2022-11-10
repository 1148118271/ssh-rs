use super::channel::Channel;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::error::SshResult;
use crate::model::Data;
use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub struct ChannelExec<S: Read + Write>(Channel<S>, Vec<u8>);

impl<S> Deref for ChannelExec<S>
where
    S: Read + Write,
{
    type Target = Channel<S>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> DerefMut for ChannelExec<S>
where
    S: Read + Write,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

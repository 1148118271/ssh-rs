use super::channel::Channel;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::error::SshResult;
use crate::model::Data;
use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub struct ChannelScp(Channel, Vec<u8>);

impl Deref for ChannelScp {
    type Target = Channel;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ChannelScp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

use std::io::{Read, Write};

use crate::{
    client::Client,
    model::{ArcMut, FlowControl},
};

pub struct Channel {
    pub(crate) server_channel_no: u32,
    pub(crate) client_channel_no: u32,
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) flow_control: FlowControl,
}

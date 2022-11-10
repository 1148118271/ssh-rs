use std::io::{Read, Write};

use crate::{
    client::Client,
    model::{ArcMut, FlowControl},
};

pub struct Channel<S>
where
    S: Read + Write,
{
    pub(crate) server_channel_no: u32,
    pub(crate) client_channel_no: u32,
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) flow_control: FlowControl,
    pub(crate) client: ArcMut<Client>,
    pub(crate) stream: ArcMut<S>,
}

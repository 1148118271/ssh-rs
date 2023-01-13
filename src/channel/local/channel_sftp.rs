use crate::channel::local::Channel;
use crate::constant::{sftp_msg_code, ssh_msg_code, ssh_str};
use crate::model::{Data, U32Iter};
use crate::SshResult;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;

pub struct ChannelSftp<S: Read + Write> {
    channel: Channel<S>,
    req_id: U32Iter,
}

impl<S> ChannelSftp<S>
where
    S: Read + Write,
{
    pub(crate) fn open(channel: Channel<S>) -> SshResult<Self> {
        let mut sftp = ChannelSftp {
            channel,
            req_id: U32Iter::default(),
        };
        sftp.get_sftp()?;
        sftp.init()?;
        Ok(sftp)
    }

    pub(crate) fn get_sftp(&mut self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel_no)
            .put_str(ssh_str::SUBSYSTEM)
            .put_u8(false as u8)
            .put_str(ssh_str::SFTP);
        self.send(data)
    }

    pub(crate) fn init(&mut self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u32(5)
            .put_u8(sftp_msg_code::SSH_FXP_INIT)
            .put_u32(2);
        self.send_data(data.to_vec())?;
        let vec = self.recv().unwrap();

        println!("vec {:?} ", vec);
        println!("vec len  {:?} ", vec.len());

        let mut rd = Data::from(vec);
        rd.get_u32();

        let t = rd.get_u8();
        let ver = rd.get_u32();

        println!("type {}, version {} ", t, ver);

        Ok(())
    }

    pub fn open_dir<P: AsRef<OsStr> + ?Sized>(&mut self, p: &P) -> SshResult<()> {
        let mut data = Data::new();

        data.put_u32(13)
            .put_u8(sftp_msg_code::SSH_FXP_OPENDIR)
            .put_u32(self.req_id.next().unwrap())
            .put_str("/opt");
        self.send_data(data.to_vec())?;
        let vec = self.recv().unwrap();

        println!("vec {:?} ", vec);

        Ok(())
    }
}

impl<S> Deref for ChannelSftp<S>
where
    S: Read + Write,
{
    type Target = Channel<S>;
    fn deref(&self) -> &Self::Target {
        &self.channel
    }
}

impl<S> DerefMut for ChannelSftp<S>
where
    S: Read + Write,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.channel
    }
}

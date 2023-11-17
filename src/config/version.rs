use std::io::{Read, Write};
use std::time::Duration;
use tracing::*;

use crate::{
    constant::{self, CLIENT_VERSION, SSH_MAGIC},
    error::{SshError, SshResult},
    model::Timeout,
};

#[derive(Debug, Clone)]
pub(crate) struct SshVersion {
    pub client_ver: String,
    pub server_ver: String,
}

impl Default for SshVersion {
    fn default() -> Self {
        Self {
            client_ver: CLIENT_VERSION.to_owned(),
            server_ver: String::new(),
        }
    }
}

fn read_version<S>(stream: &mut S, tm: Option<Duration>) -> SshResult<Vec<u8>>
where
    S: Read,
{
    let mut buf = vec![0; 128];
    let mut timeout = Timeout::new(tm);
    loop {
        match stream.read(&mut buf) {
            Ok(i) => {
                // MY TO DO: To Skip the other lines
                buf.truncate(i);
                return Ok(buf);
            }
            Err(e) => {
                if let std::io::ErrorKind::WouldBlock = e.kind() {
                    timeout.till_next_tick()?;
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };
    }
}

impl SshVersion {
    pub fn read_server_version<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> SshResult<()>
    where
        S: Read,
    {
        let buf = read_version(stream, timeout)?;
        if buf.len() < 4 || &buf[0..4] != SSH_MAGIC {
            error!("SSH version magic doesn't match");
            error!("Probably not an ssh server");
        }
        let from_utf8 = String::from_utf8(buf)?;
        let version_str = from_utf8.trim();
        info!("server version: [{}]", version_str);

        self.server_ver = version_str.to_owned();
        Ok(())
    }

    pub fn send_our_version<S>(&self, stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        info!("client version: [{}]", self.client_ver);
        let ver_string = format!("{}\r\n", self.client_ver);
        let _ = stream.write(ver_string.as_bytes())?;
        Ok(())
    }

    pub fn validate(&self) -> SshResult<()> {
        if self.server_ver.contains("SSH-2.0") {
            Ok(())
        } else {
            error!("error in version negotiation, version mismatch.");
            Err(SshError::VersionDismatchError {
                our: constant::CLIENT_VERSION.to_owned(),
                their: self.server_ver.clone(),
            })
        }
    }
}

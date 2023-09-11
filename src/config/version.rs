use std::io::{Read, Write};
use std::time::Duration;

use crate::{
    constant::{self, CLIENT_VERSION},
    error::{SshError, SshResult},
    model::Timeout,
};

type OurVer = String;
type ServerVer = String;

#[derive(Debug, Clone, Default)]
pub(crate) enum SshVersion {
    V1,
    V2(OurVer, ServerVer),
    #[default]
    Unknown,
}

fn read_version<S>(stream: &mut S, tm: Option<Duration>) -> SshResult<Vec<u8>>
where
    S: Read,
{
    let mut buf = vec![0; 128];
    let timeout = Timeout::new(tm);
    loop {
        match stream.read(&mut buf) {
            Ok(i) => {
                // MY TO DO: To Skip the other lines
                assert_eq!(&buf[0..4], constant::SSH_MAGIC);
                buf.truncate(i);
                return Ok(buf);
            }
            Err(e) => {
                if let std::io::ErrorKind::WouldBlock = e.kind() {
                    timeout.test()?;
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };
    }
}

impl SshVersion {
    pub fn from<S>(stream: &mut S, timeout: Option<Duration>) -> SshResult<Self>
    where
        S: Read,
    {
        let buf = read_version(stream, timeout)?;
        let from_utf8 = crate::util::from_utf8(buf)?;
        let version_str = from_utf8.trim();
        log::info!("server version: [{}]", version_str);

        if version_str.contains("SSH-2.0") {
            Ok(SshVersion::V2(
                CLIENT_VERSION.to_string(),
                version_str.to_string(),
            ))
        } else if version_str.contains("SSH-1.0") {
            Ok(SshVersion::V1)
        } else {
            Ok(SshVersion::Unknown)
        }
    }

    pub fn write<S>(stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        log::info!("client version: [{}]", CLIENT_VERSION);
        let ver_string = format!("{}\r\n", CLIENT_VERSION);
        let _ = stream.write(ver_string.as_bytes())?;
        Ok(())
    }

    pub fn validate(&self) -> SshResult<()> {
        if let SshVersion::V2(_, _) = self {
            log::info!("version negotiation was successful.");
            Ok(())
        } else {
            let err_msg = "error in version negotiation, version mismatch.";
            log::error!("{}", err_msg);
            Err(SshError::from(err_msg))
        }
    }
}

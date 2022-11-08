use std::io::{Read, Write};

use crate::{
    constant::CLIENT_VERSION,
    data::Data,
    error::{SshError, SshResult},
    h::H,
};

type OurVer = String;
type ServerVer = String;

#[derive(Debug, Clone)]
pub(crate) enum SshVersion {
    V1,
    V2(OurVer, ServerVer),
    Unknown,
}

impl Default for SshVersion {
    fn default() -> Self {
        SshVersion::Unknown
    }
}

impl SshVersion {
    pub fn from<S>(stream: &mut S, h: &mut H) -> SshResult<Self>
    where
        S: Read,
    {
        let buf = Data::read(stream, 128)?;
        let from_utf8 = crate::util::from_utf8(buf.into())?;
        let version_str = from_utf8.trim();
        log::info!("server version: [{}]", version_str);

        if version_str.contains("SSH-2.0") {
            h.set_v_s(version_str);
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

    pub fn write<S>(stream: &mut S, h: &mut H) -> SshResult<()>
    where
        S: Write,
    {
        log::info!("client version: [{}]", CLIENT_VERSION);
        h.set_v_c(CLIENT_VERSION);
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

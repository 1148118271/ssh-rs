use crate::error::{SshError, SshResult};
use crate::slog::log;
use rand::rngs::OsRng;
use rand::Rng;
use std::{
    path::Path,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn from_utf8(v: Vec<u8>) -> SshResult<String> {
    match String::from_utf8(v) {
        Ok(v) => Ok(v),
        Err(e) => {
            let err_msg = format!("Byte to utf8 string error, error info: {:?}", e);
            log::error!("{}", err_msg);
            Err(SshError::from(err_msg))
        }
    }
}

pub(crate) fn sys_time_to_secs(time: SystemTime) -> SshResult<u64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(t) => Ok(t.as_secs()),
        Err(e) => Err(SshError::from(format!(
            "SystemTimeError difference: {:?}",
            e.duration()
        ))),
    }
}

// a random cookie
pub(crate) fn cookie() -> Vec<u8> {
    let cookie: [u8; 16] = OsRng.gen();
    cookie.to_vec()
}

pub(crate) fn vec_u8_to_string(v: Vec<u8>, pat: &str) -> SshResult<Vec<String>> {
    let result = from_utf8(v)?;
    let r: Vec<&str> = result.split(pat).collect();
    let mut vec = vec![];
    for x in r {
        vec.push(x.to_string())
    }
    Ok(vec)
}

pub(crate) fn str_to_i64(v: &str) -> SshResult<i64> {
    match i64::from_str(v) {
        Ok(v) => Ok(v),
        Err(_) => Err(SshError::from("str to i64 error")),
    }
}

pub(crate) fn check_path(path: &Path) -> SshResult<()> {
    if path.to_str().is_none() {
        return Err(SshError::from("invalid path."));
    }
    Ok(())
}

pub(crate) fn file_time(v: Vec<u8>) -> SshResult<(i64, i64)> {
    let mut t = vec![];
    for x in v {
        if x == b'T' || x == 32 || x == 10 {
            continue;
        }
        t.push(x)
    }
    let a = t.len() / 2;
    let ct = from_utf8(t[..(a - 1)].to_vec())?;
    let ut = from_utf8(t[a..(t.len() - 1)].to_vec())?;
    Ok((str_to_i64(&ct)?, str_to_i64(&ut)?))
}

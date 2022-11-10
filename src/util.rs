use crate::error::{SshError, SshResult};
use crate::slog::log;
use rand::rngs::OsRng;
use rand::Rng;
use std::{
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

// 十六位随机数
pub(crate) fn cookie() -> Vec<u8> {
    let cookie: [u8; 16] = OsRng.gen();
    cookie.to_vec()
}

#[allow(dead_code)]
pub(crate) fn vec_u8_to_string(v: Vec<u8>, pat: &str) -> SshResult<Vec<String>> {
    let result = from_utf8(v)?;
    let r: Vec<&str> = result.split(pat).collect();
    let mut vec = vec![];
    for x in r {
        vec.push(x.to_string())
    }
    Ok(vec)
}

#[allow(dead_code)]
pub(crate) fn str_to_u32(v: &str) -> SshResult<u32> {
    match u32::from_str(v) {
        Ok(v) => Ok(v),
        Err(_) => Err(SshError::from("str to u32 error")),
    }
}

#[allow(dead_code)]
pub(crate) fn str_to_i64(v: &str) -> SshResult<i64> {
    match i64::from_str(v) {
        Ok(v) => Ok(v),
        Err(_) => Err(SshError::from("str to i64 error")),
    }
}

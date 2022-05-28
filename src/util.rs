use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use rand::rngs::OsRng;
use error::{SshError, SshErrorKind, SshResult};
use slog::log;


pub(crate) fn from_utf8(v: Vec<u8>) -> SshResult<String> {
    match String::from_utf8(v) {
        Ok(v) => Ok(v),
        Err(e) => {
            log::error!("Byte to utf8 string error, error info: {:?}", e);
            Err(SshError::from(SshErrorKind::FromUtf8Error))
        }
    }
}


pub(crate) fn sys_time_to_secs(time: SystemTime) -> SshResult<u64> {
     match time.duration_since(UNIX_EPOCH) {
        Ok(t) => Ok(t.as_secs()),
        Err(e) => {
            Err(SshError::from(
                SshErrorKind::UnknownError(
                    format!("SystemTimeError difference: {:?}", e.duration()))))
        }
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
        Err(_) => {
            Err(SshError::from(SshErrorKind::UnknownError("str to u32 error".to_string())))
        }
    }
}


#[allow(dead_code)]
pub(crate) fn str_to_i64(v: &str) -> SshResult<i64> {
    match i64::from_str(v) {
        Ok(v) => Ok(v),
        Err(_) => {
            Err(SshError::from(SshErrorKind::UnknownError("str to i64 error".to_string())))
        }
    }
}

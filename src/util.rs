use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use rand::Rng;
use rand::rngs::OsRng;
use encryption::ChaCha20Poly1305;
use error::{SshError, SshErrorKind, SshResult};
use slog::log;
use crate::{Client, Config};
// use crate::channel::ChannelWindowSize;
use crate::global::{/*CHANNEL_WINDOW,CLIENT, */ CONFIG, ENCRYPTION_KEY};


pub(crate) fn from_utf8(v: Vec<u8>) -> SshResult<String> {
    match String::from_utf8(v) {
        Ok(v) => Ok(v),
        Err(e) => {
            log::error!("Byte to utf8 string error, error info: {:?}", e);
            Err(SshError::from(SshErrorKind::FromUtf8Error))
        }
    }
}


pub fn unlock<T>(guard: MutexGuard<'static, T>) {
    drop(guard);
}


pub(crate) fn update_config(v: Option<Mutex<Config>>) {
    unsafe {
        CONFIG = v;
    }
}

pub(crate) fn config() -> SshResult<MutexGuard<'static, Config>> {
    unsafe {
         match &mut CONFIG {
            None => {
                log::error!("config null pointer");
                Err(SshError::from(SshErrorKind::ConfigNullError))
            }
            Some(v) => {
                match v.lock() {
                    Ok(c) => Ok(c),
                    Err(e) => {
                        log::error!("get config mutex error, error info: {:?}", e);
                        Err(SshError::from(SshErrorKind::MutexError))
                    }
                }
            }
        }
    }
}


pub(crate) fn encryption_key() -> Result<&'static mut ChaCha20Poly1305, SshError>  {
    unsafe {
        match &mut ENCRYPTION_KEY {
            None => {
                log::error!("Encrypted null pointer");
                Err(SshError::from(SshErrorKind::EncryptionNullError))
            },
            Some(v) => Ok(v)
        }
    }
}
pub(crate) fn update_encryption_key(v: Option<ChaCha20Poly1305>) {
    unsafe {
        ENCRYPTION_KEY = v
    }
}

// pub(crate) fn get_channel_window(k: u32) -> SshResult<Option<MutexGuard<'static, ChannelWindowSize>>> {
//     unsafe {
//         if let None = CHANNEL_WINDOW {
//             CHANNEL_WINDOW = Some(HashMap::new())
//         }
//
//         if let Some(map) = &mut CHANNEL_WINDOW {
//             return match map.get(&k) {
//                 None => Ok(None),
//                 Some(v) => {
//                     match v.lock() {
//                         Ok(v) => {
//                             Ok(Some(v))
//                         }
//                         Err(e) => {
//                             log::error!("get channel_window mutex error, error info: {:?}", e);
//                             Err(SshError::from(SshErrorKind::MutexError))
//                         }
//                     }
//                 }
//             }
//         }
//         Ok(None)
//     }
// }
//
// pub(crate) fn set_channel_window(k: u32, v: ChannelWindowSize) {
//     unsafe {
//         if let None = CHANNEL_WINDOW {
//             CHANNEL_WINDOW = Some(HashMap::new())
//         }
//
//         if let Some(map) = &mut CHANNEL_WINDOW {
//             map.insert(k, Mutex::new(v));
//         }
//     }
// }

// 十六位随机数
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

pub(crate) fn str_to_u32(v: &str) -> SshResult<u32> {
    match u32::from_str(v) {
        Ok(v) => Ok(v),
        Err(_) => Err(SshError::from(SshErrorKind::UnknownError("str to u32 error".to_string())))
    }
}

pub(crate) fn str_to_i64(v: &str) -> SshResult<i64> {
    match i64::from_str(v) {
        Ok(v) => Ok(v),
        Err(_) => Err(SshError::from(SshErrorKind::UnknownError("str to i64 error".to_string())))
    }
}

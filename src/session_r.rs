use std::io::Read;
use crate::client::Client;
use crate::constant::size;
use crate::data::Data;
use crate::{Session, SshError, SshResult};
use crate::window_size::WindowSize;


impl Session {
    /// 接收服务端版本
    pub(crate) fn read_version(&mut self) -> Vec<u8> {
        let client = self.client.as_mut().unwrap();
        let mut v = [0_u8; 128];
        loop {
            match client.stream.read(&mut v) {
                Ok(i) => { return (&v[..i]).to_vec() }
                Err(_) => continue
            };
        }
    }

    pub fn read(&mut self) -> Result<Vec<Data>, SshError> {
        self.read_data(None)
    }

    pub fn read_data(&mut self, lws: Option<&mut WindowSize>) -> SshResult<Vec<Data>> {
        let client = self.client.as_mut().unwrap();
        // 判断超时时间
        // 如果超时,即抛出异常
        client.timeout.is_timeout()?;

        let mut results = vec![];
        let mut result = vec![0; size::BUF_SIZE as usize];
        let len = match client.stream.read(&mut result) {
            Ok(len) => {
                if len <= 0 {
                    return Ok(results)
                }

                // 从服务段正常读取到数据的话
                // 就刷新超时时间
                client.timeout.renew();

                len
            },
            Err(e) => {
                if Client::is_would_block(&e) {
                    return Ok(results)
                }
                return Err(SshError::from(e))
            }
        };

        result.truncate(len);
        // 处理未加密数据
        if !self.is_encryption {
            client.process_data(result, &mut results);
        }
        // 处理加密数据
        else {
            match self.encryption.as_mut() {
                None => return Err(SshError::from("encryption algorithm is none.")),
                Some(encryption) => client.process_data_encrypt(result, &mut results, lws, encryption)?
            }
        }
        Ok(results)
    }
}

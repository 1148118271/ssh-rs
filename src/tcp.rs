use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering::Relaxed;
use ring::error::Unspecified;
use crate::{global_variable, size};
use crate::error::{SshError, SshErrorKind};
use crate::global_variable::encryption_key;


pub struct Client {
    pub(crate) stream: TcpStream,
    sequence: Sequence,
    pub(crate) sender_window_size: u32,
}

impl Client {
    pub fn clone(&self) -> Result<Client, SshError>{
        let client = Client {
            stream: match self.stream.try_clone() {
                Ok(v) => v,
                Err(e) => return Err(SshError::from(e))
            },
            sequence: self.sequence.clone(),
            sender_window_size: self.sender_window_size
        };
        Ok(client)
    }
}

#[derive(Clone)]
struct Sequence {
    client_sequence_num: u32,
    server_sequence_num: u32
}

impl Sequence {

    fn client_auto_increment(&mut self) {
        if self.client_sequence_num == u32::MAX {
            self.client_sequence_num = 0;
        }
        self.client_sequence_num += 1;
    }

    fn server_auto_increment(&mut self) {
        if self.server_sequence_num == u32::MAX {
            self.server_sequence_num = 0;
        }
        self.server_sequence_num += 1;
    }
}


impl Client {
    pub fn connect<A: ToSocketAddrs>(adder: A) -> Result<Client, SshError> {
        match TcpStream::connect(adder) {
            Ok(stream) =>
                Ok(
                    Client{
                        stream,
                        sequence: Sequence {
                            client_sequence_num: 0,
                            server_sequence_num: 0
                        },
                        sender_window_size: 0
                    }
                ),
            Err(e) => Err(SshError::from(e))
        }

    }

    pub fn read_version(&mut self) -> Vec<u8>  {
        let mut v = [0_u8; 128];
        loop {
            match self.stream.read(&mut v) {
                Ok(i) => { return (&v[..i]).to_vec() }
                Err(_) => continue
            };
        }
    }

    pub fn read(&mut self) -> Result<Vec<Vec<u8>>, SshError> {
        let mut results = vec![];
        let mut buf = vec![0; size::BUF_SIZE as usize];
        let result = self.stream.read(&mut buf);

        if result.is_err() {
            return Ok(results)
        }
        let len = result.unwrap();
        if !global_variable::IS_ENCRYPT.load(Relaxed) {
            self.sequence.server_auto_increment();
            results.push((&buf[..len]).to_vec());
            self.sender_window_size += len as u32;
            return Ok(results)
        }

        if len == 0 {
            return Ok(results)
        }

        self.read_handle((&buf[..len]).to_vec(), &mut results)?;

        Ok(results)
    }

    fn read_handle(&mut self, mut result: Vec<u8>, results: &mut Vec<Vec<u8>>) -> Result<(), SshError> {
        self.sequence.server_auto_increment();
        let key = encryption_key();
        let mut packet_len_slice = [0_u8; 4];
        let len = &result[..4];
        packet_len_slice.copy_from_slice(len);
        let packet_len_slice = key.server_key.decrypt_packet_length(self.sequence.server_sequence_num, packet_len_slice);
        let packet_len = u32::from_be_bytes(packet_len_slice);
        let data_len = (packet_len + 4 + 16) as usize;
        loop {
            if result.len() >= data_len { break }
            let mut buf = vec![0; size::BUF_SIZE as usize];
            let len = self.stream.read(&mut buf)?;
            buf.truncate(len);
            result.extend(buf)
        }

        let (this, remaining) = result.split_at_mut(data_len);
        let decryption_result =
            key.decryption(self.sequence.server_sequence_num, &mut this.to_vec())?;
        self.sender_window_size += (decryption_result.len() + 16) as u32;
        results.push(decryption_result);
        if  remaining.len() > 0 {
            self.read_handle(remaining.to_vec(), results)?;
        }
        Ok(())
    }

    pub fn write_version(&mut self, buf: &[u8]) -> Result<(), SshError> {
        match self.stream.write(&buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), SshError> {
        let mut buf = buf.to_vec();
        if global_variable::IS_ENCRYPT.load(Relaxed) {
            let key = encryption_key();
            key.encryption(self.sequence.client_sequence_num, &mut buf);
        }
        self.sequence.client_auto_increment();
        match self.stream.write(&buf) {
            Ok(_) => {}
            Err(e) => return Err(SshError::from(e))
        };
        match self.stream.flush() {
            Ok(_) => {}
            Err(e) => return Err(SshError::from(e))
        };
        Ok(())
    }

    pub(crate) fn close(self) -> Result<(), SshError> {
        match self.stream.shutdown(Shutdown::Both) {
            Ok(o) => Ok(o),
            Err(e) => Err(SshError::from(e))
        }
    }
}

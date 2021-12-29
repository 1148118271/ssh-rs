use std::io;
use std::io::{Read, Write};
use std::sync::Arc;
use crate::constants::{message, strings, size};
use crate::constants::message::SSH_MSG_CHANNEL_DATA;
use crate::encryption;
use crate::encryption::ChaCha20Poly1305;
use crate::hash::HASH;
use crate::key_exchange::KeyExchange;
use crate::packet::{Data, Packet};
use crate::tcp::Client;

pub struct Channel {
    pub(crate) stream: Client,
    pub(crate) server_channel: u32,
    pub(crate) client_channel: u32,
    pub(crate) key_exchange: KeyExchange
}


impl Channel {
    pub fn read(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![];
        self.window_adjust();
        let results = self.stream.read()?;
        for result in results {
            let message_code = result[5];
            match message_code {
                message::SSH_MSG_GLOBAL_REQUEST => {
                    let mut data = Data::new();
                    data.put_u8(message::SSH_MSG_REQUEST_FAILURE);
                    let mut packet = Packet::from(data);
                    packet.build();
                    self.stream.write(packet.as_slice())?;
                }


                message::SSH_MSG_CHANNEL_DATA => {
                    let mut data = Packet::processing_data(result);
                    data.get_u8();
                    data.get_u32();
                    let vec = data.get_u8s();
                    buf.extend(vec);
                }

                message::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                    let mut data = Packet::processing_data(result);
                    let msg_code = data.get_u8();
                    let server_channel = data.get_u32();
                    let windows_size = data.get_u32();
                    println!("信息编码: {}, 通道编号: {}, 窗口大小: {}", msg_code, server_channel, windows_size);
                }

                message::SSH_MSG_KEXINIT => {
                    let mut data = Packet::processing_data(result);
                    // 重置加密算法
                    if encryption::is_encrypt() {
                        encryption::update_is_encrypt();
                        encryption::update_encryption_key(None);
                    }
                    // 密钥协商
                    self.key_exchange.algorithm_negotiation(data, &mut self.stream)?;
                    // 发送公钥
                    self.key_exchange.send_public_key(&mut self.stream)?;
                }

                message::SSH_MSG_KEX_ECDH_REPLY => {
                    // 生成session_id并且获取signature
                    let sig = self.key_exchange.generate_session_id_and_get_signature(result)?;
                    // 验签
                    self.key_exchange.verify_signature(&sig);
                    // 新的密钥
                    self.key_exchange.new_keys(&mut self.stream)?;

                    // 修改加密算法
                    let hash = HASH::new(&self.key_exchange.h.k, &self.key_exchange.session_id, &self.key_exchange.session_id);
                    let poly1305 = ChaCha20Poly1305::new(hash);
                    encryption::update_is_encrypt();
                    encryption::update_encryption_key(Some(poly1305));
                }

                _ => {}
            }
        }
        Ok(buf)
    }


    pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut data = Data::new();
        data.put_u8(SSH_MSG_CHANNEL_DATA)
            .put_u32(self.server_channel)
            .put_bytes(buf);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.stream.write(packet.as_slice())?)
    }


}



impl Channel {

    pub fn window_adjust(&mut self) -> io::Result<()> {
        if self.stream.sender_window_size >= (size::LOCAL_WINDOW_SIZE / 2) {
            let mut data = Data::new();
            data.put_u8(message::SSH_MSG_CHANNEL_WINDOW_ADJUST)
                .put_u32(self.server_channel)
                .put_u32(size::LOCAL_WINDOW_SIZE - self.stream.sender_window_size);
            let mut packet = Packet::from(data);
            packet.build();
            self.stream.write(packet.as_slice());
            self.stream.sender_window_size = 0;
        }
        Ok(())
    }

    pub fn open_shell(&mut self) -> io::Result<()> {
        loop {
            let results = self.stream.read()?;
            for buf in results {
                let message_code = buf[5];
                match message_code {
                    message::SSH_MSG_GLOBAL_REQUEST => {
                        let mut data = Data::new();
                        data.put_u8(message::SSH_MSG_REQUEST_FAILURE);
                        let mut packet = Packet::from(data);
                        packet.build();
                        self.stream.write(packet.as_slice())?;
                    }

                    message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        let mut data = Packet::processing_data(buf);
                        data.get_u8();
                        data.get_u32();
                        self.server_channel = data.get_u32();
                        // 请求伪终端
                        self.request_pty()?;
                        // 打开shell通道
                        self.get_shell()?;
                    }

                    message::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                        let mut data = Packet::processing_data(buf);
                        let msg_code = data.get_u8();
                        let server_channel = data.get_u32();
                        let windows_size = data.get_u32();
                        println!("信息编码: {}, 通道编号: {}, 窗口大小: {}", msg_code, server_channel, windows_size);
                    }

                    message::SSH_MSG_CHANNEL_SUCCESS => {
                        return Ok(())
                    }
                    _ => {}
                }
            }
        }
    }

    fn get_shell(&mut self) -> io::Result<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel)
            .put_str(strings::SHELL)
            .put_u8(true as u8);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.stream.write(packet.as_slice())?)
    }

    fn request_pty(&mut self) -> io::Result<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel)
            .put_str(strings::PTY_REQ)
            .put_u8(false as u8)
            .put_str(strings::XTERM_VAR)
            .put_u32(80)
            .put_u32(24)
            .put_u32(640)
            .put_u32(480);
        let model = [
            128,                  // TTY_OP_ISPEED
            0, 1, 0xc2, 0,        // 115200
            129,                  // TTY_OP_OSPEED
            0, 1, 0xc2, 0,        // 115200 again
            0_u8,                 // TTY_OP_END
        ];
        data.put_bytes(&model);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.stream.write(packet.as_slice())?)
    }
}

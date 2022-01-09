#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::process::exit;
    use std::sync::atomic::Ordering::Relaxed;
    use crate::packet::{Data, Packet};
    use crate::{global_variable, message, SSH, strings};

    #[test]
    fn test1() {
        // let a = [0, 0, 0, 64, 11, 94, 0, 0, 0, 1, 0, 0, 0, 43, 1, 115, 99, 112, 58, 32, 47, 111, 116, 112, 47, 116, 101, 115, 116, 58, 32, 78, 111, 32, 115, 117, 99, 104, 32, 102, 105, 108, 101, 32, 111, 114, 32, 100, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 195, 222, 146, 137, 72, 126, 171, 190, 238, 206];
        // let mut data = Packet::processing_data(a.to_vec());
        // data.get_u8();
        // data.get_u32();
        // let vec = data.get_u8s();
        // println!("{}", String::from_utf8(vec).unwrap());
        // println!("{:?}", String::from_utf8(vec![0x10]).unwrap())

    }

    #[test]
    fn test() {
        let mut command = b"scp -t /opt/test";
        let ssh: SSH = SSH::new();
        let mut session = ssh.get_session("192.168.3.101:22").unwrap();
        session.set_nonblocking(true).unwrap();
        session.set_user_and_password("ubuntu".to_string(), "gaoxiangkang".to_string());
        session.connect().unwrap();
        let mut channel = session.open_channel().unwrap();
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(channel.server_channel)
            .put_str(strings::EXEC)
            .put_u8(true as u8)
            .put_bytes(b"scp -t /opt/test");
        let mut packet = Packet::from(data);
        packet.build();
        channel.stream.write(packet.as_slice()).unwrap();
        'FOR_1:
            loop {
                let results = channel.stream.read().unwrap();
                for buf in results {
                    let message_code = buf[5];
                    match message_code {
                        message::SSH_MSG_CHANNEL_DATA => {
                            let mut data = Packet::processing_data(buf);
                            data.get_u8();
                            data.get_u32();
                            let vec = data.get_u8s();
                            if vec[0] == 0 {
                                break 'FOR_1
                            }
                        }
                        _ => channel.other_info(message_code, buf).unwrap()
                    }

                }
            }

        let mut file = File::open("/Users/gaoxiangkang/Desktop/anime.min.js").unwrap();
        let metadata = file.metadata().unwrap();

        let file_info = format!("C0644 {} anime.min.js\n", metadata.size());

        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(channel.server_channel)
            .put_str(file_info.as_str());
        packet.put_data(data);
        packet.build();
        channel.stream.write(packet.as_slice()).unwrap();
        'FOR_2:
            loop {
                let results = channel.stream.read().unwrap();
                for buf in results {
                    let message_code = buf[5];
                    match message_code {
                        message::SSH_MSG_CHANNEL_DATA => {
                            let mut data = Packet::processing_data(buf);
                            data.get_u8();
                            data.get_u32();
                            let vec = data.get_u8s();
                            if vec[0] == 0 {
                                break 'FOR_2
                            } else {
                                println!("error: {}", String::from_utf8(vec).unwrap());
                                exit(0);
                            }
                        }
                        _ => channel.other_info(message_code, buf).unwrap()
                    }
                }
            }
        println!("{:?}", file_info);
        let mut buf = [0; 1024];

        loop {
            let len = file.read(&mut buf).unwrap();
            if len <= 0  {
                break;
            }
            let mut data = Data::new();
            data.put_u8(message::SSH_MSG_CHANNEL_DATA)
                .put_u32(channel.server_channel)
                .put_bytes(&buf[..len]);
            packet.put_data(data);
            packet.build();
            channel.stream.write(packet.as_slice()).unwrap();
        }
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(channel.server_channel)
            .put_bytes(&[0]);
        packet.put_data(data);
        packet.build();
        channel.stream.write(packet.as_slice()).unwrap();

    }
}
#[cfg(test)]
mod tests {
    use std::{fs, os};
    use std::fs::{File, OpenOptions, Permissions};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::exit;
    use std::str::FromStr;
    use std::string::FromUtf8Error;
    use std::sync::atomic::Ordering::Relaxed;
    use filetime::{FileTime, set_file_times};
    use crate::packet::{Data, Packet};
    use crate::{Channel, global, message, SSH, SshError, strings, util};
    use crate::error::{SshErrorKind, SshResult};


    #[test]
    fn test1() {
        //let a = [0, 0, 0, 32, 6, 98, 0, 0, 0, 0, 0, 0, 0, 11, 101, 120, 105, 116, 45, 115, 116, 97, 116, 117, 115, 0, 0, 0, 0, 1, 177, 44, 62, 135, 192, 26];
        //let a = [0, 0, 2, 96, 4, 80, 0, 0, 0, 23, 104, 111, 115, 116, 107, 101, 121, 115, 45, 48, 48, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 1, 151, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 129, 0, 210, 237, 63, 2, 26, 203, 55, 185, 42, 198, 35, 54, 147, 250, 93, 198, 161, 218, 47, 186, 140, 210, 160, 192, 152, 44, 231, 241, 151, 60, 224, 24, 212, 180, 17, 210, 30, 209, 12, 34, 178, 108, 232, 4, 197, 61, 138, 86, 43, 252, 98, 208, 187, 5, 163, 44, 228, 211, 119, 61, 129, 82, 34, 34, 254, 27, 208, 103, 70, 11, 197, 78, 185, 52, 169, 221, 229, 82, 15, 76, 199, 79, 183, 172, 11, 1, 61, 162, 90, 247, 119, 148, 50, 64, 3, 128, 223, 149, 163, 68, 143, 209, 142, 186, 95, 145, 75, 234, 23, 206, 162, 224, 205, 208, 91, 147, 107, 234, 194, 204, 235, 245, 217, 161, 112, 51, 156, 209, 33, 214, 254, 57, 116, 119, 8, 200, 31, 84, 200, 126, 147, 214, 213, 161, 91, 44, 95, 140, 46, 147, 68, 99, 45, 146, 211, 31, 219, 244, 188, 38, 61, 32, 9, 72, 184, 217, 146, 37, 82, 85, 52, 50, 78, 230, 155, 197, 84, 4, 47, 252, 228, 100, 226, 205, 95, 101, 61, 15, 32, 38, 135, 172, 24, 184, 47, 186, 236, 119, 153, 197, 215, 58, 220, 193, 246, 53, 196, 108, 15, 46, 222, 181, 218, 250, 35, 90, 190, 204, 238, 67, 65, 224, 62, 56, 98, 178, 18, 235, 162, 175, 144, 127, 90, 81, 185, 149, 79, 14, 14, 44, 82, 75, 148, 83, 145, 205, 153, 216, 88, 180, 183, 145, 80, 30, 156, 49, 170, 144, 242, 19, 187, 209, 93, 65, 157, 121, 224, 192, 158, 171, 128, 230, 169, 101, 199, 153, 25, 46, 83, 166, 153, 60, 69, 110, 234, 49, 193, 110, 41, 188, 227, 155, 53, 28, 198, 179, 154, 49, 15, 50, 92, 42, 143, 118, 46, 41, 86, 103, 138, 75, 54, 131, 61, 173, 3, 212, 6, 213, 204, 127, 232, 85, 151, 79, 230, 228, 20, 195, 150, 84, 21, 180, 101, 84, 170, 3, 172, 10, 38, 33, 137, 242, 182, 133, 61, 87, 41, 169, 254, 80, 191, 19, 78, 24, 64, 209, 92, 246, 111, 3, 121, 104, 228, 240, 199, 73, 13, 98, 239, 117, 103, 44, 199, 181, 57, 56, 251, 147, 187, 96, 83, 247, 163, 85, 0, 0, 0, 104, 0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 200, 55, 187, 139, 219, 52, 80, 180, 230, 147, 93, 177, 108, 30, 103, 208, 233, 136, 65, 83, 59, 3, 165, 49, 83, 157, 237, 221, 127, 61, 128, 74, 85, 22, 97, 55, 28, 19, 183, 71, 141, 212, 53, 186, 9, 108, 230, 25, 98, 25, 57, 221, 239, 146, 26, 220, 157, 229, 142, 127, 225, 27, 229, 223, 0, 0, 0, 51, 0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 252, 176, 114, 51, 126, 145, 94, 218, 114, 201, 162, 106, 215, 173, 30, 213, 153, 192, 247, 81, 122, 107, 227, 101, 242, 225, 6, 28, 145, 99, 236, 81, 107, 98, 207, 38];
        //let a = [0, 0, 0, 64, 11, 94, 0, 0, 0, 1, 0, 0, 0, 43, 1, 115, 99, 112, 58, 32, 47, 111, 116, 112, 47, 116, 101, 115, 116, 58, 32, 78, 111, 32, 115, 117, 99, 104, 32, 102, 105, 108, 101, 32, 111, 114, 32, 100, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 195, 222, 146, 137, 72, 126, 171, 190, 238, 206];
        // let a = [0, 0, 0, 48, 9, 94, 0, 0, 0, 0, 0, 0, 0, 29, 67, 48, 55, 54, 52, 32, 49, 49, 50, 51, 52, 32, 97, 110, 105, 109, 101, 46, 109, 105, 110, 46, 106, 115, 95, 98, 97, 107, 10, 151, 91, 112, 246, 150, 197, 218, 76, 152];
        // let mut data = Packet::processing_data(a.to_vec());
        // data.get_u8();
        // data.get_u32();
        // let vec = data.get_u8s();
        // println!("{}", String::from_utf8(vec).unwrap());
        // println!("{:?}", String::from_utf8(vec![0x10]).unwrap())
        // let i = u32::from_str_radix("0775", 8).unwrap();
        // println!("{}", i)

        let path = Path::new("User");

        let option = path.file_name().unwrap();
        println!("{:?}", option);

        // println!("{:}", 7 % 10);
        //u32::f
        // let mut count = 0;
        // for _ in 0..7 {
        //     count+=2;
        // }
        // println!("count {:}", count);
    }

    // #[test]
    // fn test() {
    //     let p = true;
    //     let mut command = b"scp -t /opt/test";
    //     let ssh: SSH = SSH::new();
    //     let mut session = ssh.get_session("192.168.3.101:22").unwrap();
    //     session.set_nonblocking(true).unwrap();
    //     session.set_user_and_password("ubuntu".to_string(), "gaoxiangkang".to_string());
    //     session.connect().unwrap();
    //     let mut channel = session.open_channel().unwrap();
    //     let mut data = Data::new();
    //     data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
    //         .put_u32(channel.server_channel)
    //         .put_str(strings::EXEC)
    //         .put_u8(true as u8)
    //         .put_bytes(b"scp -t /opt/test");
    //     let mut packet = Packet::from(data);
    //     packet.build();
    //     channel.stream.lock().unwrap().write(packet.as_slice()).unwrap();
    //     'FOR_1:
    //         loop {
    //             let results = channel.stream.lock().unwrap().read().unwrap();
    //             for buf in results {
    //                 let message_code = buf[5];
    //                 match message_code {
    //                     message::SSH_MSG_CHANNEL_DATA => {
    //                         let mut data = Packet::processing_data(buf);
    //                         data.get_u8();
    //                         data.get_u32();
    //                         let vec = data.get_u8s();
    //                         if vec[0] == 0 {
    //                             break 'FOR_1
    //                         }
    //                     }
    //                     _ => channel.other_info(message_code, buf).unwrap()
    //                 }
    //
    //             }
    //         }
    //
    //     let mut file = File::open("/Users/gaoxiangkang/Desktop/anime.min.js").unwrap();
    //     let metadata = file.metadata().unwrap();
    //
    //     let file_info = format!("C0644 {} anime.min.js\n", metadata.size());
    //
    //     let mut data = Data::new();
    //     data.put_u8(message::SSH_MSG_CHANNEL_DATA)
    //         .put_u32(channel.server_channel)
    //         .put_str(file_info.as_str());
    //     packet.put_data(data);
    //     packet.build();
    //     channel.stream.lock().unwrap().write(packet.as_slice()).unwrap();
    //     'FOR_2:
    //         loop {
    //             let results = channel.stream.lock().unwrap().read().unwrap();
    //             for buf in results {
    //                 let message_code = buf[5];
    //                 match message_code {
    //                     message::SSH_MSG_CHANNEL_DATA => {
    //                         let mut data = Packet::processing_data(buf);
    //                         data.get_u8();
    //                         data.get_u32();
    //                         let vec = data.get_u8s();
    //                         if vec[0] == 0 {
    //                             break 'FOR_2
    //                         } else {
    //                             println!("error: {}", String::from_utf8(vec).unwrap());
    //                             exit(0);
    //                         }
    //                     }
    //                     _ => channel.other_info(message_code, buf).unwrap()
    //                 }
    //             }
    //         }
    //     println!("{:?}", file_info);
    //     let mut buf = [0; 1024 * 2];
    //     let mut v = vec![];
    //     loop {
    //         let len = file.read(&mut buf).unwrap();
    //         if len <= 0  {
    //             break;
    //         }
    //         v.extend(&buf[..len])
    //
    //     }
    //     v.truncate(v.len());
    //     let mut data = Data::new();
    //     data.put_u8(message::SSH_MSG_CHANNEL_DATA)
    //         .put_u32(channel.server_channel)
    //         .put_bytes(&v);
    //     packet.put_data(data);
    //     packet.build();
    //     channel.stream.lock().unwrap().write(packet.as_slice()).unwrap();
    //     let mut data = Data::new();
    //     data.put_u8(message::SSH_MSG_CHANNEL_DATA)
    //         .put_u32(channel.server_channel)
    //         // '\0'
    //         .put_bytes(&[0]);
    //     packet.put_data(data);
    //     packet.build();
    //     channel.stream.lock().unwrap().write(packet.as_slice()).unwrap();
    //
    //
    //     let mut data = Data::new();
    //     data.put_u8(message::SSH_MSG_CHANNEL_DATA)
    //         .put_u32(channel.server_channel)
    //         // '\0'
    //         .put_bytes(&['E' as u8]);
    //     packet.put_data(data);
    //     packet.build();
    //     channel.stream.lock().unwrap().write(packet.as_slice()).unwrap();
    //    //  channel.close().unwrap()
    // }

    // #[test]
    // fn test2() {
    //     let ssh: SSH = SSH::new();
    //     let mut session = ssh.get_session("192.168.3.101:22").unwrap();
    //     session.set_nonblocking(true).unwrap();
    //     session.set_user_and_password("ubuntu".to_string(), "gaoxiangkang".to_string());
    //     session.connect().unwrap();
    //     let mut channel = session.open_channel().unwrap();
    //     let mut data = Data::new();
    //     data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
    //         .put_u32(channel.server_channel)
    //         .put_str(strings::EXEC)
    //         .put_u8(true as u8)
    //         .put_bytes(b"scp -f -r -q -p /opt/test");
    //     let mut packet = Packet::from(data);
    //     packet.build();
    //     channel.stream.lock().unwrap().write(packet.as_slice()).unwrap();
    //
    //     send_end(&mut channel);
    //     let vec = read_data(&mut channel).unwrap();
    //     println!("{}", String::from_utf8(vec).unwrap());
    //     // send_end(&mut channel);
    //     // let vec = read_data(&mut channel).unwrap();
    //     // println!("{}", String::from_utf8(vec).unwrap());
    //     // send_end(&mut channel);
    //     // let mut st = vec![];
    //     // loop {
    //     //     let mut vec = read_data(&mut channel).unwrap();
    //     //     if &vec[vec.len() - 1] == &0 {
    //     //         vec.remove(vec.len() - 1);
    //     //         st.append(&mut vec);
    //     //         break;
    //     //     }
    //     //     st.append(&mut vec);
    //     // }
    //     // println!("st len  = {}", st.len());
    //     // send_end(&mut channel);
    //     // let vec = read_data(&mut channel).unwrap();
    //     // println!("{}", String::from_utf8(vec).unwrap());
    //     // send_end(&mut channel);
    //     // let mut st = vec![];
    //     // loop {
    //     //     let mut vec = read_data(&mut channel).unwrap();
    //     //     if &vec[vec.len() - 1] == &0 {
    //     //         vec.remove(vec.len() - 1);
    //     //         st.append(&mut vec);
    //     //         break;
    //     //     }
    //     //     st.append(&mut vec);
    //     // }
    //     // println!("st len  = {}", st.len());
    //     //
    //     // send_end(&mut channel);
    //     //
    //     // let vec = read_data(&mut channel).unwrap();
    //     // println!("{}", String::from_utf8(vec).unwrap());
    //     //
    //     // send_end(&mut channel);
    //     // let vec = read_data(&mut channel).unwrap();
    // }

    // #[test]
    // fn testf() {
    //     let result = fs::metadata("/Users/gaoxiangkang/Desktop/test/test.txt")
    //         .unwrap();
    //     let i = result.as_inner();
    //     let x = i.as_inner();
    //     let a = unsafe {
    //         &x as *const stat as *mut stat
    //     };
    //     a.st_mtime = 0;
    //     // let x = result.as_raw_stat();
    //     // unsafe {
    //     //     let mut a = (&x.st_mtime as *const c_long as *mut c_long);
    //     //     println!("{:p}", a);
    //     //
    //     // }
    // }

    #[test]
    fn test3() {
        let ssh: SSH = SSH::new();
        let mut session = ssh.get_session("47.105.46.145:22").unwrap();
        session.set_nonblocking(true).unwrap();
        session.set_user_and_password("root".to_string(), "Gaoxiangkang@123".to_string());
        session.connect().unwrap();
        let mut channel = session.open_channel().unwrap();
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(channel.server_channel)
            .put_str(strings::EXEC)
            .put_u8(true as u8)
            .put_bytes(b"scp -f -r -q -p /opt/blogs");
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client().unwrap();
        client.write(packet.as_slice()).unwrap();
        util::unlock(client);
        send_end(&mut channel);

        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();
        println!("{:?}", string);
        // let (modify_time, access_time) = file_time(vec).unwrap();
        // println!("modify_time => {}, access_time => {}", modify_time, access_time);
        send_end(&mut channel);

        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();
        let file_info = string.trim();
        let split = file_info.split(" ").collect::<Vec<&str>>();
        println!("{:?}", split);
        send_end(&mut channel);

        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();

        println!("{:?}", string);

        send_end(&mut channel);

        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();

        println!("{:?}", string);

        send_end(&mut channel);
        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();

        println!("{:?}", string);

        send_end(&mut channel);
        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();

        println!("{:?}", string);

        send_end(&mut channel);
        let vec = read_data(&mut channel).unwrap();

        send_end(&mut channel);
        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();

        println!("{:?}", string);

        send_end(&mut channel);
        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();

        println!("{:?}", string);

        send_end(&mut channel);
        let vec = read_data(&mut channel).unwrap();
        let string = util::from_utf8(vec).unwrap();

        println!("{:?}", string);

        // send_end(&mut channel);
        //
        // let vec = read_data(&mut channel).unwrap();

        //
        // let permissions = split.get(0).unwrap_or(&"C0644").to_string();
        // let size_str = split.get(1).unwrap_or(&"0");
        // let size = util::str_to_u32(size_str).unwrap();
        // let name = split.get(2).unwrap_or(&"").to_string();
        //
        // let local_path = PathBuf::from("/Users/gaoxiangkang/Desktop/test/");
        //
        // let path = local_path.join(name);
        // if path.exists() {
        //     fs::remove_file(path.as_path());
        // }
        // let mut file = match OpenOptions::new()
        //     .create(true)
        //     .write(true)
        //     .append(true)
        //     .open(path.as_path()) {
        //     Ok(v) => v,
        //     Err(e) => {
        //         log::info!("file processing error, error info: {}", e);
        //         panic!("ssss")
        //     }
        // };
        //
        // send_end(&mut channel);
        //
        // loop {
        //     let data = read_data(&mut channel).unwrap();
        //     if data.is_empty() { continue }
        //     if &data[data.len() - 1] == &0 {
        //         file.write(&data[..(data.len() - 1)]).unwrap();
        //         break;
        //     }
        //     file.write(&data).unwrap();
        // }
        //
        // let modify_time = filetime::FileTime::from_unix_time(modify_time as i64, 0);
        // let access_time = filetime::FileTime::from_unix_time(access_time as i64, 0);
        //
        // filetime::set_file_times(path.as_path(), access_time, modify_time);
        //
        // if cfg!(unix) {
        //     use std::os::unix::fs::PermissionsExt;
        //     let mode_str = permissions.replace("C", "");
        //     let mode = u32::from_str_radix(&mode_str, 8).unwrap();
        //     file.set_permissions(Permissions::from_mode(mode)).unwrap();
        // }
        //
        // send_end(&mut channel);
        // println!("sss");
        // read_data(&mut channel).unwrap();
        // let mut st = vec![];
        // loop {
        //     let mut vec = read_data(&mut channel).unwrap();
        //     if &vec[vec.len() - 1] == &0 {
        //         vec.remove(vec.len() - 1);
        //         st.append(&mut vec);
        //         break;
        //     }
        //     st.append(&mut vec);
        // }
        // println!("st len  = {}", st.len());
        // send_end(&mut channel);
        // let vec = read_data(&mut channel).unwrap();
        // println!("{}", String::from_utf8(vec).unwrap());
    }

    fn file_time(v: Vec<u8>) -> SshResult<(u32, u32)> {
        let mut t = vec![];
        for x in v {
            if x == 'T' as u8
                || x == 32
                || x == 10 {
                continue
            }
            t.push(x)
        }
        let a = t.len() / 2;
        let ct = util::from_utf8((&t[..(a - 1)]).to_vec())?;
        let ut = util::from_utf8((&t[a..(t.len() -1)]).to_vec())?;
        Ok((util::str_to_u32(&ct)?, util::str_to_u32(&ut)?))
    }

    fn send_end(channel: &mut Channel) {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(channel.server_channel)
            .put_bytes(&[0]);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client().unwrap();
        client.write(packet.as_slice()).unwrap();
    }

    fn read_data(channel: &mut Channel) -> SshResult<Vec<u8>> {
        let mut v = vec![];
        loop {
            if !v.is_empty() { break }
            let mut client = util::client().unwrap();
            let results = client.read().unwrap();
            util::unlock(client);
            for buf in results {
                let message_code = buf[5];
                match message_code {
                    message::SSH_MSG_CHANNEL_DATA => {
                        let mut data = Packet::processing_data(buf);
                        data.get_u8();
                        data.get_u32();
                        v.extend(data.get_u8s())
                    }
                    message::SSH_MSG_CHANNEL_CLOSE => {
                        channel.remote_close = true;
                        channel.close();
                        return Ok(v)
                    }
                    _ => channel.other(message_code, buf).unwrap()
                }
            }
        }
        Ok(v)
    }

    fn check_ack(byte: u8) -> bool {
       return byte != 1 && byte != 2
    }
}
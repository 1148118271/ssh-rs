// #[cfg(test)]
// mod tests {
//     use std::{fs, os};
//     use std::fs::{File, OpenOptions, Permissions, read_dir};
//     use std::io::{Read, Write};
//     use std::os::unix::fs::MetadataExt;
//     use std::path::{Path, PathBuf};
//     use std::process::exit;
//     use std::str::FromStr;
//     use std::string::FromUtf8Error;
//     use std::sync::atomic::Ordering::Relaxed;
//     use filetime::{FileTime, set_file_times};
//     use crate::packet::{Data, Packet};
//     use crate::{Channel, global, message, scp_flag, SSH, SshError, strings, util};
//     use crate::channel::ChannelWindowSize;
//     use crate::error::{SshErrorKind, SshResult};
//
//
//     #[test]
//     fn test1() {
//
//         let size = 2097152;
//
//         let s1 = 102526;
//
//
//         let s2 = 1994626;
//         let s3 = 1994628;
//
//
//         println!("{}", size & s2);
//
//
//         // let ssh: SSH = SSH::new();
//         // let mut session = ssh.get_session("127.0.0.1：22").unwrap();
//         // session.set_nonblocking(true).unwrap();
//         // session.set_user_and_password("ubuntu", "123456");
//         // session.connect().unwrap();
//         // let mut scp = session.open_scp().unwrap();
//         // scp.upload("/Users/gaoxiangkang/Goland", "/opt/test").unwrap();
//     }
//
//
//     fn t1(buf: PathBuf, channel: &mut Channel) {
//         let mut packet = Packet::new();
//         // 发送时间
//         let time = "T1647767946 0 1647767946 0\n";
//
//         let mut data = Data::new();
//         data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//             .put_u32(channel.server_channel)
//             .put_str(time);
//         packet.put_data(data);
//         packet.build();
//
//         let mut client = util::client().unwrap();
//         client.write(packet.as_slice()).unwrap();
//         util::unlock(client);
//
//         // 接收返回码
//         let vec = read_data(channel).unwrap();
//         println!("code : {}", &vec[0]);
//
//         if buf.is_dir() {
//             // 发送文件夹
//             let file_info = format!("D0755 0 {}\n", buf.file_name().unwrap().to_str().unwrap());
//             println!("{}", buf.to_str().unwrap().to_string());
//             let mut data = Data::new();
//             data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//                 .put_u32(channel.server_channel)
//                 .put_str(file_info.as_str());
//             packet.put_data(data);
//             packet.build();
//
//             let mut client = util::client().unwrap();
//             client.write(packet.as_slice()).unwrap();
//             util::unlock(client);
//
//             // 接收返回码
//             let vec = read_data(channel).unwrap();
//             println!("code : {}", &vec[0]);
//             let mut count = 0;
//             for x in read_dir(buf).unwrap() {
//                 count = count + 1;
//                 let buf1 = x.unwrap().path();
//                 t1(buf1, channel);
//             }
//             println!("=>>>>>>EDN");
//             let mut data = Data::new();
//             data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//                 .put_u32(channel.server_channel)
//                 .put_bytes(&[scp_flag::E as u8, b'\n']);
//             packet.put_data(data);
//             packet.build();
//
//             let mut client = util::client().unwrap();
//             client.write(packet.as_slice()).unwrap();
//             util::unlock(client);
//
//             // 接收返回码
//             let vec = read_data(channel).unwrap();
//             println!("code : {}", &vec[0]);
//         } else {
//             let file_info = format!("C0644 0 {}\n", buf.file_name().unwrap().to_str().unwrap());
//             println!("{}", buf.to_str().unwrap().to_string());
//             let mut data = Data::new();
//             data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//                 .put_u32(channel.server_channel)
//                 .put_str(file_info.as_str());
//             packet.put_data(data);
//             packet.build();
//
//             let mut client = util::client().unwrap();
//             client.write(packet.as_slice()).unwrap();
//             util::unlock(client);
//
//             let mut data = Data::new();
//             data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//                 .put_u32(channel.server_channel)
//                 .put_bytes(&[0]);
//             packet.put_data(data);
//             packet.build();
//
//             let mut client = util::client().unwrap();
//             client.write(packet.as_slice()).unwrap();
//             util::unlock(client);
//
//
//             // 接收返回码
//             let vec = read_data(channel).unwrap();
//             println!("code : {:?}", &vec[0]);
//             //println!("msg : {}", String::from_utf8(vec).unwrap());
//         }
//     }
//
//     #[test]
//     fn test() {
//         let ssh: SSH = SSH::new();
//         let mut session = ssh.get_session("127.0.0.1:22").unwrap();
//         session.set_nonblocking(true).unwrap();
//         session.set_user_and_password("ubuntu", "123456");
//         session.connect().unwrap();
//         let mut channel = session.open_channel().unwrap();
//         let mut data = Data::new();
//         data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
//             .put_u32(channel.server_channel)
//             .put_str(strings::EXEC)
//             .put_u8(true as u8)
//             .put_bytes(b"scp -t -r -q -p /opt/test");
//         let mut packet = Packet::from(data);
//         packet.build();
//         let mut client = util::client().unwrap();
//         client.write(packet.as_slice()).unwrap();
//         util::unlock(client);
//
//
//         // 接收返回码
//         let vec = read_data(&mut channel).unwrap();
//         println!("code : {}", &vec[0]);
//
//         t1(PathBuf::from("/Users/gaoxiangkang/zig"), &mut channel);
//
//         // // 发送时间
//         // let time = "T1647767946 0 1647767946 0\n";
//         //
//         // let mut data = Data::new();
//         // data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//         //     .put_u32(channel.server_channel)
//         //     .put_str(time);
//         // packet.put_data(data);
//         // packet.build();
//         //
//         // let mut client = util::client().unwrap();
//         // client.write(packet.as_slice()).unwrap();
//         // util::unlock(client);
//         //
//         //
//         // // 发送文件夹
//         // let file_info = format!("D0755 0 gxk\n");
//         // let mut data = Data::new();
//         // data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//         //     .put_u32(channel.server_channel)
//         //     .put_str(file_info.as_str());
//         // packet.put_data(data);
//         // packet.build();
//         //
//         // let mut client = util::client().unwrap();
//         // client.write(packet.as_slice()).unwrap();
//         // util::unlock(client);
//         //
//         // // 接收返回码
//         // let vec = read_data(&mut channel).unwrap();
//         // println!("code : {}", &vec[0]);
//         //
//         //
//         // let mut data = Data::new();
//         // data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//         //     .put_u32(channel.server_channel)
//         //     .put_bytes(&[scp_flag::E, b'\n']);
//         // packet.put_data(data);
//         // packet.build();
//         //
//         // let mut client = util::client().unwrap();
//         // client.write(packet.as_slice()).unwrap();
//         // util::unlock(client);
//         //
//         // // 发送时间
//         // let time = "T1647767946 0 1647767946 0\n";
//         // // [84, 49, 54, 53, 49, 54, 53, 50, 55, 53, 49, 32, 48, 32, 49, 54, 53, 49, 54, 54, 48, 54, 52, 49, 32, 48, 10]
//         // // [84, 49, 54, 53, 49, 54, 53, 50, 55, 53, 49, 32, 48, 32, 49, 54, 53, 49, 54, 54, 48, 54, 52, 49, 32, 48, 10]
//         // println!("t {:?}", time.as_bytes());
//         //
//         // let mut data = Data::new();
//         // data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//         //     .put_u32(channel.server_channel)
//         //     .put_str(time);
//         // packet.put_data(data);
//         // packet.build();
//         //
//         // let mut client = util::client().unwrap();
//         // client.write(packet.as_slice()).unwrap();
//         // util::unlock(client);
//         //
//         //
//         //
//         // // 接收返回码
//         // let vec = read_data(&mut channel).unwrap();
//         // println!("code : {}", &vec[0]);
//         //
//         // // 发送文件
//         // let mut file = File::open("/Users/gaoxiangkang/sql.sql").unwrap();
//         // let metadata = file.metadata().unwrap();
//         //
//         // let file_info = format!("C0644 {} anime.min.js\n", metadata.size());
//         // println!("file_info = {}", file_info);
//         // let mut data = Data::new();
//         // data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//         //     .put_u32(channel.server_channel)
//         //     .put_str(file_info.as_str());
//         // packet.put_data(data);
//         // packet.build();
//         //
//         // let mut client = util::client().unwrap();
//         // client.write(packet.as_slice()).unwrap();
//         // util::unlock(client);
//         //
//         //
//         // // 接收返回码
//         // let vec = read_data(&mut channel).unwrap();
//         // println!("code : {}", &vec[0]);
//         // let string = util::from_utf8((&vec[1..]).to_vec()).unwrap();
//         // println!("{:?}", string);
//         //
//         //
//         // // 发送文件详情
//         // let mut buf = [0; 1024 * 2];
//         // let mut v = vec![];
//         // loop {
//         //     let len = file.read(&mut buf).unwrap();
//         //     if len <= 0  {
//         //         break;
//         //     }
//         //     v.extend(&buf[..len])
//         //
//         // }
//         // v.truncate(v.len());
//         // v.extend_from_slice(&[0]);
//         // let mut data = Data::new();
//         // data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//         //     .put_u32(channel.server_channel)
//         //     .put_bytes(&v);
//         // packet.put_data(data);
//         // packet.build();
//         //
//         // let mut client = util::client().unwrap();
//         // client.write(packet.as_slice()).unwrap();
//         // util::unlock(client);
//         //
//         // let vec = read_data(&mut channel).unwrap();
//         // let string = util::from_utf8(vec).unwrap();
//         // println!("{:?}", string);
//         //
//         // // 发送结束
//         // send_end(&mut channel);
//         // let vec = read_data(&mut channel).unwrap();
//         // let string = util::from_utf8(vec).unwrap();
//         // println!("{:?}", string);
//         // let vec = read_data(&mut channel).unwrap();
//         // let string = util::from_utf8(vec).unwrap();
//         // println!("{:?}", string);
//         //
//         // let vec = read_data(&mut channel).unwrap();
//         // let string = util::from_utf8(vec).unwrap();
//         // println!("{:?}", string);
//         channel.close().unwrap();
//
//     }
//
//
//     #[test]
//     fn test3() {
//         let ssh: SSH = SSH::new();
//         let mut session = ssh.get_session("127.0.0.1:22").unwrap();
//         session.set_nonblocking(true).unwrap();
//         session.set_user_and_password("ubuntu", "123456");
//         session.connect().unwrap();
//         let mut channel = session.open_channel().unwrap();
//         let mut data = Data::new();
//         data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
//             .put_u32(channel.server_channel)
//             .put_str(strings::EXEC)
//             .put_u8(true as u8)
//             .put_bytes(b"scp -f -r -q -p /opt/test");
//         let mut packet = Packet::from(data);
//         packet.build();
//         let mut client = util::client().unwrap();
//         client.write(packet.as_slice()).unwrap();
//         util::unlock(client);
//         send_end(&mut channel);
//
//         let vec = read_data(&mut channel).unwrap();
//         println!("{:?}", vec);
//         let string = util::from_utf8(vec).unwrap();
//         println!("{:?}", string);
//
//         // let (modify_time, access_time) = file_time(vec).unwrap();
//         // println!("modify_time => {}, access_time => {}", modify_time, access_time);
//         send_end(&mut channel);
//         //
//         let vec = read_data(&mut channel).unwrap();
//         let string = util::from_utf8(vec).unwrap();
//         println!("{:?}", string);
//         send_end(&mut channel);
//
//         let vec = read_data(&mut channel).unwrap();
//         let string = util::from_utf8(vec).unwrap();
//
//         println!("{:?}", string);
//
//         send_end(&mut channel);
//
//         let vec = read_data(&mut channel).unwrap();
//         let string = util::from_utf8(vec).unwrap();
//
//         println!("{:?}", string);
//
//         send_end(&mut channel);
//
//         let vec = read_data(&mut channel).unwrap();
//         let string = util::from_utf8(vec).unwrap();
//
//         println!("{:?}", string);
//
//     }
//
//     fn file_time(v: Vec<u8>) -> SshResult<(u32, u32)> {
//         let mut t = vec![];
//         for x in v {
//             if x == 'T' as u8
//                 || x == 32
//                 || x == 10 {
//                 continue
//             }
//             t.push(x)
//         }
//         let a = t.len() / 2;
//         let ct = util::from_utf8((&t[..(a - 1)]).to_vec())?;
//         let ut = util::from_utf8((&t[a..(t.len() -1)]).to_vec())?;
//         Ok((util::str_to_u32(&ct)?, util::str_to_u32(&ut)?))
//     }
//
//     fn send_end(channel: &mut Channel) {
//         let mut data = Data::new();
//         data.put_u8(message::SSH_MSG_CHANNEL_DATA)
//             .put_u32(channel.server_channel)
//             .put_bytes(&[0]);
//         let mut packet = Packet::from(data);
//         packet.build();
//         let mut client = util::client().unwrap();
//         client.write(packet.as_slice()).unwrap();
//     }
//
//     fn read_data(channel: &mut Channel) -> SshResult<Vec<u8>> {
//         let mut v = vec![];
//         loop {
//             if !v.is_empty() { break }
//             let mut client = util::client().unwrap();
//             let results = client.read().unwrap();
//             util::unlock(client);
//             for mut buf in results {
//                 let message_code = buf.get_u8();
//                 match message_code {
//                     message::SSH_MSG_CHANNEL_DATA => {
//                         buf.get_u32();
//                         v.extend(buf.get_u8s())
//                     },
//                     message::SSH_MSG_CHANNEL_CLOSE => {
//                         channel.remote_close = true;
//                         channel.close();
//                         println!("close");
//                         return Ok(v)
//                     }
//                     _ => channel.other(message_code, buf).unwrap()
//                 }
//             }
//         }
//         Ok(v)
//     }
//
//     fn check_ack(byte: u8) -> bool {
//         return byte != 1 && byte != 2
//     }
// }

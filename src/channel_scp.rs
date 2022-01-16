// use std::fs::File;
// use std::io::Write;
// use std::sync::LockResult;
// use crate::{Channel, message, scp_arg, SshError, strings};
// use crate::error::{SshErrorKind, SshResult};
// use crate::packet::{Data, Packet};
//
// pub struct ChannelScp {
//     pub(crate) channel: Channel,
//     pub(crate) is_dir: bool,
//     pub(crate) is_preserve_times: bool,
// }
//
// impl ChannelScp {
//
//     pub fn download(&mut self, local_path: &str, remote_path: &str) -> SshResult<()> {
//         check_path(remote_path)?;
//         check_path(local_path)?;
//         self.exec_scp(self.download_command_init(remote_path).as_str());
//         loop {
//             let results = self.read()?;
//         }
//     }
//
//
//     fn process(&mut self, results: Vec<Vec<u8>>) {
//         let mut vec = vec![];
//         for result in results {
//             if result.is_empty() { continue; }
//             let message_code = result[5];
//             match message_code {
//                 message::SSH_MSG_CHANNEL_DATA => {
//                     let mut data = Packet::processing_data(buf);
//                     data.get_u8();
//                     let cc = data.get_u32();
//                     if cc == self.channel.client_channel {
//                         vec.extend(data.get_u8s())
//                     }
//                 }
//                 message::SSH_MSG_CHANNEL_CLOSE => {
//                     let mut data = Packet::processing_data(buf);
//                     data.get_u8();
//                     let cc = data.get_u32();
//                     if cc == self.channel.client_channel {
//                         self.channel.remote_close = true;
//                         self.channel.close()
//                     }
//                 }
//                 _ => self.channel.other_info(message_code, result)?
//             }
//         }
//     }
//
//     fn close() {
//
//     }
//
//     // fn read_data(&mut self) -> SshResult<Vec<u8>> {
//     //     let mut vec = vec![];
//     //     loop {
//     //
//     //         for result in results {
//     //             let message_code = result[5];
//     //             match message_code {
//     //                 message::SSH_MSG_CHANNEL_DATA => {
//     //                     let mut data = Packet::processing_data(buf);
//     //                     data.get_u8();
//     //                     let cc = data.get_u32();
//     //                     if cc == self.channel.client_channel {
//     //                         vec.extend(data.get_u8s())
//     //                     }
//     //                 }
//     //                 message::SSH_MSG_CHANNEL_CLOSE => {
//     //                     let mut data = Packet::processing_data(buf);
//     //                     data.get_u8();
//     //                     let cc = data.get_u32();
//     //                     if cc == self.channel.client_channel {
//     //                         self.channel.close();
//     //                         return Ok(vec)
//     //                     }
//     //                 }
//     //                 _ => self.channel.other_info(message_code, result).unwrap()
//     //             }
//     //         }
//     //     }
//     // }
//
//     fn exec_scp(&mut self, command: &str) -> SshResult<()> {
//         let mut data = Data::new();
//         data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
//             .put_u32(self.channel.server_channel)
//             .put_str(strings::EXEC)
//             .put_u8(true as u8)
//             .put_str(command);
//         let mut packet = Packet::from(data);
//         packet.build();
//         self.channel.write(packet.as_slice())
//     }
//
//     fn download_command_init(&self, remote_path: &str) -> String {
//         let mut cmd = format!(
//             "{} {} {}",
//             strings::SCP,
//             scp_arg::SOURCE,
//             scp_arg::QUIET,
//         );
//         if self.is_dir {
//             cmd.push_str(" ");
//             cmd.push_str(scp_arg::RECURSIVE)
//         }
//         if self.is_preserve_times {
//             cmd.push_str(" ");
//             cmd.push_str(scp_arg::PRESERVE_TIMES)
//         }
//         cmd.push_str(" ");
//         cmd.push_str(remote_path);
//         cmd
//     }
//
// }
//
//
// fn check_path(path: &str) -> SshResult<()> {
//     match path.is_empty() {
//         true => Err(SshError::from(SshErrorKind::PathNullError)),
//         false => Ok(())
//     }
// }
//
// fn check_ack(byte: u8) {
//     match byte {
//
//         _ => {}
//     }
// }
//
// pub struct ScpFile {
//     create_time: u32,
//     modify_time: u32,
//     permissions: String,
//     size: u32,
//     name: String,
//     is_dir: bool,
// }
//
// impl ScpFile {
//     fn new() -> Self {
//         ScpFile {
//             create_time: 0,
//             modify_time: 0,
//             size: 0,
//             permissions: String::new(),
//             name: String::new(),
//             is_dir: false,
//         }
//     }
//
//     fn is_null(&self) -> bool {
//         return self.create_time == 0
//             && self.modify_time == 0
//             && self.size == 0
//             && self.permissions.is_empty()
//             && self.name.is_empty()
//             && self.is_dir == false
//     }
// }
//

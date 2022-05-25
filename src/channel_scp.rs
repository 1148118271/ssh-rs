use std::borrow::BorrowMut;
use std::ffi::OsStr;
use std::fs;
use std::fs::{File, metadata, OpenOptions, read_dir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use constant::{permission, scp, ssh_msg_code, ssh_str};
use packet::Data;
use error::{SshErrorKind, SshResult, SshError};
use slog::log;
use crate::{util, Channel, client};



pub struct ChannelScp {
    pub(crate) channel: Channel,
    pub(crate) local_path: PathBuf,
}


// fn t1(buf: PathBuf) {
//     if buf.is_dir() {
//         println!("{}", buf.to_str().unwrap() );
//         for x in read_dir(buf).unwrap() {
//             let buf1 = x.unwrap().path();
//             t1(buf1);
//         }
//         println!(">>>>> EDN <<<<<");
//     } else {
//         println!("{}", buf.to_str().unwrap() );
//     }
//
// }
//
// #[test] fn t() {
//     let root_path = "/Users/gaoxiangkang/Goland";
//     let mut this_path = root_path;
//     let mut buf = PathBuf::from(this_path);
//     t1(buf);
//     // println!("{}", buf.to_str().unwrap() );
//
// }

impl ChannelScp {


    pub(crate) fn open(channel: Channel) -> Self {
        ChannelScp {
            channel,
            local_path: Default::default(),
        }
    }


    // pub fn upload<S: AsRef<OsStr> + ?Sized>(&mut self, local_path: &S, remote_path: &S) -> SshResult<()> {
    //     let local_path = Path::new(local_path);
    //     let remote_path = Path::new(remote_path);
    //
    //     check_path(local_path)?;
    //     check_path(remote_path)?;
    //
    //     let remote_path_str = remote_path.to_str().unwrap();
    //
    //     self.exec_scp(self.upload_command_init(remote_path_str).as_str())?;
    //     self.get_end()?;
    //     let mut scp_file = ScpFile::new();
    //     scp_file.local_path = local_path.to_path_buf();
    //     self.file_all(&mut scp_file)?;
    //     self.channel.close();
    //     Ok(())
    // }
    //
    //
    // fn file_all(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
    //     println!("buf ---> {}", scp_file.local_path.to_str().unwrap());
    //     scp_file.name = scp_file.local_path.file_name().unwrap().to_str().unwrap().to_string();
    //     self.send_time(scp_file)?;
    //     if scp_file.local_path.is_dir() {
    //         self.send_dir(scp_file)?;
    //         for p in read_dir(scp_file.local_path.as_path()).unwrap() {
    //             let buf1 = p.unwrap().path();
    //             scp_file.local_path = buf1.clone();
    //             self.file_all(scp_file);
    //         }
    //         println!("=>>>>>>EDN");
    //         self.send_bytes(&[scp::E as u8, b'\n']).unwrap();
    //         self.get_end().unwrap();
    //     } else {
    //         scp_file.size = scp_file.local_path.as_path().metadata()?.len();
    //         self.send_file(scp_file);
    //     }
    //     Ok(())
    // }
    //
    //
    // fn send_file(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
    //     let cmd = format!("C0{} {} {}\n", permission::FILE, scp_file.size, scp_file.name);
    //     self.send(&cmd)?;
    //     self.get_end()?;
    //     let mut file = File::open(scp_file.local_path.as_path()).unwrap();
    //     let mut count = 0;
    //     loop {
    //         let mut s = [0u8; 20480];
    //         let i = file.read(&mut s).unwrap();
    //         count = count + i;
    //         self.send_bytes(&s[..i]).unwrap();
    //         println!("count = {}, size = {}", count, scp_file.size);
    //         if count == scp_file.size as usize {
    //             println!("end 0");
    //             self.send_bytes(&[0]).unwrap();
    //             break
    //         }
    //     }
    //     println!("b end");
    //     self.get_end().unwrap();
    //     Ok(())
    // }
    //
    // fn send_dir(&mut self, scp_file: &ScpFile) -> SshResult<()> {
    //     let cmd = format!("D0{} 0 {}\n", permission::DIR, scp_file.name);
    //     self.send(&cmd)?;
    //     self.get_end()
    // }
    //
    //
    // fn send_time(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
    //     self.get_time(scp_file)?;
    //     // "T1647767946 0 1647767946 0\n";
    //     let cmd = format!("T{} 0 {} 0\n", scp_file.modify_time, scp_file.access_time);
    //     self.send(&cmd)?;
    //     self.get_end()
    // }
    //
    //
    //
    // fn get_time(&self, scp_file: &mut ScpFile) -> SshResult<()> {
    //     println!("{:?}", scp_file.local_path.as_path());
    //     let metadata = metadata(scp_file.local_path.as_path()).unwrap();
    //     // 最后修改时间
    //     let modified_time = match metadata.modified() {
    //         Ok(t) => t,
    //         Err(_) => SystemTime::now(),
    //     };
    //     let modified_time = match modified_time.duration_since(UNIX_EPOCH) {
    //         Ok(t) => t.as_secs(),
    //         Err(e) => {
    //             return Err(SshError::from(
    //                 SshErrorKind::UnknownError(
    //                     format!("SystemTimeError difference: {:?}", e.duration()))))
    //         }
    //     };
    //
    //     // 最后访问时间
    //     let accessed_time = match metadata.accessed() {
    //         Ok(t) => t,
    //         Err(_) => SystemTime::now(),
    //     };
    //     let accessed_time = match accessed_time.duration_since(UNIX_EPOCH) {
    //         Ok(d) => d.as_secs(),
    //         Err(e) => {
    //             return Err(SshError::from(
    //                         SshErrorKind::UnknownError(
    //                             format!("SystemTimeError difference: {:?}", e.duration()))))
    //         }
    //     };
    //     scp_file.modify_time = modified_time as i64;
    //     scp_file.access_time = accessed_time as i64;
    //     Ok(())
    // }
    //
    // fn get_end(&mut self) -> SshResult<()> {
    //     let vec = self.read_data()?;
    //     println!("code: {:?}", *&vec[0]);
    //     match *&vec[0] {
    //         scp::END => Ok(()),
    //         // error
    //         scp::ERR | scp::FATAL_ERR => {
    //             let s = util::from_utf8(vec).unwrap();
    //             println!("err {}", s);
    //             Err(SshError::from(SshErrorKind::ScpError(s)))
    //         },
    //         _ => Err(SshError::from(SshErrorKind::ScpError("unknown error.".to_string())))
    //     }
    // }
    //
    // fn upload_command_init(&self, remote_path: &str) -> String {
    //     // let mut cmd = format!(
    //     //     "{} {} {} {}",
    //     //     strings::SCP,
    //     //     scp::SINK,
    //     //     scp::QUIET,
    //     //     scp::RECURSIVE
    //     // );
    //     // let mut cmd = format!(
    //     //     "{} {} {} {}",
    //     //     strings::SCP,
    //     //     scp::SINK,
    //     //     scp::QUIET,
    //     //     scp::RECURSIVE
    //     // );
    //     // if self.is_sync_permissions {
    //     //     cmd.push_str(" ");
    //     //     cmd.push_str(scp::PRESERVE_TIMES)
    //     // }
    //     let mut cmd = String::new();
    //     cmd.push_str("scp -t -r -q -p ");
    //     cmd.push_str(remote_path);
    //     cmd
    // }



    pub(crate) fn send_str(&mut self, cmd: &str) -> SshResult<()> {
        self.send_bytes(cmd.as_bytes())
    }

    pub(crate) fn send_end(&mut self) -> SshResult<()> {
        self.send_bytes(&[scp::END])
    }

    pub(crate) fn send_bytes(&mut self, bytes: &[u8]) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.channel.server_channel)
            .put_u8s(bytes);
        let client = client::default()?;
        client.write_data(data, Some(self.channel.window_size.borrow_mut()))
    }

    pub(crate) fn read_data(&mut self) -> SshResult<Vec<u8>> {
        let mut vec = vec![];
        loop {
            if !vec.is_empty() { break }
            let client = client::default()?;
            let results = client.read_data(Some(self.channel.window_size.borrow_mut()))?;

            for mut result in results {
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_CHANNEL_DATA => {
                        let cc = result.get_u32();
                        if cc == self.channel.client_channel {
                            vec.extend(result.get_u8s())
                        }
                    }
                    ssh_msg_code::SSH_MSG_CHANNEL_CLOSE => {
                        let cc = result.get_u32();
                        if cc == self.channel.client_channel {
                            self.channel.remote_close = true;
                            self.channel.close()?;
                            return Ok(vec)
                        }
                    },
                    _ => self.channel.other(message_code, result)?
                }
            }
        }
        Ok(vec)
    }

    pub(crate) fn exec_scp(&mut self, command: &str) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.channel.server_channel)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        let client = client::default()?;
        client.write(data)
    }

    pub(crate) fn command_init(&self, remote_path: &str, arg: &str) -> String {
        format!(
            "{} {} {} {} {} {}",
            ssh_str::SCP,
            arg,
            scp::QUIET,
            scp::RECURSIVE,
            scp::PRESERVE_TIMES,
            remote_path
        )
    }
}


pub(crate) fn check_path(path: &Path) -> SshResult<()> {
    if let None = path.to_str() {
        return Err(SshError::from(SshErrorKind::PathNullError))
    }
    Ok(())
}


pub struct ScpFile {
    pub(crate) modify_time: i64,
    pub(crate) access_time: i64,
    pub(crate) size: u64,
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    pub(crate) local_path: PathBuf,
}

impl ScpFile {
    pub(crate) fn new() -> Self {
        ScpFile {
            modify_time: 0,
            access_time: 0,
            size: 0,
            name: String::new(),
            is_dir: false,
            local_path: Default::default(),
        }
    }
}



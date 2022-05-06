use std::ffi::OsStr;
use std::fs;
use std::fs::{File, metadata, OpenOptions, Permissions};
use std::io::Write;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::ptr::read;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use crate::{Channel, message, permission, scp_arg, scp_flag, SshError, strings, util};
use crate::error::{SshErrorKind, SshResult};
use crate::packet::{Data, Packet};

pub struct ChannelScp {
    pub(crate) channel: Channel,
    pub(crate) local_path: PathBuf,
    pub(crate) is_sync_permissions: bool,

}

#[test] fn t() {
    println!("{}", u32::from_str_radix("775", 8).unwrap());

}

impl ChannelScp {

    pub fn upload<S: AsRef<OsStr> + ?Sized>(&mut self, local_path: &S, remote_path: &S) -> SshResult<()> {
        let local_path = Path::new(local_path);
        let remote_path = Path::new(remote_path);

        check_path(local_path)?;
        check_path(remote_path)?;

        let local_path_str = local_path.to_str().unwrap();
        let remote_path_str = remote_path.to_str().unwrap();

        self.local_path = local_path.to_path_buf();

        self.exec_scp(self.upload_command_init(remote_path_str).as_str())?;

        let mut scp_file = ScpFile::new();

        scp_file.local_path = local_path.to_path_buf();



        Ok(())
    }


    fn process_u(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        loop {
            let data = self.read_data()?;
            match *&data[0] {
                scp_flag::END => {
                    match scp_file.local_path.is_dir() {
                        true => {}
                        false => {}
                    }
                },
                // error
                scp_flag::ERR | scp_flag::FATAL_ERR =>
                    return Err(SshError::from(SshErrorKind::ScpError(util::from_utf8(data)?))),
                _ => return Err(SshError::from(SshErrorKind::ScpError("unknown error.".to_string())))
            }
        }
    }

    fn process_dir_u(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        if self.is_sync_permissions && !cfg!(windows) {
            self.send_time(scp_file)?
        }


        Ok(())
    }


    fn send_time(&self, scp_file: &mut ScpFile) -> SshResult<()> {
        self.get_time(scp_file)?;
        // "T1647767946 0 1647767946 0\n";
        let cmd = format!("T{} 0 {}\n", scp_file.modify_time, scp_file.access_time);
        self.send(&cmd);
        Ok(())
    }

    fn get_time(&self, scp_file: &mut ScpFile) -> SshResult<()> {
        let metadata = metadata(scp_file.local_path.as_path())?;
        // 最后修改时间
        let modified_time = match metadata.modified() {
            Ok(t) => t,
            Err(_) => SystemTime::now(),
        };
        let modified_time = match modified_time.duration_since(UNIX_EPOCH) {
            Ok(t) => t.as_secs(),
            Err(e) => {
                return Err(SshError::from(
                    SshErrorKind::UnknownError(
                        format!("SystemTimeError difference: {:?}", e.duration()))))
            }
        };

        // 最后访问时间
        let accessed_time = match metadata.accessed() {
            Ok(t) => t,
            Err(_) => SystemTime::now(),
        };
        let accessed_time = match accessed_time.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                return Err(SshError::from(
                            SshErrorKind::UnknownError(
                                format!("SystemTimeError difference: {:?}", e.duration()))))
            }
        };
        scp_file.modify_time = modified_time as i64;
        scp_file.access_time = accessed_time as i64;
        Ok(())
    }


    fn upload_command_init(&self, remote_path: &str) -> String {
        let mut cmd = format!(
            "{} {} {} {}",
            strings::SCP,
            scp_arg::SOURCE,
            scp_arg::QUIET,
            scp_arg::RECURSIVE
        );
        if self.is_sync_permissions && !cfg!(windows) {
            cmd.push_str(" ");
            cmd.push_str(scp_arg::PRESERVE_TIMES)
        }
        cmd.push_str(" ");
        cmd.push_str(remote_path);
        cmd
    }

    pub fn download<S: AsRef<OsStr> + ?Sized>(&mut self, local_path: &S, remote_path: &S) -> SshResult<()> {
        let local_path = Path::new(local_path);
        let remote_path = Path::new(remote_path);

        check_path(local_path)?;
        check_path(remote_path)?;

        let local_path_str = local_path.to_str().unwrap();
        let remote_path_str = remote_path.to_str().unwrap();

        self.local_path = local_path.to_path_buf();

        log::info!("start to synchronize files, \
        remote [{}] files will be synchronized to the local [{}] folder.", remote_path_str, local_path_str);

        self.exec_scp(self.download_command_init(remote_path_str).as_str())?;
        let mut scp_file = ScpFile::new();
        scp_file.local_path = self.local_path.clone();
        self.process_d(&mut scp_file)?;
        Ok(())
    }

    /// whether to synchronize the remote file permissions, the last modification time, the last access time
    /// the windows operating system does not support file permissions synchronization,
    /// only the last modification time and last access time synchronization
    pub fn set_is_sync_permissions(&mut self, b: bool) {
        self.is_sync_permissions = b;
    }

    fn process_d(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        loop {
            self.send_end()?;
            let data = self.read_data()?;
            if data.is_empty() {
                break;
            }
            let code = &data[0];
            match *code {
                scp_flag::T => {
                    // 处理时间
                    let (modify_time, access_time) = file_time(data)?;
                    scp_file.modify_time = modify_time;
                    scp_file.access_time = access_time;
                }
                scp_flag::C => self.process_file_d(data, scp_file)?,
                scp_flag::D => self.process_dir_d(data, scp_file)?,
                scp_flag::E => {
                    match scp_file.local_path.parent() {
                        None => {}
                        Some(v) => {
                            let buf = v.to_path_buf();
                            if !buf.eq(&self.local_path) {
                                scp_file.local_path = buf;
                            }
                        }
                    }
                }
                // error
                scp_flag::ERR | scp_flag::FATAL_ERR =>
                    return Err(SshError::from(SshErrorKind::ScpError(util::from_utf8(data)?))),
                _ => return Err(SshError::from(SshErrorKind::ScpError("unknown error.".to_string())))
            }
        }
        log::info!("file sync successful.");
        Ok(())
    }

    fn process_dir_d(&mut self, data: Vec<u8>, scp_file: &mut ScpFile) -> SshResult<()> {
        let string = util::from_utf8(data)?;
        let dir_info = string.trim();
        let split = dir_info.split(" ").collect::<Vec<&str>>();
        match split.get(2) {
            None => return Ok(()),
            Some(v) => scp_file.name = v.to_string()
        }
        scp_file.is_dir = true;
        let buf = scp_file.local_path.join(&scp_file.name);
        log::info!("folder sync, name: [{}]", scp_file.name);
        if !buf.exists() {
            fs::create_dir(buf.as_path())?;
        }

        scp_file.local_path = buf;

        match fs::File::open(scp_file.local_path.as_path()) {
            Ok(file) => {
                self.sync_permissions(scp_file, file);
            }
            Err(e) => {
                log::error!("failed to open the folder, \
            it is possible that the path does not exist, \
            which does not affect subsequent operations. \
            error info: {:?}", e);
                return Err(SshError::from(SshErrorKind::ScpError(format!("file open error: {}", e.to_string()))))
            }
        };
        Ok(())
    }

    fn process_file_d(&mut self, data: Vec<u8>, scp_file: &mut ScpFile) -> SshResult<()> {
        let string = util::from_utf8(data)?;
        let file_info = string.trim();
        let split = file_info.split(" ").collect::<Vec<&str>>();
        let size_str = *split.get(1).unwrap_or(&"0");
        let size = util::str_to_i64(size_str)?;
        scp_file.size = size as u64;
        match split.get(2) {
            None => return Ok(()),
            Some(v) => scp_file.name = v.to_string()
        }
        scp_file.is_dir = false;
        self.save_file(scp_file)?;
        Ok(())
    }

    fn save_file(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        log::info!("file sync, name: [{}] size: [{}]", scp_file.name, scp_file.size);
        let path = scp_file.local_path.join(scp_file.name.as_str());
        if path.exists() {
            fs::remove_file(path.as_path())?;
        }

        let mut file = match OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(path.as_path()) {
            Ok(v) => v,
            Err(e) => {
                log::error!("file processing error, error info: {}", e);
                return Err(SshError::from(SshErrorKind::ScpError(format!("{:?} file processing exception", path))))
            }
        };

        self.send_end()?;
        let mut count = 0;
        loop {
            let data = self.read_data()?;
            if data.is_empty() { continue }
            count += data.len() as u64;

            if count == scp_file.size + 1 {
                if let Err(e) = file.write_all(&data[..(data.len() - 1)]) {
                    return Err(SshError::from(e))
                }
                log::info!("{}/{}", scp_file.size, scp_file.size);
                break;
            }
            if let Err(e) = file.write_all(&data) {
                return Err(SshError::from(e))
            }
            log::info!("{}/{}", scp_file.size, count);
        }

        self.sync_permissions(scp_file, file);
        Ok(())
    }





    fn sync_permissions(&self, scp_file: &mut ScpFile, file: File) {
        if !self.is_sync_permissions {
            return;
        }

        let modify_time = filetime::FileTime::from_unix_time(scp_file.modify_time, 0);
        let access_time = filetime::FileTime::from_unix_time(scp_file.access_time, 0);
        if let Err(e) = filetime::set_file_times(scp_file.local_path.as_path(), access_time, modify_time) {
            log::error!("the file time synchronization is abnormal,\
             which may be caused by the operating system,\
              which does not affect subsequent operations.\
               error info: {:?}", e)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::PermissionsExt;
            // error default mode 0755
            match u32::from_str_radix(match scp_file.is_dir {
                true => permission::DIR,
                false => permission::FILE
            }, 8) {
                Ok(mode) => {
                    if let Err(_) = file.set_permissions(Permissions::from_mode(mode)) {
                        log::error!("the operating system does not allow modification of file permissions, \
                        which does not affect subsequent operations.");
                    }
                }
                Err(v) => {
                    log::error!("Unknown error {}", v)
                }
            }
        }
    }


    fn send(&self, cmd: &str) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.channel.server_channel)
            .put_bytes(cmd.as_bytes());
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

    fn send_end(&self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_DATA)
            .put_u32(self.channel.server_channel)
            .put_bytes(&[scp_flag::END]);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

    fn read_data(&mut self) -> SshResult<Vec<u8>> {
        let mut vec = vec![];
        loop {
            if !vec.is_empty() { break }
            let mut client = util::client()?;
            let results = client.read()?;
            util::unlock(client);
            for mut result in results {
                let message_code = result.get_u8();
                match message_code {
                    message::SSH_MSG_CHANNEL_DATA => {
                        let cc = result.get_u32();
                        if cc == self.channel.client_channel {
                            vec.extend(result.get_u8s())
                        }
                    }
                    message::SSH_MSG_CHANNEL_CLOSE => {
                        let cc = result.get_u32();
                        if cc == self.channel.client_channel {
                            self.channel.remote_close = true;
                            self.channel.close()?;
                            return Ok(vec)
                        }
                    }
                    _ => self.channel.other(message_code, result)?
                }
            }
        }
        Ok(vec)
    }

    fn exec_scp(&mut self, command: &str) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.channel.server_channel)
            .put_str(strings::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        let mut packet = Packet::from(data);
        packet.build();
        let mut client = util::client()?;
        client.write(packet.as_slice())
    }

    fn download_command_init(&self, remote_path: &str) -> String {
        let mut cmd = format!(
            "{} {} {} {}",
            strings::SCP,
            scp_arg::SOURCE,
            scp_arg::QUIET,
            scp_arg::RECURSIVE
        );
        if self.is_sync_permissions {
            cmd.push_str(" ");
            cmd.push_str(scp_arg::PRESERVE_TIMES)
        }
        cmd.push_str(" ");
        cmd.push_str(remote_path);
        cmd
    }

}


fn file_time(v: Vec<u8>) -> SshResult<(i64, i64)> {
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
    Ok((util::str_to_i64(&ct)?, util::str_to_i64(&ut)?))
}

fn check_path(path: &Path) -> SshResult<()> {
    if let None = path.to_str() {
        return Err(SshError::from(SshErrorKind::PathNullError))
    }
    Ok(())
}


pub struct ScpFile {
    modify_time: i64,
    access_time: i64,
    size: u64,
    name: String,
    is_dir: bool,
    local_path: PathBuf,
}

impl ScpFile {
    fn new() -> Self {
        ScpFile {
            modify_time: 0,
            access_time: 0,
            size: 0,
            name: String::new(),
            is_dir: false,
            local_path: Default::default()
        }
    }
}



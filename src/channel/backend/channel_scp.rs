use super::channel::ChannelBroker;
use crate::{
    constant::{permission, scp, size},
    error::{SshError, SshResult},
    model::ScpFile,
    util::file_time,
};
use crate::{
    constant::{ssh_msg_code, ssh_str},
    util,
};
use crate::{model::Data, util::check_path};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    ops::{Deref, DerefMut},
    path::Path,
    time::SystemTime,
};

pub struct ScpBroker(ChannelBroker, Option<ScpFile>);

impl ScpBroker {
    pub(crate) fn open(channel: ChannelBroker) -> Self {
        ScpBroker(channel, None)
    }

    fn exec_scp(&mut self, command: &str) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
            .put_u32(self.server_channel_no)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        self.send(data)
    }

    fn command_init(&self, remote_path: &str, arg: &str) -> String {
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

    fn send_end(&mut self) -> SshResult<()> {
        self.send_bytes(&[scp::END])
    }

    fn get_end(&mut self) -> SshResult<()> {
        let vec = self.recv()?;
        if vec.is_empty() {
            Err(SshError::from("read a closed channel"))
        } else {
            match vec[0] {
                scp::END => Ok(()),
                // error
                scp::ERR | scp::FATAL_ERR => Err(SshError::from(util::from_utf8(vec)?)),
                _ => Err(SshError::from("unknown error.")),
            }
        }
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> SshResult<()> {
        self.send_data(bytes.to_vec().into())?;
        Ok(())
    }
}

// upload related
impl ScpBroker {
    /// upload a file from local path to remote path
    ///
    /// this method is equivalent to shell command
    /// ```bash
    /// scp -P port local_path user@ip:remote_path
    /// ```
    ///
    pub fn upload<P: AsRef<OsStr> + ?Sized>(
        mut self,
        local_path: &P,
        remote_path: &P,
    ) -> SshResult<()> {
        let local_path = Path::new(local_path);
        let remote_path = Path::new(remote_path);

        check_path(local_path)?;
        check_path(remote_path)?;

        let remote_path_str = remote_path.to_str().unwrap();
        let local_path_str = local_path.to_str().unwrap();

        log::info!(
            "start to upload files, \
        local [{}] files will be synchronized to the remote [{}] folder.",
            local_path_str,
            remote_path_str
        );

        self.exec_scp(self.command_init(remote_path_str, scp::SINK).as_str())?;
        self.get_end()?;
        let mut scp_file = ScpFile::new();
        scp_file.local_path = local_path.to_path_buf();
        self.file_all(&mut scp_file)?;

        log::info!("files upload successful.");

        self.0.close()
    }

    fn file_all(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        // 如果获取不到文件或者目录名的话，就不处理该数据
        // 如果文件不是有效的Unicode数据的话，也不处理
        scp_file.name = match scp_file.local_path.file_name() {
            None => return Ok(()),
            Some(name) => match name.to_str() {
                None => return Ok(()),
                Some(name) => name.to_string(),
            },
        };
        self.send_time(scp_file)?;
        if scp_file.local_path.is_dir() {
            // 文件夹如果读取异常的话。就略过该文件夹
            // 详细的错误信息请查看 [std::fs::read_dir] 方法介绍
            if let Err(e) = fs::read_dir(scp_file.local_path.as_path()) {
                log::error!("read dir error, error info: {}", e);
                return Ok(());
            }
            self.send_dir(scp_file)?;
            for p in fs::read_dir(scp_file.local_path.as_path()).unwrap() {
                match p {
                    Ok(dir_entry) => {
                        scp_file.local_path = dir_entry.path().clone();
                        self.file_all(scp_file)?
                    }
                    Err(e) => {
                        // 暂不处理
                        log::error!("dir entry error, error info: {}", e);
                    }
                }
            }

            self.send_bytes(&[scp::E, b'\n'])?;
            self.get_end()?;
        } else {
            scp_file.size = scp_file.local_path.as_path().metadata()?.len();
            self.send_file(scp_file)?
        }
        Ok(())
    }

    fn send_file(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        let mut file = match File::open(scp_file.local_path.as_path()) {
            Ok(f) => f,
            // 文件打开异常，不影响后续操作
            Err(e) => {
                log::error!(
                    "failed to open the folder, \
            it is possible that the path does not exist, \
            which does not affect subsequent operations. \
            error info: {:?}",
                    e
                );
                return Ok(());
            }
        };

        log::debug!(
            "name: [{}] size: [{}] type: [file] start upload.",
            scp_file.name,
            scp_file.size
        );

        let cmd = format!(
            "C0{} {} {}\n",
            permission::FILE,
            scp_file.size,
            scp_file.name
        );
        self.send_bytes(cmd.as_bytes())?;
        self.get_end()?;

        let mut count = 0;
        let mut chunk = [0u8; size::FILE_CHUNK];

        loop {
            let i = file.read(&mut chunk)?;
            count += i;
            self.send_bytes(&chunk[..i])?;
            if count == scp_file.size as usize {
                self.send_end()?;
                break;
            }
        }
        self.get_end()?;

        log::debug!("file: [{}] upload completed.", scp_file.name);

        Ok(())
    }

    fn send_dir(&mut self, scp_file: &ScpFile) -> SshResult<()> {
        log::debug!(
            "name: [{}] size: [0], type: [dir] start upload.",
            scp_file.name
        );

        let cmd = format!("D0{} 0 {}\n", permission::DIR, scp_file.name);
        self.send_bytes(cmd.as_bytes())?;
        self.get_end()?;

        log::debug!("dir: [{}] upload completed.", scp_file.name);

        Ok(())
    }

    fn send_time(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        self.get_time(scp_file)?;
        let cmd = format!("T{} 0 {} 0\n", scp_file.modify_time, scp_file.access_time);
        self.send_bytes(cmd.as_bytes())?;
        self.get_end()
    }

    fn get_time(&self, scp_file: &mut ScpFile) -> SshResult<()> {
        let metadata = scp_file.local_path.as_path().metadata()?;
        // 最后修改时间
        let modified_time = match metadata.modified() {
            Ok(t) => t,
            Err(_) => SystemTime::now(),
        };
        let modified_time = util::sys_time_to_secs(modified_time)?;

        // 最后访问时间
        let accessed_time = match metadata.accessed() {
            Ok(t) => t,
            Err(_) => SystemTime::now(),
        };
        let accessed_time = util::sys_time_to_secs(accessed_time)?;

        scp_file.modify_time = modified_time as i64;
        scp_file.access_time = accessed_time as i64;
        Ok(())
    }
}

// download related
impl ScpBroker {
    /// download a file from remote path to local path
    ///
    /// this method is equivalent to shell command
    /// ```bash
    /// scp -P port user@ip:remote_path local_path
    /// ```
    ///
    /// This method is running in the backend
    /// that needs `end_download` to explicitly end it
    ///
    pub fn start_download<P: AsRef<OsStr> + ?Sized>(
        &mut self,
        local_path: &P,
        remote_path: &P,
    ) -> SshResult<()> {
        let local_path = Path::new(local_path);
        let remote_path = Path::new(remote_path);

        check_path(local_path)?;
        check_path(remote_path)?;

        let local_path_str = local_path.to_str().unwrap();
        let remote_path_str = remote_path.to_str().unwrap();

        log::info!(
            "start to download files, \
        remote [{}] files will be synchronized to the local [{}] folder.",
            remote_path_str,
            local_path_str
        );

        self.exec_scp(self.command_init(remote_path_str, scp::SOURCE).as_str())?;
        let mut scp_file = ScpFile::new();
        scp_file.local_path = local_path.to_path_buf();
        self.1 = Some(scp_file);
        Ok(())
    }

    /// explicitly end the download routine and sync the filesystem
    ///
    /// this method will block until all donwload tasks end
    ///
    pub fn end_download(mut self) -> SshResult<()> {
        let mut scp_file = self.1.take().unwrap();
        let local_path = scp_file.local_path.clone();
        self.process_d(&mut scp_file, &local_path)
    }

    fn process_d(&mut self, scp_file: &mut ScpFile, local_path: &Path) -> SshResult<()> {
        while !self.close {
            self.send_end()?;
            let data = self.recv()?;
            if data.is_empty() {
                break;
            }
            let code = &data[0];
            match *code {
                scp::T => {
                    // 处理时间
                    let (modify_time, access_time) = file_time(data)?;
                    scp_file.modify_time = modify_time;
                    scp_file.access_time = access_time;
                }
                scp::C => self.process_file_d(data, scp_file)?,
                scp::D => self.process_dir_d(data, scp_file)?,
                scp::E => match scp_file.local_path.parent() {
                    None => {}
                    Some(v) => {
                        let buf = v.to_path_buf();
                        if !buf.eq(local_path) {
                            scp_file.local_path = buf;
                        }
                    }
                },
                // error
                scp::ERR | scp::FATAL_ERR => return Err(SshError::from(util::from_utf8(data)?)),
                _ => return Err(SshError::from("unknown error.")),
            }
        }
        Ok(())
    }

    fn process_dir_d(&mut self, data: Vec<u8>, scp_file: &mut ScpFile) -> SshResult<()> {
        let string = util::from_utf8(data)?;
        let dir_info = string.trim();
        let split = dir_info.split(' ').collect::<Vec<&str>>();
        match split.get(2) {
            None => return Ok(()),
            Some(v) => scp_file.name = v.to_string(),
        }
        scp_file.is_dir = true;
        let buf = scp_file.join(&scp_file.name);
        log::debug!(
            "name: [{}] size: [0], type: [dir] start download.",
            scp_file.name
        );
        if !buf.exists() {
            fs::create_dir(buf.as_path())?;
        }

        scp_file.local_path = buf;

        #[cfg(windows)]
        self.sync_permissions(scp_file);

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            match fs::File::open(scp_file.local_path.as_path()) {
                Ok(file) => {
                    self.sync_permissions(scp_file, file);
                }
                Err(e) => {
                    log::error!(
                        "failed to open the folder, \
            it is possible that the path does not exist, \
            which does not affect subsequent operations. \
            error info: {:?}, path: {:?}",
                        e,
                        scp_file.local_path.to_str()
                    );
                    return Err(SshError::from(format!("file open error: {}", e)));
                }
            };
        }

        log::debug!("dir: [{}] download completed.", scp_file.name);
        Ok(())
    }

    fn process_file_d(&mut self, data: Vec<u8>, scp_file: &mut ScpFile) -> SshResult<()> {
        let string = util::from_utf8(data)?;
        let file_info = string.trim();
        let split = file_info.split(' ').collect::<Vec<&str>>();
        let size_str = *split.get(1).unwrap_or(&"0");
        let size = util::str_to_i64(size_str)?;
        scp_file.size = size as u64;
        match split.get(2) {
            None => return Ok(()),
            Some(v) => scp_file.name = v.to_string(),
        }
        scp_file.is_dir = false;
        self.save_file(scp_file)
    }

    fn save_file(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        log::debug!(
            "name: [{}] size: [{}] type: [file] start download.",
            scp_file.name,
            scp_file.size
        );
        let path = scp_file.join(&scp_file.name);
        if path.exists() {
            fs::remove_file(path.as_path())?;
        }
        let mut file = match OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(path.as_path())
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("file processing error, error info: {}", e);
                return Err(SshError::from(format!(
                    "{:?} file processing exception",
                    path
                )));
            }
        };
        self.send_end()?;
        let mut count = 0;
        while !self.close {
            let data = self.recv()?;
            if data.is_empty() {
                break;
            }
            count += data.len() as u64;
            if count == scp_file.size + 1 {
                if let Err(e) = file.write_all(&data[..(data.len() - 1)]) {
                    return Err(SshError::from(e));
                }
                break;
            }
            if let Err(e) = file.write_all(&data) {
                return Err(SshError::from(e));
            }
        }

        #[cfg(windows)]
        self.sync_permissions(scp_file);

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.sync_permissions(scp_file, file);

        log::debug!("file: [{}] download completed.", scp_file.name);
        Ok(())
    }

    #[cfg(windows)]
    fn sync_permissions(&self, scp_file: &mut ScpFile) {
        let modify_time = filetime::FileTime::from_unix_time(scp_file.modify_time, 0);
        let access_time = filetime::FileTime::from_unix_time(scp_file.access_time, 0);
        if let Err(e) =
            filetime::set_file_times(scp_file.local_path.as_path(), access_time, modify_time)
        {
            log::error!(
                "the file time synchronization is abnormal,\
             which may be caused by the operating system,\
              which does not affect subsequent operations.\
               error info: {:?}",
                e
            )
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn sync_permissions(&self, scp_file: &mut ScpFile, file: fs::File) {
        let modify_time = filetime::FileTime::from_unix_time(scp_file.modify_time, 0);
        let access_time = filetime::FileTime::from_unix_time(scp_file.access_time, 0);
        if let Err(e) =
            filetime::set_file_times(scp_file.local_path.as_path(), access_time, modify_time)
        {
            log::error!(
                "the file time synchronization is abnormal,\
             which may be caused by the operating system,\
              which does not affect subsequent operations.\
               error info: {:?}",
                e
            )
        }

        use std::os::unix::fs::PermissionsExt;
        // error default mode 0755
        match u32::from_str_radix(
            match scp_file.is_dir {
                true => crate::constant::permission::DIR,
                false => crate::constant::permission::FILE,
            },
            8,
        ) {
            Ok(mode) => {
                if file
                    .set_permissions(fs::Permissions::from_mode(mode))
                    .is_err()
                {
                    log::error!(
                        "the operating system does not allow modification of file permissions, \
                        which does not affect subsequent operations."
                    );
                }
            }
            Err(v) => {
                log::error!("Unknown error {}", v)
            }
        }
    }
}

impl Deref for ScpBroker {
    type Target = ChannelBroker;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ScpBroker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

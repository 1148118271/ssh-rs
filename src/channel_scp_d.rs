use std::ffi::OsStr;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use crate::constant::{permission, scp};
use crate::error::{SshError, SshErrorKind, SshResult};
use crate::slog::log;
use crate::channel_scp::{ChannelScp, ScpFile, check_path};
use crate::util;

impl ChannelScp {
    ///   download
    pub fn download<S: AsRef<OsStr> + ?Sized>(&mut self, local_path: &S, remote_path: &S) -> SshResult<()> {
        let local_path = Path::new(local_path);
        let remote_path = Path::new(remote_path);

        check_path(local_path)?;
        check_path(remote_path)?;

        let local_path_str = local_path.to_str().unwrap();
        let remote_path_str = remote_path.to_str().unwrap();

        self.local_path = local_path.to_path_buf();

        log::info!("start to download files, \
        remote [{}] files will be synchronized to the local [{}] folder.", remote_path_str, local_path_str);

        self.exec_scp(self.command_init(remote_path_str, scp::SOURCE).as_str())?;
        let mut scp_file = ScpFile::new();
        scp_file.local_path = self.local_path.clone();
        self.process_d(&mut scp_file)?;
        Ok(())
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
                scp::T => {
                    // 处理时间
                    let (modify_time, access_time) = file_time(data)?;
                    scp_file.modify_time = modify_time;
                    scp_file.access_time = access_time;
                }
                scp::C => self.process_file_d(data, scp_file)?,
                scp::D => self.process_dir_d(data, scp_file)?,
                scp::E => {
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
                scp::ERR | scp::FATAL_ERR =>
                    return Err(SshError::from(SshErrorKind::ScpError(util::from_utf8(data)?))),
                _ => return Err(SshError::from(SshErrorKind::ScpError("unknown error.".to_string())))
            }
        }
        log::info!("files download successful.");
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
        log::debug!("name: [{}] size: [0], type: [dir] start download.", scp_file.name);
        if !buf.exists() {
            fs::create_dir(buf.as_path())?;
        }

        scp_file.local_path = buf;

        match File::open(scp_file.local_path.as_path()) {
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
        log::debug!("dir: [{}] download completed.", scp_file.name);
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
        log::debug!("name: [{}] size: [{}] type: [file] start download.", scp_file.name, scp_file.size);
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
                break;
            }
            if let Err(e) = file.write_all(&data) {
                return Err(SshError::from(e))
            }
        }
        self.sync_permissions(scp_file, file);
        log::debug!("file: [{}] download completed.", scp_file.name);
        Ok(())
    }

    fn sync_permissions(&self, scp_file: &mut ScpFile, file: File) {
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
                    if let Err(_) = file.set_permissions(fs::Permissions::from_mode(mode)) {
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
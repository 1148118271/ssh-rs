use crate::channel_scp::{check_path, ChannelScp, ScpFile};
use crate::constant::{permission, scp};
use crate::error::{SshError, SshResult};
use crate::slog::log;
use crate::util;
use std::ffi::OsStr;
use std::fs::{read_dir, File};
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

impl ChannelScp {
    pub fn upload<S: AsRef<OsStr> + ?Sized>(mut self, local_path: &S, remote_path: &S) -> SshResult<()> {
        let local_path = Path::new(local_path);
        let remote_path = Path::new(remote_path);

        check_path(local_path)?;
        check_path(remote_path)?;

        let remote_path_str = remote_path.to_str().unwrap();
        let local_path_str = local_path.to_str().unwrap();

        log::info!("start to upload files, \
        local [{}] files will be synchronized to the remote [{}] folder.", local_path_str, remote_path_str);

        self.exec_scp(self.command_init(remote_path_str, scp::SINK).as_str())?;
        self.get_end()?;
        let mut scp_file = ScpFile::new();
        scp_file.local_path = local_path.to_path_buf();
        self.file_all(&mut scp_file)?;

        log::info!("files upload successful.");

        self.channel.close()
    }


    fn file_all(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        // 如果获取不到文件或者目录名的话，就不处理该数据
        // 如果文件不是有效的Unicode数据的话，也不处理
        scp_file.name = match scp_file.local_path.file_name() {
            None => return Ok(()),
            Some(name) => match name.to_str() {
                None => return Ok(()),
                Some(name) => name.to_string()
            }
        };
        self.send_time(scp_file)?;
        if scp_file.local_path.is_dir() {
            // 文件夹如果读取异常的话。就略过该文件夹
            // 详细的错误信息请查看 read_dir 方法介绍
            if let Err(e) = read_dir(scp_file.local_path.as_path()) {
                log::error!("read dir error, error info: {}", e);
                return Ok(())
            }
            self.send_dir(scp_file)?;
            for p in read_dir(scp_file.local_path.as_path()).unwrap() {
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

            self.send_bytes(&[scp::E as u8, b'\n'])?;
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
                log::error!("failed to open the folder, \
            it is possible that the path does not exist, \
            which does not affect subsequent operations. \
            error info: {:?}", e);
                return Ok(())
            }
        };

        log::debug!("name: [{}] size: [{}] type: [file] start upload.", scp_file.name, scp_file.size);

        let cmd = format!("C0{} {} {}\n", permission::FILE, scp_file.size, scp_file.name);
        self.send_str(&cmd)?;
        self.get_end()?;

        let mut count = 0;
        loop {
            let mut s = [0u8; 20480];
            let i = file.read(&mut s)?;
            count = count + i;
            self.send_bytes(&s[..i])?;
            if count == scp_file.size as usize {
                self.send_bytes(&[0])?;
                break
            }
        }
        self.get_end()?;

        log::debug!("file: [{}] upload completed.", scp_file.name);

        return Ok(())
    }

    fn send_dir(&mut self, scp_file: &ScpFile) -> SshResult<()> {

        log::debug!("name: [{}] size: [0], type: [dir] start upload.", scp_file.name);

        let cmd = format!("D0{} 0 {}\n", permission::DIR, scp_file.name);
        self.send_str(&cmd)?;
        self.get_end()?;

        log::debug!("dir: [{}] upload completed.", scp_file.name);

        return Ok(())
    }


    fn send_time(&mut self, scp_file: &mut ScpFile) -> SshResult<()> {
        self.get_time(scp_file)?;
        // "T1647767946 0 1647767946 0\n";
        let cmd = format!("T{} 0 {} 0\n", scp_file.modify_time, scp_file.access_time);
        self.send_str(&cmd)?;
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

    fn get_end(&mut self) -> SshResult<()> {
        let vec = self.read_data()?;
        match *&vec[0] {
            scp::END => Ok(()),
            // error
            scp::ERR | scp::FATAL_ERR => {
                Err(SshError::from(util::from_utf8(vec)?))
            },
            _ => Err(SshError::from("unknown error."))
        }
    }
}

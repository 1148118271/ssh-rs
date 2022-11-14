use std::path::PathBuf;

pub(crate) struct ScpFile {
    pub modify_time: i64,
    pub access_time: i64,
    pub size: u64,
    pub name: String,
    pub is_dir: bool,
    pub local_path: PathBuf,
}

impl ScpFile {
    pub fn new() -> Self {
        ScpFile {
            modify_time: 0,
            access_time: 0,
            size: 0,
            name: String::new(),
            is_dir: false,
            local_path: Default::default(),
        }
    }

    pub fn join(&self, filename: &str) -> PathBuf {
        if self.local_path.is_dir() {
            self.local_path.join(filename)
        } else {
            self.local_path.clone()
        }
    }
}

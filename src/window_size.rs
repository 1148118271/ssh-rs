use constant::size::LOCAL_WINDOW_SIZE;

pub(crate) struct WindowSize {
    /// 本地窗口大小
    local_window_size: u32,
    /// 远程窗口大小
    remote_window_size : u32
}

impl WindowSize {
    pub(crate) fn new() -> Self {
        WindowSize {
            local_window_size: LOCAL_WINDOW_SIZE,
            remote_window_size: 0
        }
    }

    pub fn add_remote_window_size(&mut self, ws: u32) {
        self.remote_window_size = self.remote_window_size + ws;
    }
}
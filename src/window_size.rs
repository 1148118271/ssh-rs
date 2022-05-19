
struct WindowSize {
    client_channel_no: u32,
    server_channel_no: u32,
    /// 本地窗口大小
    local_window_size: u32,
    /// 远程窗口大小
    remote_window_size : u32
}

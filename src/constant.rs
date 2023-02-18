/// 客户端版本
pub(crate) const CLIENT_VERSION: &str = "SSH-2.0-SSH_RS-0.3.3";
pub(crate) const SSH_MAGIC: &[u8] = b"SSH-";

/// ssh通讯时用到的常量字符串
#[allow(dead_code)]
pub(crate) mod ssh_str {
    /// 准备认证
    pub const SSH_USERAUTH: &str = "ssh-userauth";
    /// 开始认证
    pub const SSH_CONNECTION: &str = "ssh-connection";
    /// 公钥验证方式
    pub const PUBLIC_KEY: &str = "publickey";
    /// 密码认证方式
    pub const PASSWORD: &str = "password";
    /// 打开一个会话
    pub const SESSION: &str = "session";
    /// 启动一个命令解释程序
    pub const SHELL: &str = "shell";
    /// 执行一个命令
    pub const EXEC: &str = "exec";
    /// 执行文件传输
    pub const SCP: &str = "scp";
    /// 请求一个伪终端
    pub const PTY_REQ: &str = "pty-req";
    /// 伪终端的样式
    pub const XTERM_VAR: &str = "xterm-256color";
}

#[allow(dead_code)]
pub(crate) mod permission {
    /// 文件夹默认权限
    pub const DIR: &str = "775";
    /// 文件默认权限
    pub const FILE: &str = "664";
}

/// scp 操作时用到的常量
#[allow(dead_code)]
pub(crate) mod scp {
    // scp 参数常量
    /// 意味着当前机器上的scp，将本地文件传输到另一个scp上
    pub const SOURCE: &str = "-f";
    /// 意味着当前机器上的scp，即将收到另一个scp传输过来的文件
    pub const SINK: &str = "-t";
    /// 递归复制整个目录
    pub const RECURSIVE: &str = "-r";
    /// 详细方式显示输出
    pub const VERBOSE: &str = "-v";
    /// 保留原文件的修改时间，访问时间和访问权限
    pub const PRESERVE_TIMES: &str = "-p";
    /// 不显示传输进度条
    pub const QUIET: &str = "-q";
    /// 限定用户所能使用的带宽
    pub const LIMIT: &str = "-l";

    // scp传输时的状态常量
    /// 代表当前接收的数据是文件的最后修改时间和最后访问时间
    /// "T1647767946 0 1647767946 0\n";
    pub const T: u8 = b'T';
    /// 代表当前接收的数据是文件夹
    /// "D0775 0 dirName\n"
    pub const D: u8 = b'D';
    /// 代表当前接收的数据是文件
    /// "C0664 200 fileName.js\n"
    pub const C: u8 = b'C';
    /// 代表当前文件夹传输结束，需要返回上层文件夹
    /// "D\n"
    pub const E: u8 = b'E';

    /// 代表结束当前操作
    // '\0'
    pub const END: u8 = 0;
    /// scp操作异常
    pub const ERR: u8 = 1;
    /// scp操作比较严重的异常
    pub const FATAL_ERR: u8 = 2;
}

/// 一些默认大小
#[allow(dead_code)]
pub(crate) mod size {
    pub const FILE_CHUNK: usize = 30000;
    /// 最大数据包大小
    pub const BUF_SIZE: usize = 32768;
    /// 默认客户端的窗口大小
    pub const LOCAL_WINDOW_SIZE: u32 = 2097152;
}

/// ssh 消息码
#[allow(dead_code)]
pub(crate) mod ssh_msg_code {
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;
    pub const SSH_MSG_KEXDH_INIT: u8 = 30;
    pub const SSH_MSG_KEXDH_REPLY: u8 = 31;
    pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
    pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
    pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;
    pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
    pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
    pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;
    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
    pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
    pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
    pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
    pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
    pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

    // 异常消息码
    pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u8 = 1;
    pub const SSH_DISCONNECT_PROTOCOL_ERROR: u8 = 2;
    pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u8 = 3;
    pub const SSH_DISCONNECT_RESERVED: u8 = 4;
    pub const SSH_DISCONNECT_MAC_ERROR: u8 = 5;
    pub const SSH_DISCONNECT_COMPRESSION_ERROR: u8 = 6;
    pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u8 = 7;
    pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u8 = 8;
    pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u8 = 9;
    pub const SSH_DISCONNECT_CONNECTION_LOST: u8 = 10;
    pub const SSH_DISCONNECT_BY_APPLICATION: u8 = 11;
    pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u8 = 12;
    pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u8 = 13;
    pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u8 = 14;
    pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u8 = 15;

    // 通道连接失败码 SSH_MSG_CHANNEL_OPEN_FAILURE
    pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
    pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
    pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;
}

/// 密钥交换后进行HASH时候需要的常量值
pub(crate) const ALPHABET: [u8; 6] = [b'A', b'B', b'C', b'D', b'E', b'F'];

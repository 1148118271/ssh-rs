/// 客户端版本
pub(crate) const CLIENT_VERSION: &str = "SSH-2.0-SSH_RS-0.3.2";
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
    /// 启动一个子系统
    pub const SUBSYSTEM: &str = "subsystem";
    /// sftp 子系统
    pub const SFTP: &str = "sftp";
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

/// sftp 消息码
///
#[allow(dead_code)]
pub(crate) mod sftp_msg_code {
    // 客户端初始化
    pub const SSH_FXP_INIT: u8 = 1;
    // 服务器初始化
    pub const SSH_FXP_VERSION: u8 = 2;
    // 打开文件包
    pub const SSH_FXP_OPEN: u8 = 3;
    // 关闭句柄
    pub const SSH_FXP_CLOSE: u8 = 4;
    // 读取文件
    pub const SSH_FXP_READ: u8 = 5;
    // 写入文件
    pub const SSH_FXP_WRITE: u8 = 6;
    // 获取文件属性 - 根据文件路径
    pub const SSH_FXP_LSTAT: u8 = 7;
    // 获取文件属性 - 根据文件句柄
    pub const SSH_FXP_FSTAT: u8 = 8;
    // 设置文件属性 - 根据文件路径
    pub const SSH_FXP_SETSTAT: u8 = 9;
    // 设置文件属性 - 根据文件句柄
    pub const SSH_FXP_FSETSTAT: u8 = 10;
    // 打开目录
    pub const SSH_FXP_OPENDIR: u8 = 11;
    // 读取目录
    pub const SSH_FXP_READDIR: u8 = 12;
    // 删除文件
    pub const SSH_FXP_REMOVE: u8 = 13;
    // 创建目录
    pub const SSH_FXP_MKDIR: u8 = 14;
    // 删除目录
    pub const SSH_FXP_RMDIR: u8 = 15;
    // 相对路径转为绝对路径
    pub const SSH_FXP_REALPATH: u8 = 16;
    // 同 SSH_FXP_LSTAT
    // SH_FXP_STAT遵循在服务器上的符号链接，然而SSH_FXP_LSTAT不遵循符号链接
    pub const SSH_FXP_STAT: u8 = 17;
    // 重命名文件
    pub const SSH_FXP_RENAME: u8 = 18;
    // 读取符号链接的目标
    pub const SSH_FXP_READLINK: u8 = 19;
    // 请求创建链接
    pub const SSH_FXP_LINK: u8 = 21;
    // 在指定的文件上创建字节范围锁
    pub const SSH_FXP_BLOCK: u8 = 22;
    // 移除之前获取的字节范围锁
    pub const SSH_FXP_UNBLOCK: u8 = 23;
    // 响应状态
    pub const SSH_FXP_STATUS: u8 = 101;
    // 句柄响应
    pub const SSH_FXP_HANDLE: u8 = 102;
    // 数据响应
    pub const SSH_FXP_DATA: u8 = 103;
    // 名称响应
    pub const SSH_FXP_NAME: u8 = 104;
    // 属性响应
    pub const SSH_FXP_ATTRS: u8 = 105;

    // 拓展
    pub const SSH_FXP_EXTENDED: u8 = 200;
    pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;
}

/// sftp 状态码
///
#[allow(dead_code)]
pub(crate) mod sftp_msg_status_code {
    // 操作成功完成
    pub const SSH_FX_OK: u8 = 0;
    // 读取超长/没有更多的返回目录项
    pub const SSH_FX_EOF: u8 = 1;
    // 引用了一个不存在的文件
    pub const SSH_FX_NO_SUCH_FILE: u8 = 2;
    // 用户权限不足
    pub const SSH_FX_PERMISSION_DENIED: u8 = 3;
    // 返回错误但是不存在特定错误码
    pub const SSH_FX_FAILURE: u8 = 4;
    // 数据包格式错误或者协议不兼容
    pub const SSH_FX_BAD_MESSAGE: u8 = 5;
    // 没有连接到服务器(只能本地返回此错误)
    pub const SSH_FX_NO_CONNECTION: u8 = 6;
    // 与服务器连接丢失(只能本地返回此错误)
    pub const SSH_FX_CONNECTION_LOST: u8 = 7;
    // 服务器不支持该操作
    pub const SSH_FX_OP_UNSUPPORTED: u8 = 8;
    // 句柄值无效
    pub const SSH_FX_INVALID_HANDLE: u8 = 9;
    // 文件路径不存在或者无效
    pub const SSH_FX_NO_SUCH_PATH: u8 = 10;
    // 文件已存在
    pub const SSH_FX_FILE_ALREADY_EXISTS: u8 = 11;
    // 文件处于只读/保护状态
    pub const SSH_FX_WRITE_PROTECT: u8 = 12;
    // 无法完成指定的操作-驱动器中没有可用的介质
    pub const SSH_FX_NO_MEDIA: u8 = 13;
    // 无法完成指定的操作-文件系统上可用空间不足
    pub const SSH_FX_NO_SPACE_ON_FILESYSTEM: u8 = 14;
    // 超过用户的储存配额
    pub const SSH_FX_QUOTA_EXCEEDED: u8 = 15;
    // 未知的请求引用主题
    pub const SSH_FX_UNKNOWN_PRINCIPAL: u8 = 16;
    // 文件被锁定,无法打开
    pub const SSH_FX_LOCK_CONFLICT: u8 = 17;
    // 目录不为空
    pub const SSH_FX_DIR_NOT_EMPTY: u8 = 18;
    // 指定的文件不是目录
    pub const SSH_FX_NOT_A_DIRECTORY: u8 = 19;
    // 文件名无效
    pub const SSH_FX_INVALID_FILENAME: u8 = 20;
    // 过多的符号链接
    pub const SSH_FX_LINK_LOOP: u8 = 21;
    // 文件无法删除
    pub const SSH_FX_CANNOT_DELETE: u8 = 22;
    // 参数超出范围/多参数不能以前使用
    pub const SSH_FX_INVALID_PARAMETER: u8 = 23;
    // 指定的目录是上下文的目录,某些目录无法使用
    pub const SSH_FX_FILE_IS_A_DIRECTORY: u8 = 24;
    // 读取或写入失败,另一个进程的字节范围锁与请求重叠
    pub const SSH_FX_BYTE_RANGE_LOCK_CONFLICT: u8 = 25;
    // 字节范围锁请求被拒绝
    pub const SSH_FX_BYTE_RANGE_LOCK_REFUSED: u8 = 26;
    // 删除文件操作被挂起
    pub const SSH_FX_DELETE_PENDING: u8 = 27;
    // 文件已损坏
    pub const SSH_FX_FILE_CORRUPT: u8 = 28;
    // 无法将指定的主体指派为文件的所有者
    pub const SSH_FX_OWNER_INVALID: u8 = 29;
    // 无法将指定的主体分配为文件的主要组
    pub const SSH_FX_GROUP_INVALID: u8 = 30;
    // 无法完成请求操作,因为尚未授权指定的字节范围锁定
    pub const SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK: u8 = 31;
}

/// file flags
///
#[allow(dead_code)]
pub(crate) mod sftp_file_flags {
    // 读取文件
    /// Open the file for reading.
    ///
    pub const SSH_FXF_READ: u32 = 0x00000001;

    // 写入文件
    /// Open the file for writing.
    /// If both this and SSH_FXF_READ are specified, the file is opened for both reading and writing.
    ///
    pub const SSH_FXF_WRITE: u32 = 0x00000002;

    // 追加内容到文件
    /// Force all writes to append data at the end of the file.
    /// The offset parameter to write will be ignored.
    ///
    pub const SSH_FXF_APPEND: u32 = 0x00000004;

    // 创建文件
    /// If this flag is specified, then a new file will be created if one
    /// does not already exist (if O_TRUNC is specified, the new file will
    /// be truncated to zero length if it previously exists).
    ///
    pub const SSH_FXF_CREAT: u32 = 0x00000008;

    // 截断文件
    /// Forces an existing file with the same name to be truncated to zero
    /// length when creating a file by specifying SSH_FXF_CREAT.
    /// SSH_FXF_CREAT MUST also be specified if this flag is used.
    ///
    pub const SSH_FXF_TRUNC: u32 = 0x00000010;

    // 创建文件时，不能有旧文件
    /// Causes the request to fail if the named file already exists.
    /// SSH_FXF_CREAT MUST also be specified if this flag is used.
    ///
    pub const SSH_FXF_EXCL: u32 = 0x00000020;

    // 应将文件视为文本
    /// Indicates that the server should treat the file as text and
    /// convert it to the canonical newline convention in use.
    ///
    pub const SSH_FXF_TEXT: u32 = 0x00000040;
}

/// 密钥交换后进行HASH时候需要的常量值
pub(crate) const ALPHABET: [u8; 6] = [b'A', b'B', b'C', b'D', b'E', b'F'];

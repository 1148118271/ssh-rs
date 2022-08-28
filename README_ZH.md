# ssh-rs ✨

[English](https://github.com/1148118271/ssh-rs/blob/main/README.md)  |  [简体中文](https://github.com/1148118271/ssh-rs/blob/main/README_ZH.md)

rust实现的ssh2.0客户端。

如果在使用中遇到任何问题，欢迎 [issues](https://github.com/1148118271/ssh-rs/issues)
或者 [PR](https://github.com/1148118271/ssh-rs/pulls) 。

## 连接方式：

### 1. 密码连接:
```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    session.set_user_and_password("用户", "密码");
    session.connect("ip:port").unwrap();
}
```

### 2. 公钥连接:
#### 目前只支持加密格式是`-----BEGIN RSA PRIVATE KEY-----`这种的`RSA-PKCS#1-PEM`类型的加密文件。

#### 1. 使用密钥文件地址：
```rust
use ssh_rs::{Session, ssh};
use ssh_rs::key_pair::KeyPairType;

fn main() {
    let mut session: Session = ssh::create_session();
    // pem格式密钥地址 -> /xxx/xxx/id_rsa
    // KeyPairType::SshRsa rsa类型算法，目前只支持rsa
    session.set_user_and_key_pair_path("用户", "pem格式密钥地址", KeyPairType::SshRsa).unwrap();
    session.connect("ip:port").unwrap();
}    
```

#### 2. 使用密钥字符串：
```rust
use ssh_rs::{Session, ssh};
use ssh_rs::key_pair::KeyPairType;

fn main() {
    let mut session: Session = ssh::create_session();
    // pem格式密钥字符串:
    //      -----BEGIN RSA PRIVATE KEY-----
    //          xxxxxxxxxxxxxxxxxxxxx
    //      -----END RSA PRIVATE KEY-----
    // KeyPairType::SshRsa rsa类型算法，目前只支持rsa
    session.set_user_and_key_pair("用户", "pem格式密钥字符串", KeyPairType::SshRsa).unwrap();
    session.connect("ip:port").unwrap();
}
```


## 启用全局日志：

```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    // is_enable_log 是否启用全局日志
    // 默认为 false（不启用）
    // 可设置为 true（启用）
    session.is_enable_log(true);
    session.set_user_and_password("用户", "密码");
    session.connect("ip:port").unwrap();
}
```


## 设置超时时间：

```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    // set_timeout 设置超时时间
    // 单位为 秒
    // 默认超时时间是 30秒
    session.set_timeout(15);
    session.set_user_and_password("用户", "密码");
    session.connect("ip:port").unwrap();
}
```


## 使用方式：

### 目前只支持 exec shell scp 这三种功能

### 1. exec

```rust
use ssh_rs::{ChannelExec, Session, ssh};

fn main() {
    let mut session: Session = session();
    // 方式一
    let exec: ChannelExec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // 方式二
    let channel = session.open_channel().unwrap();
    let exec = channel.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // 关闭会话
    session.close().unwrap();
}
```

### 2. shell

```rust
use std::thread::sleep;
use std::time::Duration;
use ssh_rs::{Channel, ChannelShell, Session, ssh};

fn main() {
    let mut session: Session = session();
    // 方式一
    let mut shell: ChannelShell = session.open_shell().unwrap();
    run_shell(&mut shell);
    // 方式二
    let channel: Channel = session.open_channel().unwrap();
    let mut shell = channel.open_shell().unwrap();
    run_shell(&mut shell);
    // 关闭通道
    shell.close().unwrap();
    // 关闭会话
    session.close().unwrap();
}

fn run_shell(shell: &mut ChannelShell) {
    sleep(Duration::from_millis(500));
    let vec = shell.read().unwrap();
    println!("{}", String::from_utf8(vec).unwrap());

    shell.write(b"ls -all\n").unwrap();

    sleep(Duration::from_millis(500));

    let vec = shell.read().unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
}
```

### 3. scp

```rust
use ssh_rs::{Channel, ChannelScp, Session, ssh};

fn main() {
    let mut session: Session = session();
    // 方式一
    // 上传
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("本地路径", "远程路径").unwrap();
    // 下载
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("本地路径", "远程路径").unwrap();

    // 方式二
    // 上传
    let channel: Channel = session.open_channel().unwrap();
    let scp: ChannelScp = channel.open_scp().unwrap();
    scp.upload("本地路径", "远程路径").unwrap();
    // 下载
    let channel: Channel = session.open_channel().unwrap();
    let scp: ChannelScp = channel.open_scp().unwrap();
    scp.download("本地路径", "远程路径").unwrap();

    session.close().unwrap();
}

```


## 算法支持：

### 1. 密钥交换算法
`curve25519-sha256`
`ecdh-sha2-nistp256`

### 2. 主机密钥算法
`ssh-ed25519`
`ssh-rsa`

### 3. 加密算法（客户端到服务端）
`chacha20-poly1305@openssh.com`
`aes128-ctr`

### 4. 加密算法（服务端到客户端）
`chacha20-poly1305@openssh.com`
`aes128-ctr`

### 5. MAC算法（客户端到服务端）
`hmac-sha1`

### 6. MAC算法（服务端到客户端）
`hmac-sha1`

### 7. 压缩算法（客户端到服务端）
`none`

### 8. 压缩算法（服务端到客户端）
`none`

---

#### ☃️ 会继续添加其它算法。
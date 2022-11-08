# ssh-rs ✨

[English](https://github.com/1148118271/ssh-rs/blob/main/README.md)  |  [简体中文](https://github.com/1148118271/ssh-rs/blob/main/README_ZH.md)

rust实现的ssh2.0客户端。

如果在使用中遇到任何问题，欢迎 [issues](https://github.com/1148118271/ssh-rs/issues)
或者 [PR](https://github.com/1148118271/ssh-rs/pulls) 。

## 连接方式：

### 1. 密码连接:

```rust
fn main() {
    use ssh_rs::ssh;
    let mut session = ssh::create_session()
        .username("用户")
        .password("密码")
        .build();
    session.connect("ip:port").unwrap();
}
```

### 2. 公钥连接:

#### 目前只支持加密格式是 `-----BEGIN RSA PRIVATE KEY-----` 这种的 `RSA-PKCS#1-PEM` 类型的加密文件。

#### 1. 使用密钥文件地址：

```rust
fn main() {
    let mut session: Session<TcpStream> = ssh::create_session();
    // pem格式密钥地址 -> /xxx/xxx/id_rsa
    // 密钥文件的开头需为
    //      -----BEGIN RSA PRIVATE KEY-----
    // 结尾为
    //       -----END RSA PRIVATE KEY-----
    // 一般可以使用命令 `ssh-keygen -t rsa -m PEM` 生成
    // KeyPairType::SshRsa rsa类型算法，目前只支持rsa
    use ssh_rs::ssh;
    let mut session = ssh::create_session()
        .username("用户")
        .private_key_path("pem格式密钥地址")
        .build();
    session.connect("ip:port").unwrap();
}    
```

#### 2. 使用密钥字符串：

```rust
fn main() {
    // pem格式密钥字符串:
    //      -----BEGIN RSA PRIVATE KEY-----
    //          xxxxxxxxxxxxxxxxxxxxx
    //      -----END RSA PRIVATE KEY-----
    // KeyPairType::SshRsa rsa类型算法，目前只支持rsa
    use ssh_rs::ssh;
    let mut session = ssh::create_session()
        .username("用户")
        .private_key("pem格式密钥字符串")
        .build();
    session.connect("ip:port").unwrap();
}
```

## 启用全局日志：

```rust
fn main() {
    // is_enable_log 是否启用全局日志
    // 默认为 false（不启用）
    // 可设置为 true（启用）
    ssh::is_enable_log(true);
    
    let mut session: Session<TcpStream> = ssh::create_session();
    session.set_user_and_password("用户", "密码");
    session.connect("ip:port").unwrap();
}
```

## 设置超时时间：

```rust
fn main() {
    let mut session: Session<TcpStream> = ssh::create_session();
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
use ssh_rs::ssh;

fn main() {
    ssh::is_enable_log(true);

    let mut session = ssh::create_session()
        .username("用户")
        .password("密码")
        .build();
    session.connect("ip:port").unwrap();
    // 方式一
    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // 方式二
    let channel = session.open_channel().unwrap();
    let exec = channel.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // 关闭会话
    session.close();
}
```

### 2. shell

```rust
use ssh_rs::{ssh, ChannelShell};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let mut session = ssh::create_session()
        .username("用户")
        .password("密码")
        .build();
    session.connect("ip:port").unwrap();
    // 方式一
    let mut shell = session.open_shell().unwrap();
    run_shell(&mut shell);
    // 方式二
    let channel = session.open_channel().unwrap();
    let mut shell = channel.open_shell().unwrap();
    run_shell(&mut shell);
    // 关闭通道
    shell.close().unwrap();
    // 关闭会话
    session.close();
}

fn run_shell(shell: &mut ChannelShell<std::net::TcpStream>) {
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
use ssh_rs::ssh;

fn main() {
    let mut session = ssh::create_session()
        .username("用户")
        .password("密码")
        .build();
    session.connect("ip:port").unwrap();

    // 方式一
    // 上传
    let scp = session.open_scp().unwrap();
    scp.upload("本地路径", "远程路径").unwrap();
    // 下载
    let scp = session.open_scp().unwrap();
    scp.download("本地路径", "远程路径").unwrap();

    // 方式二
    // 上传
    let channel = session.open_channel().unwrap();
    let scp = channel.open_scp().unwrap();
    scp.upload("本地路径", "远程路径").unwrap();
    // 下载
    let channel = session.open_channel().unwrap();
    let scp = channel.open_scp().unwrap();
    scp.download("本地路径", "远程路径").unwrap();

    session.close().unwrap();
}

```

## bio:

```rust
use ssh_rs::algorithm;
use ssh_rs::ssh;

fn main() {
    ssh::is_enable_log(true);

    let mut session = ssh::create_session_without_default()
        .username("用户")
        .password("密码")
        .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_pubkey_algorithms(algorithm::PubKey::SshRsa) // 需要打开特性 "dangerous-algorithms"
        .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithm::Compress::None)
        .add_mac_algortihms(algorithm::Mac::HmacSha1)
        .build();
    session.connect("ip:port").unwrap();
    // Usage 1
    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Close session.
    session.close();
}
```

## 算法支持：

### 1. 密钥交换算法

* `curve25519-sha256`
* `ecdh-sha2-nistp256`

### 2. 主机密钥算法

* `ssh-ed25519`
* `rsa-sha2-256`
* `rsa-sha` (behind feature "dangerous-rsa-sha1")

### 3. 加密算法（客户端到服务端）

* `chacha20-poly1305@openssh.com`
* `aes128-ctr`

### 4. 加密算法（服务端到客户端）

* `chacha20-poly1305@openssh.com`
* `aes128-ctr`

### 5. MAC算法（客户端到服务端）

* `hmac-sha1`

### 6. MAC算法（服务端到客户端）

* `hmac-sha1`

### 7. 压缩算法（客户端到服务端）

* `none`

### 8. 压缩算法（服务端到客户端）

* `none`

---

#### ☃️ 会继续添加其它算法。

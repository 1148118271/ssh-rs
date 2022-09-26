# ssh-rs ✨

[English](https://github.com/1148118271/ssh-rs/blob/main/README.md)  |  [简体中文](https://github.com/1148118271/ssh-rs/blob/main/README_ZH.md)

Rust implementation of ssh2.0 client.

If you encounter any problems in use, welcome [issues](https://github.com/1148118271/ssh-rs/issues)
or [PR](https://github.com/1148118271/ssh-rs/pulls) .

## Connection method：

### 1. Password:
```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    session.set_user_and_password("user", "password");
    session.connect("ip:port").unwrap();
}
```

### 2. Public key:
#### Currently, only `RSA-PKCS#1-PEM` type encrypted files with the encryption format `-----BEGIN RSA PRIVATE KEY-----` are supported.

#### 1. Use key file path：
```rust
use ssh_rs::{Session, ssh};
use ssh_rs::key_pair::KeyPairType;

fn main() {
    let mut session: Session = ssh::create_session();
    // pem format key path -> /xxx/xxx/id_rsa
    // KeyPairType::SshRsa -> Rsa type algorithm, currently only supports rsa.
    session.set_user_and_key_pair_path("user", "pem format key path", KeyPairType::SshRsa).unwrap();
    session.connect("ip:port").unwrap();
}    
```

#### 2. Use key string：
```rust
use ssh_rs::{Session, ssh};
use ssh_rs::key_pair::KeyPairType;

fn main() {
    let mut session: Session = ssh::create_session();
    // pem format key string:
    //      -----BEGIN RSA PRIVATE KEY-----
    //          xxxxxxxxxxxxxxxxxxxxx
    //      -----END RSA PRIVATE KEY-----
    // KeyPairType::SshRsa -> Rsa type algorithm, currently only supports rsa.
    session.set_user_and_key_pair("user", "pem format key string", KeyPairType::SshRsa).unwrap();
    session.connect("ip:port").unwrap();
}
```

## Enable global logging：

```rust
use ssh_rs::{Session, ssh};

fn main() {
    // is_enable_log Whether to enable global logging
    // The default is false(Do not enable)
    // Can be set as true (enable)
    ssh::is_enable_log(true);
    
    let mut session: Session = ssh::create_session();
    session.set_user_and_password("user", "password");
    session.connect("ip:port").unwrap();
}
```


## Set timeout：

```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    // set_timeout
    // The unit is seconds
    // The default timeout is 30 seconds
    session.set_timeout(15);
    session.set_user_and_password("user", "password");
    session.connect("ip:port").unwrap();
}
```


## How to use：

### Currently only supports exec shell scp these three functions.

### 1. exec

```rust
use ssh_rs::{ChannelExec, Session, ssh};

fn main() {
    let mut session: Session = session();
    // Usage 1
    let exec: ChannelExec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Usage 2
    let channel = session.open_channel().unwrap();
    let exec = channel.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Close session.
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
    // Usage 1
    let mut shell: ChannelShell = session.open_shell().unwrap();
    run_shell(&mut shell);
    // Usage 2
    let channel: Channel = session.open_channel().unwrap();
    let mut shell = channel.open_shell().unwrap();
    run_shell(&mut shell);
    // Close channel.
    shell.close().unwrap();
    // Close session.
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
    // Usage 1
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("local path", "remote path").unwrap();
   
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("local path", "remote path").unwrap();

    // Usage 2
    let channel: Channel = session.open_channel().unwrap();
    let scp: ChannelScp = channel.open_scp().unwrap();
    scp.upload("local path", "remote path").unwrap();
  
    let channel: Channel = session.open_channel().unwrap();
    let scp: ChannelScp = channel.open_scp().unwrap();
    scp.download("local path", "remote path").unwrap();

    session.close().unwrap();
}

```


## Algorithm support：


### 1. Kex algorithms
`curve25519-sha256`
`ecdh-sha2-nistp256`

### 2. Server host key algorithms
`ssh-ed25519`
`ssh-rsa`

### 3. Encryption algorithms (client to server)
`chacha20-poly1305@openssh.com`
`aes128-ctr`

### 4. Encryption algorithms (server to client)
`chacha20-poly1305@openssh.com`
`aes128-ctr`

### 5. Mac algorithms (client to server)
`hmac-sha1`

### 6. Mac algorithms (server to client)
`hmac-sha1`

### 7. Compression algorithms (client to server)
`none`

### 8. Compression algorithms (server to client)
`none`

---

### ☃️ Additional algorithms will continue to be added.
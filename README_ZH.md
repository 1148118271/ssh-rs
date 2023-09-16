# ssh-rs ✨

[English](https://github.com/1148118271/ssh-rs/blob/main/README.md)  |  [简体中文](https://github.com/1148118271/ssh-rs/blob/main/README_ZH.md)

rust实现的ssh2.0客户端。

如果在使用中遇到任何问题，欢迎 [issues](https://github.com/1148118271/ssh-rs/issues)
或者 [PR](https://github.com/1148118271/ssh-rs/pulls) 。

### 连接方式：

#### 1. 密码连接:

```rust
fn main() {
    let session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .connect("ip:port")
        .unwrap()
        .run_local();
}
```

#### 2. 公钥连接:

```rust
fn main() {
    let session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa") // 文件地址
        .connect("ip:port")
        .unwrap()
        .run_local();
}    
```

```rust
fn main() {
    let session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key("rsa_string") // 文件字符串
        .connect("ip:port")
        .unwrap()
        .run_local();
}
```

### 启用全局日志：

```rust
use ssh;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
// this will generate some basic event logs
// a builder for `FmtSubscriber`.
let subscriber = FmtSubscriber::builder()
    // all spans/events with a level higher than INFO (e.g, info, warn, etc.)
    // will be written to stdout.
    .with_max_level(Level::INFO)
    // completes the builder.
    .finish();

tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
```

### 设置超时时间：

```rust
ssh::create_session().timeout(Some(std::time::Duration::from_secs(5)));
```

### 目前只支持 exec shell scp 三种使用方式： 

1. [exec示例](examples/exec/src/main.rs) 
2. [shell示例](examples/shell/src/main.rs) 
3. [scp示例](examples/scp/src/main.rs)

### 自定义连接方式:

[bio示例](examples/bio/src/main.rs)

### 算法支持：

#### 1. 密钥交换算法

* `curve25519-sha256`
* `ecdh-sha2-nistp256`

#### 2. 主机密钥算法

* `ssh-ed25519`
* `rsa-sha2-512`
* `rsa-sha2-256`
* `rsa-sha` (features = ["deprecated-rsa-sha1"])

#### 3. 加密算法（客户端到服务端）

* `chacha20-poly1305@openssh.com`
* `aes128-ctr`
* `aes192-ctr`
* `aes256-ctr`
* `aes128-cbc` (features = ["deprecated-aes-cbc"])
* `aes192-cbc` (features = ["deprecated-aes-cbc"])
* `aes256-cbc` (features = ["deprecated-aes-cbc"])
* `3des-cbc` (features = ["deprecated-des-cbc"])


#### 4. 加密算法（服务端到客户端）

* `chacha20-poly1305@openssh.com`
* `aes128-ctr`

#### 5. MAC算法（客户端到服务端）

* `hmac-sha1`

#### 6. MAC算法（服务端到客户端）

* `hmac-sha1`

#### 7. 压缩算法（客户端到服务端）

* `none`

#### 8. 压缩算法（服务端到客户端）

* `none`

---

#### ☃️ 会继续添加其它算法。

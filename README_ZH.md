# ssh-rs ✨

[English](https://github.com/1148118271/ssh-rs/blob/main/README.md)  |  [简体中文](https://github.com/1148118271/ssh-rs/blob/main/README_ZH.md)

rust实现的ssh2.0客户端。

如果在使用中遇到任何问题，欢迎 [issues](https://github.com/1148118271/ssh-rs/issues)
或者 [PR](https://github.com/1148118271/ssh-rs/pulls) 。

## 连接方式：

### 1. 密码连接:

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

### 2. 公钥连接:

#### 目前支持ras1 rsa2

#### 1. 使用密钥文件地址：

```rust
fn main() {
    let session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .connect("ip:port")
        .unwrap()
        .run_local();
}    
```

#### 2. 使用密钥字符串：

```rust
fn main() {
    let session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key("rsa_string")
        .connect("ip:port")
        .unwrap()
        .run_local();
}
```

## 启用全局日志：

```rust
 ssh::debug();
```

## 设置超时时间：

```rust
ssh::create_session().timeout(50);
```

## [bio示例](examples/scp/src/main.rs)

## 使用方式：

### 目前只支持 exec shell scp 这三种功能

### 1. [exec示例](examples/exec/src/main.rs)
### 2. [shell示例](examples/shell/src/main.rs)
### 3. [scp示例](examples/scp/src/main.rs)

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

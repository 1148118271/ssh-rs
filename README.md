### 除加密库外 纯rust实现的ssh-2.0client协议

#### 使用方法：
shell
```rust
fn main() {
    let ssh = ZmSsh::new();
    let mut session = ssh.get_session("192.168.3.101:22").unwrap();
    session.set_nonblocking(true).unwrap();
    session.set_user_and_password("root".to_string(), "123456".to_string());
    session.connect().unwrap();
    let mut channel = session.open_channel().unwrap();
    let mut shell = channel.open_shell().unwrap();
    
    // thread::sleep(time::Duration::from_millis(500));
    // let result = shell.read().unwrap();
    // println!("{}", String::from_utf8(result).unwrap());
    // shell.close().unwrap();
    // session.close().unwrap();

    let c1 = Arc::new(Mutex::new(shell));
    let c2 = Arc::clone(&c1);
    let t1 = thread::spawn(move || {
        loop {
            let mut x = c1.lock().unwrap().read().unwrap();
            if x.is_empty() { continue }
            stdout().write(x.as_slice()).unwrap();
            stdout().flush();
        }
    });

    let t2 = thread::spawn(move || {
        loop {
            let mut cm = String::new();
            stdin().read_line(&mut cm).unwrap();
            c2.lock().unwrap().write(cm.as_bytes()).unwrap();
        }
    });

    t1.join().unwrap();
    t2.join().unwrap();

}
```
exec
```rust

fn main() {
    let ssh = ZmSsh::new();
    let mut session = ssh.get_session("192.168.3.101:22").unwrap();
    session.set_user_and_password("root".to_string(), "123456".to_string());
    session.connect().unwrap();
    let mut channel = session.open_channel().unwrap();
    let mut exec = channel.open_exec().unwrap();
    let vec = exec.set_command("ps -ef |grep ssh").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    session.close().unwrap();
}
```


```
支持的算法:
    密钥交换：  
        curve25519-sha256,ecdh-sha2-nistp256
    数字签名：
        ssh-ed25519
    加密：
        chacha20-poly1305@openssh.com
        

支持的验证方式：
    密码验证


支持的命令解释程序:
    shell, exec
```


### 目前暂不支持 scp，sftp


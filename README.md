## In addition to encryption library, pure RUST implementation of SSH-2.0 client protocol



### Quick example (简单例子):
#### shell
```rust
fn main() {
    let ssh = SSH::new();
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

    loop {
        thread::sleep(time::Duration::from_millis(200));
        let result = shell.read().unwrap();
        stdout().write(result.as_slice()).unwrap();
        stdout().flush();
        let mut cm = String::new();
        stdin().read_line(&mut cm).unwrap();
        shell.write(cm.as_bytes()).unwrap();
    }

}
```
#### exec
```rust

fn main() {
    let ssh = SSH::new();
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


### Supported algorithms (支持的算法):
| algorithms                    | is supported  |
|-------------------------------|---------------|
| curve25519-sha256             | √             |   
| ecdh-sha2-nistp256            | √             |  
| ssh-ed25519                   | √             |  
| rsa                           | √             |  
| chacha20-poly1305@openssh.com | √             |



### Supported authentication modes (支持的身份验证方式):

| user auth        | is supported |
|------------------|--------------|
| publickey        | ×            |   
| password         | √            |  
| hostbased        | ×            |  



### Supported channels (支持的连接通道)
| channel   | is supported  |
|-----------|---------------|
| shell     | √             |   
| exec      | √             |  
| subsystem | ×             |  



### Not currently supported *scp*, *sftp* (目前不支持 scp sftp)


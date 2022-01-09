## In addition to encryption library, pure RUST implementation of SSH-2.0 client protocol



### Quick example (简单例子):
```rust
fn main() {
    let ssh = SSH::new();
    let mut session = ssh.get_session("192.168.3.101:22").unwrap();
    session.set_nonblocking(true).unwrap();
    session.set_user_and_password("root".to_string(), "123456".to_string());
    session.connect().unwrap();
    let channel: Channel = session.open_channel().unwrap();
    exec(channel);
    let channel: Channel = session.open_channel().unwrap();
    shell(channel);
    // l_shell(channel);
    // t_shell(channel);
}

fn exec(channel: Channel) {
    let exec: ChannelExec = channel.open_exec().unwrap();
    let vec = exec.set_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
}

fn shell(channel: Channel) {
    let mut shell = channel.open_shell().unwrap();
    thread::sleep(time::Duration::from_millis(200));
    let vec = shell.read().unwrap();
    let result = String::from_utf8(vec).unwrap();
    println!("{}", result);
    shell.write(b"ls -a\r").unwrap();
    thread::sleep(time::Duration::from_millis(200));
    let vec = shell.read().unwrap();
    let result = String::from_utf8(vec).unwrap();
    println!("{}", result);
    shell.close().unwrap();
}

fn l_shell(channel: Channel) {
    let mut shell = channel.open_shell().unwrap();
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

fn t_shell(channel: Channel) {
    let shell = channel.open_shell().unwrap();
    let c1 = Arc::new(Mutex::new(shell));
    let c2 = Arc::clone(&c1);
    let t1 = thread::spawn( move || {
        loop {
            let x = c1.lock().unwrap().read().unwrap();
            if x.is_empty() { continue }
            stdout().write(x.as_slice()).unwrap();
            stdout().flush().unwrap();
        }
    });

    let t2 = thread::spawn( move || {
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


## In addition to encryption library, pure RUST implementation of SSH-2.0 client protocol

### Because there is a lot of unfinished work, there may be problems if you compile the code directly from the main branch

### Quick example (简单例子):
```rust
fn main() {
    let ssh: SSH = SSH::new();
    // enable logging
    ssh.enable_log(true).unwrap();
    let mut session = ssh.get_session("127.0.0.1:22").unwrap();
    session.set_user_and_password("root", "123456");
    session.connect().unwrap();
    
    // exec(&mut session);
    // shell(&mut session);
    // t_shell(&mut session);
    
  
    // let mut scp = session.open_scp().unwrap();
    // file upload
    // scp.upload("localPath", "remotePath").unwrap();
    // file download
    // scp.download("localPath", "remotePath").unwrap();
}

fn exec(session: &mut Session) {
    let exec: ChannelExec = session.open_exec().unwrap();
    let vec = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
}

fn shell(session: &mut Session) {
    let mut shell = session.open_shell().unwrap();
    thread::sleep(time::Duration::from_millis(200));
    let vec = shell.read().unwrap();
    let result = String::from_utf8(vec).unwrap();
    println!("{}", result);
    shell.write(b"ls -a\n").unwrap();
    thread::sleep(time::Duration::from_millis(200));
    let vec = shell.read().unwrap();
    let result = String::from_utf8(vec).unwrap();
    println!("{}", result);
    shell.close().unwrap();
}

fn t_shell(session: &mut Session) {
    let shell = session.open_shell().unwrap();
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



### Not currently supported *sftp* (目前不支持 sftp)


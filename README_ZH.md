# ssh-rs ? 

---

[English](https://github.com/1148118271/ssh-rs/blob/main/README.md)  |  [��������](https://github.com/1148118271/ssh-rs/blob/main/README_ZH.md)

rustʵ�ֵ�ssh2.0�ͻ��ˡ�

�����ʹ���������κ����⣬��ӭ [issues](https://github.com/1148118271/ssh-rs/issues) 
���� [PR](https://github.com/1148118271/ssh-rs/pulls) ��

### ���ӷ�ʽ��

---

#### 1. ��������:
```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    session.set_user_and_password("�û�", "����");
    session.connect("ip:port").unwrap();
}
```

#### 2. ��Կ����:
##### Ŀǰֻ֧�ּ��ܸ�ʽ��`-----BEGIN RSA PRIVATE KEY-----`���ֵ�`RSA-PKCS#1-PEM`���͵ļ����ļ���

##### 1. ʹ����Կ�ļ���ַ��
```rust
use ssh_rs::{Session, ssh};
use ssh_rs::key_pair::KeyPairType;

fn main() {
    let mut session: Session = ssh::create_session();
    // pem��ʽ��Կ��ַ -> /xxx/xxx/id_rsa
    // KeyPairType::SshRsa rsa�����㷨��Ŀǰֻ֧��rsa
    session.set_user_and_key_pair_path("�û�", "pem��ʽ��Կ��ַ", KeyPairType::SshRsa).unwrap();
    session.connect("ip:port").unwrap();
}    
```

##### 2. ʹ����Կ�ַ�����
```rust
use ssh_rs::{Session, ssh};
use ssh_rs::key_pair::KeyPairType;

fn main() {
    let mut session: Session = ssh::create_session();
    // pem��ʽ��Կ�ַ���:
    //      -----BEGIN RSA PRIVATE KEY-----
    //          xxxxxxxxxxxxxxxxxxxxx
    //      -----END RSA PRIVATE KEY-----
    // KeyPairType::SshRsa rsa�����㷨��Ŀǰֻ֧��rsa
    session.set_user_and_key_pair("�û�", "pem��ʽ��Կ�ַ���", KeyPairType::SshRsa).unwrap();
    session.connect("ip:port").unwrap();
}
```


### ����ȫ����־��

---

```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    // is_enable_log �Ƿ�����ȫ����־
    // Ĭ��Ϊ false�������ã�
    // ������Ϊ true�����ã�
    session.is_enable_log(true);
    session.set_user_and_password("�û�", "����");
    session.connect("ip:port").unwrap();
}
```


### ���ó�ʱʱ�䣺

---

```rust
use ssh_rs::{Session, ssh};

fn main() {
    let mut session: Session = ssh::create_session();
    // set_timeout ���ó�ʱʱ��
    // ��λΪ ��
    // Ĭ�ϳ�ʱʱ���� 30��
    session.set_timeout(15);
    session.set_user_and_password("�û�", "����");
    session.connect("ip:port").unwrap();
}
```


### ʹ�÷�ʽ��

---

#### Ŀǰֻ֧�� exec shell scp �����ֹ���

#### 1. exec

```rust
use ssh_rs::{ChannelExec, Session, ssh};

fn main() {
    let mut session: Session = session();
    // ��ʽһ
    let exec: ChannelExec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // ��ʽ��
    let channel = session.open_channel().unwrap();
    let exec = channel.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // �رջỰ
    session.close().unwrap();
}
```

#### 2. shell

```rust
use std::thread::sleep;
use std::time::Duration;
use ssh_rs::{Channel, ChannelShell, Session, ssh};

fn main() {
    let mut session: Session = session();
    // ��ʽһ
    let mut shell: ChannelShell = session.open_shell().unwrap();
    run_shell(&mut shell);
    // ��ʽ��
    let channel: Channel = session.open_channel().unwrap();
    let mut shell = channel.open_shell().unwrap();
    run_shell(&mut shell);
    // �ر�ͨ��
    shell.close().unwrap();
    // �رջỰ
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

#### 3. scp

```rust
use ssh_rs::{Channel, ChannelScp, Session, ssh};

fn main() {
    let mut session: Session = session();
    // ��ʽһ
    // �ϴ�
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("����·��", "Զ��·��").unwrap();
    // ����
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("����·��", "Զ��·��").unwrap();

    // ��ʽ��
    // �ϴ�
    let channel: Channel = session.open_channel().unwrap();
    let scp: ChannelScp = channel.open_scp().unwrap();
    scp.upload("����·��", "Զ��·��").unwrap();
    // ����
    let channel: Channel = session.open_channel().unwrap();
    let scp: ChannelScp = channel.open_scp().unwrap();
    scp.download("����·��", "Զ��·��").unwrap();

    session.close().unwrap();
}

```


### �㷨֧�֣�

---

#### 1. ��Կ�����㷨
`curve25519-sha256`
`ecdh-sha2-nistp256` 

#### 2. ������Կ�㷨
`ssh-ed25519`
`ssh-rsa` 

#### 3. �����㷨���ͻ��˵�����ˣ�
`chacha20-poly1305@openssh.com`
`aes128-ctr` 

#### 4. �����㷨������˵��ͻ��ˣ�
`chacha20-poly1305@openssh.com`
`aes128-ctr` 

#### 5. MAC�㷨���ͻ��˵�����ˣ�
`hmac-sha1`

#### 6. MAC�㷨������˵��ͻ��ˣ�
`hmac-sha1`

#### 7. ѹ���㷨���ͻ��˵�����ˣ�
`none`

#### 8. ѹ���㷨������˵��ͻ��ˣ�
`none`

---

#### ?? �������������㷨��
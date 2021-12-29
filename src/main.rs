use std::io::{stdin, stdout, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use zm_ssh::ZmSsh;

fn main() {
    let ssh = ZmSsh::new();
    let mut session = ssh.get_session("192.168.3.101:22").unwrap();
    session.set_user_and_password("ubuntu".to_string(), "gaoxiangkang".to_string());
    session.connect().unwrap();
    let mut channel = session.open_channel().unwrap();
    channel.open_shell().unwrap();

    let c1 = Arc::new(Mutex::new(channel));
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





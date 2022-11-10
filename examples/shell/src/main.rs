use ssh_rs::{ssh, LocalShell};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    ssh::debug();

    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .connect("127.0.0.1:22")
        .unwrap()
        .run_local();
    // Usage 1
    let mut shell = session.open_shell().unwrap();
    run_shell(&mut shell);

    // Close channel.
    shell.close().unwrap();
    // Close session.
    session.close();
}

fn run_shell(shell: &mut LocalShell<std::net::TcpStream>) {
    sleep(Duration::from_millis(500));
    let vec = shell.read().unwrap();
    println!("{}", String::from_utf8(vec).unwrap());

    shell.write(b"ls -all\n").unwrap();

    sleep(Duration::from_millis(500));

    let vec = shell.read().unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
}

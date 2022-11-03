use ssh_rs::{ssh, Channel, ChannelShell, Session};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let mut session = ssh::create_session();
    session.set_user_and_password("ubuntu", "password");
    session.connect("127.0.0.1:22").unwrap();
    // Usage 1
    let mut shell = session.open_shell().unwrap();
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

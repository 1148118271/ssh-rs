use ssh_rs::{ssh, LocalShell, SshErrorKind};
use std::time::Duration;

fn main() {
    ssh::enable_log();

    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .timeout(Some(Duration::from_millis(1000)))
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
    let out = shell.read().unwrap();
    print!("{}", String::from_utf8(out).unwrap());

    shell.write(b"ls -lah\n").unwrap();

    loop {
        match shell.read() {
            Ok(out) => print!("{}", String::from_utf8(out).unwrap()),
            Err(e) => {
                if let SshErrorKind::Timeout = e.kind() {
                    break;
                } else {
                    panic!("{}", e.to_string())
                }
            }
        }
    }
}

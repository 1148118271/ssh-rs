use ssh_rs::ssh;

fn main() {
    ssh::is_enable_log(true);

    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .build();
    session.connect("127.0.0.1:22").unwrap();
    // Usage 1
    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Usage 2
    let channel = session.open_channel().unwrap();
    let exec = channel.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Close session.
    session.close();
}

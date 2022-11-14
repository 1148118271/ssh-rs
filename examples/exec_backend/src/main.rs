use ssh_rs::ssh;

fn main() {
    ssh::enable_log();

    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .connect("127.0.0.1:22")
        .unwrap()
        .run_backend();
    let exec = session.open_exec().unwrap();

    const CMD: &str = "ls -lah";

    // send the command to server
    println!("Send command {}", CMD);
    exec.send_command(CMD).unwrap();

    // process other data
    println!("Do someother thing");

    // get command result
    let vec: Vec<u8> = exec.get_result().unwrap();
    println!("{}", String::from_utf8(vec).unwrap());

    // Close session.
    session.close();
}

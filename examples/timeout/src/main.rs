use ssh_rs::ssh;
use std::net::TcpListener;
use std::time::Duration;

fn main() {
    ssh::enable_log();

    let _listener = TcpListener::bind("127.0.0.1:7777").unwrap();
    match ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .timeout(Some(Duration::from_secs(5)))
        .connect("127.0.0.1:7777")
    {
        Err(e) => println!("Got error {}", e),
        _ => unreachable!(),
    }
}

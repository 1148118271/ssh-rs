use ssh_rs::ssh;
use std::net::TcpListener;

fn main() {
    ssh::debug();

    let _listener = TcpListener::bind("127.0.0.1:7777").unwrap();
    match ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .timeout(5)
        .connect("127.0.0.1:7777")
    {
        Err(e) => println!("Got error {}", e),
        _ => unreachable!(),
    }
}

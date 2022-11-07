use ssh_rs::constant::algorithms;
use ssh_rs::key_pair::KeyType;
use ssh_rs::ssh;

fn main() {
    ssh::is_enable_log(true);

    let mut session = ssh::create_session_without_default()
        .username("ubuntu")
        .private_key_path("./id_rsa", KeyType::SshRsa)
        .add_kex_algorithms(algorithms::Kex::Curve25519Sha256)
        .add_pubkey_algorithms(algorithms::PubKey::SshRsa)
        .add_enc_algorithms(algorithms::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithms::Compress::None)
        .add_mac_algortihms(algorithms::Mac::HmacSha1)
        .build();
    session.connect("127.0.0.1:22").unwrap();
    // Usage 1
    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Close session.
    session.close().unwrap();
}

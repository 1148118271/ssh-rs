use ssh_rs::algorithm;
use ssh_rs::ssh;

fn main() {
    ssh::is_enable_log(true);

    let mut session = ssh::create_session_without_default()
        .username("ubuntu")
        .private_key_path("./id_rsa")
        .password("password")
        .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_pubkey_algorithms(algorithm::PubKey::SshRsa)
        .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithm::Compress::None)
        .add_mac_algortihms(algorithm::Mac::HmacSha1)
        .build();
    session.connect("127.0.0.1:22").unwrap();
    // Usage 1
    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Close session.
    session.close();
}

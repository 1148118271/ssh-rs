use ssh_rs::{ssh, ChannelScp};

fn main() {
    let mut session = ssh::create_session();
    session.set_user_and_password("ubuntu", "password");
    session.connect("127.0.0.1:22").unwrap();
    // Usage 1

    // upload a file
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("./src/main.rs", "./").unwrap();
    assert_file("/home/ubuntu/main.rs");

    // upload with a rename
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("./src/main.rs", "./abc").unwrap();
    assert_file("/home/ubuntu/abc");

    // upload to an implicit dir
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("./src/main.rs", "./test").unwrap();
    assert_file("/home/ubuntu/test/main.rs");

    // upload a dir
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("./src", "./test").unwrap();
    assert_file("/home/ubuntu/test/src/main.rs");
    assert_file("/home/ubuntu/test/src");

    // upload a with a rename
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.upload("./src", "./crs").unwrap();
    assert_file("/home/ubuntu/crs/main.rs");
    assert_file("/home/ubuntu/crs");

    // download a file
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("./", "test/a").unwrap();
    assert_file("./a");

    // download with a rename
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("./b", "test/a").unwrap();
    assert_file("./b");

    // download to an implicit dir
    let scp: ChannelScp = session.open_scp().unwrap();
    let _ = std::fs::create_dir("dir");
    scp.download("./dir", "test/a").unwrap();
    assert_file("./dir/a");
    assert_file("./dir");

    // download a dir
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("./", "test").unwrap();
    assert_file("./test/a");
    assert_file("./test");

    // download with a rename
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("./dir2", "test").unwrap();
    assert_file("./dir2/a");
    assert_file("./dir2");

    // download with a rename #2
    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("./dir2/", "test").unwrap();
    assert_file("./dir2/a");
    assert_file("./dir2");

    // Usage 2
    // let channel: Channel = session.open_channel().unwrap();
    // let scp: ChannelScp = channel.open_scp().unwrap();
    // scp.upload("local path", "remote path").unwrap();

    // let channel: Channel = session.open_channel().unwrap();
    // let scp: ChannelScp = channel.open_scp().unwrap();
    // scp.download("local path", "remote path").unwrap();

    session.close().unwrap();
}

fn assert_file(filename: &str) {
    let file = std::path::Path::new(filename);

    println!("Assert {}", filename);
    assert!(file.exists());

    let _ = std::fs::remove_file(file);
    let _ = std::fs::remove_dir(file);
}

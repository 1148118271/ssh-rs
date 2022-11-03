use ssh_rs::{ssh, Channel, ChannelScp, Session};

fn main() {
    ssh::is_enable_log(true);
    let mut session = ssh::create_session();
    session.set_user_and_password("ubuntu", "password");
    session.connect("127.0.0.1:22").unwrap();
    // Usage 1
    // let scp: ChannelScp = session.open_scp().unwrap();
    // scp.upload("local path", "remote path").unwrap();

    let scp: ChannelScp = session.open_scp().unwrap();
    scp.download("local path", "remote path").unwrap();

    // Usage 2
    // let channel: Channel = session.open_channel().unwrap();
    // let scp: ChannelScp = channel.open_scp().unwrap();
    // scp.upload("local path", "remote path").unwrap();

    // let channel: Channel = session.open_channel().unwrap();
    // let scp: ChannelScp = channel.open_scp().unwrap();
    // scp.download("local path", "remote path").unwrap();

    session.close().unwrap();
}

impl<S> SessionInner<S>
where
    S: Read + Write,
{
    pub fn open_channel(&mut self) -> SshResult<Channel<S>> {
        log::info!("channel opened.");
        self.send_open_channel(self.client_channel_no)?;
        let (server_channel_no, rws) = self.receive_open_channel()?;
        // 打开成功， 通道号+1
        let mut win_size = WindowSize::new();
        win_size.server_channel_no = server_channel_no;
        win_size.client_channel_no = self.client_channel_no;
        win_size.add_remote(rws);

        self.client_channel_no += 1;

        Ok(Channel {
            remote_close: false,
            local_close: false,
            window_size: win_size,
            client: self.get_client()?,
        })
    }


    pub fn open_shell(&mut self) -> SshResult<ChannelShell<S>> {
        let channel = self.open_channel()?;
        channel.open_shell()
    }

    pub fn open_scp(&mut self) -> SshResult<ChannelScp<S>> {
        let channel = self.open_channel()?;
        channel.open_scp()
    }
}


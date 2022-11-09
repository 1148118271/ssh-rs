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
        win_size.add_remote_window_size(rws);

        self.client_channel_no += 1;

        Ok(Channel {
            remote_close: false,
            local_close: false,
            window_size: win_size,
            client: self.get_client()?,
        })
    }

    pub fn open_exec(&mut self) -> SshResult<ChannelExec<S>> {
        let channel = self.open_channel()?;
        channel.open_exec()
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

impl<S> SessionInner<S>
where
    S: Read + Write,
{
    // 本地请求远程打开通道
    fn send_open_channel(&mut self, client_channel_no: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_channel_no)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        self.get_client()?.as_ref().borrow_mut().write(data)
    }

    // 远程回应是否可以打开通道
    fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let results = self.get_client()?.as_ref().borrow_mut().read()?;
            for mut result in results {
                if result.is_empty() {
                    continue;
                }
                let message_code = result.get_u8();
                match message_code {
                    // 打开请求通过
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        // 接收方通道号
                        result.get_u32();
                        // 发送方通道号
                        let server_channel_no = result.get_u32();
                        // 远程初始窗口大小
                        let rws = result.get_u32();
                        // 远程的最大数据包大小， 暂时不需要
                        result.get_u32();
                        return Ok((server_channel_no, rws));
                    }
                    /*
                        byte SSH_MSG_CHANNEL_OPEN_FAILURE
                        uint32 recipient channel
                        uint32 reason code
                        string description，ISO-10646 UTF-8 编码[RFC3629]
                        string language tag，[RFC3066]
                    */
                    // 打开请求拒绝
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                        result.get_u32();
                        // 失败原因码
                        let code = result.get_u32();
                        // 消息详情 默认utf-8编码
                        let description = String::from_utf8(result.get_u8s())
                            .unwrap_or_else(|_| String::from("error"));
                        // language tag 暂不处理， 应该是 en-US
                        result.get_u8s();

                        let err_msg = match code {
                            ssh_msg_code::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED => {
                                format!("SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: {}", description)
                            }
                            ssh_msg_code::SSH_OPEN_CONNECT_FAILED => {
                                format!("SSH_OPEN_CONNECT_FAILED: {}", description)
                            }
                            ssh_msg_code::SSH_OPEN_UNKNOWN_CHANNEL_TYPE => {
                                format!("SSH_OPEN_UNKNOWN_CHANNEL_TYPE: {}", description)
                            }
                            ssh_msg_code::SSH_OPEN_RESOURCE_SHORTAGE => {
                                format!("SSH_OPEN_RESOURCE_SHORTAGE: {}", description)
                            }
                            _ => description,
                        };
                        return Err(SshError::from(err_msg));
                    }
                    _ => {}
                }
            }
        }
    }
}

use std::io::{Read, Write};

use crate::algorithm::{
    encryption,
    key_exchange::{self, KeyExchange},
    mac,
    public_key::{self, PublicKey},
};
use crate::constant::ssh_msg_code;
use crate::data::Data;
use crate::error::{SshError, SshResult};
use crate::slog::log;
use crate::window_size::WindowSize;
use crate::{algorithm::hash, config::algorithm::AlgList};
use crate::{client::Client, h::H, util};

/// 发送客户端的算法列表
pub(crate) fn send_algorithm<S>(
    h: &mut H,
    client: &mut Client<S>,
    rws: Option<&mut WindowSize>,
) -> SshResult<()>
where
    S: Read + Write,
{
    log::info!(
        "client algorithms: [{:?}]",
        client.config.lock().unwrap().algs
    );
    let mut data = Data::new();
    data.put_u8(ssh_msg_code::SSH_MSG_KEXINIT);
    data.extend(util::cookie());
    data.extend(client.config.lock().unwrap().algs.as_i());
    data.put_str("")
        .put_str("")
        .put_u8(false as u8)
        .put_u32(0_u32);
    // 客户端算法
    h.set_i_c(data.clone().as_slice());
    match rws {
        None => client.write(data)?,
        Some(ws) => client.write_data(data, Some(ws))?,
    }
    Ok(())
}

/// 获取服务端的算法列表
pub(crate) fn receive_algorithm<S>(
    h: &mut H,
    client: &mut Client<S>,
    mut rws: Option<&mut WindowSize>,
) -> SshResult<AlgList>
where
    S: Read + Write,
{
    loop {
        let results = match &mut rws {
            None => client.read()?,
            Some(ws) => client.read_data(Some(ws))?,
        };
        for result in results {
            if result.is_empty() {
                continue;
            }
            let message_code = result[0];
            if message_code == ssh_msg_code::SSH_MSG_KEXINIT {
                h.set_i_s(result.as_slice());

                return AlgList::from(result);
            }
        }
    }
}

/// 发送客户端公钥
pub(crate) fn send_qc<S>(
    client: &mut Client<S>,
    public_key: &[u8],
    rws: Option<&mut WindowSize>,
) -> SshResult<()>
where
    S: Read + Write,
{
    let mut data = Data::new();
    data.put_u8(ssh_msg_code::SSH_MSG_KEXDH_INIT);
    data.put_u8s(public_key);
    match rws {
        None => client.write(data),
        Some(ws) => client.write_data(data, Some(ws)),
    }
}

/// 接收服务端公钥和签名，并验证签名的正确性
pub(crate) fn verify_signature_and_new_keys<S>(
    client: &mut Client<S>,
    public_key: &mut Box<dyn PublicKey>,
    key_exchange: &mut Box<dyn KeyExchange>,
    h: &mut H,
    mut rws: Option<&mut WindowSize>,
) -> SshResult<Vec<u8>>
where
    S: Read + Write,
{
    let mut session_id = vec![];
    loop {
        let results = match &mut rws {
            None => client.read()?,
            Some(ws) => client.read_data(Some(ws))?,
        };
        for mut result in results {
            if result.is_empty() {
                continue;
            }
            let message_code = result.get_u8();
            match message_code {
                ssh_msg_code::SSH_MSG_KEXDH_REPLY => {
                    // 生成session_id并且获取signature
                    let sig = generate_signature(result, h, key_exchange)?;
                    // 验签
                    session_id = hash::digest(&h.as_bytes(), key_exchange.get_hash_type());
                    let flag = public_key.verify_signature(&h.k_s, &session_id, &sig)?;
                    if !flag {
                        log::error!("signature verification failure.");
                        return Err(SshError::from("signature verification failure."));
                    }
                    log::info!("signature verification success.");
                }
                ssh_msg_code::SSH_MSG_NEWKEYS => {
                    match &mut rws {
                        None => new_keys(client, None)?,
                        Some(ws) => new_keys(client, Some(ws))?,
                    };
                    return Ok(session_id);
                }
                _ => {}
            }
        }
    }
}

/// 生成签名
pub(crate) fn generate_signature(
    mut data: Data,
    h: &mut H,
    key_exchange: &mut Box<dyn KeyExchange>,
) -> SshResult<Vec<u8>> {
    let ks = data.get_u8s();
    h.set_k_s(&ks);
    // TODO 未进行密钥指纹验证！！
    let qs = data.get_u8s();
    h.set_q_c(key_exchange.get_public_key());
    h.set_q_s(&qs);
    let vec = key_exchange.get_shared_secret(qs)?;
    h.set_k(&vec);
    let h = data.get_u8s();
    let mut hd = Data::from(h);
    hd.get_u8s();
    let signature = hd.get_u8s();
    Ok(signature)
}

/// SSH_MSG_NEWKEYS 代表密钥交换完成
pub(crate) fn new_keys<S>(
    client: &mut Client<S>,
    rws: Option<&mut WindowSize>,
) -> Result<(), SshError>
where
    S: Read + Write,
{
    let mut data = Data::new();
    data.put_u8(ssh_msg_code::SSH_MSG_NEWKEYS);
    match rws {
        None => client.write(data)?,
        Some(ws) => client.write_data(data, Some(ws))?,
    }
    log::info!("send new keys");
    Ok(())
}

pub(crate) fn key_agreement<S>(
    h: &mut H,
    client: &mut Client<S>,
    mut rws: Option<&mut WindowSize>,
) -> SshResult<hash::HashType>
where
    S: Read + Write,
{
    log::info!("start for key negotiation.");
    log::info!("send client algorithm list.");
    match &mut rws {
        None => send_algorithm(h, client, None)?,
        Some(ws) => send_algorithm(h, client, Some(ws))?,
    }
    log::info!("receive server algorithm list.");
    let server_algs = match &mut rws {
        None => receive_algorithm(h, client, None)?,
        Some(ws) => receive_algorithm(h, client, Some(ws))?,
    };

    let negotiated = client
        .config
        .lock()
        .unwrap()
        .algs
        .match_with(&server_algs)?;

    let mut key_exchange = key_exchange::from(negotiated.key_exchange.0[0].as_str())?;
    let mut public_key = public_key::from(negotiated.public_key.0[0].as_str());
    match &mut rws {
        None => send_qc(client, key_exchange.get_public_key(), None)?,
        Some(ws) => send_qc(client, key_exchange.get_public_key(), Some(ws))?,
    }
    let session_id = match &mut rws {
        None => verify_signature_and_new_keys(client, &mut public_key, &mut key_exchange, h, None)?,
        Some(ws) => {
            verify_signature_and_new_keys(client, &mut public_key, &mut key_exchange, h, Some(ws))?
        }
    };
    // session id 只使用第一次密钥交换时生成的
    if client.session_id.is_empty() {
        if session_id.is_empty() {
            return Err(SshError::from("session id is none."));
        }
        client.session_id = session_id;
    }
    let hash_type = key_exchange.get_hash_type();
    let hash = hash::hash::Hash::new(h.clone(), &client.session_id, hash_type);
    // mac 算法
    let mac = mac::from(negotiated.c_mac.0[0].as_str());
    // 加密算法
    let encryption = encryption::from(negotiated.c_encryption.0[0].as_str(), hash, mac);

    client.encryption = Some(encryption);
    client.is_encryption = true;
    client.negotiated = negotiated;

    log::info!("key negotiation successful.");
    Ok(hash_type)
}

use crate::constant::ssh_msg_code;
use crate::error::{SshError, SshResult};
use crate::data::Data;
use crate::slog::log;
use crate::config::{
    Config,
    CompressionAlgorithm,
    EncryptionAlgorithm,
    KeyExchangeAlgorithm,
    MacAlgorithm,
    PublicKeyAlgorithm
};
use crate::{
    util,
    h::H,
    client::Client,
};
use crate::algorithm::hash;
use crate::algorithm::key_exchange::KeyExchange;
use crate::algorithm::public_key::PublicKey;



/// 发送客户端的算法列表
pub(crate) fn send_algorithm(h: &mut H,
                             client: &mut Client,
) -> SshResult<()>
{
    log::info!("client algorithms: [{}]", client.config.algorithm.client_algorithm.to_string());
    let mut data = Data::new();
    data.put_u8(ssh_msg_code::SSH_MSG_KEXINIT);
    data.extend(util::cookie());
    data.extend(client.config.algorithm.client_algorithm.as_i());
    data.put_str("")
    .put_str("")
    .put_u8(false as u8)
    .put_u32(0_u32);
    // 客户端算法
    h.set_i_c(data.clone().as_slice());
    client.write(data)?;
    Ok(())
}

/// 获取服务端的算法列表
pub(crate) fn receive_algorithm(h: &mut H,
                                client: &mut Client,
) -> SshResult<()>
{
    loop {
        let results = client.read()?;
        for result in results {
            if result.is_empty() { continue }
            let message_code = result[0];
            match message_code {
                ssh_msg_code::SSH_MSG_KEXINIT => {
                    h.set_i_s(result.clone().as_slice());
                    processing_server_algorithm(&mut client.config, result)?;
                    return Ok(());
                }
                _ => {}
            }
        }
    }
}

/// 处理服务端的算法列表
pub(crate) fn processing_server_algorithm(config: &mut Config, mut data: Data) -> SshResult<()> {
    data.get_u8();
    // 跳过16位cookie
    data.skip(16);
    let server_algorithm = &mut config.algorithm.server_algorithm;
    server_algorithm.key_exchange_algorithm     =   KeyExchangeAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.public_key_algorithm       =   PublicKeyAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.c_encryption_algorithm     =   EncryptionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.s_encryption_algorithm     =   EncryptionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.c_mac_algorithm            =   MacAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.s_mac_algorithm            =   MacAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.c_compression_algorithm    =   CompressionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    server_algorithm.s_compression_algorithm    =   CompressionAlgorithm(util::vec_u8_to_string(data.get_u8s(), ",")?);
    log::info!("server algorithms: [{}]", server_algorithm.to_string());
    return Ok(())
}


/// 发送客户端公钥
pub(crate) fn send_qc(client: &mut Client, public_key: &[u8]) -> SshResult<()> {
    let mut data = Data::new();
    data.put_u8(ssh_msg_code::SSH_MSG_KEXDH_INIT);
    data.put_u8s(public_key);
    client.write(data)
}

/// 接收服务端公钥和签名，并验证签名的正确性
pub(crate) fn verify_signature_and_new_keys(client: &mut Client,
                                            public_key: &mut Box<dyn PublicKey>,
                                            key_exchange: &mut Box<dyn KeyExchange>,
                                            h: &mut H
) -> SshResult<Vec<u8>>
{
    let mut session_id = vec![];
    loop {
        let results = client.read()?;
        for mut result in results {
            if result.is_empty() { continue }
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
                        return Err(SshError::from("signature verification failure."))
                    }
                    log::info!("signature verification success.");
                }
                ssh_msg_code::SSH_MSG_NEWKEYS => {
                    new_keys(client)?;
                    return Ok(session_id)
                }
                _ => {}
            }
        }
    }
}

/// 生成签名
pub(crate) fn generate_signature(mut data: Data,
                                 h: &mut H,
                                 key_exchange: &mut Box<dyn KeyExchange>
) -> SshResult<Vec<u8>>
{
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
pub(crate) fn new_keys(client: &mut Client) -> Result<(), SshError> {
    let mut data = Data::new();
    data.put_u8(ssh_msg_code::SSH_MSG_NEWKEYS);
    client.write(data)?;
    log::info!("send new keys");
    Ok(())
}


pub(crate) fn key_agreement(h: &mut H,
                            client: &mut Client,
) -> SshResult<hash::HashType>
{
    log::info!("start for key negotiation.");
    log::info!("send client algorithm list.");
    send_algorithm(h, client)?;
    log::info!("receive server algorithm list.");
    receive_algorithm(h, client)?;

    let mut key_exchange = client.config.algorithm.matching_key_exchange_algorithm()?;
    let mut public_key = client.config.algorithm.matching_public_key_algorithm()?;

    send_qc(client, key_exchange.get_public_key())?;
    let session_id = verify_signature_and_new_keys(client, &mut public_key, &mut key_exchange, h)?;
    // session id 只使用第一次密钥交换时生成的
    if client.session_id.is_empty() {
        if session_id.is_empty() {
            return Err(SshError::from("session id is none."))
        }
        client.session_id = session_id;
    }
    let hash_type = key_exchange.get_hash_type();
    let hash = hash::hash::HASH::new(h.clone(), &client.session_id, hash_type);
    // mac 算法
    let mac = client.config.algorithm.matching_mac_algorithm()?;
    // 加密算法
    let encryption = client.config.algorithm.matching_encryption_algorithm(hash, mac)?;

    client.encryption = Some(encryption);
    client.is_encryption = true;

    log::info!("key negotiation successful.");
    Ok(hash_type)
}
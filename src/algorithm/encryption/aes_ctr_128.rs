use aes::Aes128Ctr;
use aes::cipher::{NewCipher, StreamCipher};
use ring::hmac;
use crate::algorithm::hash;
use crate::{SshError, SshResult};
use crate::algorithm::encryption::Encryption;
use crate::error::SshErrorKind;


const BSIZE: u32 = 16;
const IV_SIZE: u32 = 16;


pub struct AesCtr128 {
    pub(crate) client_key: Aes128Ctr,
    pub(crate) server_key: Aes128Ctr,
}

impl Encryption for AesCtr128 {
    fn bsize(&self) -> u32 {
        BSIZE
    }
    fn iv_size(&self) -> u32 {
        IV_SIZE
    }

    fn new() -> Self {
        let hash = hash::get();
        let (ck, sk) = hash.extend_key(BSIZE);
        let mut ckey = [0u8; 16];
        let mut skey = [0u8; 16];

        let mut civ = [0u8; 16];
        let mut siv = [0u8; 16];

        ckey.clone_from_slice(&ck[..16]);
        skey.clone_from_slice(&sk[..16]);

        // TODO IV 需要计算长度
        civ.clone_from_slice(&hash.iv_c_s[..16]);
        siv.clone_from_slice(&hash.iv_s_c[..16]);

        // TODO unwrap 未处理
        let c = Aes128Ctr::new_from_slices(&ckey, &civ).unwrap();
        let r = Aes128Ctr::new_from_slices(&skey, &siv).unwrap();

        AesCtr128 {
            client_key: c,
            server_key: r,
        }
    }

    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
        unsafe {
            println!("buf str => {}", String::from_utf8_unchecked(buf.clone()));
            println!("buf  => {:?}", buf)
        }
        println!(">>>>>>>");
        let vec = buf.clone();
        let mut hk = [0_u8; 20];
        println!("hk {:?}", hk);
        let ik_c_s = &hash::get().ik_c_s[..20];
        println!("ik_c_s {:?}", ik_c_s);
        hk.clone_from_slice(ik_c_s);
        println!("hk {:?}", hk);
        let s_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &hk);
        let mut s_ctx = hmac::Context::with_key(&s_key);
        s_ctx.update(client_sequence_num.to_be_bytes().as_slice());
        s_ctx.update(vec.as_slice());
        let tag = s_ctx.sign();
        self.client_key.apply_keystream(buf);
        buf.extend(tag.as_ref())
    }

    fn decrypt(&mut self, sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        let pl = self.packet_len(sequence_number, buf);
        println!("pl => {}", pl);
        let data = &mut buf[..(pl + 20) as usize];
        let (d, m) = data.split_at_mut(pl as usize);
        self.server_key.apply_keystream(d);
        let mut hk = [0_u8; 20];
        hk.clone_from_slice(&(hash::get().ik_c_s[..20]));
        let s_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &hk);
        let mut s_ctx = hmac::Context::with_key(&s_key);
        s_ctx.update(sequence_number.to_be_bytes().as_slice());
        s_ctx.update(d);
        let tag = s_ctx.sign();
        let t = tag.as_ref();
        if m != t {
            return Err(SshError::from(SshErrorKind::EncryptionError))
        }
        Ok(d.to_vec())
    }

    fn packet_len(&mut self, sequence_number: u32, buf: &[u8]) -> u32 {
        let mut r = vec![0_u8; self.bsize() as usize];
        r.clone_from_slice(&buf[..self.bsize() as usize]);
        self.server_key.apply_keystream(&mut r);
        let mut u32_bytes = [0_u8; 4];
        u32_bytes.clone_from_slice(&r[..4]);
        println!("u32_bytes => {:?}", u32_bytes);
        let packet_len = u32::from_be_bytes(u32_bytes);
        println!("packet_len => {}", packet_len);
        packet_len
    }

    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
        // TODO 20 是 hmac 长度
        (self.packet_len(sequence_number, buf) + 20) as usize

    }

}
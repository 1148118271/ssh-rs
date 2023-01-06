use crate::algorithm::encryption::Encryption;
use crate::algorithm::hash::Hash;
use crate::algorithm::mac::Mac;
use crate::error::SshError;
use crate::SshResult;
use aes::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use aes::{Aes128Ctr, Aes192Ctr, Aes256Ctr};

// 拓展数据
struct Extend {
    // hmac
    mac: Box<dyn Mac>,
    ik_c_s: Vec<u8>,
    ik_s_c: Vec<u8>,
}
impl Extend {
    fn from(mac: Box<dyn Mac>, ik_c_s: Vec<u8>, ik_s_c: Vec<u8>) -> Self {
        Extend {
            mac,
            ik_c_s,
            ik_s_c,
        }
    }
}

const CTR128_BLOCK_SIZE: usize = 16;
const CTR192_BLOCK_SIZE: usize = 24;
const CTR256_BLOCK_SIZE: usize = 32;
const IV_SIZE: usize = 16;

// aes-128-ctr
pub(crate) struct Ctr128 {
    pub(crate) client_key: Aes128Ctr,
    pub(crate) server_key: Aes128Ctr,
    extend: Extend,
}

impl Encryption for Ctr128 {
    fn bsize(&self) -> usize {
        CTR128_BLOCK_SIZE
    }

    fn iv_size(&self) -> usize {
        IV_SIZE
    }

    fn group_size(&self) -> usize {
        IV_SIZE
    }

    fn new(hash: Hash, mac: Box<dyn Mac>) -> Self
    where
        Self: Sized,
    {
        crate::new!(Aes128Ctr, Ctr128, hash, mac, CTR128_BLOCK_SIZE, IV_SIZE)
    }

    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
        crate::encrypt!(self, client_sequence_num, buf)
    }

    fn decrypt(&mut self, server_sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        crate::decrypt!(self, server_sequence_number, buf)
    }

    fn packet_len(&mut self, _: u32, buf: &[u8]) -> usize {
        crate::pl!(self, buf)
    }

    fn data_len(&mut self, server_sequence_number: u32, buf: &[u8]) -> usize {
        crate::dl!(self, server_sequence_number, buf)
    }

    fn is_cp(&self) -> bool {
        false
    }
}

// aes-192-ctr
pub(crate) struct Ctr192 {
    pub(crate) client_key: Aes192Ctr,
    pub(crate) server_key: Aes192Ctr,
    extend: Extend,
}

impl Encryption for Ctr192 {
    fn bsize(&self) -> usize {
        CTR192_BLOCK_SIZE
    }

    fn iv_size(&self) -> usize {
        IV_SIZE
    }

    fn group_size(&self) -> usize {
        IV_SIZE
    }

    fn new(hash: Hash, mac: Box<dyn Mac>) -> Self
    where
        Self: Sized,
    {
        crate::new!(Aes192Ctr, Ctr192, hash, mac, CTR192_BLOCK_SIZE, IV_SIZE)
    }

    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
        crate::encrypt!(self, client_sequence_num, buf)
    }

    fn decrypt(&mut self, server_sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        crate::decrypt!(self, server_sequence_number, buf)
    }

    fn packet_len(&mut self, _: u32, buf: &[u8]) -> usize {
        crate::pl!(self, buf)
    }

    fn data_len(&mut self, server_sequence_number: u32, buf: &[u8]) -> usize {
        crate::dl!(self, server_sequence_number, buf)
    }

    fn is_cp(&self) -> bool {
        false
    }
}

// aes-256-ctr
pub(crate) struct Ctr256 {
    pub(crate) client_key: Aes256Ctr,
    pub(crate) server_key: Aes256Ctr,
    extend: Extend,
}

impl Encryption for Ctr256 {
    fn bsize(&self) -> usize {
        CTR256_BLOCK_SIZE
    }

    fn iv_size(&self) -> usize {
        IV_SIZE
    }

    fn group_size(&self) -> usize {
        IV_SIZE
    }

    fn new(hash: Hash, mac: Box<dyn Mac>) -> Self
    where
        Self: Sized,
    {
        crate::new!(Aes256Ctr, Ctr256, hash, mac, CTR256_BLOCK_SIZE, IV_SIZE)
    }

    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
        crate::encrypt!(self, client_sequence_num, buf)
    }

    fn decrypt(&mut self, server_sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        crate::decrypt!(self, server_sequence_number, buf)
    }

    fn packet_len(&mut self, _: u32, buf: &[u8]) -> usize {
        crate::pl!(self, buf)
    }

    fn data_len(&mut self, server_sequence_number: u32, buf: &[u8]) -> usize {
        crate::dl!(self, server_sequence_number, buf)
    }

    fn is_cp(&self) -> bool {
        false
    }
}

#[macro_export]
macro_rules! new {
    ($name1: ident, $name2: ident, $hash: expr, $mac: ident, $bs: expr, $is: expr) => {{
        let (ck, sk) = $hash.mix_ek($bs);
        let mut ckey = [0u8; $bs];
        let mut skey = [0u8; $bs];
        ckey.clone_from_slice(&ck[..$bs]);
        skey.clone_from_slice(&sk[..$bs]);

        let mut civ = [0u8; $is];
        let mut siv = [0u8; $is];
        civ.clone_from_slice(&$hash.iv_c_s[..$is]);
        siv.clone_from_slice(&$hash.iv_s_c[..$is]);

        // TODO unwrap 未处理
        let c = $name1::new_from_slices(&ckey, &civ).unwrap();
        let r = $name1::new_from_slices(&skey, &siv).unwrap();
        // hmac
        let (ik_c_s, ik_s_c) = $hash.mix_ik($mac.bsize());
        $name2 {
            client_key: c,
            server_key: r,
            extend: Extend::from($mac, ik_c_s, ik_s_c),
        }
    }};
}

#[macro_export]
macro_rules! encrypt {
    ($self: expr, $ssb: expr, $buf: expr) => {{
        let vec = $buf.clone();
        let tag = $self
            .extend
            .mac
            .sign(&$self.extend.ik_c_s, $ssb, vec.as_slice());
        $self.client_key.apply_keystream($buf);
        $buf.extend(tag.as_ref())
    }};
}

#[macro_export]
macro_rules! decrypt {
    ($self: expr, $ssb: expr, $buf: expr) => {{
        let pl = $self.packet_len($ssb, $buf);
        let data = &mut $buf[..(pl + $self.extend.mac.bsize())];
        let (d, m) = data.split_at_mut(pl);
        $self.server_key.apply_keystream(d);
        let tag = $self.extend.mac.sign(&$self.extend.ik_s_c, $ssb, d);
        let t = tag.as_ref();
        if m != t {
            return Err(SshError::from("encryption error."));
        }
        Ok(d.to_vec())
    }};
}

#[macro_export]
macro_rules! dl {
    ($self: expr, $ssb: expr, $buf: expr) => {{
        let pl = $self.packet_len($ssb, $buf);
        let bsize = $self.extend.mac.bsize();
        pl + bsize
    }};
}

#[macro_export]
macro_rules! pl {
    ($self: expr, $buf: expr) => {{
        let bsize = $self.bsize();
        let mut r = vec![0_u8; bsize];
        r.clone_from_slice(&$buf[..bsize]);
        $self.server_key.apply_keystream(&mut r);
        let pos: usize = $self.server_key.current_pos();
        $self.server_key.seek(pos - bsize);
        let mut u32_bytes = [0_u8; 4];
        u32_bytes.clone_from_slice(&r[..4]);
        let packet_len = u32::from_be_bytes(u32_bytes);
        (packet_len + 4) as usize
    }};
}

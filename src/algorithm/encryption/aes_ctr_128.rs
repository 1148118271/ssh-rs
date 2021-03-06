use aes::Aes128Ctr;
use aes::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use crate::algorithm::{hash, mac};
use crate::{SshError, SshResult};
use crate::algorithm::encryption::Encryption;



const BSIZE: usize = 16;
const IV_SIZE: usize = 16;


pub struct AesCtr128 {
    pub(crate) client_key: Aes128Ctr,
    pub(crate) server_key: Aes128Ctr,
}

impl Encryption for AesCtr128 {
    fn bsize(&self) -> usize {
        BSIZE
    }
    fn iv_size(&self) -> usize {
        IV_SIZE
    }

    fn new() -> Self {
        let hash = hash::get();
        let (ck, sk) = hash.extend_key(BSIZE);
        let mut ckey = [0u8; BSIZE];
        let mut skey = [0u8; BSIZE];

        let mut civ = [0u8; BSIZE];
        let mut siv = [0u8; BSIZE];

        ckey.clone_from_slice(&ck[..BSIZE]);
        skey.clone_from_slice(&sk[..BSIZE]);

        civ.clone_from_slice(&hash.iv_c_s[..IV_SIZE]);
        siv.clone_from_slice(&hash.iv_s_c[..IV_SIZE]);

        // TODO unwrap 未处理
        let c = Aes128Ctr::new_from_slices(&ckey, &civ).unwrap();
        let r = Aes128Ctr::new_from_slices(&skey, &siv).unwrap();

        AesCtr128 {
            client_key: c,
            server_key: r,
        }
    }

    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
        let vec = buf.clone();
        let mac = mac::get();
        let tag = mac.sign(&hash::get().ik_c_s[..mac::get().bsize()], client_sequence_num, vec.as_slice());
        self.client_key.apply_keystream(buf);
        buf.extend(tag.as_ref())
    }

    fn decrypt(&mut self, server_sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        let pl = self.packet_len(server_sequence_number, buf);
        let data = &mut buf[..(pl + 20)];
        let (d, m) = data.split_at_mut(pl);
        self.server_key.apply_keystream(d);
        let mac = mac::get();
        let tag = mac.sign(&hash::get().ik_s_c[..mac::get().bsize()], server_sequence_number, d);
        let t = tag.as_ref();
        if m != t {
            return Err(SshError::from("encryption error."))
        }
        Ok(d.to_vec())
    }

    fn packet_len(&mut self, _: u32, buf: &[u8]) -> usize {
        let bsize = self.bsize();
        let mut r = vec![0_u8; bsize];
        r.clone_from_slice(&buf[..bsize]);
        self.server_key.apply_keystream(&mut r);
        let pos: usize = self.server_key.current_pos();
        self.server_key.seek(pos - bsize);
        let mut u32_bytes = [0_u8; 4];
        u32_bytes.clone_from_slice(&r[..4]);
        let packet_len = u32::from_be_bytes(u32_bytes);
        (packet_len + 4) as usize
    }

    fn data_len(&mut self, server_sequence_number: u32, buf: &[u8]) -> usize {
        let pl = self.packet_len(server_sequence_number, buf);
        let bsize = mac::get().bsize();
        pl + bsize
    }

    fn is_cp(&self) -> bool {
        false
    }
}

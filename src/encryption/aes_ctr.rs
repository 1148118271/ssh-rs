use aes::Aes128Ctr;
use aes::cipher::{NewCipher, StreamCipher};
use ring::hmac;
use crate::encryption::HASH;
use crate::SshError;

pub struct AesCtr {
    pub(crate) client_key: Aes128Ctr,
    pub(crate) server_key: Aes128Ctr,
    pub(crate) hash      : HASH
}

impl AesCtr {
    pub(crate) fn bsize() -> u32 {
        16
    }
    pub(crate) fn iv_size() -> u32 {
        16
    }

    pub(crate) fn new(hash: HASH) -> AesCtr {
        let (ck, sk) = hash.extend_key(AesCtr::bsize());
        let mut ckey = [0u8; 16];
        let mut skey = [0u8; 16];

        let mut civ = [0u8; 16];
        let mut siv = [0u8; 16];

        ckey.clone_from_slice(&ck[..16]);
        skey.clone_from_slice(&sk[..16]);

        civ.clone_from_slice(&hash.iv_c_s[..16]);
        siv.clone_from_slice(&hash.iv_s_c[..16]);


        let mut c = Aes128Ctr::new_from_slices(&ckey, &civ).unwrap();
        let mut r = Aes128Ctr::new_from_slices(&skey, &siv).unwrap();

        AesCtr {
            client_key: c,
            server_key: r,
            hash
        }
    }

    pub(crate) fn encryption(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
        let vec = buf.clone();
        let mut hk = [0_u8; 20];
        hk.clone_from_slice(&(self.hash.ik_c_s[..20]));

        let s_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &hk);
        let mut s_ctx = hmac::Context::with_key(&s_key);
        s_ctx.update(client_sequence_num.to_be_bytes().as_slice());
        s_ctx.update(vec.as_slice());
        let tag = s_ctx.sign();
        self.client_key.apply_keystream(buf);
        buf.extend(tag.as_ref())
    }

    pub(crate) fn decryption(&mut self, buf: &mut Vec<u8>) -> Result<Vec<u8>, SshError> {
        self.server_key.apply_keystream(buf);
        return Ok(buf.clone())
    }

    pub(crate) fn packet_and_data_len(&mut self, buf: &[u8]) -> (u32, u32) {
        let mut r = vec![0_u8; AesCtr::bsize() as usize];
        r.clone_from_slice(&buf[..AesCtr::bsize() as usize]);
        self.server_key.apply_keystream(&mut r);
        let mut u32_bytes = [0_u8; 4];
        u32_bytes.clone_from_slice(&r[..4]);
        let packet_len = u32::from_be_bytes(u32_bytes);
        (packet_len, packet_len + AesCtr::bsize())
    }

}
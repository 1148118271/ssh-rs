use aes::Aes128Ctr;
use aes::cipher::{NewCipher, StreamCipher};
use ring::hmac;
use crate::encryption::HASH;
use crate::SshError;

pub struct AesCtr {
    pub client_key: Aes128Ctr,
    pub server_key: Aes128Ctr,
    pub hash      : HASH
}

impl AesCtr {
    pub fn bsize() -> u32 {
        16
    }
    pub fn iv_size() -> u32 {
        16
    }

    pub fn new(hash: HASH) -> AesCtr {
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

    pub fn encryption(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
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

    pub fn decryption(&mut self, buf: &mut Vec<u8>) -> Result<Vec<u8>, SshError> {

        self.server_key.apply_keystream(buf);

        return Ok(buf.clone())

        // let mut packet_len_slice = [0_u8; 4];
        // let len = &buf[..4];
        // packet_len_slice.copy_from_slice(len);
        // let packet_len_slice = self.server_key.decrypt_packet_length(sequence_number, packet_len_slice);
        // let packet_len = u32::from_be_bytes(packet_len_slice);
        // let (buf, tag_) = buf.split_at_mut((packet_len + 4) as usize);
        // let mut tag = [0_u8; 16];
        // tag.copy_from_slice(tag_);
        // match self.server_key.open_in_place(sequence_number, buf, &tag) {
        //     Ok(result) =>  Ok([&packet_len_slice[..], result].concat()),
        //     Err(_) => Err(SshError::from(SshErrorKind::EncryptionError))
        // }

    }
}
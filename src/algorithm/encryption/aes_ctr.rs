use crate::algorithm::encryption::Encryption;
use crate::algorithm::hash::Hash;
use crate::algorithm::mac::Mac;
use crate::error::SshError;
use crate::SshResult;
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr;

type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
type Aes192Ctr64BE = ctr::Ctr64BE<aes::Aes192>;
type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

const CTR128_KEY_SIZE: usize = 16;
const CTR192_KEY_SIZE: usize = 24;
const CTR256_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;
const BLOCK_SIZE: usize = 16;

// extend data for data encryption
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

macro_rules! crate_aes_ctr {
    ($name: ident, $alg: ident, $key_size: expr) => {
        pub(super) struct $name {
            pub(super) client_key: $alg,
            pub(super) server_key: $alg,
            extend: Extend,
        }

        impl Encryption for $name {
            fn bsize(&self) -> usize {
                BLOCK_SIZE
            }

            fn iv_size(&self) -> usize {
                IV_SIZE
            }

            fn new(hash: Hash, mac: Box<dyn Mac>) -> Self
            where
                Self: Sized,
            {
                let (ck, sk) = hash.mix_ek($key_size);
                let mut ckey = [0u8; $key_size];
                let mut skey = [0u8; $key_size];
                ckey.clone_from_slice(&ck[..$key_size]);
                skey.clone_from_slice(&sk[..$key_size]);

                let mut civ = [0u8; IV_SIZE];
                let mut siv = [0u8; IV_SIZE];
                civ.clone_from_slice(&hash.iv_c_s[..IV_SIZE]);
                siv.clone_from_slice(&hash.iv_s_c[..IV_SIZE]);

                let c = $alg::new(&ckey.into(), &civ.into());
                let r = $alg::new(&skey.into(), &siv.into());
                // hmac
                let (ik_c_s, ik_s_c) = hash.mix_ik(mac.bsize());
                $name {
                    client_key: c,
                    server_key: r,
                    extend: Extend::from(mac, ik_c_s, ik_s_c),
                }
            }

            fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
                let tag = self
                    .extend
                    .mac
                    .sign(&self.extend.ik_c_s, client_sequence_num, buf);
                self.client_key.apply_keystream(buf);
                buf.extend(tag.as_ref())
            }

            fn decrypt(
                &mut self,
                server_sequence_number: u32,
                buf: &mut [u8],
            ) -> SshResult<Vec<u8>> {
                let pl = self.packet_len(server_sequence_number, buf);
                let data = &mut buf[..(pl + self.extend.mac.bsize())];
                let (d, m) = data.split_at_mut(pl);
                self.server_key.apply_keystream(d);
                let tag = self
                    .extend
                    .mac
                    .sign(&self.extend.ik_s_c, server_sequence_number, d);
                let t = tag.as_ref();
                if m != t {
                    return Err(SshError::EncryptionError(
                        "Failed to decrypt the server traffic".to_owned(),
                    ));
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
                let packet_len = u32::from_be_bytes(r[..4].try_into().unwrap());
                (packet_len + 4) as usize
            }

            fn data_len(&mut self, server_sequence_number: u32, buf: &[u8]) -> usize {
                let pl = self.packet_len(server_sequence_number, buf);
                let bsize = self.extend.mac.bsize();
                pl + bsize
            }

            fn no_pad(&self) -> bool {
                false
            }
        }
    };
}

// aes-128-ctr
crate_aes_ctr!(Ctr128, Aes128Ctr64BE, CTR128_KEY_SIZE);
// aes-192-ctr
crate_aes_ctr!(Ctr192, Aes192Ctr64BE, CTR192_KEY_SIZE);
// aes-256-ctr
crate_aes_ctr!(Ctr256, Aes256Ctr64BE, CTR256_KEY_SIZE);

use ring::digest;

const ALPHABET: [char; 6] = ['A', 'B', 'C', 'D', 'E', 'F'];

pub struct HASH {
    pub k     : Vec<u8>,
    pub h     : Vec<u8>,
    pub iv_c_s: Vec<u8>,
    pub iv_s_c: Vec<u8>,
    pub ek_c_s: Vec<u8>,
    pub ek_s_c: Vec<u8>,
    pub ik_c_s: Vec<u8>,
    pub ik_s_c: Vec<u8>
}

impl HASH {
    pub fn new(k: &[u8], h: &[u8], session_id: &[u8]) -> Self {
        let mut keys = vec![];
        for v in ALPHABET {
            keys.push(HASH::derive_key(k.clone(), h.clone(), v as u8, session_id));
        }
       HASH {
            k: k.to_vec(),
            h: h.to_vec(),

            // iv
            iv_c_s: keys[0].clone(),
            iv_s_c: keys[1].clone(),

            // key
            ek_c_s: keys[2].clone(),
            ek_s_c: keys[3].clone(),

            //  MAC
            ik_c_s: keys[4].clone(),
            ik_s_c: keys[5].clone()
        }
    }

    fn derive_key(k: &[u8], h: &[u8], key_char: u8, session_id: &[u8]) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::new();
        key.extend(k);
        key.extend(h);
        key.push(key_char);
        key.extend(session_id);
        digest::digest(&digest::SHA256, key.as_slice()).as_ref().to_vec()
    }

    pub fn extend_key(&self, key_size: u32) -> (Vec<u8>, Vec<u8>) {
        let mut ck = self.ek_c_s.to_vec();
        let mut sk = self.ek_s_c.to_vec();
        while key_size as usize > ck.len() {
            ck.extend(self.extend(ck.as_slice()));
            sk.extend(self.extend(sk.as_slice()));
        }
        (ck, sk)
    }

    fn extend(&self, key: &[u8]) -> Vec<u8> {
        let mut hash: Vec<u8> = Vec::new();
        hash.extend(self.k.clone());
        hash.extend(self.h.clone());
        hash.extend(key);
        // TODO 暂时默认使用 SHA256
        digest::digest(&digest::SHA256, hash.as_slice()).as_ref().to_vec()
    }

    // fn extend_keys(&mut self, k: &[u8], h: &[u8]) {
    //     self.iv_c_s.extend(&self.extend_key(k, h, self.iv_c_s.as_slice()));
    //     self.iv_s_c.extend(&self.extend_key(k, h, self.iv_s_c.as_slice()));
    //     self.ek_c_s.extend(&self.extend_key(k, h, self.ek_c_s.as_slice()));
    //     self.ek_s_c.extend(&self.extend_key(k, h, self.ek_s_c.as_slice()));
    //     self.ik_c_s.extend(&self.extend_key(k, h, self.ik_c_s.as_slice()));
    //     self.ik_s_c.extend(&self.extend_key(k, h, self.ik_s_c.as_slice()));
    // }

}

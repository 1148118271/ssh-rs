use ring::digest;

pub struct HASH {
    pub iv_c_s: Vec<u8>,
    pub iv_s_c: Vec<u8>,
    pub ek_c_s: Vec<u8>,
    pub ek_s_c: Vec<u8>,
    pub ik_c_s: Vec<u8>,
    pub ik_s_c: Vec<u8>
}

impl HASH {
    pub fn new(k: &[u8], h: &[u8], session_id: &[u8]) -> Self {
        let alphabet = ['A', 'B', 'C', 'D', 'E', 'F'];
        let mut keys = vec![];
        for v in alphabet {
            keys.push(HASH::derive_key(k, h, v as u8, session_id));
        }
        let mut hash = HASH {
            iv_c_s: keys[0].clone(),
            iv_s_c: keys[1].clone(),
            ek_c_s: keys[2].clone(),
            ek_s_c: keys[3].clone(),
            ik_c_s: keys[4].clone(),
            ik_s_c: keys[5].clone()
        };
        hash.extend_keys(k, h);
        hash
    }

    fn derive_key(k: &[u8], h: &[u8], key_char: u8, session_id: &[u8]) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::new();
        key.extend(k);
        key.extend(h);
        key.push(key_char);
        key.extend(session_id);
        digest::digest(&digest::SHA256, key.as_slice()).as_ref().to_vec()
    }


    fn extend_key(&self, k: &[u8], h: &[u8], key: &[u8]) -> Vec<u8>{
        let mut hash: Vec<u8> = Vec::new();
        hash.extend(k);
        hash.extend(h);
        hash.extend(key);
        digest::digest(&digest::SHA256, hash.as_slice()).as_ref().to_vec()
    }

    fn extend_keys(&mut self, k: &[u8], h: &[u8]) {
        self.iv_c_s.extend(&self.extend_key(k, h, self.iv_c_s.as_slice()));
        self.iv_s_c.extend(&self.extend_key(k, h, self.iv_s_c.as_slice()));
        self.ek_c_s.extend(&self.extend_key(k, h, self.ek_c_s.as_slice()));
        self.ek_s_c.extend(&self.extend_key(k, h, self.ek_s_c.as_slice()));
        self.ik_c_s.extend(&self.extend_key(k, h, self.ik_c_s.as_slice()));
        self.ik_s_c.extend(&self.extend_key(k, h, self.ik_s_c.as_slice()));
    }

}

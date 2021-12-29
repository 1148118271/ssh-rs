use ring::aead::chacha20_poly1305_openssh;
use ring::aead::chacha20_poly1305_openssh::{OpeningKey, SealingKey};
use crate::hash::HASH;


pub struct ChaCha20Poly1305 {
    pub client_key: SealingKey,
    pub server_key: OpeningKey,
}

impl ChaCha20Poly1305 {
    pub fn new(hash: HASH) -> ChaCha20Poly1305 {
        let sealing_key_data = hash.ek_c_s;
        let opening_key_data = hash.ek_s_c;

        let mut sealing_key = [0_u8; 64];
        let mut opening_key = [0_u8; 64];
        sealing_key.copy_from_slice(&sealing_key_data);
        opening_key.copy_from_slice(&opening_key_data);

        ChaCha20Poly1305 {
            client_key: chacha20_poly1305_openssh::SealingKey::new(&sealing_key),
            server_key: chacha20_poly1305_openssh::OpeningKey::new(&opening_key)
        }
    }

    pub fn encryption(&self, sequence_number: u32, buf: &mut Vec<u8>) {
        let mut tag = [0_u8; 16];
        self.client_key.seal_in_place(sequence_number, buf, &mut tag);
        buf.append(&mut tag.to_vec());
    }

    pub fn decryption(&self, sequence_number: u32, buf: &mut Vec<u8>) -> Vec<u8> {
        let mut packet_len_slice = [0_u8; 4];
        let len = &buf[..4];
        packet_len_slice.copy_from_slice(len);
        let packet_len_slice = self.server_key.decrypt_packet_length(sequence_number, packet_len_slice);
        let packet_len = u32::from_be_bytes(packet_len_slice);
        let (buf, tag_) = buf.split_at_mut((packet_len + 4) as usize);
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(tag_);
        let result = self.server_key.open_in_place(sequence_number, buf, &tag).unwrap();
        [&packet_len_slice[..], result].concat()
    }

}
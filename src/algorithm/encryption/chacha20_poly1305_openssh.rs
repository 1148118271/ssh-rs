use ring::aead::chacha20_poly1305_openssh::{OpeningKey, SealingKey};
use crate::algorithm::encryption::Encryption;
use crate::algorithm::hash;
use crate::error::SshError;


const BSIZE: usize = 64;

pub struct ChaCha20Poly1305 {
    client_key: SealingKey,
    server_key: OpeningKey,
}

impl Encryption for ChaCha20Poly1305 {
    fn bsize(&self) -> usize {
        BSIZE
    }

    fn iv_size(&self) -> usize {
       0
    }


    fn new() -> ChaCha20Poly1305 {
        let hash = hash::get();
        let (ck, sk) = hash.extend_key(BSIZE);
        let mut sealing_key = [0_u8; BSIZE];
        let mut opening_key = [0_u8; BSIZE];
        sealing_key.copy_from_slice(&ck);
        opening_key.copy_from_slice(&sk);

        ChaCha20Poly1305 {
            client_key: SealingKey::new(&sealing_key),
            server_key: OpeningKey::new(&opening_key)
        }
    }

    fn encrypt(&mut self, sequence_number: u32, buf: &mut Vec<u8>) {
        let mut tag = [0_u8; 16];
        self.client_key.seal_in_place(sequence_number, buf, &mut tag);
        buf.append(&mut tag.to_vec());
    }

    fn decrypt(&mut self, sequence_number: u32, buf: &mut [u8]) -> Result<Vec<u8>, SshError> {
        let mut packet_len_slice = [0_u8; 4];
        let len = &buf[..4];
        packet_len_slice.copy_from_slice(len);
        let packet_len_slice = self.server_key.decrypt_packet_length(sequence_number, packet_len_slice);
        let packet_len = u32::from_be_bytes(packet_len_slice);
        let (buf, tag_) = buf.split_at_mut((packet_len + 4) as usize);
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(tag_);
        match self.server_key.open_in_place(sequence_number, buf, &tag) {
            Ok(result) =>  Ok([&packet_len_slice[..], result].concat()),
            Err(_) => Err(SshError::from("encryption error."))
        }
    }

    fn packet_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
        let mut packet_len_slice = [0_u8; 4];
        packet_len_slice.copy_from_slice(&buf[..4]);
        let packet_len_slice = self.server_key
            .decrypt_packet_length(
                sequence_number,
                packet_len_slice);
        u32::from_be_bytes(packet_len_slice) as usize
    }

    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
        let packet_len = self.packet_len(sequence_number, buf);
        packet_len + 4 + 16
    }

    fn is_cp(&self) -> bool {
        true
    }
}

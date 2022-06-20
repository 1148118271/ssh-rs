
mod hash;
mod hash_type;


pub(crate) mod h;


pub(crate) use hash_type::HashType;
pub(crate) use hash::get;


use crate::algorithm::key_exchange;


pub(crate) fn digest(data: &[u8]) -> Vec<u8> {
    let hash_type = key_exchange::get().get_hash_type();
    let result = match hash_type {
        HashType::SHA1 => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data),
        HashType::SHA256 => ring::digest::digest(&ring::digest::SHA256, data),
    };
    result.as_ref().to_vec()
}
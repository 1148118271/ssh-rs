#[allow(clippy::module_inception)]
pub mod hash;
mod hash_type;

pub use hash_type::HashType;

pub fn digest(data: &[u8], hash_type: HashType) -> Vec<u8> {
    let result = match hash_type {
        HashType::SHA1 => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data),
        HashType::SHA256 => ring::digest::digest(&ring::digest::SHA256, data),
    };
    result.as_ref().to_vec()
}

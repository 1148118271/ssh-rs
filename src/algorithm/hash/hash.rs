use ring::digest;
use crate::constant::HashType;

pub(crate) fn digest(t: HashType, data: &[u8]) -> &[u8] {
    let result = match t {
        HashType::SHA1 => digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data),
        HashType::SHA256 => digest::digest(&digest::SHA256, data),
    };
    return result.as_ref()
}
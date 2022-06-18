use ring::hmac;
use ring::hmac::Context;
use crate::algorithm::hash;
use crate::algorithm::mac::Mac;

const BSIZE: usize = 20;

pub(crate) struct HMacSha1 {
    pub(crate) c: Context,
    pub(crate) s: Context
}

impl Mac for HMacSha1 {
    fn bsize() -> usize {
        BSIZE
    }

    fn new() -> Self {
        let ikc = &hash::get().ik_c_s[..BSIZE];
        let iks = &hash::get().ik_s_c[..BSIZE];

        let ck = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, ikc);
        let sk = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, iks);

        let mut cc = Context::with_key(&ck);
        let mut sc = Context::with_key(&sk);

        Self {
            c: cc,
            s: sc
        }
    }

}
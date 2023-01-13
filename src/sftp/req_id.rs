
pub(crate) struct ReqId(u32);

impl ReqId {
    pub(crate) fn new() -> Self {
        ReqId(0)
    }

    pub(crate) fn get(&mut self) -> u32 {
        let id = self.0;
        let n_id = id + 1;
        if n_id > u32::MAX {
            self.0 = 0;
        } else {
            self.0 = n_id
        }
        id
    }
}

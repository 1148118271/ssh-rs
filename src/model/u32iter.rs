pub(crate) struct U32Iter {
    num: u32,
}

impl Iterator for U32Iter {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.num == u32::MAX {
            self.num = 0;
        } else {
            self.num += 1;
        }
        Some(self.num)
    }
}

impl Default for U32Iter {
    fn default() -> Self {
        Self { num: u32::MAX }
    }
}

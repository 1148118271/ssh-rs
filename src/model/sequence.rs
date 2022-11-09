#[derive(Default)]
pub(crate) struct Sequence {
    client_sequence_num: SeqIter,
    server_sequence_num: SeqIter,
}

impl Sequence {
    pub fn get_client(&mut self) -> u32 {
        self.client_sequence_num.next().unwrap()
    }

    pub fn get_server(&mut self) -> u32 {
        self.server_sequence_num.next().unwrap()
    }

    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

struct SeqIter {
    num: u32,
}

impl Iterator for SeqIter {
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

impl Default for SeqIter {
    fn default() -> Self {
        Self { num: u32::MAX }
    }
}

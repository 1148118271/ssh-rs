pub enum TerminalSizeType {
    Character,
    Pixel,
}

pub struct TerminalSize {
    width: u32,
    height: u32,
    type_: TerminalSizeType,
}

impl TerminalSize {
    pub fn from(width: u32, height: u32) -> Self {
        TerminalSize {
            width,
            height,
            type_: TerminalSizeType::Character,
        }
    }

    pub fn from_type(width: u32, height: u32, type_: TerminalSizeType) -> Self {
        TerminalSize {
            width,
            height,
            type_,
        }
    }

    pub(crate) fn fetch(&self) -> (u32, u32, u32, u32) {
        match self.type_ {
            TerminalSizeType::Character => (self.width, self.height, 0, 0),
            TerminalSizeType::Pixel => (0, 0, self.width, self.height),
        }
    }
}

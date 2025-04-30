use log::warn;

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum Class {
    IN = 1,
    Unkown(u16),
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            x => {
                warn!("unkown value for record class {}", x);
                Self::Unkown(x)
            }
        }
    }
}

impl Into<u16> for Class {
    fn into(self) -> u16 {
        match self {
            Self::IN => 1,
            Self::Unkown(x) => x,
        }
    }
}

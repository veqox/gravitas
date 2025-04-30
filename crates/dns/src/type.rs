use log::warn;

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum Type {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    OPT = 41,
    CAA = 257,
    Unknown(u16),
}

impl From<u16> for Type {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            35 => Self::NAPTR,
            41 => Self::OPT,
            257 => Self::CAA,
            x => {
                warn!("unkown value for record type {}", x);
                Self::Unknown(x)
            }
        }
    }
}

impl Into<u16> for Type {
    fn into(self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::PTR => 12,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::SRV => 33,
            Self::NAPTR => 35,
            Self::OPT => 41,
            Self::CAA => 257,
            Self::Unknown(x) => x,
        }
    }
}

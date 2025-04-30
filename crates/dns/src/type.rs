use log::warn;

/// DNS type values as per [RFC 1035 Section 3.2.2](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
/// and [RFC 3403 Section 4.1](https://www.rfc-editor.org/rfc/rfc3403#section-4.1)
/// and [RFC 3596 Section 2.1](https://www.rfc-editor.org/rfc/rfc3596#section-2.1)
/// and [RFC 6891 Section 6.1.1](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1)
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
    NAPTR = 35,
    OPT = 41,
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
            35 => Self::NAPTR,
            41 => Self::OPT,
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
            Self::NAPTR => 35,
            Self::OPT => 41,
            Self::Unknown(x) => x,
        }
    }
}

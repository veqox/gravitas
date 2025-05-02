use log::warn;

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum Type {
    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    A = 1,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    NS = 2,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    CNAME = 5,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    SOA = 6,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    PTR = 12,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    MX = 15,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    TXT = 16,

    /// [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596#section-2.1)
    AAAA = 28,

    /// [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1)
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
            Self::OPT => 41,
            Self::Unknown(x) => x,
        }
    }
}

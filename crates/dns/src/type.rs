use log::warn;

#[derive(Debug)]
#[repr(u16)]
pub enum Type {
    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    A,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    NS,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    CNAME,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    SOA,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    PTR,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    MX,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    TXT,

    /// [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596#section-2.1)
    AAAA,

    /// [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782)
    SRV,

    /// [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1)
    OPT,

    /// [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)
    DS,

    /// [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)
    RRSIG,

    /// [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)
    /// [RFC 9077](https://www.rfc-editor.org/rfc/rfc9077)
    NSEC,

    /// [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)
    DNSKEY,

    /// [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155)
    /// [RFC 9077](https://www.rfc-editor.org/rfc/rfc9077)
    NSEC3,

    /// [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155)
    NSEC3PARAM,

    /// [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460)
    SVCB,

    /// [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460)
    HTTPS,

    /// [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659)
    CAA,

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
            41 => Self::OPT,
            43 => Self::DS,
            46 => Self::RRSIG,
            47 => Self::NSEC,
            48 => Self::DNSKEY,
            50 => Self::NSEC3,
            51 => Self::NSEC3PARAM,
            64 => Self::SVCB,
            65 => Self::HTTPS,
            257 => Self::CAA,
            _ => {
                warn!("unkown value for record type {}", value);
                Self::Unknown(value)
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
            Self::OPT => 41,
            Self::DS => 43,
            Self::RRSIG => 46,
            Self::NSEC => 47,
            Self::DNSKEY => 48,
            Self::NSEC3 => 50,
            Self::NSEC3PARAM => 51,
            Self::SVCB => 64,
            Self::HTTPS => 65,
            Self::CAA => 257,
            Self::Unknown(code) => code,
        }
    }
}

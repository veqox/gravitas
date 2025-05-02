use log::warn;

/// DNS header field layout as per [RFC 1035 Section 4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     FLAGS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub flags: Flags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/// DNS flags field layout as per [RFC 1035 Section 4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
/// and [RFC 2535 Section 6.1](https://www.rfc-editor.org/rfc/rfc2535#section-6.1).
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug)]
pub struct Flags {
    pub qr: u8,         // 1 bit
    pub opcode: OpCode, // 4 bits
    pub aa: u8,         // 1 bit
    pub tc: u8,         // 1 bit
    pub rd: u8,         // 1 bit
    pub ra: u8,         // 1 bit
    pub z: u8,          // 1 bit
    pub ad: u8,         // 1 bit
    pub cd: u8,         // 1 bit
    pub rcode: RCode,   // 4 bits
}

impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Flags {
            qr: (value >> 15 & 0b1) as u8,
            opcode: ((value >> 11 & 0b1111) as u8).into(),
            aa: (value >> 10 & 0b1) as u8,
            tc: (value >> 9 & 0b1) as u8,
            rd: (value >> 8 & 0b1) as u8,
            ra: (value >> 7 & 0b1) as u8,
            z: (value >> 6 & 0b1) as u8,
            ad: (value >> 5 & 0b1) as u8,
            cd: (value >> 4 & 0b1) as u8,
            rcode: ((value & 0b1111) as u8).into(),
        }
    }
}

impl Into<u16> for Flags {
    fn into(self) -> u16 {
        let mut value = 0u16;
        value |= (self.qr as u16) << 15;
        value |= (Into::<u8>::into(self.opcode) as u16 & 0b1111) << 11;
        value |= (self.aa as u16) << 10;
        value |= (self.tc as u16) << 9;
        value |= (self.rd as u16) << 8;
        value |= (self.ra as u16) << 7;
        value |= (self.z as u16) << 6;
        value |= (self.ad as u16) << 5;
        value |= (self.cd as u16) << 4;
        value |= Into::<u8>::into(self.rcode) as u16 & 0b1111;
        value
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum OpCode {
    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    Query = 0,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    /// [RFC 3425](https://www.rfc-editor.org/rfc/rfc3425#section-3)
    ///
    /// Obsolete
    IQuery = 1,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    Status = 2,

    /// [RFC 1996](https://www.rfc-editor.org/rfc/rfc1996)
    Notify = 4,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136#section-1)
    Update = 5,

    /// [RFC 8490](https://www.rfc-editor.org/rfc/rfc8490#section-5.4)
    ///
    /// DNS Stateful Operations
    DSO = 6,

    /// Unassigned values
    Unkown(u8),
}

impl From<u8> for OpCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            6 => Self::DSO,
            x => {
                warn!("unkown value for opcode {}", x);
                Self::Unkown(x)
            }
        }
    }
}

impl Into<u8> for OpCode {
    fn into(self) -> u8 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::DSO => 6,
            Self::Unkown(x) => x,
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum RCode {
    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    NoError = 0,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    FormatErr = 1,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    ServFail = 2,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    NXDomain = 3,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    NotImp = 4,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    Refused = 5,

    /// Unassigned values
    Unkown(u8),
}

impl From<u8> for RCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            _ => Self::Unkown(value),
        }
    }
}

impl Into<u8> for RCode {
    fn into(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatErr => 1,
            Self::ServFail => 2,
            Self::NXDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::Unkown(x) => x,
        }
    }
}

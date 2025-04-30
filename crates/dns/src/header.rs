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

/// DNS opcode values as per [RFC 1035 Section 4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
/// and [RFC 1996](https://www.rfc-editor.org/rfc/rfc1996)
/// and [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
#[derive(Debug)]
#[repr(u8)]
pub enum OpCode {
    Query = 0,
    Status = 2,
    Notify = 4,
    Update = 5,
    Unkown(u8),
}

impl From<u8> for OpCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Query,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
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
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Unkown(x) => x,
        }
    }
}

/// DNS rcode values as per [RFC 1035 Section 4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
#[derive(Debug)]
#[repr(u8)]
pub enum RCode {
    NoError = 0,
    /// The name server was unable to interpret the query.
    FormatError = 1,
    /// The name server was unable to process this query due to a problem with the name server.
    ServerFailure = 2,
    /// Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    NameError = 3,
    /// The name server does not support the requested kind of query.
    NotImplemented = 4,
    /// The name server refuses to perform the specified operation for policy reasons.
    /// For example, a name server may not wish to provide the information to the particular requester,
    /// or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
    Refused = 5,
    Unkown(u8),
}

impl From<u8> for RCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            x => {
                warn!("unkown value for rcode {}", x);
                Self::Unkown(x)
            }
        }
    }
}

impl Into<u8> for RCode {
    fn into(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::Unkown(x) => x,
        }
    }
}

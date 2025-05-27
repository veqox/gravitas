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
            qr: ((value >> 15) & 0b1) as u8,
            opcode: (((value >> 11) & 0b1111) as u8).into(),
            aa: ((value >> 10) & 0b1) as u8,
            tc: ((value >> 9) & 0b1) as u8,
            rd: ((value >> 8) & 0b1) as u8,
            ra: ((value >> 7) & 0b1) as u8,
            z: ((value >> 6) & 0b1) as u8,
            ad: ((value >> 5) & 0b1) as u8,
            cd: ((value >> 4) & 0b1) as u8,
            rcode: ((value & 0b1111) as u8).into(),
        }
    }
}

impl From<Flags> for u16 {
    fn from(val: Flags) -> Self {
        let mut value = 0u16;
        value |= (val.qr as u16) << 15;
        value |= (Into::<u8>::into(val.opcode) as u16 & 0b1111) << 11;
        value |= (val.aa as u16) << 10;
        value |= (val.tc as u16) << 9;
        value |= (val.rd as u16) << 8;
        value |= (val.ra as u16) << 7;
        value |= (val.z as u16) << 6;
        value |= (val.ad as u16) << 5;
        value |= (val.cd as u16) << 4;
        value |= Into::<u8>::into(val.rcode) as u16 & 0b1111;
        value
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum OpCode {
    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    Query,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    Status,

    /// [RFC 1996](https://www.rfc-editor.org/rfc/rfc1996)
    Notify,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136#section-1)
    Update,

    /// [RFC 8490](https://www.rfc-editor.org/rfc/rfc8490#section-5.4)
    DSO,

    Unknown(u8),
}

impl From<u8> for OpCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Query,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            6 => Self::DSO,
            _ => {
                warn!("unknown value for opcode {}", value);
                Self::Unknown(value)
            }
        }
    }
}

impl From<OpCode> for u8 {
    fn from(val: OpCode) -> Self {
        match val {
            OpCode::Query => 0,
            OpCode::Status => 2,
            OpCode::Notify => 4,
            OpCode::Update => 5,
            OpCode::DSO => 6,
            OpCode::Unknown(x) => x,
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum RCode {
    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    NoError,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    FormatErr,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    ServFail,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    NXDomain,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    NotImp,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1)
    Refused,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
    YXDomain,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
    YXRRSet,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
    NXRRSet,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
    /// [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    NotAuth,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
    NotZone,

    /// [RFC 8490](https://www.rfc-editor.org/rfc/rfc8490)
    DSOTYPENI,

    /// [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891)
    /// [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADVERS,

    /// [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADSIG,

    /// [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADKEY,

    /// [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADTIME,

    /// [RFC 2930](https://www.rfc-editor.org/rfc/rfc2930)
    BADMODE,

    /// [RFC 2930](https://www.rfc-editor.org/rfc/rfc2930)
    BADNAME,

    /// [RFC 2930](https://www.rfc-editor.org/rfc/rfc2930)
    BADALG,

    /// [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADTRUNC,

    /// [RFC 7873](https://www.rfc-editor.org/rfc/rfc7873)
    BADCOOKIE,

    Unknown(u8),
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
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            11 => Self::DSOTYPENI,
            16 => Self::BADSIG,
            17 => Self::BADKEY,
            18 => Self::BADTIME,
            19 => Self::BADMODE,
            20 => Self::BADNAME,
            21 => Self::BADALG,
            22 => Self::BADTRUNC,
            23 => Self::BADCOOKIE,
            other => Self::Unknown(other),
        }
    }
}

impl From<RCode> for u8 {
    fn from(val: RCode) -> Self {
        match val {
            RCode::NoError => 0,
            RCode::FormatErr => 1,
            RCode::ServFail => 2,
            RCode::NXDomain => 3,
            RCode::NotImp => 4,
            RCode::Refused => 5,
            RCode::YXDomain => 6,
            RCode::YXRRSet => 7,
            RCode::NXRRSet => 8,
            RCode::NotAuth => 9,
            RCode::NotZone => 10,
            RCode::DSOTYPENI => 11,
            RCode::BADVERS | RCode::BADSIG => 16,
            RCode::BADKEY => 17,
            RCode::BADTIME => 18,
            RCode::BADMODE => 19,
            RCode::BADNAME => 20,
            RCode::BADALG => 21,
            RCode::BADTRUNC => 22,
            RCode::BADCOOKIE => 23,
            RCode::Unknown(x) => x,
        }
    }
}

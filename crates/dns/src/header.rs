/* https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     FLAGS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub flags: Flags, // 16 bits
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct Flags {
    pub qr: u8,         // 1 bit
    pub opcode: OpCode, // 4 bits
    pub aa: u8,         // 1 bit
    pub tc: u8,         // 1 bit,
    pub rd: u8,         // 1 bit
    pub ra: u8,         // 1 bit
    pub z: u8,          // 3 bits
    pub rcode: RCode,   // 4 bits
}

#[derive(Debug)]
#[repr(u8)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    Undefined(u8),
}

impl OpCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            x => Self::Undefined(x),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Undefined(x) => x,
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum RCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Undefined(u8),
}

impl RCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            x => Self::Undefined(x),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::Undefined(x) => x,
        }
    }
}

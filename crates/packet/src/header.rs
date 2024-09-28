/* https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
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

use crate::Packet;

pub const HEADER_SIZE: usize = 12;

#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub flags: Flags, // 16 bits
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn try_parse_section(
        packet: [u8; Packet::MAX_SIZE],
        pos: &mut usize,
    ) -> Result<Self, std::array::TryFromSliceError> {
        let header: [u8; HEADER_SIZE] = packet[*pos..*pos + HEADER_SIZE].try_into()?;
        *pos = *pos + HEADER_SIZE;

        Ok(Self {
            id: u16::from_be_bytes(header[0..2].try_into()?),
            flags: Flags::from_be_bytes(header[2..4].try_into()?),
            qdcount: u16::from_be_bytes(header[4..6].try_into()?),
            ancount: u16::from_be_bytes(header[6..8].try_into()?),
            nscount: u16::from_be_bytes(header[8..10].try_into()?),
            arcount: u16::from_be_bytes(header[10..12].try_into()?),
        })
    }

    pub fn serialize_section(&self, packet: &mut [u8; Packet::MAX_SIZE], pos: &mut usize) {
        packet[*pos..*pos + 2].copy_from_slice(&self.id.to_be_bytes());
        *pos += 2;

        let flags: [u8; 2] = Flags::to_be_bytes(&self.flags);
        packet[*pos..*pos + 2].copy_from_slice(&flags);
        *pos += 2;

        packet[*pos..*pos + 2].copy_from_slice(&self.qdcount.to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + 2].copy_from_slice(&self.ancount.to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + 2].copy_from_slice(&self.nscount.to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + 2].copy_from_slice(&self.arcount.to_be_bytes());
        *pos += 2;
    }
}

#[derive(Debug)]
pub struct Flags {
    pub qr: u8,         // 1 bit
    pub opcode: Opcode, // 4 bits
    pub aa: u8,         // 1 bit
    pub tc: u8,         // 1 bit,
    pub rd: u8,         // 1 bit
    pub ra: u8,         // 1 bit
    pub z: u8,          // 3 bits
    pub rcode: RCodes,  // 4 bits
}

impl Flags {
    pub fn from_be_bytes(value: [u8; 2]) -> Self {
        Self {
            qr: value[0] & 0b10000000 >> 7,
            opcode: Opcode::from_u8(value[0] & 0b01111000 >> 3),
            aa: value[0] & 0b00000100 >> 2,
            tc: value[0] & 0b00000010 >> 1,
            rd: value[0] & 0b00000001,
            ra: value[1] & 0b10000000 >> 7,
            z: value[1] & 0b01110000 >> 4,
            rcode: RCodes::from_u8(value[1] & 0b00001111),
        }
    }

    pub fn to_be_bytes(&self) -> [u8; 2] {
        let mut value: [u8; 2] = [0; 2];

        value[0] |= self.qr << 7;
        value[0] |= self.opcode.to_u8() << 3;
        value[0] |= self.aa << 2;
        value[0] |= self.rd;

        value[1] |= self.ra << 7;
        value[1] |= self.z << 4;
        value[1] |= self.rcode.to_u8();

        value
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4, // RFC-1996
    Update = 5, // RFC-2136
    Undefined(u8),
}

impl Opcode {
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
pub enum RCodes {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Undefined(u8),
}

impl RCodes {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => RCodes::NoError,
            1 => RCodes::FormatError,
            2 => RCodes::ServerFailure,
            3 => RCodes::NameError,
            4 => RCodes::NotImplemented,
            5 => RCodes::Refused,
            x => RCodes::Undefined(x),
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

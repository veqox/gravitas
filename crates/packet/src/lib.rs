// https://www.rfc-editor.org/rfc/rfc1035

use std::array::TryFromSliceError;

pub const PACKET_SIZE: usize = 512;

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

#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub flags: Flags, // 16 bits
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl TryFrom<[u8; 12]> for Header {
    type Error = ();

    fn try_from(value: [u8; 12]) -> Result<Self, Self::Error> {
        Ok(Self {
            id: u16::from_be_bytes(value[0..2].try_into().unwrap()),
            flags: value[2..4].try_into().unwrap(),
            qdcount: u16::from_be_bytes(value[4..6].try_into().unwrap()),
            ancount: u16::from_be_bytes(value[6..8].try_into().unwrap()),
            nscount: u16::from_be_bytes(value[8..10].try_into().unwrap()),
            arcount: u16::from_be_bytes(value[10..12].try_into().unwrap()),
        })
    }
}

#[derive(Debug)]
pub struct Flags {
    pub qr: bool,       // 1 bit
    pub opcode: Opcode, // 4 bits
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,        // 3 bits
    pub rcode: Rcode, // 4 bits
}

impl TryFrom<&[u8]> for Flags {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value: [u8; 2] = value.try_into()?;

        Ok(Self {
            qr: value[0] & 1 > 0,
            opcode: ((value[0] & 0b00011110) >> 1).into(),
            aa: value[0] & (1 << 5) > 0,
            tc: value[0] & (1 << 6) > 0,
            rd: value[0] & (1 << 7) > 0,
            ra: value[1] & 1 > 0,
            z: ((value[1] & 0b00001110) >> 1),
            rcode: ((value[1] & 0b11110000) >> 4).into(),
        })
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Undefined(u8),
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            x => Opcode::Undefined(x),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Undefined(u8),
}

impl From<u8> for Rcode {
    fn from(value: u8) -> Self {
        match value {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            x => Rcode::Undefined(x),
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
}

impl TryFrom<[u8; PACKET_SIZE]> for Packet {
    type Error = ();

    fn try_from(slice: [u8; PACKET_SIZE]) -> Result<Self, Self::Error> {
        let header: [u8; 12] = slice[0..12].try_into().unwrap();

        Ok(Self {
            header: Header::try_from(header).unwrap(),
        })
    }
}

/*
fn to_num<T>(slice: &[u8]) -> T
where
    T: From<<T as std::ops::BitOr>::Output(T)>,
{
    slice
        .iter()
        .enumerate()
        .fold(T::default(), |acc, (i, b)| acc | (*b as T))
}
*/

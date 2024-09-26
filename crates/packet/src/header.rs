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
        packet: [u8; crate::PACKET_SIZE],
        pos: &mut usize,
    ) -> Result<Self, std::array::TryFromSliceError> {
        let header: [u8; HEADER_SIZE] = packet[*pos..*pos + HEADER_SIZE].try_into()?;
        *pos = *pos + HEADER_SIZE;

        Ok(Self {
            id: u16::from_be_bytes(header[0..2].try_into()?),
            flags: header[2..4].try_into()?,
            qdcount: u16::from_be_bytes(header[4..6].try_into()?),
            ancount: u16::from_be_bytes(header[6..8].try_into()?),
            nscount: u16::from_be_bytes(header[8..10].try_into()?),
            arcount: u16::from_be_bytes(header[10..12].try_into()?),
        })
    }
}

#[derive(Debug)]
pub struct Flags {
    pub qr: u8,         // 1 bit
    pub opcode: Opcode, // 4 bits
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,
    pub ra: u8,
    pub z: u8,        // 3 bits
    pub rcode: Rcode, // 4 bits
}

impl TryFrom<&[u8]> for Flags {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value: [u8; 2] = value[0..2].try_into()?;

        Ok(Self {
            qr: value[0] & 0b10000000 >> 7,
            opcode: (value[0] & 0b01111000 >> 3).into(),
            aa: value[0] & 0b00000100 >> 2,
            tc: value[0] & 0b00000010 >> 1,
            rd: value[0] & 0b00000001,
            ra: value[1] & 0b10000000 >> 7,
            z: value[1] & 0b01110000 >> 4,
            rcode: (value[1] & 0b00001111).into(),
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

/* https://www.rfc-editor.org/rfc/rfc1035#section-4.1.3

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

use crate::{error::DNSError, packet::Packet, utils::DomainName};

#[derive(Debug)]
pub struct ResourceRecord<'a> {
    pub r_name: DomainName<'a>,
    pub r_type: Type,
    pub r_class: Class,
    pub ttl: u32,
    pub rd_length: u16,
    pub r_data: &'a [u8],
}

impl<'a> ResourceRecord<'a> {
    pub fn try_parse_section(
        packet: &'a [u8; Packet::MAX_SIZE],
        pos: &mut usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let name = DomainName::parse_section(packet, pos)?;

        let r#type = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
        *pos += 2;

        let class = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
        *pos += 2;

        let ttl = u32::from_be_bytes(packet[*pos..*pos + 4].try_into()?);
        *pos += 4;

        let rd_length = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
        *pos += 2;

        let r_data = &packet[*pos..*pos + rd_length as usize];
        *pos += rd_length as usize;

        Ok(Self {
            r_name: name,
            r_type: Type::try_from_u16(r#type)?,
            r_class: Class::try_from_u16(class)?,
            ttl,
            rd_length,
            r_data,
        })
    }

    pub fn try_serialize_section(&self, packet: &mut [u8; Packet::MAX_SIZE], pos: &mut usize) {
        self.r_name.serialize_section(packet, pos);

        packet[*pos..*pos + 2].copy_from_slice(&self.r_type.to_u16().to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + 2].copy_from_slice(&self.r_class.to_u16().to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + 4].copy_from_slice(&self.ttl.to_be_bytes());
        *pos += 4;

        packet[*pos..*pos + 2].copy_from_slice(&self.rd_length.to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + self.rd_length as usize].copy_from_slice(&self.r_data);
        *pos += self.rd_length as usize;
    }
}

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
    SRV = 33,
    NAPTR = 35,
    OPT = 41,
    CAA = 257,
    Unknown(u16),
}

impl Type {
    pub fn try_from_u16(value: u16) -> Result<Self, DNSError> {
        match value {
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            5 => Ok(Self::CNAME),
            6 => Ok(Self::SOA),
            12 => Ok(Self::PTR),
            15 => Ok(Self::MX),
            16 => Ok(Self::TXT),
            28 => Ok(Self::AAAA),
            33 => Ok(Self::SRV),
            35 => Ok(Self::NAPTR),
            41 => Ok(Self::OPT),
            257 => Ok(Self::CAA),
            x => Ok(Self::Unknown(x)),
        }
    }

    pub fn to_u16(&self) -> u16 {
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
            Self::NAPTR => 35,
            Self::OPT => 41,
            Self::CAA => 257,
            Self::Unknown(x) => *x,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum Class {
    IN = 1,
    Size(u16),
}

impl Class {
    pub fn try_from_u16(value: u16) -> Result<Self, DNSError> {
        match value {
            1 => Ok(Self::IN),
            x => Ok(Self::Size(x)),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::IN => 1,
            Self::Size(x) => *x,
        }
    }
}

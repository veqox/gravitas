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

#[derive(Debug)]
pub struct ResourceRecord {
    pub r_name: Vec<Vec<u8>>,
    pub r_type: Type,
    pub r_class: Class,
    pub ttl: u32,
    pub rd_length: u16,
    pub r_data: Vec<u8>,
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
    pub fn from_u16(value: u16) -> Self {
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
            35 => Self::NAPTR,
            41 => Self::OPT,
            257 => Self::CAA,
            x => Self::Unknown(x),
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
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::IN,
            x => Self::Size(x),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::IN => 1,
            Self::Size(x) => *x,
        }
    }
}

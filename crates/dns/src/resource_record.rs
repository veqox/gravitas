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

use crate::header::RCode;

#[derive(Debug)]
pub struct ResourceRecord<'a> {
    pub r_name: Vec<&'a [u8]>,
    pub r_type: Type,
    pub class_or_size: ClassOrSize,
    pub ttl_or_flags: TtlOrOptFlags,
    pub rd_length: u16,
    pub r_data: Record<'a>,
}

#[derive(Debug)]
#[repr(u16)]
pub enum ClassOrSize {
    Class(Class),
    Size(u16),
}

impl ClassOrSize {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Class(Class::IN),
            x => Self::Size(x),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Class(Class::IN) => 1,
            Self::Size(x) => *x,
        }
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum TtlOrOptFlags {
    Ttl(u32),
    OptFlags(OptFlags),
}

#[derive(Debug)]
pub struct OptFlags {
    pub ext_rcode: u8,
    pub version: u8,
    pub do_flag: u8, // 1 bit
    pub z: u16,      // 15 bits must be zero
}

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
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

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum Class {
    IN = 1,
}

impl Class {
    pub fn try_from_u16(value: u16) -> Result<Self, RCode> {
        match value {
            1 => Ok(Class::IN),
            _ => Err(RCode::NotImplemented),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::IN => 1,
        }
    }
}

#[derive(Debug)]
pub enum Record<'a> {
    A(ARecord<'a>),
    NS(NSRecord<'a>),
    CNAME(CNAMERecord<'a>),
    SOA(SOARecord<'a>),
    PTR(PTRRecord<'a>),
    MX(MXRecord<'a>),
    TXT(TXTRecord<'a>),
    AAAA(AAAARecord<'a>),
    OPT(OPTRecord<'a>),
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ADDRESS                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct ARecord<'a> {
    pub address: &'a [u8; 4],
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   NSDNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct NSRecord<'a> {
    pub nsdname: Vec<&'a [u8]>,
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     CNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct CNAMERecord<'a> {
    pub cname: Vec<&'a [u8]>,
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     MNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     RNAME                     /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    SERIAL                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    REFRESH                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     RETRY                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    EXPIRE                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    MINIMUM                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct SOARecord<'a> {
    pub mname: Vec<&'a [u8]>,
    pub rname: Vec<&'a [u8]>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   PTRDNAME                    /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct PTRRecord<'a> {
    pub ptrdname: Vec<&'a [u8]>,
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  PREFERENCE                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   EXCHANGE                    /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct MXRecord<'a> {
    pub preference: u16,
    pub exchange: Vec<&'a [u8]>,
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   TXT-DATA                    /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct TXTRecord<'a> {
    pub text: &'a [u8],
}

/* https://www.rfc-editor.org/rfc/rfc3596#section-2.2

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ADDRESS                    |
|                                               |
|                                               |
|                                               |
|                                               |
|                                               |
|                                               |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct AAAARecord<'a> {
    pub address: &'a [u8; 16],
}

// https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
#[derive(Debug)]
pub struct OPTRecord<'a> {
    pub options: Vec<Option<'a>>,
}

/* https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  OPTON-CODE                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 OPTION-LENGTH                 |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                  OPTON-DATA                   /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct Option<'a> {
    pub code: u16,
    pub length: u16,
    pub data: &'a [u8],
}

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

use crate::{
    error::DNSError,
    header::Header,
    question::{QClass, QType},
};

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: Vec<Vec<u8>>,
    pub r_type: Type,
    pub r_class: Class,
    pub ttl: u32,
    pub rd_length: u16,
    pub r_data: Vec<u8>,
}

impl ResourceRecord {
    pub fn try_parse_section(
        packet: [u8; crate::PACKET_SIZE],
        pos: &mut usize,
        header: &Header,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let mut resource_records: Vec<ResourceRecord> = vec![];

        for _ in 0..header.arcount {
            let mut name: Vec<Vec<u8>> = vec![];

            while packet[*pos] != 0 {
                let length = packet[*pos] as usize;
                *pos += 1;

                let label = &packet[*pos..*pos + length];
                *pos += length;

                name.push(label.to_vec());
            }
            *pos += 1;

            let r#type = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
            *pos += 2;

            let class = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
            *pos += 2;

            let ttl = u32::from_be_bytes(packet[*pos..*pos + 4].try_into()?);
            *pos += 4;

            let rd_length = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
            *pos += 2;

            let r_data = packet[*pos..*pos + rd_length as usize].to_vec();
            *pos += rd_length as usize;

            resource_records.push(ResourceRecord {
                name,
                r_type: r#type.try_into()?,
                r_class: class.try_into()?,
                ttl,
                rd_length,
                r_data,
            });
        }

        Ok(resource_records)
    }

    pub fn try_serialize_section(
        self,
        packet: &mut [u8; crate::PACKET_SIZE],
        pos: &mut usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        todo!()
    }
}

#[derive(Debug, Clone)]
#[repr(u16)]
pub enum Type {
    A = 1,
    NS = 2,
    // MD = 3, Obsolete
    // MF = 4, Obsolete
    CNAME = 5,
    SOA = 6,
    // MB = 7, Experimental
    // MG = 8, Experimental
    // MR = 9, Experimental
    // NULL = 10, Experimental
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
}

impl TryFrom<u16> for Type {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            5 => Ok(Self::CNAME),
            6 => Ok(Self::SOA),
            11 => Ok(Self::WKS),
            12 => Ok(Self::PTR),
            13 => Ok(Self::HINFO),
            15 => Ok(Self::MX),
            16 => Ok(Self::TXT),
            x => Err(DNSError::InvalidType(x)),
        }
    }
}

impl From<QType> for Type {
    fn from(value: QType) -> Self {
        match value {
            QType::Type(t) => t,
            _ => panic!("Invalid type"),
        }
    }
}

#[derive(Debug, Clone)]
#[repr(u16)]
pub enum Class {
    IN = 1,
    // CS = 2, Obsolete
    CH = 3,
    HS = 4,
}

impl TryFrom<u16> for Class {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Class::IN),
            3 => Ok(Class::CH),
            4 => Ok(Class::HS),
            _ => Err(DNSError::InvalidClass(value)),
        }
    }
}

impl From<QClass> for Class {
    fn from(value: QClass) -> Self {
        match value {
            QClass::Class(t) => t,
            _ => panic!("Invalid class"),
        }
    }
}

/* https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2

  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

use crate::{
    error::DNSError,
    header::Header,
    resource_record::{Class, Type},
};

#[derive(Debug, Clone)]
pub struct Question {
    pub q_name: Vec<Vec<u8>>,
    pub q_type: QType,
    pub q_class: QClass,
}

impl Question {
    pub fn try_parse_section(
        packet: [u8; crate::PACKET_SIZE],
        pos: &mut usize,
        header: &Header,
    ) -> Result<Vec<Question>, Box<dyn std::error::Error>> {
        let mut questions: Vec<Question> = vec![];

        for _ in 0..header.qdcount {
            let mut qname: Vec<Vec<u8>> = vec![];

            while packet[*pos] != 0 {
                let length = packet[*pos] as usize;
                *pos += 1;

                let label = &packet[*pos..*pos + length];
                *pos += length;

                qname.push(label.to_vec());
            }
            *pos += 1;

            let qtype = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
            *pos += 2;

            let qclass = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
            *pos += 2;

            questions.push(Question {
                q_name: qname,
                q_type: qtype.try_into()?,
                q_class: qclass.try_into()?,
            });
        }

        return Ok(questions);
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
pub enum QType {
    Type(Type),
    AXFR = 252,
    MAILB = 253,
    // MAILA = 254, Obsolete
    ALL = 255,
}

impl TryFrom<u16> for QType {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Type::try_from(value) {
            Ok(t) => Ok(Self::Type(t)),
            Err(DNSError::InvalidType(252)) => Ok(Self::AXFR),
            Err(DNSError::InvalidType(253)) => Ok(Self::MAILB),
            Err(DNSError::InvalidType(255)) => Ok(Self::ALL),
            Err(DNSError::InvalidType(x)) => Err(DNSError::InvalidQType(x)),
            _ => unreachable!(),
        }
    }
}

impl From<Type> for QType {
    fn from(value: Type) -> Self {
        Self::Type(value)
    }
}

#[derive(Debug, Clone)]
#[repr(u16)]
pub enum QClass {
    Class(Class),
    ANY = 255,
}

impl TryFrom<u16> for QClass {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Class::try_from(value) {
            Ok(t) => Ok(Self::Class(t)),
            Err(DNSError::InvalidClass(252)) => Ok(Self::ANY),
            Err(DNSError::InvalidClass(x)) => Err(DNSError::InvalidQClass(x)),
            _ => unreachable!(),
        }
    }
}

impl From<Class> for QClass {
    fn from(value: Class) -> Self {
        Self::Class(value)
    }
}

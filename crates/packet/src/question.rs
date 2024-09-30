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
    packet::Packet,
    resource_record::{Class, Type},
    utils::DomainName,
};

#[derive(Debug, Clone)]
pub struct Question<'a> {
    pub q_name: DomainName<'a>,
    pub q_type: Type,
    pub q_class: Class,
}

impl<'a> Question<'a> {
    pub fn try_parse_section(
        packet: &'a [u8; Packet::MAX_SIZE],
        pos: &mut usize,
    ) -> Result<Question<'a>, Box<dyn std::error::Error>> {
        let qname = DomainName::parse_section(packet, pos)?;

        let qtype = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
        *pos += 2;

        let qclass = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
        *pos += 2;

        Ok(Self {
            q_name: qname,
            q_type: Type::try_from_u16(qtype)?,
            q_class: Class::try_from_u16(qclass)?,
        })
    }

    pub fn serialize_section(&self, packet: &mut [u8; Packet::MAX_SIZE], pos: &mut usize) {
        self.q_name.serialize_section(packet, pos);

        packet[*pos..*pos + 2].copy_from_slice(&self.q_type.to_u16().to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + 2].copy_from_slice(&self.q_class.to_u16().to_be_bytes());
        *pos += 2;
    }
}

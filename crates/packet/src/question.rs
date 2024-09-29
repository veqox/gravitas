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
    header::Header,
    packet::Packet,
    resource_record::{Class, Type},
};

#[derive(Debug, Clone)]
pub struct Question<'a> {
    pub q_name: Vec<&'a [u8]>,
    pub q_type: Type,
    pub q_class: Class,
}

impl<'a> Question<'a> {
    pub fn try_parse_section(
        packet: &'a [u8; Packet::MAX_SIZE],
        pos: &mut usize,
        header: &Header,
    ) -> Result<Vec<Question<'a>>, Box<dyn std::error::Error>> {
        let mut questions: Vec<Question> = vec![];

        for _ in 0..header.qdcount {
            let mut qname: Vec<&'a [u8]> = vec![];

            while packet[*pos] != 0 {
                let length = packet[*pos] as usize;
                *pos += 1;

                let label = &packet[*pos..*pos + length];
                *pos += length;

                qname.push(label);
            }
            *pos += 1;

            let qtype = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
            *pos += 2;

            let qclass = u16::from_be_bytes(packet[*pos..*pos + 2].try_into()?);
            *pos += 2;

            questions.push(Question {
                q_name: qname,
                q_type: Type::try_from_u16(qtype)?,
                q_class: Class::try_from_u16(qclass)?,
            });
        }

        return Ok(questions);
    }

    pub fn serialize_section(&self, packet: &mut [u8; Packet::MAX_SIZE], pos: &mut usize) {
        for label in self.q_name.iter() {
            packet[*pos] = label.len() as u8;
            *pos += 1;
            packet[*pos..*pos + label.len()].copy_from_slice(label);
            *pos += label.len();
        }
        packet[*pos] = 0;
        *pos += 1;

        packet[*pos..*pos + 2].copy_from_slice(&self.q_type.to_u16().to_be_bytes());
        *pos += 2;

        packet[*pos..*pos + 2].copy_from_slice(&self.q_class.to_u16().to_be_bytes());
        *pos += 2;
    }
}

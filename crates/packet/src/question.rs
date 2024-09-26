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

use crate::header::Header;

#[derive(Debug)]
pub struct Question {
    pub qname: Vec<Vec<u8>>,
    pub qtype: [u8; 2],
    pub qclass: [u8; 2],
}

impl Question {
    pub fn try_parse_section(
        packet: [u8; crate::PACKET_SIZE],
        pos: &mut usize,
        header: &Header,
    ) -> Result<Vec<Question>, std::array::TryFromSliceError> {
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

            let qtype: [u8; 2] = packet[*pos..*pos + 2].try_into()?;
            *pos += 2;

            let qclass: [u8; 2] = packet[*pos..*pos + 2].try_into()?;
            *pos += 2;

            questions.push(Question {
                qname,
                qtype,
                qclass,
            });
        }

        return Ok(questions);
    }
}

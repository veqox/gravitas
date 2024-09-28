/* https://www.rfc-editor.org/rfc/rfc1035#section-4.1

+---------------------
|        Header       |
+---------------------+
|       Question      | the question for the name server
+---------------------+
|        Answer       | RRs answering the question
+---------------------+
|      Authority      | RRs pointing toward an authority
+---------------------+
|      Additional     | RRs holding additional information
+---------------------+
*/

use crate::header::Header;
use crate::question::Question;
use crate::resource_record::ResourceRecord;

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Packet {
    pub const MAX_SIZE: usize = 512;
}

impl TryFrom<[u8; Packet::MAX_SIZE]> for Packet {
    type Error = Box<dyn std::error::Error>;

    fn try_from(packet: [u8; Self::MAX_SIZE]) -> Result<Self, Self::Error> {
        let mut pos = 0;
        let header: Header = Header::try_parse_section(packet, &mut pos)?;
        let questions = Question::try_parse_section(packet, &mut pos, &header)?;
        let answers = ResourceRecord::try_parse_section(packet, &mut pos, &header)?;
        let authorities = ResourceRecord::try_parse_section(packet, &mut pos, &header)?;
        let additionals = ResourceRecord::try_parse_section(packet, &mut pos, &header)?;

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl Packet {
    pub fn try_serialize_into<'a>(
        &self,
        buf: &'a mut [u8; Self::MAX_SIZE],
    ) -> Result<&'a [u8], Box<dyn std::error::Error>> {
        let mut pos = 0;

        self.header.serialize_section(buf, &mut pos);

        for question in &self.questions {
            question.serialize_section(buf, &mut pos);
        }

        for answer in &self.answers {
            answer.try_serialize_section(buf, &mut pos);
        }

        for authority in &self.authorities {
            authority.try_serialize_section(buf, &mut pos);
        }

        for additonal in &self.additionals {
            additonal.try_serialize_section(buf, &mut pos);
        }

        Ok(&buf[..pos]) // Return the portion of the buffer that was used
    }
}

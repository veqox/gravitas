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
pub struct Packet<'a> {
    pub header: Header,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub authorities: Vec<ResourceRecord<'a>>,
    pub additionals: Vec<ResourceRecord<'a>>,
}

impl<'a> Packet<'a> {
    pub const MAX_SIZE: usize = 512;

    pub fn try_from(
        packet: &'a [u8; Packet::MAX_SIZE],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut pos = 0;
        let header: Header = Header::try_parse_section(packet, &mut pos)?;
        let questions = Question::try_parse_section(packet, &mut pos, &header)?;
        let answers = (0..header.ancount)
            .map(|_| ResourceRecord::try_parse_section(packet, &mut pos))
            .collect::<Result<Vec<_>, _>>()?;
        let authorities = (0..header.nscount)
            .map(|_| ResourceRecord::try_parse_section(packet, &mut pos))
            .collect::<Result<Vec<_>, _>>()?;
        let additionals = (0..header.arcount)
            .map(|_| ResourceRecord::try_parse_section(packet, &mut pos))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn try_serialize_into(
        &self,
        buf: &'a mut [u8; Packet::MAX_SIZE],
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

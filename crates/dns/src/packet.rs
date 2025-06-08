use crate::header::Header;
use crate::proto::{Parse, ParseError, Parser, Serialize, SerializeError, Serializer};
use crate::question::Question;
use crate::rr::ResourceRecord;

/// DNS packet layout as per [RFC 1035 Section 4.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1)
///
/// ```text
/// +---------------------+
/// |        Header       |
/// +---------------------+
/// |       Question      | the question for the name server
/// +---------------------+
/// |        Answer       | RRs answering the question
/// +---------------------+
/// |      Authority      | RRs pointing toward an authority
/// +---------------------+
/// |      Additional     | RRs holding additional information
/// +---------------------+
/// ```
#[derive(Debug)]
pub struct Packet<'a> {
    pub header: Header,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub authorities: Vec<ResourceRecord<'a>>,
    pub additionals: Vec<ResourceRecord<'a>>,
}

impl<'a> Parse<'a> for Packet<'a> {
    fn parse(parser: &mut Parser<'a>) -> Result<Self, ParseError> {
        let header = Header::parse(parser)?;

        let mut questions = Vec::with_capacity(header.qdcount.into());
        for _ in 0..header.qdcount {
            questions.push(Question::parse(parser)?);
        }

        let mut answers = Vec::with_capacity(header.ancount.into());
        for _ in 0..header.ancount {
            answers.push(ResourceRecord::parse(parser)?);
        }

        let mut authorities = Vec::with_capacity(header.nscount.into());
        for _ in 0..header.nscount {
            authorities.push(ResourceRecord::parse(parser)?);
        }

        let mut additionals = Vec::with_capacity(header.arcount.into());
        for _ in 0..header.arcount {
            additionals.push(ResourceRecord::parse(parser)?);
        }

        Ok(Packet {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl<'a> Serialize<'a> for Packet<'a> {
    fn serialize(self, serializer: &mut Serializer<'a>) -> Result<usize, SerializeError> {
        self.header.serialize(serializer)?;

        for question in self.questions {
            question.serialize(serializer)?;
        }

        for answers in self.answers {
            answers.serialize(serializer)?;
        }

        for authority in self.authorities {
            authority.serialize(serializer)?;
        }

        for additional in self.additionals {
            additional.serialize(serializer)?;
        }

        Ok(serializer.position())
    }
}

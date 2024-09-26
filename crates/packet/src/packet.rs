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

pub const PACKET_SIZE: usize = 512;

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl TryFrom<[u8; PACKET_SIZE]> for Packet {
    type Error = std::array::TryFromSliceError;

    fn try_from(packet: [u8; PACKET_SIZE]) -> Result<Self, Self::Error> {
        let mut pos = 0;
        let header: Header = Header::try_parse_section(packet, &mut pos)?;
        let questions: Vec<Question> = Question::try_parse_section(packet, &mut pos, &header)?;

        Ok(Self {
            header,
            questions,
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        })
    }
}

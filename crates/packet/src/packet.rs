use std::u8;

use crate::header::{Header, HEADER_SIZE};
use crate::question::Question;
use crate::resource_record::ResourceRecord;

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

    fn try_from(slice: [u8; PACKET_SIZE]) -> Result<Self, Self::Error> {
        let mut pos = 0;
        let header: Header = slice[pos..pos + HEADER_SIZE].try_into()?;
        pos += HEADER_SIZE;

        let mut questions: Vec<Question> = vec![];
        for _ in 0..header.qdcount {
            let mut qname: Vec<Vec<u8>> = vec![];

            while slice[pos] != 0 {
                let length = slice[pos] as usize;
                pos += 1;

                let label = &slice[pos..pos + length];
                pos += length;

                qname.push(label.to_vec());
            }

            let qtype: [u8; 2] = slice[pos..pos + 2].try_into()?;
            pos += 2;

            let qclass: [u8; 2] = slice[pos..pos + 2].try_into()?;
            pos += 2;

            questions.push(Question {
                qname,
                qtype,
                qclass,
            });
        }

        Ok(Self {
            header,
            questions,
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        })
    }
}

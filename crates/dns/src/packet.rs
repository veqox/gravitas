use crate::header::Header;
use crate::question::Question;
use crate::resource_record::ResourceRecord;

/// DNS packet layout as per [RFC 1035 Section 4.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1)
///
/// ```text
/// +---------------------
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

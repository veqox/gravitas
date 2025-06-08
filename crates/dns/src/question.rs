use std::fmt::Debug;

use crate::{
    DomainName,
    class::Class,
    proto::{Parse, ParseError, Parser, Serialize, SerializeError, Serializer},
    r#type::Type,
};

/// DNS question field layout as per [RFC 1035 Section 4.1.2](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2)
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                     QNAME                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug)]
pub struct Question<'a> {
    pub name: DomainName<'a>,
    pub r#type: Type,
    pub class: Class,
}

impl<'a> Parse<'a> for Question<'a> {
    fn parse(parser: &mut Parser<'a>) -> Result<Self, ParseError> {
        Ok(Question {
            name: DomainName::parse(parser)?,
            r#type: parser.consume_u16()?.into(),
            class: parser.consume_u16()?.into(),
        })
    }
}

impl<'a> Serialize<'a> for Question<'a> {
    fn serialize(self, serializer: &mut Serializer<'a>) -> Result<usize, SerializeError> {
        self.name.serialize(serializer)?;
        serializer.write_u16(self.r#type.into())?;
        serializer.write_u16(self.class.into())?;

        Ok(serializer.position())
    }
}

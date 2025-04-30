use crate::{class::Class, r#type::Type};

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
#[derive(Debug, Clone)]
pub struct Question<'a> {
    pub name: Vec<&'a [u8]>,
    pub r#type: Type,
    pub class: Class,
}

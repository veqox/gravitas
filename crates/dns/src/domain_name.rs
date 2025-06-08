use std::fmt::Display;
use std::str;

use crate::proto::{Parse, ParseError, Parser, Serialize, SerializeError, Serializer};

#[derive(Debug)]
pub struct DomainName<'a> {
    pub labels: Vec<&'a str>,
}

impl<'a> DomainName<'a> {
    pub fn size(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum()
    }
}

impl<'a> From<Vec<&'a str>> for DomainName<'a> {
    fn from(labels: Vec<&'a str>) -> Self {
        Self { labels }
    }
}

impl<'a> Parse<'a> for Vec<&'a str> {
    fn parse(parser: &mut Parser<'a>) -> Result<Self, ParseError> {
        let mut labels = vec![];

        loop {
            let len = parser.consume_u8()? as usize;

            match len {
                0 => break,
                len if len & 0xC0 == 0xC0 => {
                    let pointer: u16 = (((len & 0x3F) as u16) << 8) | parser.consume_u8()? as u16;

                    let pos = parser.position();

                    parser.seek(pointer.into())?;

                    labels.extend(Self::parse(parser)?);

                    parser.seek(pos)?;

                    break;
                }
                1..=63 => {
                    let label = str::from_utf8(parser.consume_bytes(len)?)
                        .map_err(|_| ParseError::InvalidUtf8)?;

                    labels.push(label);
                }
                _ => return Err(ParseError::InvalidLabelLength(len)),
            }
        }

        Ok(labels)
    }
}

impl<'a> Parse<'a> for DomainName<'a> {
    fn parse(parser: &mut Parser<'a>) -> Result<Self, ParseError> {
        Ok(Vec::<&str>::parse(parser)?.into())
    }
}

impl<'a> Serialize<'a> for DomainName<'a> {
    fn serialize(self, serializer: &mut Serializer<'a>) -> Result<usize, SerializeError> {
        for label in self.labels {
            serializer.write_u8(label.len() as u8)?;
            serializer.write_bytes(label.as_bytes())?;
        }
        serializer.write_u8(0)?;

        Ok(serializer.position())
    }
}

impl Default for DomainName<'_> {
    fn default() -> Self {
        Self { labels: Vec::new() }
    }
}

impl Display for DomainName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::with_capacity(self.size());

        for (i, part) in self.labels.iter().enumerate() {
            if i > 0 {
                result.push('.');
            }
            result.push_str(part);
        }

        result.push('.');

        f.write_str(&result)
    }
}

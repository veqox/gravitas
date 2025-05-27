use log::warn;
use std::str;

use crate::{
    DomainName,
    header::Header,
    packet::Packet,
    question::Question,
    resource_record::{self, Record},
    r#type::Type,
};

#[derive(Debug)]
pub enum ParseError {
    BufferOverflow(usize, usize),
    InvalidLabelLength(usize),
    InvalidUtf8,
    NotImplemented,
}

#[derive(Debug)]
pub struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Packet<'a>, ParseError> {
        let mut parser = Self { pos: 0, buf };

        let header = parser.consume_header()?;

        let mut questions = Vec::with_capacity(header.qdcount.into());
        for _ in 0..header.qdcount {
            questions.push(parser.consume_question()?);
        }

        let mut answers = Vec::with_capacity(header.ancount.into());
        for _ in 0..header.ancount {
            answers.push(parser.consume_resource_record()?);
        }

        let mut authorities = Vec::with_capacity(header.nscount.into());
        for _ in 0..header.nscount {
            authorities.push(parser.consume_resource_record()?);
        }

        let mut additionals = Vec::with_capacity(header.arcount.into());
        for _ in 0..header.arcount {
            additionals.push(parser.consume_resource_record()?);
        }

        if parser.pos != buf.len() {
            warn!("{} bytes left in buffer", buf.len() - parser.pos);
        }

        Ok(Packet {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    fn seek(&mut self, pos: usize) -> Result<(), ParseError> {
        if pos > self.buf.len() {
            return Err(ParseError::BufferOverflow(self.pos, self.buf.len()));
        }

        self.pos = pos;

        Ok(())
    }

    fn consume_u32(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_be_bytes([
            self.consume_u8()?,
            self.consume_u8()?,
            self.consume_u8()?,
            self.consume_u8()?,
        ]))
    }

    fn consume_u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes([self.consume_u8()?, self.consume_u8()?]))
    }

    fn consume_u8(&mut self) -> Result<u8, ParseError> {
        let value = self.read_u8()?;
        self.pos += size_of::<u8>();
        Ok(value)
    }

    fn read_u8(&self) -> Result<u8, ParseError> {
        if self.pos >= self.buf.len() {
            return Err(ParseError::BufferOverflow(self.pos, self.buf.len()));
        }

        Ok(self.buf[self.pos])
    }

    fn consume_bytes(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + len > self.buf.len() {
            return Err(ParseError::BufferOverflow(self.pos + len, self.buf.len()));
        }

        let bytes = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn consume_domain_name(&mut self) -> Result<DomainName<'a>, ParseError> {
        Ok(DomainName::from_labels(self.consume_labels()?))
    }

    fn consume_labels(&mut self) -> Result<Vec<&'a str>, ParseError> {
        let mut labels = vec![];

        loop {
            let len = self.consume_u8()? as usize;

            match len {
                0 => break,
                len if len & 0xC0 == 0xC0 => {
                    let pointer: u16 = (((len & 0x3F) as u16) << 8) | self.consume_u8()? as u16;

                    let pos = self.pos;

                    self.seek(pointer.into())?;

                    labels.extend(self.consume_labels()?);

                    self.seek(pos)?;

                    break;
                }
                1..=63 => {
                    let label = str::from_utf8(self.consume_bytes(len)?)
                        .map_err(|_| ParseError::InvalidUtf8)?;

                    labels.push(label);
                }
                _ => return Err(ParseError::InvalidLabelLength(len)),
            }
        }

        Ok(labels)
    }

    fn consume_header(&mut self) -> Result<Header, ParseError> {
        Ok(Header {
            id: self.consume_u16()?,
            flags: self.consume_u16()?.into(),
            qdcount: self.consume_u16()?,
            ancount: self.consume_u16()?,
            nscount: self.consume_u16()?,
            arcount: self.consume_u16()?,
        })
    }

    fn consume_question(&mut self) -> Result<Question<'a>, ParseError> {
        let q_name = self.consume_domain_name()?;
        let q_type = self.consume_u16()?.into();
        let q_class = self.consume_u16()?.into();

        Ok(Question {
            name: q_name,
            r#type: q_type,
            class: q_class,
        })
    }

    fn consume_resource_record(
        &mut self,
    ) -> Result<resource_record::ResourceRecord<'a>, ParseError> {
        let r_name = self.consume_domain_name()?;
        let r_type = self.consume_u16()?.into();
        let class = self.consume_u16()?.into();
        let ttl = self.consume_u32()?;
        let rd_length = self.consume_u16()?;

        let r_data = match &r_type {
            Type::A => Record::A {
                address: (self.consume_bytes(4)?).try_into().unwrap(),
            },
            Type::NS => Record::NS {
                nsdname: self.consume_domain_name()?,
            },
            Type::CNAME => Record::CNAME {
                cname: self.consume_domain_name()?,
            },
            Type::SOA => Record::SOA {
                mname: self.consume_domain_name()?,
                rname: self.consume_domain_name()?,
                serial: self.consume_u32()?,
                refresh: self.consume_u32()?,
                retry: self.consume_u32()?,
                expire: self.consume_u32()?,
                minimum: self.consume_u32()?,
            },
            Type::PTR => Record::PTR {
                ptrdname: self.consume_domain_name()?,
            },
            Type::MX => Record::MX {
                preference: self.consume_u16()?,
                exchange: self.consume_domain_name()?,
            },
            Type::TXT => Record::TXT {
                text: self.consume_bytes(rd_length.into())?,
            },
            Type::AAAA => Record::AAAA {
                address: self.consume_bytes(16)?.try_into().unwrap(),
            },
            Type::OPT => Record::OPT {
                options: {
                    let mut options = Vec::new();
                    let start = self.pos;

                    while (self.pos - start) < rd_length.into() {
                        options.push({
                            let code = self.consume_u16()?.into();
                            let len = self.consume_u16()?;
                            let data = self.consume_bytes(len.into())?;

                            resource_record::Option { code, len, data }
                        });
                    }

                    options
                },
            },

            Type::Unknown(_) => Record::Unkown {
                data: self.consume_bytes(rd_length.into())?,
            },
            x => {
                warn!("known record type not implemented {:?}", x);
                Record::Unkown {
                    data: self.consume_bytes(rd_length.into())?,
                }
            }
        };

        Ok(resource_record::ResourceRecord {
            name: r_name,
            r#type: r_type,
            class,
            ttl,
            rd_length,
            data: r_data,
        })
    }
}

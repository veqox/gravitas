use crate::{
    header::{Flags, Header, OpCode, RCode},
    packet::Packet,
    question::Question,
    resource_record::{Class, ResourceRecord, Type},
};

pub struct Parser<'a> {
    pos: usize,
    packet: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn parse(packet: &'a [u8]) -> Result<Packet<'a>, RCode> {
        let mut parser = Self { pos: 0, packet };

        let header = parser.consume_header()?;

        let mut questions = vec![];
        for _ in 0..header.qdcount {
            questions.push(parser.consume_question()?);
        }

        let mut answers = vec![];
        for _ in 0..header.ancount {
            answers.push(parser.consume_resource_record()?);
        }

        let mut authorities = vec![];
        for _ in 0..header.nscount {
            authorities.push(parser.consume_resource_record()?);
        }

        let mut additionals = vec![];
        for _ in 0..header.arcount {
            additionals.push(parser.consume_resource_record()?);
        }

        Ok(Packet {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    fn consume_u32(&mut self) -> Result<u32, RCode> {
        let value = u32::from_be_bytes(
            self.packet[self.pos..self.pos + std::mem::size_of::<u32>()]
                .try_into()
                .map_err(|_| RCode::FormatError)?,
        );
        self.pos += std::mem::size_of::<u32>();
        Ok(value)
    }

    fn consume_u16(&mut self) -> Result<u16, RCode> {
        let value = u16::from_be_bytes(
            self.packet[self.pos..self.pos + std::mem::size_of::<u16>()]
                .try_into()
                .map_err(|_| RCode::FormatError)?,
        );
        self.pos += std::mem::size_of::<u16>();
        Ok(value)
    }

    fn consume_u8(&mut self) -> Result<u8, RCode> {
        if self.pos >= self.packet.len() {
            return Err(RCode::FormatError);
        }

        let value = self.packet[self.pos];
        self.pos += std::mem::size_of::<u8>();
        Ok(value)
    }

    fn read_u8(&self) -> Result<u8, RCode> {
        if self.pos >= self.packet.len() {
            return Err(RCode::FormatError);
        }

        Ok(self.packet[self.pos])
    }

    fn consume_bytes(&mut self, len: usize) -> Result<&'a [u8], RCode> {
        if self.pos + len > self.packet.len() {
            return Err(RCode::FormatError);
        }

        let bytes = &self.packet[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn consume_domain_name(&mut self) -> Result<Vec<&'a [u8]>, RCode> {
        let mut labels = vec![];

        loop {
            let len = self.consume_u8()? as usize;
            if len == 0 {
                break;
            }

            let label = self.consume_bytes(len)?;
            labels.push(label);
        }

        Ok(labels)
    }

    fn consume_header(&mut self) -> Result<Header, RCode> {
        Ok(Header {
            id: self.consume_u16()?,
            flags: self.consume_flags()?,
            qdcount: self.consume_u16()?,
            ancount: self.consume_u16()?,
            nscount: self.consume_u16()?,
            arcount: self.consume_u16()?,
        })
    }

    fn consume_flags(&mut self) -> Result<Flags, RCode> {
        if self.pos + 2 >= self.packet.len() {
            return Err(RCode::FormatError);
        }

        Ok(Flags {
            qr: (self.read_u8()? & 0b10000000) >> 7,
            opcode: OpCode::from_u8((self.read_u8()? & 0b01111000) >> 3),
            aa: (self.read_u8()? & 0b00000100) >> 2,
            tc: (self.read_u8()? & 0b00000010) >> 1,
            rd: self.consume_u8()? & 0b00000001,
            ra: (self.read_u8()? & 0b10000000) >> 7,
            z: (self.read_u8()? & 0b01110000) >> 4,
            rcode: RCode::from_u8(self.consume_u8()? & 0b00001111),
        })
    }

    fn consume_question(&mut self) -> Result<Question<'a>, RCode> {
        let q_name = self.consume_domain_name()?;
        let q_type = Type::from_u16(self.consume_u16()?);
        let q_class = Class::from_u16(self.consume_u16()?);

        Ok(Question {
            q_name,
            q_type,
            q_class,
        })
    }

    fn consume_resource_record(&mut self) -> Result<ResourceRecord<'a>, RCode> {
        let r_name = self.consume_domain_name()?;
        let r_type = Type::from_u16(self.consume_u16()?);
        let r_class = Class::from_u16(self.consume_u16()?);
        let ttl = self.consume_u32()?;
        let rd_length = self.consume_u16()?;

        let r_data = self.consume_bytes(rd_length as usize)?;

        Ok(ResourceRecord {
            r_name,
            r_type,
            r_class,
            ttl,
            rd_length,
            r_data,
        })
    }
}

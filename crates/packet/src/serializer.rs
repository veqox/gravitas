use crate::{
    header::{Flags, Header},
    packet::Packet,
    question::Question,
    resource_record::ResourceRecord,
};

pub struct Serializer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Serializer<'a> {
    pub fn serialize(packet: &'a Packet, buf: &'a mut [u8; 512]) {
        let mut serializer = Self { buf, pos: 0 };

        serializer.write_header(&packet.header);

        for question in &packet.questions {
            serializer.write_question(question);
        }

        for answers in &packet.answers {
            serializer.write_resource_record(answers);
        }

        for authority in &packet.authorities {
            serializer.write_resource_record(authority);
        }

        for additional in &packet.additionals {
            serializer.write_resource_record(additional);
        }
    }

    fn write_u32(&mut self, value: u32) {
        self.buf[self.pos..self.pos + size_of::<u32>()].copy_from_slice(&value.to_be_bytes());
        self.pos += size_of::<u32>();
    }

    fn write_u16(&mut self, value: u16) {
        self.buf[self.pos..self.pos + size_of::<u16>()].copy_from_slice(&value.to_be_bytes());
        self.pos += size_of::<u16>();
    }

    fn write_u8(&mut self, value: u8) {
        self.buf[self.pos] = value;
        self.pos += size_of::<u8>();
    }

    fn write_bytes(&mut self, bytes: &'a [u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    fn write_domain_name(&mut self, domain_name: &Vec<&'a [u8]>) {
        for label in domain_name {
            self.write_u8(label.len() as u8);
            self.write_bytes(label);
        }
        self.write_u8(0);
    }

    fn write_header(&mut self, header: &Header) {
        self.write_u16(header.id);
        self.write_flags(&header.flags);
        self.write_u16(header.qdcount);
        self.write_u16(header.ancount);
        self.write_u16(header.nscount);
        self.write_u16(header.arcount);
    }

    fn write_flags(&mut self, flags: &Flags) {
        self.write_u8(flags.qr << 7 | flags.opcode.to_u8() << 3 | flags.aa << 2 | flags.rd);
        self.write_u8(flags.ra << 7 | flags.z << 4 | flags.rcode.to_u8());
    }

    fn write_question(&mut self, question: &Question<'a>) {
        self.write_domain_name(&question.q_name);
        self.write_u16(question.q_type.to_u16());
        self.write_u16(question.q_class.to_u16());
    }

    fn write_resource_record(&mut self, resource_record: &ResourceRecord<'a>) {
        self.write_domain_name(&resource_record.r_name);
        self.write_u16(resource_record.r_type.to_u16());
        self.write_u16(resource_record.r_class.to_u16());
        self.write_u32(resource_record.ttl);
        self.write_u16(resource_record.r_data.len() as u16);
        self.write_bytes(resource_record.r_data);
    }
}

use crate::{
    Class, DomainName, Type,
    header::Header,
    packet::Packet,
    question::Question,
    rr,
    rr::{Record, ResourceRecord},
};

pub struct Serializer<'a> {
    buf: &'a mut [u8; 4096],
    pos: usize,
}

impl<'a> Serializer<'a> {
    pub fn serialize(packet: Packet, buf: &'a mut [u8; 4096]) -> usize {
        let mut serializer = Self { buf, pos: 0 };

        serializer.write_header(packet.header);

        for question in packet.questions {
            serializer.write_question(question);
        }

        for answers in packet.answers {
            serializer.write_resource_record(answers);
        }

        for authority in packet.authorities {
            serializer.write_resource_record(authority);
        }

        for additional in packet.additionals {
            serializer.write_resource_record(additional);
        }

        serializer.pos
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

    fn write_domain_name(&mut self, domain_name: DomainName<'a>) {
        for label in domain_name.labels {
            self.write_u8(label.len() as u8);
            self.write_bytes(label.as_bytes());
        }
        self.write_u8(0);
    }

    fn write_header(&mut self, header: Header) {
        self.write_u16(header.id);
        self.write_u16(header.flags.into());
        self.write_u16(header.qdcount);
        self.write_u16(header.ancount);
        self.write_u16(header.nscount);
        self.write_u16(header.arcount);
    }

    fn write_question(&mut self, question: Question<'a>) {
        self.write_domain_name(question.name);
        self.write_u16(question.r#type.into());
        self.write_u16(question.class.into());
    }

    fn write_resource_record(&mut self, resource_record: ResourceRecord<'a>) {
        match resource_record {
            ResourceRecord::Record { name, ttl, data } => {
                self.write_domain_name(name);
                self.write_u16(Type::from(&data).into());
                self.write_u16(Class::IN.into());
                self.write_u32(ttl);
                self.write_u16(data.size() as u16);

                match data {
                    Record::A { address } => self.write_bytes(address),
                    Record::NS { nsdname } => self.write_domain_name(nsdname),
                    Record::CNAME { cname } => self.write_domain_name(cname),
                    Record::SOA {
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    } => {
                        self.write_domain_name(mname);
                        self.write_domain_name(rname);
                        self.write_u32(serial);
                        self.write_u32(refresh);
                        self.write_u32(retry);
                        self.write_u32(expire);
                        self.write_u32(minimum);
                    }
                    Record::PTR { ptrdname } => self.write_domain_name(ptrdname),
                    Record::MX {
                        preference,
                        exchange,
                    } => {
                        self.write_u16(preference);
                        self.write_domain_name(exchange);
                    }
                    Record::TXT { text } => self.write_bytes(text),
                    Record::AAAA { address } => self.write_bytes(address),
                };
            }
            ResourceRecord::OPTRecord {
                size,
                flags,
                options,
            } => {
                self.write_domain_name(DomainName::default());
                self.write_u16(Type::OPT.into());
                self.write_u16(size);
                self.write_u32(flags);
                self.write_u16((options.iter().map(|o| o.size()).sum::<usize>()) as u16);

                for option in options {
                    match option {
                        rr::Option::Unknown { code, len, data } => {
                            self.write_u16(code.into());
                            self.write_u16(len);
                            self.write_bytes(data);
                        }
                    }
                }
            }
            ResourceRecord::Unknown {
                name,
                r#type,
                class,
                ttl,
                data,
            } => {
                self.write_domain_name(name);
                self.write_u16(r#type.into());
                self.write_u16(class.into());
                self.write_u32(ttl);
                self.write_u16(data.len() as u16);
                self.write_bytes(data);
            }
        }
    }
}

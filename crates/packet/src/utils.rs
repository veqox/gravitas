use crate::Packet;

#[derive(Debug, Clone)]
pub struct DomainName<'a> {
    pub labels: Vec<&'a [u8]>,
}

impl<'a> DomainName<'a> {
    pub fn parse_section(
        packet: &'a [u8; Packet::MAX_SIZE],
        pos: &mut usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut labels = vec![];

        loop {
            let len = packet[*pos] as usize;
            *pos += 1;
            if len == 0 {
                break;
            }

            let label = &packet[*pos..*pos + len];
            labels.push(label);

            *pos += len;
        }

        Ok(Self { labels })
    }

    pub fn serialize_section(&self, buf: &'a mut [u8; Packet::MAX_SIZE], pos: &mut usize) {
        for label in &self.labels {
            buf[*pos] = label.len() as u8;
            *pos += 1;

            buf[*pos..*pos + label.len()].copy_from_slice(label);
            *pos += label.len();
        }

        buf[*pos] = 0;
        *pos += 1;
    }
}

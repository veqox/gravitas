use std::net;

use dns::{resource_record::ResourceRecord, Parser, Serializer};

fn main() {
    let socket = net::UdpSocket::bind(format!("0.0.0.0:{}", 3000)).unwrap();
    let mut buf = [0; 512];

    while let Ok((_, addr)) = socket.recv_from(&mut buf) {
        let mut packet = Parser::parse(&buf).unwrap();

        packet.header.flags.qr = 1;
        packet.header.ancount = 1;
        packet.answers.push(ResourceRecord {
            r_name: packet.questions[0].q_name.clone(),
            r_type: packet.questions[0].q_type.clone(),
            r_class: packet.questions[0].q_class.clone(),
            ttl: 0,
            rd_length: 4,
            r_data: &[0, 0, 0, 0],
        });

        let mut buf = [0; 512];
        Serializer::serialize(&packet, &mut buf);

        _ = socket.send_to(&buf, addr);
    }
}

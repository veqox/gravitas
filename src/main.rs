use std::net;

use packet::{resource_record::ResourceRecord, Packet};

fn main() {
    let socket = net::UdpSocket::bind(format!("0.0.0.0:{}", 3000)).unwrap();
    let mut buf = [0; Packet::MAX_SIZE];

    while let Ok((_, addr)) = socket.recv_from(&mut buf) {
        let mut packet = Packet::try_from(&buf).unwrap();
        println!("{:?}", buf);

        packet.header.flags.qr = 1;
        packet.header.ancount = 1;
        packet.answers = vec![ResourceRecord {
            r_name: packet.questions[0].q_name.clone(),
            r_type: packet.questions[0].q_type.clone(),
            r_class: packet.questions[0].q_class.clone(),
            ttl: 1_000,
            rd_length: 4,
            r_data: &[0, 0, 0, 0],
        }];

        let mut buffer = [0; Packet::MAX_SIZE];
        let packet: &[u8] = packet.try_serialize_into(&mut buffer).unwrap();
        println!("{:?}", packet);

        socket.send_to(packet, addr).unwrap();
    }
}

use std::net;

use packet::Packet;

fn main() {
    let socket = net::UdpSocket::bind(format!("0.0.0.0:{}", 3000)).unwrap();

    let mut buf = [0; packet::PACKET_SIZE];

    while let Ok((amt, src)) = socket.recv_from(&mut buf) {
        println!("{} bytes from {}", amt, src.ip());
        let packet = Packet::try_from(buf).unwrap();
        println!("Header: {:?}", packet)
    }
}

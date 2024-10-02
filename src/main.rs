use std::net;

use packet::Parser;

fn main() {
    let socket = net::UdpSocket::bind(format!("0.0.0.0:{}", 3000)).unwrap();
    let mut buf = [0; 512];

    while let Ok((_, _)) = socket.recv_from(&mut buf) {
        let packet = Parser::parse(&buf);

        println!("{:?}", packet);
    }
}

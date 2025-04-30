use std::{net::UdpSocket, time::Instant};

use dns::{Parser, Serializer};
use log::{debug, error};

fn main() {
    env_logger::init();

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", 5300)).expect("couldn't bind to address");
    let mut buf = [0; 4096];

    while let Ok((len, addr)) = socket.recv_from(&mut buf) {
        debug!("received {} bytes from {}", len, addr.ip());

        let start = Instant::now();
        let packet = match Parser::parse(&buf[..len]) {
            Err(err) => {
                error!("failed to parse packet {:?}", err);
                continue;
            }
            Ok(packet) => packet,
        };

        debug!("packet parsed in {:?}", start.elapsed());

        let mut buf = [0; 4096];
        let len = Serializer::serialize(packet, &mut buf);
        let buf = &buf[0..len];

        _ = socket.send_to(buf, addr);
    }
}

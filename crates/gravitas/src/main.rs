use std::net::UdpSocket;
use std::time::Instant;

use dns::proto::Parser;
use log::{debug, error, info};

const LISTEN_ADDR: &str = "0.0.0.0:5300";

fn main() {
    env_logger::init();

    let socket = UdpSocket::bind(LISTEN_ADDR).expect("couldn't bind to address");

    let mut buf = [0; 4096];

    info!("listening on {}", LISTEN_ADDR);

    loop {
        let (len, addr) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                error!("failed to receive data: {}", e);
                continue;
            }
        };

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

        debug!("{:?}", packet);
    }
}

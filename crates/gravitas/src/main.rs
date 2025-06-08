use std::net::UdpSocket;
use std::time::Instant;

use dns::{
    Packet,
    proto::{Parse, Parser, Serialize, Serializer},
};
use log::{debug, error, info, warn};

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

        let mut parser = Parser::new(&buf[..len]);

        let packet = match Packet::parse(&mut parser) {
            Err(err) => {
                error!("failed to parse packet {:?}", err);
                continue;
            }
            Ok(packet) => packet,
        };

        if parser.remaining() > 0 {
            warn!("{} bytes left in buffer", parser.remaining());
        }

        debug!("packet parsed in {:?}", start.elapsed());

        debug!("{:?}", packet);

        let mut serialize_buf = [0; 4096];

        let serialize_len = match packet.serialize(&mut Serializer::new(&mut serialize_buf)) {
            Err(err) => {
                error!("failed to serialize packet {:?}", err);
                continue;
            }
            Ok(len) => len,
        };

        if buf[..len] != serialize_buf[..serialize_len] {
            error!("original:   {:?}", &buf[..len]);
            error!("serialized: {:?}", &serialize_buf[..serialize_len]);
        } else {
            debug!("serialization successful: buffers match");
        }
    }
}

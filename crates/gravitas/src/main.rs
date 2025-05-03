use std::time::Instant;

use dns::proto::Parser;
use log::{debug, error, info, warn};
use smol::net::UdpSocket;

fn main() {
    smol::block_on(async {
        env_logger::init();

        let listen_addr = "0.0.0.0:5300";
        let upstream_addr = "1.1.1.1:53";

        let socket = UdpSocket::bind(&listen_addr)
            .await
            .expect("couldn't bind to address");

        let mut buf = [0; 4096];

        info!("listening on {}", &listen_addr);

        loop {
            let (len, client_addr) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    error!("failed to receive data: {}", e);
                    continue;
                }
            };

            debug!("received {} bytes from {}", len, client_addr.ip());

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

            match packet.questions.len() {
                0 => continue,
                1 => {}
                len => {
                    warn!(
                        "received packet with {} questions from {}",
                        len, client_addr
                    );
                    continue;
                }
            }

            let question = &packet.questions[0];

            info!("processing question from {}: {:?}", client_addr, question);

            _ = socket.send_to(&buf[..len], upstream_addr).await;

            let mut buf = [0; 4096];

            let (len, _) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    error!("failed to receive response from upstream DNS server: {}", e);
                    continue;
                }
            };

            debug!(
                "received {} bytes from upstream dns server {}",
                len, upstream_addr
            );

            let packet = match Parser::parse(&buf[..len]) {
                Err(err) => {
                    error!("failed to parse upstream packet {:?}", err);
                    continue;
                }
                Ok(packet) => packet,
            };

            debug!("{:?}", packet);

            info!(
                "received {} answer(s) {:?}",
                packet.header.ancount, packet.answers
            );

            _ = socket.send_to(&buf[..len], client_addr).await
        }
    })
}

use std::net::{Ipv4Addr, SocketAddr};

use slog;
use tokio::{
    self, codec,
    net::{UdpFramed, UdpSocket},
    prelude::*,
};

use error::Error;
use mac::MacAddress;

const WAKE_ON_LAN_PORTS: [u16; 3] = [0, 7, 9];

pub fn run(log: slog::Logger, desired_mac_address: MacAddress) -> Result<(), Error> {
    let ip_addr = Ipv4Addr::new(0, 0, 0, 0).into();

    let listeners = WAKE_ON_LAN_PORTS
        .iter()
        .map(|&port| {
            let socket_addr = SocketAddr::new(ip_addr, port);

            UdpSocket::bind(&socket_addr)
                .map_err(|e| Error::BindError(port, e))
                .map(|socket| {
                    let stream = UdpFramed::new(socket, codec::BytesCodec::new());
                    let log = log.new(o!{"port" => port});

                    (log, stream)
                })
        }).collect::<Result<Vec<_>, Error>>()?;

    info!(
        log,
        "Listening for wake-on-LAN packets on ports 0, 7, and 9"
    );

    let servers = listeners.into_iter().map(move |(log, stream)| {
        stream
            .map_err({
                let log = log.clone();
                move |e| {
                    error!(log, "Error decoding stream"; "error" => %e);
                    ()
                }
            }).for_each(move |(bytes, addr)| {
                let log = log.new(o!{"remote" => addr});

                let _mac_address = match MacAddress::from_magic_packet(&bytes) {
                    Err(e) => {
                        info!(log, "Received invalid wake-on-LAN packet"; "error" => %e);
                        return future::ok(());
                    }

                    Ok(mac_address) if mac_address != desired_mac_address => {
                        info!(
                            log,
                            "Recieved wake-on-LAN packet for different mac address";
                            "desired_mac_address" => %desired_mac_address,
                            "received_mac_address" => %mac_address,
                        );
                        return future::ok(());
                    }

                    Ok(mac_address) => {
                        info!(log, "Received wake-on-LAN packet"; "mac_address" => %mac_address);
                        mac_address
                    }
                };

                return future::ok(());
            })
    });

    let server = future::join_all(servers).map(|_| ());

    tokio::run(server);

    Ok(())
}

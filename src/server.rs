//! The wake-on-lan-hook server.
use std::{
    net::{Ipv4Addr, SocketAddr},
    process::Command,
};

use slog;
use stream_cancel::{StreamExt, Tripwire};
use tokio::{
    self, codec,
    net::{UdpFramed, UdpSocket},
    prelude::*,
};
use tokio_process::CommandExt;
use tokio_signal::unix::{Signal, SIGINT, SIGTERM};

use error::Error;
use mac::MacAddress;

/// The ports to listen on.
///
/// Wake-on-LAN "magic packets" are sent on UDP ports 0, 7, or 9 *or* as an
/// Ethernet packet with EtherType `0x0842`.mac
///
/// See [the Wikipedia article][wiki] for more information.
///
/// [wiki]: https://en.wikipedia.org/wiki/Wake-on-LAN#Magic_packet
const WAKE_ON_LAN_PORTS: [u16; 3] = [0, 7, 9];

/// Run the wake-on-lan-hook server.
///
/// This will start listening on UDP ports 0, 7, and 9 for wake-on-LAN "magic
/// packets" and run the given command whenever a packet for the desired MAC
/// address is detected.
///
/// Wake-on-LAN packets for other MAC addresses will be ignored but logged.
///
/// See the [`magic_packet()`][::mac::magic_packet] parser for details about what
/// constitutes a magic packet.
pub fn run(
    log: slog::Logger,
    desired_mac_address: MacAddress,
    cmd: Vec<String>,
) -> Result<(), Error> {
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

    let mut runtime = tokio::runtime::Runtime::new().expect("Could not create tokio runtime");

    let (signal_handler, tripwire) = signal_guard(log.clone());
    let signal_handler = signal_handler.map_err({
        let log = log.clone();
        move |e| {
            error!(log, "An error occurred while listening for SIGINT and SIGTERM"; "error" => %e);
            ()
        }
    });
    runtime.spawn(signal_handler);

    let servers = listeners.into_iter().map({
        move |(log, stream)| {
            stream
                .map_err({
                    let log = log.clone();
                    move |e| {
                        error!(log, "Error decoding stream"; "error" => %e);
                        ()
                    }
                })
                .take_until(tripwire.clone())
                .for_each({
                    let cmd = cmd.clone();
                    move |(bytes, addr)| {
                        let log = log.new(o!{"remote" => addr});

                        let _mac_address = match MacAddress::from_magic_packet(&bytes) {
                            Err(e) => {
                                info!(log, "Received invalid wake-on-LAN packet"; "error" => %e);
                                return future::Either::A(future::ok(()));
                            }

                            Ok(mac_address) if mac_address != desired_mac_address => {
                                info!(
                                    log,
                                    "Recieved wake-on-LAN packet for different mac address";
                                    "desired_mac_address" => %desired_mac_address,
                                    "received_mac_address" => %mac_address,
                                );
                                return future::Either::A(future::ok(()));
                            }

                            Ok(mac_address) => {
                                info!(log, "Received wake-on-LAN packet"; "mac_address" => %mac_address);
                                mac_address
                            }
                        };

                        assert!(cmd.len() > 1);
                        let log = log.new(o!{"command" => format!("{:?}", cmd)});
                        let command_future = Command::new(&cmd[0])
                            .args(&cmd[1..])
                            .output_async()
                            .map_err({
                                let log = log.clone();
                                move |e| {
                                    crit!(log, "failed to communicate with process"; "error" => %e);
                                    ()
                                }
                            })
                            .map({
                                let log = log.clone();
                                move |output| {
                                    let log = log.new(o!{
                                        "stdout" => utf8_or_raw(&output.stdout),
                                        "stderr" => utf8_or_raw(&output.stderr),
                                    });

                                    if output.status.success() {
                                        info!(log, "Command executed successfully");
                                        future::ok(())
                                    } else {
                                        error!(log, "Command executed unsuccessfully"; "status" => output.status.code());
                                        future::err(())
                                    }
                                }
                            });

                        future::Either::B(command_future.map(|_| ()))
                    }
                })
        }
    });

    let server = future::join_all(servers).map(|_| ());

    runtime.spawn(server);
    runtime
        .shutdown_on_idle()
        .wait()
        .expect("Could not shut down tokio runtime");

    Ok(())
}

/// Attempt to parse the bytes as UTF-8.
///
/// If the bytes cannot be parsed as UTF-8 successfully, the `Debug`
/// representation of the bytes will be used instead.
fn utf8_or_raw(bytes: &[u8]) -> String {
    ::std::str::from_utf8(bytes)
        .map(Into::into)
        .unwrap_or_else(|_| format!("{:?}", bytes))
}

/// Generate a signal handling future for SIGINT and SIGTERM and a tripwire that
/// indictes when either of them is recieved.
///
/// The returned future (which msut be spawned) listens for `SIGINT` (i.e.,
/// Ctrl-C) or `SIGTERM` (i.e., a polite stop request) and, upon receipt, causes
/// the [`Tripwire`] future to resolve.
fn signal_guard(log: slog::Logger) -> (impl Future<Item = (), Error = Error>, Tripwire) {
    let (trigger, tripwire) = Tripwire::new();
    let mut trigger_guard = Some(trigger);

    let sigint = Signal::new(SIGINT).flatten_stream().map({
        let log = log.clone();
        move |_| {
            info!(log, "Received Ctrl-C; shutting down");
            ()
        }
    });
    let sigterm = Signal::new(SIGTERM).flatten_stream().map({
        let log = log.clone();
        move |_| {
            info!(log, "Received SIGTERM; shutting down");
            ()
        }
    });

    let signal_handler = sigint
        .select(sigterm)
        .take(1)
        .map_err(Error::Io)
        .for_each(move |()| {
            if let Some(trigger) = trigger_guard.take() {
                drop(trigger);
            }

            future::ok(())
        });

    (signal_handler, tripwire)
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
extern crate combine;
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate nix;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;
extern crate stream_cancel;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tokio;
extern crate tokio_process;
extern crate tokio_signal;

mod error;
mod mac;
mod server;

use std::process::exit;

use nix::unistd::getuid;
use slog::Drain;
use structopt::StructOpt;

#[derive(Debug, Eq, StructOpt, PartialEq)]
#[structopt(name = "wake-on-lan-hook")]
/// Listen for wake-on-LAN packets and execute commands.
struct Options {
    #[structopt(name = "MAC", parse(try_from_str), raw(required = "true"))]
    /// The MAC address to listen for wake-on-LAN packets for.
    mac_address: mac::MacAddress,

    #[structopt(name = "COMMAND", raw(required = "true"))]
    /// The command to execute when a wake-on-LAN packet is received.
    command: Vec<String>,
}

/// The `wake-on-lan-hook` entrypoint.
///
/// [`Options`] will be parsed from the command line arguments and will determine
/// the behaviour of the server.
fn main() {
    let options = Options::from_args();

    let exit_code = {
        let decorator = slog_term::PlainDecorator::new(std::io::stdout());
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let log = slog::Logger::root(drain, o!{});

        if !getuid().is_root() {
            crit!(
                log,
                "wake-on-lan-hook listens on privileged ports 0, 7, and 9 and must be run as root."
            );
            1
        } else {
            match server::run(log.clone(), options.mac_address, options.command) {
                Ok(_) => {
                    info!(log, "Server shut down.");
                    0
                }
                Err(e) => {
                    crit!(log, "An unexpected error occurred"; "error" => %e);
                    1
                }
            }
        }
    };

    exit(exit_code);
}

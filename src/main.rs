extern crate combine;
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;

mod error;
mod mac;

use structopt::StructOpt;

#[derive(Debug, Eq, StructOpt, PartialEq)]
#[structopt(name = "wake-on-lan-hook")]
/// Listen for wake-on-LAN packets and execute commands.
struct Options {
    #[structopt(
        name = "MAC",
        parse(try_from_str),
        raw(required = "true")
    )]
    /// The MAC address to listen for wake-on-LAN packets for.
    mac_address: mac::MacAddress,

    #[structopt(
        name = "COMMAND",
        raw(required = "true"),
    )]
    /// The command to execute when a wake-on-LAN packet is received.
    command: Vec<String>,
}

fn main() {
    let _options = Options::from_args();
}

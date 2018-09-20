use std::io;

use combine::easy;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Invalid MAC address")]
    MacParseError(#[cause] easy::Errors<char, String, usize>),

    #[fail(display = "Could not parse magic packet")]
    MagicPacketParseError(#[cause] easy::Errors<u8, String, usize>),

    #[fail(display = "Invalid packet length ({}); wake-on-LAN magic packets should be 106 bytes", _0)]
    MagicPacketLengthError(usize),

    #[fail(display = "Could not bind to wake-on-LAN port {}", _0)]
    BindError(u16, #[cause] io::Error),
}

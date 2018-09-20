//! The error types of `wake-on-lan-hook`.

use std::io;

use combine::easy;

#[derive(Debug, Fail)]
/// An error inside of `wake-on-lan-hook`.
pub enum Error {
    #[fail(display = "Invalid MAC address")]
    /// An error that occurs when a MAC address cannot be parsed from a string.
    MacParseError(#[cause] easy::Errors<char, String, usize>),

    #[fail(display = "Could not parse magic packet")]
    /// An error that occurs when a sequence of bytes does not correctly parse as a wake-on-LAN magic packet.
    MagicPacketParseError(#[cause] easy::Errors<u8, String, usize>),

    #[fail(display = "Invalid packet length ({}); wake-on-LAN magic packets should be 106 bytes",
           _0)]
    /// An error that occurs when a sequence of bytes is the wrong length to be a wake-on-LAN magic packet.
    MagicPacketLengthError(usize),

    #[fail(display = "Could not bind to wake-on-LAN port {}", _0)]
    /// An error that occurs when wake-on-lan-hook cannot bind to a port.
    BindError(u16, #[cause] io::Error),
}

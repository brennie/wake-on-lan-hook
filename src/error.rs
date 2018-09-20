use combine::easy;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Invalid MAC address")]
    MacParseError(#[cause] easy::Errors<char, String, usize>),

    #[fail(display = "Could not parse magic packet")]
    MagicPacketParseError(#[cause] easy::Errors<u8, String, usize>),

    #[fail(display = "Invalid length for packet ({}); wake-on-LAN magic packets must be exactly 102 bytes long", _0)]
    MagicPacketLengthError(usize),
}

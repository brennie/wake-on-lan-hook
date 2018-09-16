use combine::{
    char::{char, hex_digit},
    combinator::eof,
    stream::state::{IndexPositioner, State},
    ParseError, Parser, RangeStream,
};

use std::{self, fmt};

use error::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A MAC address, represented as a tuple of six of octets.
pub struct MacAddress(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

impl std::str::FromStr for MacAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<MacAddress> {
        let stream = State::with_positioner(s, IndexPositioner::new());
        mac_address()
            .easy_parse(stream)
            .map(|(mac, _)| mac)
            .map_err(Into::into)
    }
}

fn hex_byte<I>() -> impl Parser<Input = I, Output = u8>
where
    I: RangeStream<Item = char>,
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    let u8_hex_digit = || hex_digit().map(|c: char| c.to_digit(16).unwrap() as u8);

    (u8_hex_digit(), u8_hex_digit()).map(|(hi, lo)| (hi << 4) | lo)
}

fn mac_address<I>() -> impl Parser<Input = I, Output = MacAddress>
where
    I: RangeStream<Item = char>,
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    (
        hex_byte().skip(char(':')),
        hex_byte().skip(char(':')),
        hex_byte().skip(char(':')),
        hex_byte().skip(char(':')),
        hex_byte().skip(char(':')),
        hex_byte().skip(eof()),
    )
        .map(|(a, b, c, d, e, f)| MacAddress(a, b, c, d, e, f))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use combine::easy;
    use error::Error;

    #[test]
    fn test_parse() {
        assert_eq!(
            MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            MacAddress(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)
        );

        assert_eq!(
            MacAddress::from_str("aa"),
            Err(Error::MacParseError(
                easy::Errors {
                    position: 2,
                    errors: vec![
                        easy::Error::Unexpected(easy::Info::Borrowed("end of input".into())),
                        easy::Error::Expected(easy::Info::Token(':')),
                    ],
                },
            )));

        assert_eq!(
            MacAddress::from_str("aa:bb:cc:dd:ee:ff:"),
            Err(Error::MacParseError(
                easy::Errors {
                    position: 17,
                    errors: vec![
                        easy::Error::Unexpected(easy::Info::Token(':')),
                        easy::Error::Expected(easy::Info::Borrowed("end of input")),
                    ],
                }
            )));

        assert_eq!(
            MacAddress::from_str("bb:cc:dd:ee:ff:gg"),
            Err(Error::MacParseError(
                easy::Errors {
                    position: 15,
                    errors: vec![
                        easy::Error::Unexpected(easy::Info::Token('g')),
                        easy::Error::Expected(easy::Info::Borrowed("hexadecimal digit")),
                    ],
                },
            )));
    }

    #[test]
    fn test_display() {
        assert_eq!(
            MacAddress(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff).to_string(),
            "AA:BB:CC:DD:EE:FF"
        );
    }

    #[test]
    fn test_round_trip() {
        let s = "AA:BB:CC:DD:EE:FF";

        assert_eq!(MacAddress::from_str(s).unwrap().to_string(), s);
    }
}

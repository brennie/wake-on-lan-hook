use combine::{
    combinator::eof,
    parser::{
        char::hex_digit,
        item::{token, value},
        range::{range, take},
        repeat::skip_count_min_max,
    },
    stream::state::{IndexPositioner, State},
    ParseError, Parser, RangeStream,
};

use std::{fmt, str::FromStr};

use error::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A MAC address, represented as a tuple of six of octets.
pub struct MacAddress(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddress {
    pub fn from_magic_packet(s: &[u8]) -> Result<Self, Error> {
        let stream = State::with_positioner(s, IndexPositioner::new());
        magic_packet()
            .easy_parse(stream)
            .map(|(mac, _)| mac)
            .map_err(|e| {
                Error::MagicPacketParseError(e.map_range(|bs| {
                    let bytes_as_str = bs
                        .iter()
                        .map(|b| format!("0x{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("bytes [{}]", bytes_as_str)
                }))
            })
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

impl FromStr for MacAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stream = State::with_positioner(s, IndexPositioner::new());
        mac_address()
            .easy_parse(stream)
            .map(|(mac, _)| mac)
            .map_err(|e| Error::MacParseError(e.map_range(String::from)))
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
        hex_byte().skip(token(':')),
        hex_byte().skip(token(':')),
        hex_byte().skip(token(':')),
        hex_byte().skip(token(':')),
        hex_byte().skip(token(':')),
        hex_byte().skip(eof()),
    )
        .map(|(a, b, c, d, e, f)| MacAddress(a, b, c, d, e, f))
}

fn magic_packet<'a, I>() -> impl Parser<Input = I, Output = MacAddress> + 'a
where
    I: RangeStream<Item = u8, Range = &'a [u8]> + 'a,
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    let mac = |expected: &'a [u8]| range(expected);

    let header = skip_count_min_max(6, 6, token(0xFF)).message("expected magic packet header");
    let body = take(6).then(move |bytes: &'a [u8]| {
        skip_count_min_max(15, 15, mac(bytes))
            .message("expected repeated MAC address")
            .with(value(bytes))
    });

    header
        .with(body)
        .skip(eof().expected("end of packet"))
        .map(|bytes| {
            assert!(bytes.len() == 6);

            MacAddress(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
        })
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{iter, str::FromStr};

    use combine::easy;
    use error::Error;

    fn make_magic_packet(valid_header: bool, macs: Vec<MacAddress>) -> Vec<u8> {
        let mut packet = Vec::with_capacity(102);

        if valid_header {
            for _ in 0..6 {
                packet.push(0xFF);
            }
        } else {
            for _ in 0..5 {
                packet.push(0xFF);
            }
            packet.push(0xFE);
        }
        for mac in macs {
            packet.push(mac.0);
            packet.push(mac.1);
            packet.push(mac.2);
            packet.push(mac.3);
            packet.push(mac.4);
            packet.push(mac.5);
        }

        packet
    }

    #[test]
    fn test_parse() {
        assert_eq!(
            MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            MacAddress(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)
        );

        assert_eq!(
            MacAddress::from_str("aa"),
            Err(Error::MacParseError(easy::Errors {
                position: 2,
                errors: vec![
                    easy::Error::Unexpected(easy::Info::Borrowed("end of input".into())),
                    easy::Error::Expected(easy::Info::Token(':')),
                ],
            },))
        );

        assert_eq!(
            MacAddress::from_str("aa:bb:cc:dd:ee:ff:"),
            Err(Error::MacParseError(easy::Errors {
                position: 17,
                errors: vec![
                    easy::Error::Unexpected(easy::Info::Token(':')),
                    easy::Error::Expected(easy::Info::Borrowed("end of input")),
                ],
            }))
        );

        assert_eq!(
            MacAddress::from_str("bb:cc:dd:ee:ff:gg"),
            Err(Error::MacParseError(easy::Errors {
                position: 15,
                errors: vec![
                    easy::Error::Unexpected(easy::Info::Token('g')),
                    easy::Error::Expected(easy::Info::Borrowed("hexadecimal digit")),
                ],
            }))
        );
    }

    #[test]
    fn test_from_magic_packet() {
        let mac = MacAddress(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        let packet = make_magic_packet(true, iter::repeat(mac).take(16).collect());
        assert_eq!(MacAddress::from_magic_packet(&packet[..]), Ok(mac));

        let packet = make_magic_packet(false, iter::repeat(mac).take(16).collect());
        assert_eq!(
            MacAddress::from_magic_packet(&packet[..]),
            Err(Error::MagicPacketParseError(easy::Errors {
                position: 5,
                errors: vec![
                    easy::Error::Message(easy::Info::Owned("expected 1 more elements".into())),
                    easy::Error::Message(easy::Info::Borrowed("expected magic packet header")),
                ],
            }))
        );

        let packet = {
            let mut macs = iter::repeat(mac).take(15).collect::<Vec<_>>();
            macs.push(MacAddress(0, 0, 0, 0, 0, 0));

            make_magic_packet(true, macs)
        };
        assert_eq!(
            MacAddress::from_magic_packet(&packet[..]),
            Err(Error::MagicPacketParseError(easy::Errors {
                position: 96,
                errors: vec![
                    easy::Error::Message(easy::Info::Owned("expected 1 more elements".into())),
                    easy::Error::Message(easy::Info::Borrowed("expected repeated MAC address")),
                ],
            }))
        );

        let packet = {
            let mut macs = iter::repeat(mac).take(6).collect::<Vec<_>>();
            macs.extend(iter::repeat(MacAddress(0, 0, 0, 0, 0, 0)).take(10));

            make_magic_packet(true, macs)
        };
        assert_eq!(
            MacAddress::from_magic_packet(&packet[..]),
            Err(Error::MagicPacketParseError(easy::Errors {
                position: 42,
                errors: vec![
                    easy::Error::Message(easy::Info::Owned("expected 10 more elements".into())),
                    easy::Error::Message(easy::Info::Borrowed("expected repeated MAC address")),
                ],
            }))
        );
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

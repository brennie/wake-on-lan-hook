use combine::easy;

#[derive(Debug, Fail, PartialEq)]
pub enum Error {
    #[fail(display = "Invalid MAC address")]
    MacParseError(#[cause] easy::Errors<char, String, usize>),
}

pub type Result<T> = ::std::result::Result<T, Error>;

impl<'a> From<easy::Errors<char, &'a str, usize>> for Error {
    fn from(inner: easy::Errors<char, &'a str, usize>) -> Self {
        Error::MacParseError(inner.map_range(|r| String::from(r)))
    }
}

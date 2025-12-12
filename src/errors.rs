use core::fmt;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInputLength,
    InvalidEta,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInputLength => write!(f, "Input length is invalid"),
            Error::InvalidEta => write!(f, "Invalid value for Eta"),
        }
    }
}

impl core::error::Error for Error {}

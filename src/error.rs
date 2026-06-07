use crate::ufw_log::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Parse(ParseError),
    Io(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse(pe) => match pe {
                ParseError::InvalidNumber { field, value } => {
                    write!(f, "Invalid number for field '{field}': '{value}'")
                }
                ParseError::InvalidFormat { field, description } => {
                    write!(f, "Invalid format for field '{field}': {description}")
                }
            },
            Error::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

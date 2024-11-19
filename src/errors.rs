use std::{error, fmt};

#[derive(Debug)]
pub(crate) enum CombinationError {
    DeserializeError(String),
}

impl error::Error for CombinationError {}

impl fmt::Display for CombinationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CombinationError::*;
        match self {
            DeserializeError(s) => write!(f, "Could not deserialize value: {}", s),
        }
    }
}

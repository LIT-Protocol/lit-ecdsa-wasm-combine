use std::{error, fmt};

#[derive(Debug)]
pub(crate) enum CombinationError {
    DeserializeError,
}

impl error::Error for CombinationError {}

impl fmt::Display for CombinationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CombinationError::*;
        match self {
            DeserializeError => write!(f, "Could not deserialize value"),
        }
    }
}

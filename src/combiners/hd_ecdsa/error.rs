use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    InvalidKeyDeriveType(u8),
    CurveError,
}

impl From<std::num::ParseIntError> for Error {
    fn from(_: std::num::ParseIntError) -> Self {
        Self::InvalidKeyDeriveType(0)
    }
}

impl From<k256::elliptic_curve::Error> for Error {
    fn from(_: k256::elliptic_curve::Error) -> Self {
        Self::CurveError
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match write!(f, "{}", self.to_string()) {
            Ok(_) => {
                Ok(())
            },
            Err(e) => {
                Err(e)
            }
        }
    }
}
#[derive(Debug)]
pub enum Error {
    InvalidKeyDeriveType(u8),
    CurveMismatchOrInvalidShare,
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
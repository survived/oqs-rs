use snafu::Snafu;

use oqs_sys::common::OQS_STATUS;

#[derive(Debug, Snafu)]
pub enum OqsError {
    #[snafu(display("LibOqs error happened"))]
    LiboqsError,
    #[snafu(display("Other library error happened (e.g., OpenSSL)"))]
    OtherLibraryError,
}

pub trait OqsStatusEx {
    fn raise(self) -> Result<(), OqsError>;
}

impl OqsStatusEx for OQS_STATUS {
    fn raise(self) -> Result<(), OqsError> {
        use OQS_STATUS::*;
        use OqsError::*;
        match self {
            OQS_ERROR => Err(LiboqsError),
            OQS_SUCCESS => Ok(()),
            OQS_EXTERNAL_LIB_ERROR_OPENSSL => Err(OtherLibraryError),
        }
    }
}

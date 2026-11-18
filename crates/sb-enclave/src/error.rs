use sb_proto::error::{ErrorCode, ProtoError, SanitizedError};
use std::fmt;

#[derive(Debug, Clone)]
pub struct EnclaveError {
    pub code: ErrorCode,
    pub message: String,
}

impl EnclaveError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let sanitized = SanitizedError::new(code, message);
        Self {
            code: sanitized.code,
            message: sanitized.message,
        }
    }

    pub fn into_sanitized(self) -> SanitizedError {
        SanitizedError::new(self.code, self.message)
    }
}

impl From<ProtoError> for EnclaveError {
    fn from(err: ProtoError) -> Self {
        let s = err.into_sanitized();
        Self {
            code: s.code,
            message: s.message,
        }
    }
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for EnclaveError {}

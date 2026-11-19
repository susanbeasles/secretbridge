use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Validation,
    ManifestIo,
    Unauthorized,
    CapabilityDenied,
    VaultRestriction,
    StalePlan,
    SizeLimitExceeded,
    OwnershipConflict,
    CryptoFailure,
    TransportFailure,
    UpstreamFailure,
    CaptureExpired,
    CaptureUnavailable,
    InternalError,
}

/// Sanitized error safe to serialize across vsock to the untrusted host JVM.
/// Never include secret values, raw HTTP bodies, or stack traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizedError {
    pub code: ErrorCode,
    pub message: String,
}

impl SanitizedError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_ascii_message(&message.into()),
        }
    }
}

impl fmt::Display for SanitizedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SanitizedError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    Validation(String),
    StalePlan(String),
    Unauthorized(String),
    Crypto(String),
    Transport(String),
}

impl ProtoError {
    pub fn into_sanitized(self) -> SanitizedError {
        match self {
            Self::Validation(msg) => SanitizedError::new(ErrorCode::Validation, msg),
            Self::StalePlan(msg) => SanitizedError::new(ErrorCode::StalePlan, msg),
            Self::Unauthorized(msg) => SanitizedError::new(ErrorCode::Unauthorized, msg),
            Self::Crypto(msg) => SanitizedError::new(ErrorCode::CryptoFailure, msg),
            Self::Transport(msg) => SanitizedError::new(ErrorCode::TransportFailure, msg),
        }
    }
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(m) => write!(f, "validation error: {m}"),
            Self::StalePlan(m) => write!(f, "stale plan: {m}"),
            Self::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            Self::Crypto(m) => write!(f, "crypto error: {m}"),
            Self::Transport(m) => write!(f, "transport error: {m}"),
        }
    }
}

impl std::error::Error for ProtoError {}

/// Strips non-printable/non-ASCII characters and caps length so error messages
/// can never smuggle terminal escapes, bidi overrides, or oversized dumps.
pub fn sanitize_ascii_message(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(512));
    for b in raw.bytes() {
        if out.len() >= 512 {
            break;
        }
        if (0x20..=0x7E).contains(&b) {
            out.push(b as char);
        } else if b == b'\n' || b == b'\t' {
            out.push(' ');
        }
    }
    out.trim().to_string()
}

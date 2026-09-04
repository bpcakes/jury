//! Generic protected-memory and output-safety primitives for Jury.
//!
//! Jury is pre-alpha and these controls do not make it safe for real secrets.

#![forbid(unsafe_code)]

mod memory;
mod process_protection;
mod randomness;
mod redact;
mod secret;
mod streaming_redaction;

pub use memory::{
    MAX_EXTENDED_PROTECTED_BYTES, MAX_LARGE_PROTECTED_BYTES, MAX_PROTECTED_BYTES, MemoryError,
    MemoryErrorKind, ProtectedMemory, ProtectionPolicy, ProtectionStatus, RuntimeControlStatus,
};
pub use process_protection::{
    CaptureError, CaptureErrorKind, ProtectedCapture, capture_after_process_protection,
};
pub use randomness::{
    EntropyError, OsRandom, ProtectedRandomError, RandomSource, protected_random,
};
pub use redact::{
    MAX_REDACTION_INPUT_BYTES, MAX_REDACTION_SECRET_LEN, MAX_REDACTION_SECRETS,
    MAX_REDACTION_SOURCE_BYTES, MIN_REDACTABLE_LEN, Redactor, RedactorError,
};
pub use secret::{SecretBytes, SecretBytesCapacityError};
pub use streaming_redaction::{
    MAX_OUTPUT_CHUNK_LEN, MAX_REDACTION_PATTERN_BYTES, MAX_REDACTION_PATTERN_LEN,
    MAX_REDACTION_PATTERNS, StreamingRedactor, StreamingRedactorError,
};

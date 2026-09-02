use std::{
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
};

use reqwest::header::{AUTHORIZATION, HeaderValue};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{AdapterError, AdapterErrorKind};

const MIN_CREDENTIAL_BYTES: usize = 32;
const MAX_CREDENTIAL_BYTES: usize = 256;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CredentialDigest([u8; 32]);

impl CredentialDigest {
    pub(crate) fn matches_bearer(&self, authorization: Option<&HeaderValue>) -> bool {
        let Some(value) = authorization.and_then(|value| value.to_str().ok()) else {
            return false;
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        bool::from(Sha256::digest(token.as_bytes()).as_slice().ct_eq(&self.0))
    }
}

#[derive(Clone)]
pub(crate) struct BearerCredential(HeaderValue);

impl BearerCredential {
    pub(crate) fn authorization(&self) -> HeaderValue {
        self.0.clone()
    }
}

pub(crate) fn load_digest(path: &Path) -> Result<CredentialDigest, AdapterError> {
    load(path).map(|bytes| CredentialDigest(Sha256::digest(bytes.as_slice()).into()))
}

pub(crate) fn load_bearer(path: &Path) -> Result<BearerCredential, AdapterError> {
    let bytes = load(path)?;
    let mut value = b"Bearer ".to_vec();
    value.extend_from_slice(bytes.as_slice());
    let mut header = HeaderValue::from_bytes(&value)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidCredential))?;
    value.fill(0);
    header.set_sensitive(true);
    Ok(BearerCredential(header))
}

fn load(path: &Path) -> Result<Zeroizing<Vec<u8>>, AdapterError> {
    validate_private_regular_file(path)?;
    let mut bytes = Zeroizing::new(
        jury_filesystem::read_private_file(path, MAX_CREDENTIAL_BYTES + 2)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidCredential))?,
    );
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        bytes.pop();
    }
    if !(MIN_CREDENTIAL_BYTES..=MAX_CREDENTIAL_BYTES).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AdapterError::new(AdapterErrorKind::InvalidCredential));
    }
    Ok(bytes)
}

pub(crate) fn validate_private_regular_file(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute() {
        return Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidCredential))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AdapterError::new(AdapterErrorKind::InvalidCredential));
    }
    Ok(())
}

pub(crate) fn authorization_header() -> &'static reqwest::header::HeaderName {
    &AUTHORIZATION
}

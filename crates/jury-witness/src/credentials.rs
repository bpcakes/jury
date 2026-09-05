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

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, os::unix::fs::symlink};

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn credential_parser_accepts_only_bounded_header_safe_tokens() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("credential");

        for length in [MIN_CREDENTIAL_BYTES, MAX_CREDENTIAL_BYTES] {
            private_file(&path, &vec![b'a'; length])?;
            assert_eq!(load(&path)?.len(), length);
        }
        private_file(
            &path,
            &[vec![b'a'; MIN_CREDENTIAL_BYTES], b"\r\n".to_vec()].concat(),
        )?;
        assert_eq!(load(&path)?.len(), MIN_CREDENTIAL_BYTES);

        for invalid in [
            vec![b'a'; MIN_CREDENTIAL_BYTES - 1],
            vec![b'a'; MAX_CREDENTIAL_BYTES + 1],
            [vec![b'a'; MIN_CREDENTIAL_BYTES - 1], vec![0]].concat(),
            [vec![b'a'; MIN_CREDENTIAL_BYTES - 1], b" ".to_vec()].concat(),
        ] {
            private_file(&path, &invalid)?;
            assert!(load(&path).is_err());
        }
        Ok(())
    }

    #[test]
    fn credential_loader_rejects_links_and_nonprivate_files() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("credential");
        private_file(&path, &[b'a'; MIN_CREDENTIAL_BYTES])?;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(load(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        let hardlink = directory.path().join("hardlink");
        fs::hard_link(&path, &hardlink)?;
        assert!(load(&path).is_err());
        fs::remove_file(&hardlink)?;

        let link = directory.path().join("symlink");
        symlink(&path, &link)?;
        assert!(load(&link).is_err());
        Ok(())
    }
}

use std::path::PathBuf;

use jury_core::{
    identity::{UnlockedIdentity, unlock},
    witness_engine::WitnessEngineIdentity,
};
use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::identity_v1::IdentityFileV1;
use zeroize::Zeroizing;

use crate::{AdapterError, AdapterErrorKind, credentials::validate_private_regular_file};

/// Loads a role-bound witness identity without exposing private key bytes to
/// transport or persistence adapters.
///
/// The first implementation is the portable software-file provider. Hardware
/// adapters return the same object-safe engine identity without exporting
/// private key bytes or plaintext shares.
pub trait WitnessIdentityProvider {
    fn load(&self) -> Result<Box<dyn WitnessEngineIdentity>, AdapterError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareFileIdentityProvider {
    identity_file: PathBuf,
    passphrase_file: PathBuf,
}

impl SoftwareFileIdentityProvider {
    #[must_use]
    pub const fn new(identity_file: PathBuf, passphrase_file: PathBuf) -> Self {
        Self {
            identity_file,
            passphrase_file,
        }
    }
}

impl WitnessIdentityProvider for SoftwareFileIdentityProvider {
    fn load(&self) -> Result<Box<dyn WitnessEngineIdentity>, AdapterError> {
        validate_private_regular_file(&self.identity_file)?;
        validate_private_regular_file(&self.passphrase_file)?;
        let identity_bytes = jury_filesystem::read_public_file(&self.identity_file, 1024 * 1024)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidIdentity))?;
        let identity = IdentityFileV1::parse(&identity_bytes)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidIdentity))?;
        let mut passphrase = Zeroizing::new(
            jury_filesystem::read_private_file(&self.passphrase_file, 1026)
                .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidCredential))?,
        );
        while passphrase
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            passphrase.pop();
        }
        let protected = ProtectedMemory::initialize(
            passphrase.len(),
            ProtectionPolicy::Strict,
            |destination| {
                destination.copy_from_slice(&passphrase);
                Ok::<usize, ()>(destination.len())
            },
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidCredential))?;
        let unlocked = unlock(&identity, &protected)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidIdentity))?;
        match unlocked {
            UnlockedIdentity::Witness(identity) => Ok(Box::new(identity)),
            UnlockedIdentity::VaultPrincipal(_) | UnlockedIdentity::Approver(_) => {
                Err(AdapterError::new(AdapterErrorKind::InvalidIdentity))
            }
        }
    }
}

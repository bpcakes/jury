use super::*;

impl<R: RandomSource> IdentityCreator<R> {
    /// Reseals recovered role material under an independently selected new
    /// identity credential. Principal keys and the local-state seed are
    /// preserved; storage salt, nonces, root, profile, and creation time are
    /// freshly generated.
    pub fn restore(
        &mut self,
        recovered: &RecoveredIdentity,
        profile: KdfProfile,
        restored_at_ms: u64,
        passphrase: &ProtectedMemory,
    ) -> Result<CreatedIdentity, IdentityError> {
        if restored_at_ms == 0 {
            return Err(IdentityError::new(IdentityErrorKind::Format));
        }
        validate_passphrase(passphrase)?;
        recovered.validate()?;
        let policy = passphrase.status().policy();
        let identity_root =
            crypto::random_secret(32, policy, &mut self.source).map_err(map_crypto_error)?;
        let mut header = recovered.header.clone();
        header.created_at_ms = restored_at_ms;
        header.kdf_profile = profile;
        header.memory_kib = profile.memory_kib();
        header.salt = Salt16::new(fill_public(&mut self.source)?);
        header.root_wrap_nonce = Nonce12::new(fill_public(&mut self.source)?);
        header.payload_nonce = Nonce12::new(fill_public(&mut self.source)?);
        let file = seal_file(header, passphrase, &identity_root, &recovered.payload)?;
        let descriptor = descriptor_from_payload(&file.header, &recovered.payload)?;
        Ok(CreatedIdentity { file, descriptor })
    }
}

/// Core-owned private identity material recovered from an authenticated owner
/// backup. It intentionally has no API that exposes the private payload bytes.
pub struct RecoveredIdentity {
    pub(crate) header: IdentityHeaderV1,
    pub(crate) payload: ProtectedMemory,
}

impl RecoveredIdentity {
    pub(crate) fn from_parts(
        header: IdentityHeaderV1,
        payload: ProtectedMemory,
    ) -> Result<Self, IdentityError> {
        let recovered = Self { header, payload };
        recovered.validate()?;
        Ok(recovered)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        self.header
            .validate_for_active_release()
            .map_err(map_format_error)?;
        validate_payload(&self.header, &self.payload)
    }

    #[must_use]
    pub const fn principal_id(&self) -> WirePrincipalId {
        self.header.principal_id
    }

    #[must_use]
    pub const fn principal_kind(&self) -> PrincipalKind {
        self.header.principal_kind
    }

    #[must_use]
    pub const fn descriptor_fingerprint(&self) -> &Digest32 {
        &self.header.descriptor_fingerprint
    }

    pub fn public_descriptor(&self) -> Result<PrincipalDescriptorV1, IdentityError> {
        descriptor_from_payload(&self.header, &self.payload)
    }

    /// Proves exact private/public/local-seed correspondence without exporting
    /// either side. This supports explicit reuse of an existing identity.
    pub fn matches_unlocked(&self, identity: &UnlockedIdentity) -> Result<bool, IdentityError> {
        let existing = identity.secrets();
        Ok(self.header.principal_id == existing.header.principal_id
            && self.header.principal_kind == existing.header.principal_kind
            && self.header.recipient_public_key == existing.header.recipient_public_key
            && self.header.verification_public_key == existing.header.verification_public_key
            && self.header.descriptor_fingerprint == existing.header.descriptor_fingerprint
            && protected_equal(&self.payload, &existing.payload)?)
    }

    pub(crate) fn derive_local_state_key(
        &self,
        info: &[u8],
    ) -> Result<ProtectedMemory, IdentityError> {
        let seed = payload_component(&self.payload, LOCAL_SEED_RANGE)?;
        crypto::derive_hkdf_key(&seed, info).map_err(map_crypto_error)
    }

    pub(crate) fn verify_direct_slot(&self, slot: &DirectSlotV1) -> Result<(), IdentityError> {
        if !matches!(
            self.header.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) || slot.slot_schema != 1
            || slot.slot_algorithm != 1
            || slot.suite != 1
            || slot.kem != 0x647a
            || slot.kdf != 1
            || slot.aead != 3
            || slot.revision == 0
            || !matches!(
                slot.item_access_mode,
                ItemAccessMode::DirectOnly | ItemAccessMode::Mixed
            )
            || slot.recipient_principal_id != self.header.principal_id
            || slot.recipient_public_key_fingerprint
                != recipient_public_key_fingerprint(&self.header.recipient_public_key)
        {
            return Err(IdentityError::new(IdentityErrorKind::AuthenticationFailed));
        }
        let private_seed = payload_component(&self.payload, RECIPIENT_SEED_RANGE)?;
        let _secret = crypto::open_hpke(
            &private_seed,
            &slot.encapsulation,
            slot.ciphertext.as_bytes(),
            &slot.info_preimage(),
            &slot.aad_preimage(),
            32,
        )
        .map_err(map_crypto_error)?;
        Ok(())
    }
}

impl fmt::Debug for RecoveredIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredIdentity")
            .field("principal_id", &self.header.principal_id)
            .field("kind", &self.header.principal_kind)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

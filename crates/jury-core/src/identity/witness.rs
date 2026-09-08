use super::*;

impl ProtectedRevisionSecret {
    pub(crate) fn memory(&self) -> &ProtectedMemory {
        &self.bytes
    }
}

impl ProtectedWitnessShare {
    /// Consumes the share into one request-session encrypted J19 envelope.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the engine uses the injected-randomness variant")
    )]
    pub(crate) fn seal_for_request(
        self,
        target: &WitnessContributionTarget,
    ) -> Result<EncryptedWitnessContribution, IdentityError> {
        self.seal_for_request_with_source(target, &mut OsRandom)
    }

    pub(crate) fn seal_for_request_with_source(
        self,
        target: &WitnessContributionTarget,
        source: &mut (impl RandomSource + ?Sized),
    ) -> Result<EncryptedWitnessContribution, IdentityError> {
        if target.expires_at_ms == 0
            || target.session_fingerprint
                != recipient_public_key_fingerprint(&target.session_public_key)
        {
            return Err(IdentityError::new(IdentityErrorKind::Format));
        }
        let context = ContributionHpkeContext {
            suite: self.suite,
            request_digest: target.request_digest.clone(),
            action_manifest_digest: target.action_manifest_digest.clone(),
            response_id: target.response_id,
            witness_id: self.witness_id,
            witness_policy_digest: self.witness_policy_digest.clone(),
            checkpoint_digest: target.checkpoint_digest.clone(),
            share_commitment: self.share_commitment.clone(),
            share_index: self.share_index,
            capsule_set_digest: target.capsule_set_digest.clone(),
            capsule_context_digest: self.context_digest.clone(),
            session_fingerprint: target.session_fingerprint.clone(),
            expires_at_ms: target.expires_at_ms,
        };
        let (encapsulation, ciphertext) = crypto::seal_hpke_for_suite(
            self.suite,
            &target.session_public_key,
            &self.bytes,
            &context.info_preimage(),
            &context.aad_preimage(),
            source,
        )
        .map_err(map_crypto_error)?;
        Ok(EncryptedWitnessContribution {
            response_id: target.response_id,
            share_index: self.share_index,
            share_commitment: self.share_commitment,
            context_digest: self.context_digest,
            capsule_set_digest: target.capsule_set_digest.clone(),
            session_fingerprint: target.session_fingerprint.clone(),
            encapsulation,
            ciphertext: ShareCiphertext49::from_slice(&ciphertext)
                .map_err(|_| IdentityError::new(IdentityErrorKind::ProviderFailure))?,
        })
    }
}

impl EncryptedWitnessContribution {
    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_332);
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(self.response_id.as_bytes());
        output.push(self.share_index);
        output.extend_from_slice(self.share_commitment.as_bytes());
        output.extend_from_slice(self.context_digest.as_bytes());
        output.extend_from_slice(self.capsule_set_digest.as_bytes());
        output.extend_from_slice(self.session_fingerprint.as_bytes());
        output.extend_from_slice(self.encapsulation.as_bytes());
        output.extend_from_slice(self.ciphertext.as_bytes());
        output
    }

    #[must_use]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "covered by the public envelope")
    )]
    pub(crate) fn digest(&self) -> Digest32 {
        let envelope = self.canonical_bytes();
        let mut preimage = identity_jce("jury-witness-v1/contribution/hash");
        preimage.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&envelope);
        Digest32::new(Sha256::digest(preimage).into())
    }

    pub(crate) fn into_protocol(self) -> WitnessContributionEnvelopeV1 {
        WitnessContributionEnvelopeV1 {
            schema: 1,
            response_id: self.response_id,
            share_index: self.share_index,
            share_commitment: self.share_commitment,
            capsule_context_digest: self.context_digest,
            capsule_set_digest: self.capsule_set_digest,
            request_session_key_fingerprint: self.session_fingerprint,
            encapsulation: self.encapsulation,
            ciphertext: self.ciphertext,
        }
    }
}

impl fmt::Debug for ProtectedRevisionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedRevisionSecret([REDACTED])")
    }
}

impl fmt::Debug for ProtectedWitnessShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedWitnessShare([REDACTED])")
    }
}

impl WitnessIdentity {
    pub(crate) fn sign_validated_decision(
        &self,
        preimage: &[u8],
    ) -> Result<Signature64, IdentityError> {
        sign_payload_statement(&self.0.payload, preimage)
    }

    /// Opens one exact J19 revision-scoped share without exporting its bytes.
    pub(crate) fn open_contribution_share(
        &self,
        suite: VaultSuite,
        capsule: &WitnessShareCapsuleV1,
    ) -> Result<ProtectedWitnessShare, IdentityError> {
        if capsule.capsule_schema != 1
            || capsule.protocol != 1
            || capsule.construction != 1
            || capsule.revision == 0
            || !(2..=32).contains(&capsule.member_count)
            || !(2..=capsule.member_count).contains(&capsule.threshold)
            || capsule.share_index == 0
            || capsule.share_index > 32
            || !matches!(
                capsule.item_access_mode,
                ItemAccessMode::WitnessedOnly | ItemAccessMode::Mixed
            )
            || capsule.recomputed_context_digest_for_suite(suite) != capsule.context_digest
        {
            return Err(IdentityError::new(IdentityErrorKind::Format));
        }
        if capsule.witness_id != self.0.header.principal_id
            || capsule.contribution_key_fingerprint
                != recipient_public_key_fingerprint(&self.0.header.recipient_public_key)
        {
            return Err(IdentityError::new(IdentityErrorKind::AuthenticationFailed));
        }
        let private_seed = payload_component(&self.0.payload, RECIPIENT_SEED_RANGE)?;
        let share = crypto::open_hpke_for_suite(
            suite,
            &private_seed,
            &capsule.encapsulation,
            capsule.ciphertext.as_bytes(),
            &capsule.info_preimage_for_suite(suite),
            &capsule.aad_preimage_for_suite(suite),
            33,
        )
        .map_err(map_crypto_error)?;
        let commitment_matches = share
            .expose(|bytes| {
                let mut preimage = b"jury-witness-v1/share/commitment\0\0\x01".to_vec();
                preimage.extend_from_slice(capsule.context_digest.as_bytes());
                preimage.extend_from_slice(bytes);
                let digest: [u8; 32] = Sha256::digest(preimage).into();
                bool::from(digest.ct_eq(capsule.share_commitment.as_bytes()))
            })
            .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?;
        if !commitment_matches {
            return Err(IdentityError::new(IdentityErrorKind::AuthenticationFailed));
        }
        Ok(ProtectedWitnessShare {
            suite,
            bytes: share,
            witness_id: capsule.witness_id,
            witness_policy_digest: capsule.witness_policy_digest.clone(),
            share_commitment: capsule.share_commitment.clone(),
            share_index: capsule.share_index,
            context_digest: capsule.context_digest.clone(),
        })
    }
}

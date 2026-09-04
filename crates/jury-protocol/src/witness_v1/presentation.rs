#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresentationSubjectV1 {
    Item,
    Field,
    WorkingDirectory,
    OutputSink,
}

impl PresentationSubjectV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Item => 1,
            Self::Field => 2,
            Self::WorkingDirectory => 3,
            Self::OutputSink => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresentationKindV1 {
    EntitledPrivateName,
    OwnerReviewLabel,
    ExactNormalizedDisplay,
}

impl PresentationKindV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::EntitledPrivateName => 1,
            Self::OwnerReviewLabel => 2,
            Self::ExactNormalizedDisplay => 3,
        }
    }
}

/// Owner-authenticated, deliberately non-secret label for one approval subject.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerReviewLabelV1 {
    pub schema: u16,
    pub label_id: LabelId,
    pub label_revision: u64,
    pub subject_kind: PresentationSubjectV1,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub item_id: Option<ItemId>,
    pub field_id: Option<FieldId>,
    pub subject_commitment: Option<Digest32>,
    pub public_label: ReviewLabelBytes,
    pub vault_policy_sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub issuer_owner_id: PrincipalId,
    pub issuer_key_fingerprint: Digest32,
    pub issuer_key_epoch: u64,
    pub signature: Signature64,
}

impl OwnerReviewLabelV1 {
    fn append_fields(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.label_id.as_bytes());
        output.extend_from_slice(&self.label_revision.to_be_bytes());
        output.push(self.subject_kind.tag());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        optional_fixed(output, self.item_id.as_ref().map(ItemId::as_bytes));
        optional_fixed(output, self.field_id.as_ref().map(FieldId::as_bytes));
        optional_fixed(
            output,
            self.subject_commitment.as_ref().map(Digest32::as_bytes),
        );
        bytes_field(output, self.public_label.as_bytes())?;
        output.extend_from_slice(&self.vault_policy_sequence.to_be_bytes());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        optional_u64(output, self.expires_at_ms);
        output.extend_from_slice(self.issuer_owner_id.as_bytes());
        output.extend_from_slice(self.issuer_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.issuer_key_epoch.to_be_bytes());
        Ok(())
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/review-label/signature");
        self.append_fields(&mut output)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output)?;
        output.extend_from_slice(self.signature.as_bytes());
        if output.len() > MAX_PRESENTATION_BYTES {
            return Err(capacity_exhausted());
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/review-label/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        let subject_valid = match self.subject_kind {
            PresentationSubjectV1::Item => {
                self.item_id.is_some()
                    && self.field_id.is_none()
                    && self.subject_commitment.is_none()
            }
            PresentationSubjectV1::Field => {
                self.item_id.is_some()
                    && self.field_id.is_some()
                    && self.subject_commitment.is_none()
            }
            PresentationSubjectV1::WorkingDirectory | PresentationSubjectV1::OutputSink => {
                self.item_id.is_none()
                    && self.field_id.is_none()
                    && self.subject_commitment.is_some()
            }
        };
        let label = self.public_label.as_bytes();
        if self.schema != 1
            || self.label_revision == 0
            || self.vault_policy_sequence == 0
            || self.issuer_key_epoch == 0
            || label.is_empty()
            || std::str::from_utf8(label).is_err()
            || self
                .expires_at_ms
                .is_some_and(|expires_at| expires_at <= self.issued_at_ms)
            || !subject_valid
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for OwnerReviewLabelV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnerReviewLabelV1")
            .field("label_id", &self.label_id)
            .field("label_revision", &self.label_revision)
            .field("subject_kind", &self.subject_kind)
            .field("public_label", &self.public_label)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Computes the authenticated digest of a normalized current review-label set.
pub fn owner_review_label_set_digest(
    labels: &[OwnerReviewLabelV1],
) -> Result<Digest32, WitnessProtocolError> {
    if labels.len() > MAX_MANIFEST_TARGETS {
        return Err(capacity_exhausted());
    }
    let mut label_ids = labels.iter().map(|label| label.label_id).collect::<Vec<_>>();
    label_ids.sort_unstable();
    if label_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WitnessProtocolError::new(
            WitnessProtocolErrorKind::InvalidOrdering,
        ));
    }
    let mut digests = labels
        .iter()
        .map(OwnerReviewLabelV1::digest)
        .collect::<Result<Vec<_>, _>>()?;
    digests.sort_unstable();
    let mut output = jce("jury-witness-v1/review-label-set/hash");
    list_fixed(&mut output, &digests, |output, value| {
        output.extend_from_slice(value.as_bytes());
    })?;
    Ok(digest(&output))
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPresentationEntryV1 {
    pub subject_kind: PresentationSubjectV1,
    pub item_id: Option<ItemId>,
    pub field_id: Option<FieldId>,
    pub subject_commitment: Option<Digest32>,
    pub presentation_kind: PresentationKindV1,
    pub display_bytes: PresentationDisplayBytes,
    pub source_revision: Option<u64>,
    pub source_revision_seal_id: Option<RevisionSealId>,
    pub owner_review_label: Option<OwnerReviewLabelV1>,
    pub blinding_nonce: PresentationNonce,
}

impl ApprovalPresentationEntryV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        output.push(self.subject_kind.tag());
        optional_fixed(&mut output, self.item_id.as_ref().map(ItemId::as_bytes));
        optional_fixed(&mut output, self.field_id.as_ref().map(FieldId::as_bytes));
        optional_fixed(
            &mut output,
            self.subject_commitment.as_ref().map(Digest32::as_bytes),
        );
        output.push(self.presentation_kind.tag());
        bytes_field(&mut output, self.display_bytes.as_bytes())?;
        optional_u64(&mut output, self.source_revision);
        optional_fixed(
            &mut output,
            self.source_revision_seal_id
                .as_ref()
                .map(RevisionSealId::as_bytes),
        );
        match &self.owner_review_label {
            None => output.push(0),
            Some(label) => {
                output.push(1);
                output.extend_from_slice(&label.canonical_bytes()?);
            }
        }
        output.extend_from_slice(self.blinding_nonce.as_bytes());
        if output.len() > MAX_PRESENTATION_BYTES {
            return Err(capacity_exhausted());
        }
        Ok(output)
    }

    pub fn commitment(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_bytes(
            "jury-witness-v1/approval-presentation/commitment",
            &self.canonical_bytes()?,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        let revision_present = self.source_revision.is_some_and(|revision| revision > 0)
            && self.source_revision_seal_id.is_some();
        let private_subject = match self.subject_kind {
            PresentationSubjectV1::Item => {
                self.item_id.is_some()
                    && self.field_id.is_none()
                    && self.subject_commitment.is_none()
                    && revision_present
                    && self.presentation_kind != PresentationKindV1::ExactNormalizedDisplay
            }
            PresentationSubjectV1::Field => {
                self.item_id.is_some()
                    && self.field_id.is_some()
                    && self.subject_commitment.is_none()
                    && revision_present
                    && self.presentation_kind != PresentationKindV1::ExactNormalizedDisplay
            }
            PresentationSubjectV1::WorkingDirectory | PresentationSubjectV1::OutputSink => {
                self.item_id.is_none()
                    && self.field_id.is_none()
                    && self.subject_commitment.is_some()
                    && self.source_revision.is_none()
                    && self.source_revision_seal_id.is_none()
                    && self.presentation_kind != PresentationKindV1::EntitledPrivateName
            }
        };
        let label_valid = match (&self.presentation_kind, &self.owner_review_label) {
            (PresentationKindV1::OwnerReviewLabel, Some(label)) => {
                label.validate_shape().is_ok()
                    && label.subject_kind == self.subject_kind
                    && label.item_id == self.item_id
                    && label.field_id == self.field_id
                    && label.subject_commitment == self.subject_commitment
                    && label.public_label.as_bytes() == self.display_bytes.as_bytes()
            }
            (PresentationKindV1::OwnerReviewLabel, None) => false,
            (_, None) => true,
            (_, Some(_)) => false,
        };
        if self.display_bytes.is_empty() || !private_subject || !label_valid {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ApprovalPresentationEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalPresentationEntryV1")
            .field("subject_kind", &self.subject_kind)
            .field("item_id", &self.item_id)
            .field("field_id", &self.field_id)
            .field("presentation_kind", &self.presentation_kind)
            .field("display_bytes", &self.display_bytes)
            .field("owner_review_label", &self.owner_review_label)
            .finish()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPresentationV1 {
    pub entries: Vec<ApprovalPresentationEntryV1>,
}

impl ApprovalPresentationV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let encoded = self.validated_entries()?;
        let mut output = Vec::new();
        list_bytes(&mut output, &encoded)?;
        if output.len() > MAX_PRESENTATION_BYTES {
            return Err(capacity_exhausted());
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        let mut output = jce("jury-witness-v1/approval-presentation/hash");
        output.extend_from_slice(&self.canonical_bytes()?);
        Ok(digest(&output))
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        self.validated_entries().map(|_| ())
    }

    fn validated_entries(&self) -> Result<Vec<Vec<u8>>, WitnessProtocolError> {
        if self.entries.len() > MAX_MANIFEST_TARGETS + 2 {
            return Err(capacity_exhausted());
        }
        let mut prior = None;
        let mut encoded = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let bytes = entry.canonical_bytes()?;
            let key = (
                entry.subject_kind,
                entry.item_id,
                entry.field_id,
                entry.commitment()?,
            );
            if prior.as_ref().is_some_and(|prior| prior >= &key) {
                return Err(WitnessProtocolError::new(
                    WitnessProtocolErrorKind::InvalidOrdering,
                ));
            }
            prior = Some(key);
            encoded.push(bytes);
        }
        Ok(encoded)
    }
}

/// Commits to a private normalized directory or output-sink descriptor.
pub fn normalized_subject_commitment(
    subject_kind: PresentationSubjectV1,
    blinding_nonce: PresentationNonce,
    normalized_descriptor: &[u8],
) -> Result<Digest32, WitnessProtocolError> {
    if !matches!(
        subject_kind,
        PresentationSubjectV1::WorkingDirectory | PresentationSubjectV1::OutputSink
    ) || normalized_descriptor.is_empty()
        || normalized_descriptor.len() > MAX_PRESENTATION_BYTES
    {
        return Err(WitnessProtocolError::new(
            WitnessProtocolErrorKind::InvalidFormat,
        ));
    }
    let mut output = jce("jury-witness-v1/normalized-subject/commitment");
    output.push(subject_kind.tag());
    output.extend_from_slice(blinding_nonce.as_bytes());
    bytes_field(&mut output, normalized_descriptor)?;
    Ok(digest(&output))
}

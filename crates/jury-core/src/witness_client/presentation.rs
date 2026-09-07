use super::*;

impl<R: RandomSource> WitnessRequestCreator<R> {
    pub(super) fn human_presentation(
        &mut self,
        action: &WitnessActionRequest,
        slot: &WitnessedSlotV1,
        review_labels: &[OwnerReviewLabelV1],
    ) -> Result<HumanPresentation, WitnessRequestError> {
        let mut presentation_entries = Vec::new();
        let mut approval_entries = Vec::new();
        // An item label remains mandatory for human review, including stdin.
        let item_entry = self.label_presentation_entry(
            PresentationSubjectV1::Item,
            action.item_id,
            None,
            slot,
            review_labels,
        )?;
        // Child stdin authorizes exactly one field target. Its field label
        // already authenticates the item ID; a second item target is invalid.
        if action.operation_context.operation() != WitnessOperationV1::ChildStdin {
            approval_entries.push(ApprovalTargetEntryV1 {
                item_id: action.item_id,
                field_id: None,
                presentation_commitment: presentation_commitment(&item_entry)?,
            });
            presentation_entries.push(item_entry);
        }
        for field_id in &action.field_ids {
            let entry = self.label_presentation_entry(
                PresentationSubjectV1::Field,
                action.item_id,
                Some(*field_id),
                slot,
                review_labels,
            )?;
            approval_entries.push(ApprovalTargetEntryV1 {
                item_id: action.item_id,
                field_id: Some(*field_id),
                presentation_commitment: presentation_commitment(&entry)?,
            });
            presentation_entries.push(entry);
        }
        let working_directory_commitment = if let Some(display) = &action.working_directory {
            let entry = self
                .normalized_presentation_entry(PresentationSubjectV1::WorkingDirectory, display)?;
            let commitment = entry.subject_commitment.clone();
            presentation_entries.push(entry);
            commitment
        } else {
            None
        };
        let output_sink_commitment = if let Some(display) = &action.output_destination {
            let entry =
                self.normalized_presentation_entry(PresentationSubjectV1::OutputSink, display)?;
            let commitment = entry.subject_commitment.clone();
            presentation_entries.push(entry);
            commitment
        } else {
            None
        };
        Ok((
            ApprovalPresentationV1 {
                entries: presentation_entries,
            },
            approval_entries,
            working_directory_commitment,
            output_sink_commitment,
        ))
    }

    pub(super) fn label_presentation_entry(
        &mut self,
        subject_kind: PresentationSubjectV1,
        item_id: ItemId,
        field_id: Option<FieldId>,
        slot: &WitnessedSlotV1,
        review_labels: &[OwnerReviewLabelV1],
    ) -> Result<ApprovalPresentationEntryV1, WitnessRequestError> {
        let label = review_labels
            .iter()
            .find(|label| {
                label.subject_kind == subject_kind
                    && label.item_id == Some(item_id)
                    && label.field_id == field_id
            })
            .cloned()
            .ok_or_else(|| {
                WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
            })?;
        Ok(ApprovalPresentationEntryV1 {
            subject_kind,
            item_id: Some(item_id),
            field_id,
            subject_commitment: None,
            presentation_kind: PresentationKindV1::OwnerReviewLabel,
            display_bytes: PresentationDisplayBytes::new(label.public_label.as_bytes().to_vec())
                .map_err(|_| {
                    WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
                })?,
            source_revision: Some(slot.revision),
            source_revision_seal_id: Some(slot.revision_seal_id),
            owner_review_label: Some(label),
            blinding_nonce: self.draw_presentation_nonce()?,
        })
    }

    pub(super) fn normalized_presentation_entry(
        &mut self,
        subject_kind: PresentationSubjectV1,
        display: &OperationBytes,
    ) -> Result<ApprovalPresentationEntryV1, WitnessRequestError> {
        let blinding_nonce = self.draw_presentation_nonce()?;
        let subject_commitment =
            normalized_subject_commitment(subject_kind, blinding_nonce, display.as_bytes())
                .map_err(|_| {
                    WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
                })?;
        Ok(ApprovalPresentationEntryV1 {
            subject_kind,
            item_id: None,
            field_id: None,
            subject_commitment: Some(subject_commitment),
            presentation_kind: PresentationKindV1::ExactNormalizedDisplay,
            display_bytes: PresentationDisplayBytes::new(display.as_bytes().to_vec()).map_err(
                |_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation),
            )?,
            source_revision: None,
            source_revision_seal_id: None,
            owner_review_label: None,
            blinding_nonce,
        })
    }

    pub(super) fn draw_presentation_nonce(
        &mut self,
    ) -> Result<PresentationNonce, WitnessRequestError> {
        for _ in 0..IDENTIFIER_RETRY_ATTEMPTS {
            let mut nonce_bytes = [0_u8; 32];
            self.source.fill(&mut nonce_bytes).map_err(|_| {
                WitnessRequestError::new(WitnessRequestErrorKind::EntropyUnavailable)
            })?;
            if let Ok(nonce) = PresentationNonce::from_bytes(nonce_bytes) {
                return Ok(nonce);
            }
        }
        Err(WitnessRequestError::new(
            WitnessRequestErrorKind::EntropyUnavailable,
        ))
    }
}

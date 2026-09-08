use super::*;

impl<R: RandomSource> WitnessRequestCreator<R> {
    /// Authorize resealing one exact current descriptor or body into an absent
    /// destination. Human approvals bind the complete item and the displayed
    /// destination. The existing access mode is preserved, and no source policy
    /// sequence is consumed, including when its history is at capacity.
    pub fn create_recovery_reseal(
        &mut self,
        context: WitnessRequestContext<'_>,
        item_id: ItemId,
        content_role: ContentRole,
        output_destination: &OperationBytes,
    ) -> Result<PreparedWitnessRequest, WitnessRequestError> {
        let next_item_access_mode = context
            .policy
            .item(&item_id)
            .and_then(|item| item.access_mode())
            .filter(|mode| {
                matches!(
                    mode,
                    jury_protocol::vault_v1::ItemAccessMode::WitnessedOnly
                        | jury_protocol::vault_v1::ItemAccessMode::Mixed
                )
            })
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        self.create_single_target(
            context,
            item_id,
            content_role,
            None,
            OperationContextV1::Recovery {
                mode: 2,
                destination_commitment: Digest32::new([0; 32]),
                next_item_access_mode,
            },
            Some(output_destination),
        )
    }
}

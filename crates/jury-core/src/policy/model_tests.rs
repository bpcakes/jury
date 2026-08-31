use std::cell::Cell;

use ed25519_dalek::{Signer as _, SigningKey};
use jury_protected::{EntropyError, RandomSource};
use jury_protocol::vault_v1::{
    FixedBytes, PolicyJournalV1, PolicyOperationV1, PrincipalDescriptorV1, PrincipalId,
    PrincipalKind, RecipientPublicKey1216, Signature64, VerificationPublicKey32,
};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use super::replay::{
    PolicySigner, create_with_test_signer, prepare_with_test_signer, replay_policy,
};
use super::{PolicyCreator, PolicyError};

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(0x11);
        Ok(())
    }
}

struct ModelSigner {
    key: SigningKey,
    descriptor: PrincipalDescriptorV1,
    signatures: Cell<usize>,
}

impl ModelSigner {
    fn new(id_byte: u8, seed_byte: u8) -> Result<Self, PolicyError> {
        let key = SigningKey::from_bytes(&[seed_byte; 32]);
        let principal_id = PrincipalId::from_bytes([id_byte; 32])
            .map_err(|_| PolicyError::new(super::PolicyErrorKind::InvalidFormat))?;
        let mut descriptor = PrincipalDescriptorV1 {
            descriptor_version: 1,
            principal_id,
            principal_kind: PrincipalKind::Human,
            recipient_public_key: RecipientPublicKey1216::new([seed_byte; 1216]),
            verification_public_key: VerificationPublicKey32::new(key.verifying_key().to_bytes()),
            self_signature: Signature64::new([0; 64]),
        };
        let preimage = descriptor
            .self_signature_preimage()
            .map_err(|_| PolicyError::new(super::PolicyErrorKind::InvalidFormat))?;
        descriptor.self_signature = Signature64::new(key.sign(&preimage).to_bytes());
        Ok(Self {
            key,
            descriptor,
            signatures: Cell::new(0),
        })
    }
}

impl PolicySigner for ModelSigner {
    fn principal_id(&self) -> PrincipalId {
        self.descriptor.principal_id
    }

    fn descriptor(&self) -> Result<PrincipalDescriptorV1, PolicyError> {
        Ok(self.descriptor.clone())
    }

    fn sign(&self, preimage: &[u8]) -> Result<Signature64, PolicyError> {
        self.signatures.set(self.signatures.get() + 1);
        Ok(Signature64::new(self.key.sign(preimage).to_bytes()))
    }
}

fn case_error(error: impl std::fmt::Debug) -> TestCaseError {
    TestCaseError::fail(format!("{error:?}"))
}

proptest! {
    #[test]
    fn replay_matches_a_set_model_and_canonical_state_is_order_independent(
        ids in prop::collection::btree_set(1_u8..=16, 1..=8),
    ) {
        let owner = ModelSigner::new(0x21, 0x31).map_err(case_error)?;
        let mut creator = PolicyCreator::from_source(FixedRandom);
        let created = create_with_test_signer(&mut creator, &owner, 1, |_| false)
            .map_err(case_error)?;
        let signers = ids
            .iter()
            .map(|id| ModelSigner::new(*id, id.saturating_add(0x60)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(case_error)?;
        let operations = signers
            .iter()
            .map(|signer| PolicyOperationV1::PrincipalAdd {
                descriptor: signer.descriptor.clone(),
                display_label: "ExamplePrincipal".to_owned(),
                registration_proof_digest: FixedBytes::new([0x44; 32]),
            })
            .collect::<Vec<_>>();
        let forward = prepare_with_test_signer(
            &created.state,
            &owner,
            2,
            operations.clone(),
        )
        .map_err(case_error)?;
        let reverse = prepare_with_test_signer(
            &created.state,
            &owner,
            2,
            operations.into_iter().rev().collect(),
        )
        .map_err(case_error)?;

        prop_assert_eq!(forward.state.principal_count(), ids.len() + 1);
        prop_assert_eq!(forward.state.owner_count(), 1);
        prop_assert_eq!(forward.state.item_count(), 0);
        prop_assert_eq!(
            forward.state.normalized_state_hash().map_err(case_error)?,
            reverse.state.normalized_state_hash().map_err(case_error)?,
        );
        if ids.len() > 1 {
            prop_assert_ne!(
                forward.revision.recomputed_hash().map_err(case_error)?,
                reverse.revision.recomputed_hash().map_err(case_error)?,
            );
        }

        let mut journal = PolicyJournalV1 {
            genesis: created.journal.genesis,
            revisions: vec![forward.revision],
        };
        let replayed = replay_policy(&journal).map_err(case_error)?;
        prop_assert_eq!(replayed, forward.state);

        if ids.len() > 1 {
            journal.revisions[0].operations.reverse();
            prop_assert!(replay_policy(&journal).is_err());
        }
    }
}

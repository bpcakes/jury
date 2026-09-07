use std::error::Error;

use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{identity_v1::KdfProfile, vault_v1::PrincipalKind};

use crate::identity::{IdentityCreator, UnlockedIdentity, unlock};
use crate::policy::{PolicyCreator, replay_policy};
use crate::registration::{
    RegistrationCreator, RegistrationErrorKind, RegistrationProofV1, RegistrationRoleDescriptorV1,
    answer_challenge, verify_proof, verify_proof_signatures,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn protected(value: &[u8]) -> TestResult<ProtectedMemory> {
    Ok(ProtectedMemory::initialize(
        value.len(),
        ProtectionPolicy::Strict,
        |destination| {
            destination.copy_from_slice(value);
            Ok::<usize, ()>(destination.len())
        },
    )?)
}

#[test]
fn registration_binds_both_candidate_keys_role_and_vault() -> TestResult {
    let passphrase = protected(b"ExamplePassphrase1234")?;
    let mut identities = IdentityCreator::new();
    let owner = identities.create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1_788_000_000_000,
        &passphrase,
        |_| false,
    )?;
    let candidate = identities.create(
        PrincipalKind::Witness,
        KdfProfile::PortableV1,
        1_788_000_000_001,
        &passphrase,
        |id| id == &owner.descriptor.principal_id,
    )?;
    let other = identities.create(
        PrincipalKind::Witness,
        KdfProfile::PortableV1,
        1_788_000_000_002,
        &passphrase,
        |id| id == &owner.descriptor.principal_id || id == &candidate.descriptor.principal_id,
    )?;
    let owner_unlocked = unlock(&owner.file, &passphrase)?;
    let candidate_unlocked = unlock(&candidate.file, &passphrase)?;
    let other_unlocked = unlock(&other.file, &passphrase)?;
    let UnlockedIdentity::VaultPrincipal(owner_identity) = &owner_unlocked else {
        return Err("owner identity kind differs".into());
    };
    let created_policy =
        PolicyCreator::new().create(owner_identity, 1_788_000_000_100, |_| false)?;
    let policy = replay_policy(&created_policy.journal)?;
    let mut registrations = RegistrationCreator::new(ProtectionPolicy::Strict);
    let challenge = registrations.create_challenge(
        &policy,
        owner_identity,
        candidate.descriptor.clone(),
        1_788_000_000_200,
        60_000,
        Some(7),
    )?;
    let parsed_challenge =
        crate::registration::RegistrationChallengeV1::parse(&challenge.to_json_bytes()?)?;
    assert_eq!(parsed_challenge, challenge);
    assert_eq!(
        answer_challenge(&policy, &other_unlocked, &challenge, 1_788_000_000_300)
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(RegistrationErrorKind::WrongCandidate)
    );

    let proof = answer_challenge(&policy, &candidate_unlocked, &challenge, 1_788_000_000_300)?;
    let RegistrationRoleDescriptorV1::Witness { descriptor } = &proof.role_descriptor else {
        return Err("witness role descriptor is absent".into());
    };
    assert_eq!(descriptor.witness_id, candidate.descriptor.principal_id);
    assert_eq!(descriptor.share_index, 7);
    assert_eq!(
        descriptor.contribution_public_key,
        candidate.descriptor.recipient_public_key
    );
    descriptor.validate()?;
    let parsed = RegistrationProofV1::parse(&proof.to_json_bytes()?)?;
    assert_eq!(parsed, proof);
    assert_eq!(
        verify_proof_signatures(&policy, &challenge, &parsed, 1_788_000_000_400)?,
        proof.digest()?
    );
    assert_eq!(
        verify_proof(
            &policy,
            owner_identity,
            &challenge,
            &proof,
            1_788_000_000_400,
        )?,
        proof.digest()?
    );

    let mut tampered = proof.clone();
    let mut response_mac = *tampered.response_mac.as_bytes();
    response_mac[0] ^= 1;
    tampered.response_mac = jury_protocol::vault_v1::Digest32::new(response_mac);
    assert!(verify_proof_signatures(&policy, &challenge, &tampered, 1_788_000_000_400).is_err());
    assert_eq!(
        verify_proof(
            &policy,
            owner_identity,
            &challenge,
            &tampered,
            1_788_000_000_400,
        )
        .map(|_| ())
        .map_err(|error| error.kind()),
        Err(RegistrationErrorKind::AuthenticationFailed)
    );
    assert_eq!(
        verify_proof(
            &policy,
            owner_identity,
            &challenge,
            &proof,
            challenge.expires_at_ms + 1,
        )
        .map(|_| ())
        .map_err(|error| error.kind()),
        Err(RegistrationErrorKind::Expired)
    );
    verify_rollover_registration(owner_identity, &candidate_unlocked, &proof)?;
    Ok(())
}

fn verify_rollover_registration(
    owner: &crate::identity::VaultPrincipalIdentity,
    candidate: &UnlockedIdentity,
    source_proof: &RegistrationProofV1,
) -> TestResult {
    use crate::registration::answer_rollover_challenge;
    use jury_protocol::vault_v1::Signature64;

    let mut prior_role = source_proof.role_descriptor.clone();
    let RegistrationRoleDescriptorV1::Witness { descriptor } = &mut prior_role else {
        return Err("missing witness descriptor".into());
    };
    descriptor.signing_key_epoch = 7;
    descriptor.contribution_key_epoch = 9;
    descriptor.signing_key_fingerprint = crate::policy::signing_key_fingerprint(
        3,
        &descriptor.witness_id,
        7,
        &descriptor.signing_public_key,
    );
    descriptor.self_signature =
        candidate.sign_registration_statement(&descriptor.self_signature_preimage()?)?;
    descriptor.validate()?;
    let created = PolicyCreator::new().create(owner, 1_788_000_000_500, |id| {
        *id == source_proof.challenge.vault_id
    })?;
    let challenge = RegistrationCreator::new(ProtectionPolicy::Strict).create_challenge(
        &created.state,
        owner,
        source_proof.challenge.candidate_descriptor.clone(),
        1_788_000_000_700,
        60_000,
        Some(7),
    )?;
    let proof = answer_rollover_challenge(
        &created.state,
        candidate,
        &challenge,
        &prior_role,
        1_788_000_000_800,
    )?;
    verify_proof(&created.state, owner, &challenge, &proof, 1_788_000_000_900)?;
    assert_eq!(
        verify_proof_signatures(&created.state, &challenge, &proof, 1_788_000_000_900)?,
        proof.digest()?
    );
    assert!(
        verify_proof_signatures(
            &created.state,
            &source_proof.challenge,
            source_proof,
            source_proof.created_at_ms,
        )
        .is_err()
    );
    let RegistrationRoleDescriptorV1::Witness { descriptor: copied } = &proof.role_descriptor
    else {
        return Err("missing fresh witness descriptor".into());
    };
    let RegistrationRoleDescriptorV1::Witness { descriptor: prior } = &prior_role else {
        return Err("missing prior witness descriptor".into());
    };
    assert_ne!(copied.self_signature, prior.self_signature);
    let mut expected = prior.clone();
    expected.created_at_ms = challenge.issued_at_ms;
    expected.self_signature = copied.self_signature.clone();
    assert_eq!(*copied, expected);
    assert!(
        verify_proof(
            &created.state,
            owner,
            &challenge,
            source_proof,
            1_788_000_000_900
        )
        .is_err()
    );
    let mut corrupt = prior_role.clone();
    let RegistrationRoleDescriptorV1::Witness { descriptor } = &mut corrupt else {
        return Err("missing witness descriptor".into());
    };
    descriptor.self_signature = Signature64::new([0; 64]);
    assert!(
        answer_rollover_challenge(
            &created.state,
            candidate,
            &challenge,
            &corrupt,
            1_788_000_000_800
        )
        .is_err()
    );
    let mut forged = challenge.clone();
    forged.owner_signature = Signature64::new([0; 64]);
    assert!(
        answer_rollover_challenge(
            &created.state,
            candidate,
            &forged,
            &prior_role,
            1_788_000_000_800
        )
        .is_err()
    );
    assert!(
        answer_rollover_challenge(
            &created.state,
            candidate,
            &challenge,
            &prior_role,
            challenge.expires_at_ms + 1
        )
        .is_err()
    );
    Ok(())
}

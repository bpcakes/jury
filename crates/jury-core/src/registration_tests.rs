use std::error::Error;

use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{identity_v1::KdfProfile, vault_v1::PrincipalKind};

use crate::identity::{IdentityCreator, UnlockedIdentity, unlock};
use crate::policy::{PolicyCreator, replay_policy};
use crate::registration::{
    RegistrationCreator, RegistrationErrorKind, RegistrationProofV1, RegistrationRoleDescriptorV1,
    answer_challenge, verify_proof,
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
    Ok(())
}

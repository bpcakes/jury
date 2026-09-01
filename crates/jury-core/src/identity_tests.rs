use std::error::Error;

use chacha20::ChaCha20Rng;
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::{
    Deserializable, Kem, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::XWing, rand_core::SeedableRng, single_shot_seal_with_rng,
};
use jury_protected::{EntropyError, ProtectedMemory, ProtectionPolicy, RandomSource};
use jury_protocol::{
    identity_v1::{IdentityFileV1, KdfProfile},
    vault_v1::{
        AccessRole, ContentRole, Digest32, DirectCiphertext48, DirectSlotV1, Encapsulation1120,
        IdentityPayloadCiphertext149, ItemAccessMode, ItemId, PrincipalDescriptorV1, PrincipalKind,
        RecipientPublicKey1216, ResponseId, RevisionSealId, ShareCiphertext49, SlotId, VaultId,
        WitnessPolicyId, WitnessShareCapsuleV1, recipient_public_key_fingerprint,
    },
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::local_state::PrincipalLocalState;

fn protected(bytes: &[u8]) -> Result<ProtectedMemory, Box<dyn Error>> {
    Ok(ProtectedMemory::initialize(
        bytes.len(),
        ProtectionPolicy::Strict,
        |destination| {
            destination.copy_from_slice(bytes);
            Ok::<usize, ()>(destination.len())
        },
    )?)
}

fn descriptor_from_unlocked(
    unlocked: &UnlockedIdentity,
) -> Result<PrincipalDescriptorV1, IdentityError> {
    match unlocked {
        UnlockedIdentity::VaultPrincipal(identity) => identity.public_descriptor(),
        UnlockedIdentity::Approver(identity) => identity.public_descriptor(),
        UnlockedIdentity::Witness(identity) => identity.public_descriptor(),
    }
}

fn assert_self_signature(descriptor: &PrincipalDescriptorV1) -> Result<(), Box<dyn Error>> {
    let key = VerifyingKey::from_bytes(descriptor.verification_public_key.as_bytes())?;
    let signature = Signature::from_bytes(descriptor.self_signature.as_bytes());
    key.verify_strict(&descriptor.self_signature_preimage()?, &signature)?;
    Ok(())
}

fn assert_statement_signature(
    descriptor: &PrincipalDescriptorV1,
    preimage: &[u8],
    signature: &jury_protocol::vault_v1::Signature64,
) -> Result<(), Box<dyn Error>> {
    let key = VerifyingKey::from_bytes(descriptor.verification_public_key.as_bytes())?;
    key.verify_strict(preimage, &Signature::from_bytes(signature.as_bytes()))?;
    Ok(())
}

fn hpke_seal(
    public_key: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
    seed: [u8; 32],
) -> Result<(Encapsulation1120, Vec<u8>), Box<dyn Error>> {
    let public = <<XWing as Kem>::PublicKey as Deserializable>::from_bytes(public_key)
        .map_err(|_| "public key rejected")?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (encapsulation, ciphertext) = single_shot_seal_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        XWing,
    >(&OpModeS::Base, &public, info, plaintext, aad, &mut rng)
    .map_err(|_| "HPKE seal failed")?;
    Ok((
        Encapsulation1120::from_slice(&encapsulation.to_bytes())?,
        ciphertext,
    ))
}

fn recipient_public_key(seed: [u8; 32]) -> RecipientPublicKey1216 {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (_, public) = XWing::gen_keypair_with_rng(&mut rng);
    RecipientPublicKey1216::new(public.to_bytes().into())
}

fn direct_slot(
    descriptor: &PrincipalDescriptorV1,
) -> Result<(DirectSlotV1, [u8; 32]), Box<dyn Error>> {
    let plaintext = [0x91; 32];
    let mut slot = DirectSlotV1 {
        slot_schema: 1,
        slot_algorithm: 1,
        suite: 1,
        kem: 0x647a,
        kdf: 1,
        aead: 3,
        vault_id: VaultId::from_bytes([0x11; 32])?,
        item_id: ItemId::from_bytes([0x12; 32])?,
        key_epoch: 1,
        content_role: ContentRole::Descriptor,
        revision: 1,
        revision_seal_id: RevisionSealId::from_bytes([0x13; 32])?,
        recipient_principal_id: descriptor.principal_id,
        policy_sequence: 1,
        recipient_public_key_fingerprint: recipient_public_key_fingerprint(
            &descriptor.recipient_public_key,
        ),
        access_role: AccessRole::Reader,
        item_access_mode: ItemAccessMode::DirectOnly,
        encapsulation: Encapsulation1120::new([0; 1_120]),
        ciphertext: DirectCiphertext48::new([0; 48]),
    };
    let (encapsulation, ciphertext) = hpke_seal(
        descriptor.recipient_public_key.as_bytes(),
        &plaintext,
        &slot.info_preimage(),
        &slot.aad_preimage(),
        [0x14; 32],
    )?;
    slot.encapsulation = encapsulation;
    slot.ciphertext = DirectCiphertext48::from_slice(&ciphertext)?;
    Ok((slot, plaintext))
}

fn witness_capsule(
    descriptor: &PrincipalDescriptorV1,
) -> Result<(WitnessShareCapsuleV1, [u8; 33]), Box<dyn Error>> {
    let share = [0x51; 33];
    let contribution_fingerprint =
        recipient_public_key_fingerprint(&descriptor.recipient_public_key);
    let mut capsule = WitnessShareCapsuleV1 {
        capsule_schema: 1,
        protocol: 1,
        construction: 1,
        vault_id: VaultId::from_bytes([0x21; 32])?,
        genesis_fingerprint: Digest32::new([0x22; 32]),
        item_id: ItemId::from_bytes([0x23; 32])?,
        key_epoch: 1,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: SlotId::from_bytes([0x24; 32])?,
        content_role: ContentRole::Body,
        revision: 1,
        revision_seal_id: RevisionSealId::from_bytes([0x25; 32])?,
        vault_policy_sequence: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x26; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: Digest32::new([0x27; 32]),
        threshold: 2,
        member_count: 3,
        witness_id: descriptor.principal_id,
        contribution_key_fingerprint: contribution_fingerprint,
        share_index: 1,
        context_digest: Digest32::new([0; 32]),
        share_commitment: Digest32::new([0; 32]),
        encapsulation: Encapsulation1120::new([0; 1_120]),
        ciphertext: ShareCiphertext49::new([0; 49]),
    };
    capsule.context_digest = capsule.recomputed_context_digest();
    let mut commitment = b"jury-witness-v1/share/commitment\0\0\x01".to_vec();
    commitment.extend_from_slice(capsule.context_digest.as_bytes());
    commitment.extend_from_slice(&share);
    capsule.share_commitment = Digest32::new(Sha256::digest(commitment).into());
    let (encapsulation, ciphertext) = hpke_seal(
        descriptor.recipient_public_key.as_bytes(),
        &share,
        &capsule.info_preimage(),
        &capsule.aad_preimage(),
        [0x28; 32],
    )?;
    capsule.encapsulation = encapsulation;
    capsule.ciphertext = ShareCiphertext49::from_slice(&ciphertext)?;
    Ok((capsule, share))
}

#[test]
fn contribution_envelope_matches_bound_j19_bytes() -> Result<(), Box<dyn Error>> {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../conformance/witness-v1/vectors.json"))?;
    let vector = &corpus["construction_vector"]["contributions"][0];
    let envelope = hex::decode(vector["envelope_hex"].as_str().ok_or("expected envelope")?)?;
    let contribution = EncryptedWitnessContribution {
        response_id: ResponseId::from_bytes(envelope[2..34].try_into()?)?,
        share_index: envelope[34],
        share_commitment: Digest32::from_slice(&envelope[35..67])?,
        context_digest: Digest32::from_slice(&envelope[67..99])?,
        capsule_set_digest: Digest32::from_slice(&envelope[99..131])?,
        session_fingerprint: Digest32::from_slice(&envelope[131..163])?,
        encapsulation: Encapsulation1120::from_slice(&envelope[163..1_283])?,
        ciphertext: ShareCiphertext49::from_slice(&envelope[1_283..1_332])?,
    };
    assert_eq!(contribution.canonical_bytes(), envelope);
    assert_eq!(
        contribution.digest().as_bytes().as_slice(),
        hex::decode(vector["digest_hex"].as_str().ok_or("expected digest")?)?
    );
    Ok(())
}

fn assert_vault_role_lifecycle(
    vault: &CreatedIdentity,
    passphrase: &ProtectedMemory,
    wrong_passphrase: &ProtectedMemory,
) -> Result<(), Box<dyn Error>> {
    vault.file.validate()?;
    assert_self_signature(&vault.descriptor)?;
    let unlocked = unlock(&vault.file, passphrase)?;
    assert!(matches!(unlocked, UnlockedIdentity::VaultPrincipal(_)));
    assert_eq!(descriptor_from_unlocked(&unlocked)?, vault.descriptor);
    let UnlockedIdentity::VaultPrincipal(vault_identity) = &unlocked else {
        return Err("vault identity role changed".into());
    };
    let (slot, revision_secret) = direct_slot(&vault.descriptor)?;
    let opened = vault_identity.open_direct_slot(&slot)?;
    assert!(
        opened
            .bytes
            .expose(|bytes| bytes == revision_secret.as_slice())?
    );
    assert!(format!("{opened:?}").contains("[REDACTED]"));
    let statement = b"jury-v1/test/vault-statement\0\0\x01";
    assert_statement_signature(
        &vault.descriptor,
        statement,
        &vault_identity.sign_validated_statement(statement)?,
    )?;
    let local = PrincipalLocalState::for_vault_principal(
        vault_identity,
        VaultId::from_bytes([0x71; 32])?,
        Digest32::new([0x72; 32]),
    )?;
    assert!(format!("{local:?}").contains("[REDACTED]"));

    let mut tampered_slot = slot;
    let mut tampered_ciphertext = *tampered_slot.ciphertext.as_bytes();
    tampered_ciphertext[0] ^= 1;
    tampered_slot.ciphertext = DirectCiphertext48::new(tampered_ciphertext);
    assert_eq!(
        vault_identity
            .open_direct_slot(&tampered_slot)
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::AuthenticationFailed)
    );
    let debug = format!("{unlocked:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("ExamplePassphrase"));
    drop(unlocked);
    assert_eq!(
        unlock(&vault.file, wrong_passphrase)
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::AuthenticationFailed)
    );
    Ok(())
}

fn rotate_passphrase(
    creator: &mut IdentityCreator,
    vault: &CreatedIdentity,
    old_passphrase: &ProtectedMemory,
    new_passphrase: &ProtectedMemory,
) -> Result<IdentityFileV1, Box<dyn Error>> {
    let resealed = creator.change_passphrase(
        &vault.file,
        old_passphrase,
        new_passphrase,
        KdfProfile::PortableV1,
        false,
    )?;
    assert_eq!(resealed.header.principal_id, vault.file.header.principal_id);
    assert_eq!(
        resealed.header.recipient_public_key,
        vault.file.header.recipient_public_key
    );
    assert_eq!(
        resealed.header.verification_public_key,
        vault.file.header.verification_public_key
    );
    assert_ne!(resealed.header.salt, vault.file.header.salt);
    assert_ne!(
        resealed.header.root_wrap_nonce,
        vault.file.header.root_wrap_nonce
    );
    assert_ne!(
        resealed.header.payload_nonce,
        vault.file.header.payload_nonce
    );
    assert_ne!(
        resealed.root_wrap_ciphertext,
        vault.file.root_wrap_ciphertext
    );
    assert_ne!(resealed.payload_ciphertext, vault.file.payload_ciphertext);
    let descriptor = descriptor_from_unlocked(&unlock(&resealed, new_passphrase)?)?;
    assert_eq!(descriptor, vault.descriptor);
    Ok(resealed)
}

fn assert_identity_replacement(
    creator: &mut IdentityCreator,
    vault: &CreatedIdentity,
    resealed: &IdentityFileV1,
    passphrase: &ProtectedMemory,
) -> Result<(), Box<dyn Error>> {
    let replacement = creator.replace(
        resealed,
        KdfProfile::PortableV1,
        1_788_000_000_001,
        passphrase,
        |candidate| candidate == &vault.descriptor.principal_id,
    )?;
    assert_eq!(
        replacement.previous_principal_id,
        vault.descriptor.principal_id
    );
    assert_eq!(
        replacement.replacement.descriptor.principal_kind,
        PrincipalKind::Human
    );
    assert_ne!(
        replacement.replacement.descriptor.principal_id,
        vault.descriptor.principal_id
    );
    assert_ne!(
        replacement.replacement.descriptor.recipient_public_key,
        vault.descriptor.recipient_public_key
    );
    assert_ne!(
        replacement.replacement.descriptor.verification_public_key,
        vault.descriptor.verification_public_key
    );
    Ok(())
}

fn assert_approver_role_lifecycle(
    creator: &mut IdentityCreator,
    passphrase: &ProtectedMemory,
) -> Result<(), Box<dyn Error>> {
    let created = creator.create(
        PrincipalKind::Approver,
        KdfProfile::PortableV1,
        1_788_000_000_002,
        passphrase,
        |_| false,
    )?;
    assert_self_signature(&created.descriptor)?;
    let UnlockedIdentity::Approver(identity) = unlock(&created.file, passphrase)? else {
        return Err("identity unlocked as the wrong role".into());
    };
    let preimage = b"jury-witness-v1/approval-decision/signature\0\0\x01";
    assert_statement_signature(
        &created.descriptor,
        preimage,
        &identity.sign_validated_approval(preimage)?,
    )?;
    let local = PrincipalLocalState::for_approver(
        &identity,
        VaultId::from_bytes([0x71; 32])?,
        Digest32::new([0x72; 32]),
    )?;
    assert!(format!("{local:?}").contains("[REDACTED]"));
    Ok(())
}

fn assert_witness_role_lifecycle(
    creator: &mut IdentityCreator,
    passphrase: &ProtectedMemory,
) -> Result<(), Box<dyn Error>> {
    let created = creator.create(
        PrincipalKind::Witness,
        KdfProfile::PortableV1,
        1_788_000_000_002,
        passphrase,
        |_| false,
    )?;
    assert_self_signature(&created.descriptor)?;
    let UnlockedIdentity::Witness(identity) = unlock(&created.file, passphrase)? else {
        return Err("identity unlocked as the wrong role".into());
    };
    let preimage = b"jury-witness-v1/decision/signature\0\0\x01";
    assert_statement_signature(
        &created.descriptor,
        preimage,
        &identity.sign_validated_decision(preimage)?,
    )?;
    let local = PrincipalLocalState::for_witness(
        &identity,
        VaultId::from_bytes([0x71; 32])?,
        Digest32::new([0x72; 32]),
    )?;
    assert!(format!("{local:?}").contains("[REDACTED]"));
    assert_witness_contribution(&created.descriptor, &identity)
}

fn assert_witness_contribution(
    descriptor: &PrincipalDescriptorV1,
    identity: &WitnessIdentity,
) -> Result<(), Box<dyn Error>> {
    let (capsule, expected_share) = witness_capsule(descriptor)?;
    let share = identity.open_contribution_share(&capsule)?;
    assert!(
        share
            .bytes
            .expose(|bytes| bytes == expected_share.as_slice())?
    );
    assert!(format!("{share:?}").contains("[REDACTED]"));
    let mut wrong_commitment = capsule;
    wrong_commitment.share_commitment = Digest32::new([0x99; 32]);
    assert_eq!(
        identity
            .open_contribution_share(&wrong_commitment)
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::AuthenticationFailed)
    );
    let session_public_key = recipient_public_key([0x61; 32]);
    let session_fingerprint = recipient_public_key_fingerprint(&session_public_key);
    let target = WitnessContributionTarget {
        request_digest: Digest32::new([0x62; 32]),
        action_manifest_digest: Digest32::new([0x63; 32]),
        response_id: ResponseId::from_bytes([0x64; 32])?,
        checkpoint_digest: Digest32::new([0x65; 32]),
        capsule_set_digest: Digest32::new([0x66; 32]),
        session_public_key,
        session_fingerprint: session_fingerprint.clone(),
        expires_at_ms: 1_788_000_030_000,
    };
    let contribution = share.seal_for_request(&target)?;
    assert_eq!(contribution.response_id, target.response_id);
    assert_eq!(contribution.share_index, 1);
    assert_eq!(contribution.session_fingerprint, session_fingerprint);
    assert_eq!(contribution.canonical_bytes().len(), 1_332);
    assert_ne!(contribution.digest(), Digest32::new([0; 32]));
    Ok(())
}

#[test]
fn portable_role_lifecycle_preserves_only_passphrase_rotation_keys() -> Result<(), Box<dyn Error>> {
    let old_passphrase = protected(b"ExamplePassphrase-Old")?;
    let new_passphrase = protected(b"ExamplePassphrase-New")?;
    let wrong_passphrase = protected(b"ExamplePassphrase-Wrong")?;
    let mut creator = IdentityCreator::new();

    let vault = creator.create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1_788_000_000_000,
        &old_passphrase,
        |_| false,
    )?;
    assert_vault_role_lifecycle(&vault, &old_passphrase, &wrong_passphrase)?;
    let resealed = rotate_passphrase(&mut creator, &vault, &old_passphrase, &new_passphrase)?;
    assert_identity_replacement(&mut creator, &vault, &resealed, &new_passphrase)?;
    assert_approver_role_lifecycle(&mut creator, &new_passphrase)?;
    assert_witness_role_lifecycle(&mut creator, &new_passphrase)?;
    Ok(())
}

#[test]
fn ciphertext_and_role_substitution_never_release_an_identity() -> Result<(), Box<dyn Error>> {
    let passphrase = protected(b"ExamplePassphrase-Auth")?;
    let mut creator = IdentityCreator::new();
    let created = creator.create(
        PrincipalKind::Approver,
        KdfProfile::PortableV1,
        1_788_000_000_003,
        &passphrase,
        |_| false,
    )?;

    let mut tampered = created.file.clone();
    let mut ciphertext = *tampered.payload_ciphertext.as_bytes();
    ciphertext[0] ^= 1;
    tampered.payload_ciphertext = IdentityPayloadCiphertext149::new(ciphertext);
    assert_eq!(
        unlock(&tampered, &passphrase)
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::AuthenticationFailed)
    );

    let mut substituted = created.file;
    substituted.header.principal_kind = PrincipalKind::Witness;
    assert_eq!(
        unlock(&substituted, &passphrase)
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::Format)
    );

    Ok(())
}

#[test]
fn passphrase_profile_is_exact_and_value_free() -> Result<(), Box<dyn Error>> {
    for bytes in [
        vec![b'a'; 11],
        vec![b'a'; 1_025],
        b"ExamplePass\0word".to_vec(),
        b"ExamplePass\rword".to_vec(),
        b"ExamplePass\nword".to_vec(),
        vec![0xff; 12],
    ] {
        let passphrase = protected(&bytes)?;
        let error = validate_passphrase(&passphrase).err();
        assert_eq!(
            error.map(IdentityError::kind),
            Some(IdentityErrorKind::InvalidPassphrase)
        );
        assert!(!format!("{error:?}").contains("ExamplePass"));
    }
    validate_passphrase(&protected(&[b'a'; 12])?)?;
    validate_passphrase(&protected(&[b'a'; 1_024])?)?;
    validate_passphrase(&protected("Exact-例-Passphrase".as_bytes())?)?;
    Ok(())
}

#[test]
fn downgrade_and_entropy_fail_before_private_output() -> Result<(), Box<dyn Error>> {
    struct FailingRandom;

    impl RandomSource for FailingRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            let partial = destination.len().min(3);
            destination[..partial].fill(0xa5);
            Err(EntropyError)
        }
    }

    let passphrase = protected(b"ExamplePassphrase-Fail")?;
    let mut failing = IdentityCreator::from_source(FailingRandom);
    assert_eq!(
        failing
            .create(
                PrincipalKind::Human,
                KdfProfile::PortableV1,
                1_788_000_000_004,
                &passphrase,
                |_| false,
            )
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::EntropyUnavailable)
    );

    struct CollisionRandom {
        calls: usize,
    }

    impl RandomSource for CollisionRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            self.calls += 1;
            destination.fill(0x44);
            Ok(())
        }
    }

    let mut colliding = IdentityCreator::from_source(CollisionRandom { calls: 0 });
    assert_eq!(
        colliding
            .create(
                PrincipalKind::Human,
                KdfProfile::PortableV1,
                1_788_000_000_004,
                &passphrase,
                |_| true,
            )
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::RetryExhausted)
    );
    assert_eq!(colliding.source.calls, 8);

    let reused = protected(&[0x71; 32])?;
    let independent = protected(&[0x72; 32])?;
    assert_eq!(
        ensure_distinct_secrets(&reused, &reused, &independent)
            .err()
            .map(IdentityError::kind),
        Some(IdentityErrorKind::KeyCollision)
    );

    let mut creator = IdentityCreator::new();
    let created = creator.create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1_788_000_000_005,
        &passphrase,
        |_| false,
    )?;
    let mut hardened_header = created.file;
    hardened_header.header.kdf_profile = KdfProfile::HardenedV1;
    hardened_header.header.memory_kib = KdfProfile::HardenedV1.memory_kib();
    assert_eq!(
        creator
            .change_passphrase(
                &hardened_header,
                &passphrase,
                &passphrase,
                KdfProfile::PortableV1,
                false,
            )
            .map_err(|error| error.kind()),
        Err(IdentityErrorKind::KdfDowngrade)
    );
    Ok(())
}

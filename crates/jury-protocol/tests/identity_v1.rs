use std::error::Error;
use std::io;

use jury_protocol::identity_v1::{
    IdentityFileV1, IdentityFormatError, IdentityHeaderV1, KdfProfile, ProtectionMode,
    ProviderKind, ProviderMetadata,
};
use jury_protocol::vault_v1::{
    FixedBytes, PrincipalId, PrincipalKind, RecipientPublicKey1216, VerificationPublicKey32,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn corpus() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../docs/security/vectors/jury-v1-suite.json"
    ))?)
}

fn hex_value(value: &Value) -> TestResult<Vec<u8>> {
    Ok(hex::decode(
        value["hex"]
            .as_str()
            .ok_or_else(|| failure("missing vector hex"))?,
    )?)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> TestResult<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| failure("cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| failure("truncated vector"))?
            .try_into()?;
        self.offset = end;
        Ok(value)
    }

    fn bytes_field(&mut self) -> TestResult<Vec<u8>> {
        let length = usize::try_from(u32::from_be_bytes(self.take()?))?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| failure("cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| failure("truncated bytes field"))?
            .to_vec();
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> TestResult<u8> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> TestResult<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> TestResult<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> TestResult<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn done(&self) -> TestResult {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(failure("trailing bytes").into())
        }
    }
}

fn parse_header(bytes: &[u8]) -> TestResult<IdentityHeaderV1> {
    let mut cursor = Cursor::new(bytes);
    let header = IdentityHeaderV1 {
        identity_format: cursor.u16()?,
        principal_id: PrincipalId::from_bytes(cursor.take()?)?,
        principal_kind: match cursor.u8()? {
            1 => PrincipalKind::Human,
            2 => PrincipalKind::Machine,
            3 => PrincipalKind::Approver,
            4 => PrincipalKind::Witness,
            _ => return Err(failure("unknown principal kind").into()),
        },
        recipient_public_key: RecipientPublicKey1216::new(cursor.take()?),
        verification_public_key: VerificationPublicKey32::new(cursor.take()?),
        descriptor_fingerprint: FixedBytes::new(cursor.take()?),
        created_at_ms: cursor.u64()?,
        kdf_profile: match cursor.u8()? {
            1 => KdfProfile::PortableV1,
            2 => KdfProfile::HardenedV1,
            _ => return Err(failure("unknown KDF profile").into()),
        },
        argon2_version: cursor.u8()?,
        memory_kib: cursor.u32()?,
        passes: cursor.u32()?,
        lanes: cursor.u32()?,
        salt: FixedBytes::new(cursor.take()?),
        protection_mode: match cursor.u8()? {
            1 => ProtectionMode::Portable,
            2 => ProtectionMode::DeviceBound,
            _ => return Err(failure("unknown protection mode").into()),
        },
        provider_kind: ProviderKind::new(cursor.bytes_field()?)?,
        provider_metadata: ProviderMetadata::new(cursor.bytes_field()?)?,
        root_wrap_algorithm: cursor.u8()?,
        root_wrap_nonce: FixedBytes::new(cursor.take()?),
        payload_algorithm: cursor.u8()?,
        payload_nonce: FixedBytes::new(cursor.take()?),
    };
    cursor.done()?;
    Ok(header)
}

#[test]
fn portable_header_consumes_every_bound_j01a_preimage() -> TestResult {
    let corpus = corpus()?;
    let expected = hex_value(&corpus["encodings"]["identity_header_portable"])?;
    let header = parse_header(&expected)?;
    assert_eq!(header.canonical_bytes()?, expected);
    assert_eq!(
        header.hash_preimage()?,
        hex_value(&corpus["preimages"]["identity_header_hash"])?
    );
    assert_eq!(
        header.root_wrap_kdf_info(),
        hex_value(&corpus["preimages"]["kdf_identity_root_wrap"])?
    );
    assert_eq!(
        header.payload_kdf_info(),
        hex_value(&corpus["preimages"]["kdf_identity_payload"])?
    );
    assert_eq!(
        header.root_wrap_aad()?,
        hex_value(&corpus["preimages"]["identity_root_wrap_aad"])?
    );
    assert_eq!(
        header.payload_aad()?,
        hex_value(&corpus["preimages"]["identity_payload_aad"])?
    );
    header.validate_for_active_release()?;
    Ok(())
}

#[test]
fn device_header_is_parseable_but_inactive() -> TestResult {
    let corpus = corpus()?;
    let expected = hex_value(&corpus["encodings"]["identity_header_device_bound"])?;
    let header = parse_header(&expected)?;
    assert_eq!(header.canonical_bytes()?, expected);
    assert_eq!(
        header.validate_for_active_release(),
        Err(IdentityFormatError::UnsupportedProfile)
    );
    Ok(())
}

#[test]
fn identity_json_is_closed_bounded_and_byte_stable() -> TestResult {
    let corpus = corpus()?;
    let header = parse_header(&hex_value(
        &corpus["encodings"]["identity_header_portable"],
    )?)?;
    let identity = IdentityFileV1 {
        magic: "jury-identity".to_owned(),
        header,
        root_wrap_ciphertext: FixedBytes::new([0x71; 48]),
        payload_ciphertext: FixedBytes::new([0x72; 149]),
    };
    let bytes = identity.to_json_bytes()?;
    assert_eq!(IdentityFileV1::parse(&bytes)?, identity);

    let mut extra: Value = serde_json::from_slice(&bytes)?;
    extra["provider_cache"] = Value::String("forbidden".to_owned());
    let mut mutated = serde_json::to_vec_pretty(&extra)?;
    mutated.push(b'\n');
    assert_eq!(
        IdentityFileV1::parse(&mutated),
        Err(IdentityFormatError::InvalidJson)
    );

    let mut hostile = identity;
    hostile.header.memory_kib = 65_536;
    assert_eq!(
        hostile.validate(),
        Err(IdentityFormatError::UnsupportedProfile)
    );
    assert_eq!(
        IdentityFileV1::parse(b"<<<<<<< ours\n{}\n=======\n{}\n>>>>>>> theirs\n"),
        Err(IdentityFormatError::ConflictMarker)
    );
    Ok(())
}

#[test]
fn every_public_identity_kdf_limit_is_exact() -> TestResult {
    let corpus = corpus()?;
    let baseline = parse_header(&hex_value(
        &corpus["encodings"]["identity_header_portable"],
    )?)?;

    for profile in [KdfProfile::PortableV1, KdfProfile::HardenedV1] {
        let mut valid = baseline.clone();
        valid.kdf_profile = profile;
        valid.memory_kib = profile.memory_kib();
        valid.validate_for_active_release()?;

        for version in [0, 0x12, 0x14, u8::MAX] {
            let mut hostile = valid.clone();
            hostile.argon2_version = version;
            assert_eq!(
                hostile.validate_for_active_release(),
                Err(IdentityFormatError::UnsupportedProfile)
            );
        }
        for memory_kib in [
            0,
            profile.memory_kib() - 1,
            profile.memory_kib() + 1,
            u32::MAX,
        ] {
            let mut hostile = valid.clone();
            hostile.memory_kib = memory_kib;
            assert_eq!(
                hostile.validate_for_active_release(),
                Err(IdentityFormatError::UnsupportedProfile)
            );
        }
        for passes in [0, 1, 2, 4, u32::MAX] {
            let mut hostile = valid.clone();
            hostile.passes = passes;
            assert_eq!(
                hostile.validate_for_active_release(),
                Err(IdentityFormatError::UnsupportedProfile)
            );
        }
        for lanes in [0, 1, 3, 5, u32::MAX] {
            let mut hostile = valid.clone();
            hostile.lanes = lanes;
            assert_eq!(
                hostile.validate_for_active_release(),
                Err(IdentityFormatError::UnsupportedProfile)
            );
        }
    }
    Ok(())
}

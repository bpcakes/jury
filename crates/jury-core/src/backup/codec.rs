use super::*;

pub(super) struct PreparedIdentity<'a> {
    pub(super) role: RecoveryRole,
    pub(super) identity: RecoveredIdentity,
    pub(super) local_state: LocalStateArchive<'a>,
}

pub(super) struct ParsedPayload {
    pub(super) vault_bytes: Vec<u8>,
    pub(super) catalog_bytes: Vec<u8>,
    pub(super) identities: Vec<RecoveredRoleIdentity>,
}

pub(super) fn encoded_payload_len(
    vault: &[u8],
    catalog: &[u8],
    identities: &[PreparedIdentity<'_>],
) -> Result<usize, BackupError> {
    let mut length = RECOVERY_PAYLOAD_MAGIC.len() + 2;
    length = add_payload_length(length, 4 + vault.len(), BackupCapacityClass::Vault)?;
    length = add_payload_length(length, 4 + catalog.len(), BackupCapacityClass::Catalog)?;
    length = add_payload_length(length, 1, BackupCapacityClass::Envelope)?;
    for entry in identities {
        let header = serde_json::to_vec(&entry.identity.header)
            .map_err(|_| BackupError::new(BackupErrorKind::InvalidFormat))?;
        if header.len() > MAX_IDENTITY_HEADER_BYTES
            || entry.identity.payload.len() != IDENTITY_PRIVATE_PAYLOAD_BYTES
        {
            return Err(BackupError::new(BackupErrorKind::InvalidFormat));
        }
        length = add_payload_length(
            length,
            1 + 4 + header.len() + 2 + IDENTITY_PRIVATE_PAYLOAD_BYTES,
            BackupCapacityClass::Identity,
        )?;
        length = add_payload_length(
            length,
            4 + entry.local_state.audit.len(),
            BackupCapacityClass::Audit,
        )?;
        length = add_payload_length(
            length,
            4 + entry.local_state.checkpoint.len(),
            BackupCapacityClass::Checkpoint,
        )?;
        length = add_payload_length(
            length,
            4 + entry.local_state.receipts.len(),
            BackupCapacityClass::Receipts,
        )?;
    }
    Ok(length)
}

pub(super) fn add_payload_length(
    current: usize,
    added: usize,
    class: BackupCapacityClass,
) -> Result<usize, BackupError> {
    current
        .checked_add(added)
        .filter(|length| *length <= MAX_RECOVERY_PAYLOAD_BYTES)
        .ok_or_else(|| BackupError::capacity(class))
}

pub(super) fn encode_payload(
    output: &mut [u8],
    vault: &[u8],
    catalog: &[u8],
    identities: &[PreparedIdentity<'_>],
) -> Result<(), ()> {
    let mut cursor = WriteCursor::new(output);
    cursor.put(RECOVERY_PAYLOAD_MAGIC)?;
    cursor.put(&RECOVERY_PAYLOAD_VERSION.to_be_bytes())?;
    cursor.put_sized(vault)?;
    cursor.put_sized(catalog)?;
    cursor.put(&[u8::try_from(identities.len()).map_err(|_| ())?])?;
    for entry in identities {
        cursor.put(&[entry.role.tag()])?;
        let header = serde_json::to_vec(&entry.identity.header).map_err(|_| ())?;
        cursor.put_sized(&header)?;
        cursor.put(
            &u16::try_from(entry.identity.payload.len())
                .map_err(|_| ())?
                .to_be_bytes(),
        )?;
        entry
            .identity
            .payload
            .expose(|payload| cursor.put(payload))
            .map_err(|_| ())??;
        cursor.put_sized(entry.local_state.audit)?;
        cursor.put_sized(entry.local_state.checkpoint)?;
        cursor.put_sized(entry.local_state.receipts)?;
    }
    if cursor.position != output.len() {
        return Err(());
    }
    Ok(())
}

pub(super) fn parse_padded_payload(
    plaintext: &[u8],
    header: &BackupHeaderV1,
    protection: ProtectionPolicy,
) -> Result<ParsedPayload, BackupError> {
    if plaintext.len() < 4 {
        return Err(BackupError::new(BackupErrorKind::InvalidFormat));
    }
    let logical_length = usize::try_from(u32::from_be_bytes(
        plaintext[..4]
            .try_into()
            .map_err(|_| BackupError::new(BackupErrorKind::InvalidFormat))?,
    ))
    .map_err(|_| BackupError::new(BackupErrorKind::InvalidFormat))?;
    let end = 4_usize
        .checked_add(logical_length)
        .filter(|end| *end <= plaintext.len())
        .ok_or_else(|| BackupError::new(BackupErrorKind::InvalidFormat))?;
    if plaintext[end..].iter().any(|byte| *byte != 0) {
        return Err(BackupError::new(BackupErrorKind::NonCanonicalPadding));
    }
    if crypto::sha256(&plaintext[4..end]) != *header.payload_digest.as_bytes() {
        return Err(BackupError::new(BackupErrorKind::AuthenticationFailed));
    }
    parse_payload(&plaintext[4..end], protection)
}

fn parse_payload(bytes: &[u8], protection: ProtectionPolicy) -> Result<ParsedPayload, BackupError> {
    let mut cursor = ReadCursor::new(bytes);
    if cursor.take(RECOVERY_PAYLOAD_MAGIC.len())? != RECOVERY_PAYLOAD_MAGIC
        || cursor.u16()? != RECOVERY_PAYLOAD_VERSION
    {
        return Err(BackupError::new(BackupErrorKind::InvalidFormat));
    }
    let vault_bytes = cursor.sized(16 * 1024 * 1024)?.to_vec();
    let catalog_bytes = cursor.sized(MAX_CATALOG_BYTES)?.to_vec();
    let count = usize::from(cursor.u8()?);
    if !(1..=3).contains(&count) {
        return Err(BackupError::new(BackupErrorKind::InvalidFormat));
    }
    let mut identities = Vec::with_capacity(count);
    let mut prior_role = None;
    for _ in 0..count {
        let role = RecoveryRole::from_tag(cursor.u8()?)?;
        if prior_role.is_some_and(|prior| prior >= role) {
            return Err(BackupError::new(BackupErrorKind::DuplicateRole));
        }
        prior_role = Some(role);
        let header_bytes = cursor.sized(MAX_IDENTITY_HEADER_BYTES)?;
        let identity_header: IdentityHeaderV1 = serde_json::from_slice(header_bytes)
            .map_err(|_| BackupError::new(BackupErrorKind::InvalidFormat))?;
        if serde_json::to_vec(&identity_header).ok().as_deref() != Some(header_bytes) {
            return Err(BackupError::new(BackupErrorKind::InvalidFormat));
        }
        let private_length = usize::from(cursor.u16()?);
        if private_length != IDENTITY_PRIVATE_PAYLOAD_BYTES {
            return Err(BackupError::new(BackupErrorKind::InvalidFormat));
        }
        let private_bytes = cursor.take(private_length)?;
        let private = ProtectedMemory::initialize(private_length, protection, |destination| {
            destination.copy_from_slice(private_bytes);
            Ok::<usize, ()>(destination.len())
        })
        .map_err(|_| BackupError::new(BackupErrorKind::ProtectionUnavailable))?;
        let identity =
            RecoveredIdentity::from_parts(identity_header, private).map_err(map_identity_error)?;
        if role_for_kind(identity.principal_kind())? != role {
            return Err(BackupError::new(BackupErrorKind::IdentityMismatch));
        }
        let local_state = RecoveredLocalState {
            audit: cursor.sized(crate::local_state::MAX_AUDIT_BYTES)?.to_vec(),
            checkpoint: cursor
                .sized(crate::local_state::MAX_CHECKPOINT_BYTES)?
                .to_vec(),
            receipts: cursor
                .sized(crate::local_state::MAX_RECEIPTS_BYTES)?
                .to_vec(),
        };
        identities.push(RecoveredRoleIdentity {
            role,
            identity,
            local_state,
        });
    }
    if !cursor.is_finished() {
        return Err(BackupError::new(BackupErrorKind::InvalidFormat));
    }
    Ok(ParsedPayload {
        vault_bytes,
        catalog_bytes,
        identities,
    })
}

struct WriteCursor<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> WriteCursor<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn put(&mut self, value: &[u8]) -> Result<(), ()> {
        let end = self.position.checked_add(value.len()).ok_or(())?;
        self.output
            .get_mut(self.position..end)
            .ok_or(())?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn put_sized(&mut self, value: &[u8]) -> Result<(), ()> {
        self.put(&u32::try_from(value.len()).map_err(|_| ())?.to_be_bytes())?;
        self.put(value)
    }
}

struct ReadCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> ReadCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BackupError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| BackupError::new(BackupErrorKind::InvalidFormat))?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or_else(|| BackupError::new(BackupErrorKind::InvalidFormat))?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, BackupError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BackupError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| BackupError::new(BackupErrorKind::InvalidFormat),
        )?))
    }

    fn sized(&mut self, maximum: usize) -> Result<&'a [u8], BackupError> {
        let length = usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| BackupError::new(BackupErrorKind::InvalidFormat))?,
        ))
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidFormat))?;
        if length == 0 || length > maximum {
            return Err(BackupError::new(BackupErrorKind::CapacityExhausted));
        }
        self.take(length)
    }

    fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }
}

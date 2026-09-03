/// Computes the protocol signing-key fingerprint for one exact public key.
#[must_use]
pub fn signing_key_fingerprint(
    role_tag: u8,
    subject_id: &PrincipalId,
    key_epoch: u64,
    public_key: &VerificationPublicKey32,
) -> Digest32 {
    let mut output = jce("jury-witness-v1/signing-key/fingerprint");
    output.push(role_tag);
    output.extend_from_slice(subject_id.as_bytes());
    output.extend_from_slice(&key_epoch.to_be_bytes());
    output.extend_from_slice(public_key.as_bytes());
    digest(&output)
}

fn witness_operation_from_tag(tag: u8) -> Result<WitnessOperationV1, WitnessProtocolError> {
    match tag {
        1 => Ok(WitnessOperationV1::ReadStdout),
        2 => Ok(WitnessOperationV1::WritePrivateFile),
        3 => Ok(WitnessOperationV1::TemplateInjection),
        4 => Ok(WitnessOperationV1::ChildEnvironment),
        5 => Ok(WitnessOperationV1::ChildStdin),
        6 => Ok(WitnessOperationV1::ItemMutation),
        7 => Ok(WitnessOperationV1::Backup),
        8 => Ok(WitnessOperationV1::Recovery),
        9 => Ok(WitnessOperationV1::AdministrativeRekey),
        _ => Err(invalid_format()),
    }
}

struct CanonicalInput<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalInput<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn domain(&mut self, domain: &str) -> Result<(), WitnessProtocolError> {
        let expected = jce(domain);
        if self.take(expected.len())? != expected.as_slice() {
            return Err(invalid_format());
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, WitnessProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WitnessProtocolError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| invalid_format())?,
        ))
    }

    fn u32(&mut self) -> Result<u32, WitnessProtocolError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| invalid_format())?,
        ))
    }

    fn u64(&mut self) -> Result<u64, WitnessProtocolError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| invalid_format())?,
        ))
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, WitnessProtocolError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.u64().map(Some),
            _ => Err(invalid_format()),
        }
    }

    fn fixed<const N: usize>(&mut self) -> Result<FixedBytes<N>, WitnessProtocolError> {
        FixedBytes::from_slice(self.take(N)?).map_err(|_| invalid_format())
    }

    fn identifier<T, E>(
        &mut self,
        constructor: impl FnOnce([u8; 32]) -> Result<T, E>,
    ) -> Result<T, WitnessProtocolError> {
        let bytes = self.take(32)?.try_into().map_err(|_| invalid_format())?;
        constructor(bytes).map_err(|_| invalid_format())
    }

    fn length(&mut self, maximum: usize) -> Result<usize, WitnessProtocolError> {
        let length = usize::try_from(self.u32()?).map_err(|_| invalid_format())?;
        if length > maximum {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WitnessProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(invalid_format)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), WitnessProtocolError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid_format())
        }
    }
}

const fn invalid_format() -> WitnessProtocolError {
    WitnessProtocolError::new(WitnessProtocolErrorKind::InvalidFormat)
}

fn valid_interval(issued_at_ms: u64, not_before_ms: Option<u64>, expires_at_ms: u64) -> bool {
    issued_at_ms > 0
        && expires_at_ms
            .checked_sub(issued_at_ms)
            .is_some_and(|lifetime| (1..=MAX_REQUEST_LIFETIME_MS).contains(&lifetime))
        && not_before_ms
            .is_none_or(|not_before| issued_at_ms <= not_before && not_before <= expires_at_ms)
}

fn digest(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

fn hash_bytes(domain: &str, body: &[u8]) -> Result<Digest32, WitnessProtocolError> {
    let mut output = jce(domain);
    bytes_field(&mut output, body)?;
    Ok(digest(&output))
}

fn hash_signed(
    domain: &str,
    signature_preimage: &[u8],
    signature: &Signature64,
) -> Result<Digest32, WitnessProtocolError> {
    let mut output = jce(domain);
    bytes_field(&mut output, signature_preimage)?;
    output.extend_from_slice(signature.as_bytes());
    Ok(digest(&output))
}

fn bytes_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WitnessProtocolError> {
    canonical::bytes_field(output, value).map_err(|_| capacity_exhausted())
}

fn list_bytes(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), WitnessProtocolError> {
    canonical::list_bytes(output, values).map_err(|_| capacity_exhausted())
}

fn list_fixed<T>(
    output: &mut Vec<u8>,
    values: &[T],
    append: impl FnMut(&mut Vec<u8>, &T),
) -> Result<(), WitnessProtocolError> {
    canonical::list_fixed(output, values, append).map_err(|_| capacity_exhausted())
}

fn optional_fixed<const N: usize>(output: &mut Vec<u8>, value: Option<&[u8; N]>) {
    canonical::optional_fixed(output, value.map(<[u8; N]>::as_slice));
}

fn optional_bytes(output: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), WitnessProtocolError> {
    canonical::optional_bytes(output, value).map_err(|_| capacity_exhausted())
}

const fn capacity_exhausted() -> WitnessProtocolError {
    WitnessProtocolError::new(WitnessProtocolErrorKind::CapacityExhausted)
}

fn strictly_sorted_unique<T>(values: &[T], less_than: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less_than(&pair[0], &pair[1]))
}

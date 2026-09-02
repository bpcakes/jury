use std::io;

use jury_core::witness_engine::{PersistedWitnessState, WitnessStoreError};
use serde::Serialize;

use super::MAX_PERSISTED_WITNESS_STATE_BYTES;
use crate::{AdapterError, AdapterErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StateCodecError {
    Invalid,
    CapacityExhausted,
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    capacity_exhausted: bool,
}

impl BoundedJsonWriter {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_bytes,
            capacity_exhausted: false,
        }
    }
}

impl io::Write for BoundedJsonWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.maximum_bytes.saturating_sub(self.bytes.len());
        if input.len() > remaining {
            self.capacity_exhausted = true;
            return Err(io::Error::other(
                "serialized witness state exceeds capacity",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode_persisted_state(
    state: &PersistedWitnessState,
) -> Result<Vec<u8>, StateCodecError> {
    encode_json_bounded(state, MAX_PERSISTED_WITNESS_STATE_BYTES)
}

pub(super) fn encode_json_bounded(
    value: &impl Serialize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, StateCodecError> {
    let mut writer = BoundedJsonWriter::new(maximum_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.bytes),
        Err(_) if writer.capacity_exhausted => Err(StateCodecError::CapacityExhausted),
        Err(_) => Err(StateCodecError::Invalid),
    }
}

pub(super) const fn map_codec_adapter_error(error: StateCodecError) -> AdapterError {
    match error {
        StateCodecError::Invalid => AdapterError::new(AdapterErrorKind::InvalidState),
        StateCodecError::CapacityExhausted => {
            AdapterError::new(AdapterErrorKind::CapacityExhausted)
        }
    }
}

pub(super) const fn map_codec_store_error(error: StateCodecError) -> WitnessStoreError {
    match error {
        StateCodecError::Invalid => WitnessStoreError::unavailable(),
        StateCodecError::CapacityExhausted => WitnessStoreError::capacity_exhausted(),
    }
}

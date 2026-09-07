//! SQLite snapshot representation; the engine's tuple-keyed replay map is
//! encoded as records whose request carries both parts of the key.

use std::{collections::BTreeMap, fmt};

use jury_core::witness_engine::{
    PersistedWitnessState, RegisteredWitnessVault, WitnessLogicalState, WitnessReplayEntry,
};
use jury_protocol::{
    vault_v1::{PrincipalId, RequestId, VaultId},
    witness_v1::{MAX_REPLAY_RECORDS_PER_SERVICE, WitnessStateAnchorV1},
};
use serde::{Deserialize, Serialize, de, ser::SerializeSeq as _};

use super::MAX_PERSISTED_WITNESS_STATE_BYTES;
use super::state_codec::{StateCodecError, encode_json_bounded};

#[derive(Serialize, Deserialize)]
#[serde(remote = "PersistedWitnessState", deny_unknown_fields)]
struct StoredState {
    #[serde(with = "StoredLogicalState")]
    logical: WitnessLogicalState,
    published_anchor: Option<WitnessStateAnchorV1>,
    pending_anchor: Option<WitnessStateAnchorV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "WitnessLogicalState", deny_unknown_fields)]
struct StoredLogicalState {
    witness_id: PrincipalId,
    state_generation: u64,
    vaults: BTreeMap<VaultId, RegisteredWitnessVault>,
    #[serde(with = "replay_records")]
    replay: BTreeMap<(VaultId, RequestId), WitnessReplayEntry>,
    last_accepted_wall_time_ms: u64,
}

#[derive(Serialize)]
struct SnapshotRef<'a>(#[serde(with = "StoredState")] &'a PersistedWitnessState);

#[derive(Deserialize)]
struct Snapshot(#[serde(with = "StoredState")] PersistedWitnessState);

pub(super) fn encode(state: &PersistedWitnessState) -> Result<Vec<u8>, StateCodecError> {
    encode_json_bounded(&SnapshotRef(state), MAX_PERSISTED_WITNESS_STATE_BYTES)
}

pub(super) fn decode(bytes: &[u8]) -> Result<PersistedWitnessState, StateCodecError> {
    if bytes.len() > MAX_PERSISTED_WITNESS_STATE_BYTES {
        return Err(StateCodecError::CapacityExhausted);
    }
    serde_json::from_slice::<Snapshot>(bytes)
        .map(|snapshot| snapshot.0)
        .map_err(|_| StateCodecError::Invalid)
}

mod replay_records {
    use super::*;

    type ReplayMap = BTreeMap<(VaultId, RequestId), WitnessReplayEntry>;

    pub(super) fn serialize<S: serde::Serializer>(
        records: &ReplayMap,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if records.len() > MAX_REPLAY_RECORDS_PER_SERVICE {
            return Err(serde::ser::Error::custom("too many replay records"));
        }
        let mut sequence = serializer.serialize_seq(Some(records.len()))?;
        for (key, record) in records {
            if *key != (record.request.vault_id, record.request.request_id) {
                return Err(serde::ser::Error::custom("replay key differs from request"));
            }
            sequence.serialize_element(record)?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ReplayMap, D::Error> {
        struct Records;

        impl<'de> de::Visitor<'de> for Records {
            type Value = ReplayMap;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a list of replay records")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<ReplayMap, A::Error> {
                let mut records = ReplayMap::new();
                while let Some(record) = sequence.next_element::<WitnessReplayEntry>()? {
                    if records.len() >= MAX_REPLAY_RECORDS_PER_SERVICE {
                        return Err(de::Error::custom("too many replay records"));
                    }
                    let key = (record.request.vault_id, record.request.request_id);
                    if records.insert(key, record).is_some() {
                        return Err(de::Error::custom("duplicate replay request"));
                    }
                }
                Ok(records)
            }
        }

        deserializer.deserialize_seq(Records)
    }
}

use std::fmt;

use serde::{Deserialize, Serialize};

/// Failure to construct or advance a bounded revision counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionError {
    Zero,
    Exhausted,
}

impl fmt::Display for RevisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("revision and epoch values must be nonzero"),
            Self::Exhausted => formatter.write_str("revision or epoch counter is exhausted"),
        }
    }
}

impl std::error::Error for RevisionError {}

/// Monotonic policy sequence. Genesis is sequence zero.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyRevision(u64);

impl PolicyRevision {
    pub const GENESIS: Self = Self(0);

    /// Constructs a policy sequence received from authenticated state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the wire counter value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances the sequence or fails instead of wrapping.
    pub fn next(self) -> Result<Self, RevisionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(RevisionError::Exhausted)
    }
}

macro_rules! nonzero_counter {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub const INITIAL: Self = Self(1);

            /// Constructs the counter while rejecting the reserved zero value.
            pub const fn new(value: u64) -> Result<Self, RevisionError> {
                if value == 0 {
                    Err(RevisionError::Zero)
                } else {
                    Ok(Self(value))
                }
            }

            /// Returns the wire counter value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Advances the counter or fails instead of wrapping.
            pub fn next(self) -> Result<Self, RevisionError> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(RevisionError::Exhausted)
            }
        }

        impl TryFrom<u64> for $name {
            type Error = RevisionError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = u64::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

nonzero_counter!(KeyEpoch, "A nonzero item key epoch.");
nonzero_counter!(ItemRevision, "A nonzero item-content revision number.");

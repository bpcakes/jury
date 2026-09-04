//! Canonical public messages for Jury witnessed-access protocol v1.
//!
//! These are pre-alpha wire values. They contain public authorization scope and
//! encrypted contributions only; plaintext shares and private presentation
//! material are never represented here.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical::{self, jce_v1 as jce, optional_u8, optional_u64};
use crate::vault_v1::{
    AccessRole, ApprovalId, BoundedBytes, CancellationId, ContentRole, Digest32, Encapsulation1120,
    FieldId, FixedBytes, ItemAccessMode, ItemId, LabelId, PresentationNonce, PrincipalId,
    ReceiptId, RecipientPublicKey1216, RecoveryId, RequestId, ResponseId, RevisionSealId,
    RotationId, ShareCiphertext49, Signature64, SlotId, VaultId, VerificationPublicKey32,
    WitnessPolicyId,
};

pub const SUITE: u16 = 1;
pub const PROTOCOL_VERSION: u16 = 1;
pub const CONSTRUCTION: u16 = 1;
pub const MAX_POLICY_ACTORS: usize = 32;
pub const MAX_RECORDED_APPROVALS: usize = MAX_POLICY_ACTORS * 2;
pub const MAX_MANIFEST_TARGETS: usize = 64;
pub const MAX_ARGUMENTS: usize = 128;
pub const MAX_ENVIRONMENT_NAMES: usize = 64;
pub const MAX_REQUEST_LIFETIME_MS: u64 = 900_000;
pub const ACCEPTED_CLOCK_SKEW_MS: u64 = 60_000;
pub const REPLAY_RETENTION_MS: u64 = 86_400_000;
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_PRESENTATION_BYTES: usize = 64 * 1024;
pub const MAX_PUBLIC_REVIEW_LABEL_BYTES: usize = 256;
pub const MAX_APPROVAL_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_RECEIPT_JSON_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_ROTATION_ITEMS: usize = 10_000;
pub const MAX_REPLAY_RECORDS_PER_VAULT: usize = 65_536;
pub const MAX_REPLAY_RECORDS_PER_SERVICE: usize = 1_048_576;

pub type OperationBytes = BoundedBytes<4096>;
pub type ManifestBytes = BoundedBytes<MAX_MANIFEST_BYTES>;
pub type PresentationDisplayBytes = BoundedBytes<MAX_PRESENTATION_BYTES>;
pub type ReviewLabelBytes = BoundedBytes<MAX_PUBLIC_REVIEW_LABEL_BYTES>;
pub type RequestBytes = BoundedBytes<MAX_REQUEST_BYTES>;
pub type ApprovalBytes = BoundedBytes<MAX_APPROVAL_BYTES>;
pub type ResponseBytes = BoundedBytes<MAX_RESPONSE_BYTES>;
pub type CancellationBytes = BoundedBytes<{ 48 * 1024 }>;
pub type RegistrationBytes = BoundedBytes<{ 64 * 1024 }>;
pub type PolicyMaterialBytes = BoundedBytes<{ 16 * 1024 * 1024 }>;
pub type WitnessDescriptorBytes = BoundedBytes<4096>;

include!("witness_v1/base.rs");
include!("witness_v1/presentation.rs");
include!("witness_v1/request.rs");
include!("witness_v1/decision.rs");
include!("witness_v1/state_and_rotation.rs");
include!("witness_v1/receipt.rs");
include!("witness_v1/encoding.rs");

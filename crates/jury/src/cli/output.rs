use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutput {
    IdentityCreated {
        identity: String,
        principal_id: String,
        fingerprint: String,
        kind: &'static str,
        kdf_profile: &'static str,
        protection_degraded: bool,
        durability: &'static str,
    },
    IdentityStatus {
        identity: String,
        principal_id: String,
        fingerprint: String,
        kind: &'static str,
        kdf_profile: &'static str,
        memory_kib: u32,
        passes: u32,
        lanes: u32,
        stronger_profile_available: bool,
    },
    IdentityList {
        identities: Vec<IdentitySummary>,
    },
    IdentityPassphraseChanged {
        identity: String,
        principal_id: String,
        fingerprint: String,
        kdf_profile: &'static str,
        protection_degraded: bool,
        durability: &'static str,
    },
    VaultCreated {
        home_source: &'static str,
        vault_id: String,
        genesis_fingerprint: String,
        owner_principal_id: String,
        local_state: &'static str,
        durability: &'static str,
    },
    VaultStatus {
        operation: &'static str,
        home_source: &'static str,
        format_version: u16,
        suite: u16,
        vault_id: String,
        genesis_fingerprint: String,
        policy_sequence: u64,
        current_revision: String,
        principal_count: usize,
        owner_count: usize,
        item_count: usize,
        tombstone_count: usize,
        item_revision_proof_count: usize,
        artifact_bytes: usize,
    },
    AuditVerified {
        vault_id: String,
        principal_id: String,
        event_count: usize,
        latest_mac: String,
        audit_events_after_checkpoint: usize,
    },
    Mutation {
        operation: &'static str,
        item: Option<String>,
        item_id: Option<String>,
        previous_revision: String,
        current_revision: String,
        dry_run: bool,
        committed: bool,
        local_recovery_required: bool,
        redistribution_recommended: bool,
        pending_requests_invalidated: bool,
        item_quorum_claim_suppressed: bool,
        warnings: Vec<&'static str>,
    },
    FieldList {
        fields: Vec<FieldSummary>,
    },
    PrivateOutput {
        operation: &'static str,
        item: Option<String>,
        field: Option<String>,
        sink: &'static str,
        durability: Option<&'static str>,
    },
    Execution {
        operation: &'static str,
        manifest_digest: String,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        stdout_truncated: bool,
        stderr_truncated: bool,
        streamed: bool,
        protection_degraded: bool,
        local_audit_recorded: bool,
    },
    Silent,
    Safe {
        operation: &'static str,
        fields: serde_json::Value,
        lines: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySummary {
    pub(super) name: String,
    pub(super) principal_id: String,
    pub(super) fingerprint: String,
    pub(super) kind: &'static str,
    pub(super) kdf_profile: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldSummary {
    pub(super) item: String,
    pub(super) item_id: String,
    pub(super) field: String,
    pub(super) kind: &'static str,
    pub(super) updated_at_ms: u64,
}

impl CommandOutput {
    pub fn write(&self, json: bool) {
        if matches!(self, Self::Silent | Self::Execution { streamed: true, .. }) {
            return;
        }
        if json {
            println!("{}", self.json_value());
        } else {
            self.write_human();
        }
    }

    fn json_value(&self) -> serde_json::Value {
        match self {
            Self::IdentityCreated {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                protection_degraded,
                durability,
            } => serde_json::json!({
                "ok": true,
                "operation": "identity-init",
                "identity": identity,
                "principal_id": principal_id,
                "fingerprint": fingerprint,
                "kind": kind,
                "kdf_profile": kdf_profile,
                "protection_degraded": protection_degraded,
                "durability": durability,
                "maturity": "pre-alpha"
            }),
            Self::IdentityStatus {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                memory_kib,
                passes,
                lanes,
                stronger_profile_available,
            } => serde_json::json!({
                "ok": true,
                "operation": "identity-status",
                "identity": identity,
                "principal_id": principal_id,
                "fingerprint": fingerprint,
                "kind": kind,
                "kdf_profile": kdf_profile,
                "memory_kib": memory_kib,
                "passes": passes,
                "lanes": lanes,
                "stronger_profile_available": stronger_profile_available,
                "public_fields_authenticated": false,
                "private_payload_verified": false,
                "protection_mode": "portable",
                "maturity": "pre-alpha"
            }),
            Self::IdentityList { identities } => serde_json::json!({
                "ok": true,
                "operation": "identity-list",
                "count": identities.len(),
                "identities": identities
                    .iter()
                    .map(|identity| serde_json::json!({
                        "name": identity.name,
                        "principal_id": identity.principal_id,
                        "fingerprint": identity.fingerprint,
                        "kind": identity.kind,
                        "kdf_profile": identity.kdf_profile,
                        "public_fields_authenticated": false,
                        "private_payload_verified": false
                    }))
                    .collect::<Vec<_>>(),
                "maturity": "pre-alpha"
            }),
            Self::IdentityPassphraseChanged {
                identity,
                principal_id,
                fingerprint,
                kdf_profile,
                protection_degraded,
                durability,
            } => serde_json::json!({
                "ok": true,
                "operation": "identity-passphrase-change",
                "identity": identity,
                "principal_id": principal_id,
                "fingerprint": fingerprint,
                "kdf_profile": kdf_profile,
                "principal_keys_changed": false,
                "protection_degraded": protection_degraded,
                "durability": durability,
                "maturity": "pre-alpha"
            }),
            Self::VaultCreated {
                home_source,
                vault_id,
                genesis_fingerprint,
                owner_principal_id,
                local_state,
                durability,
            } => serde_json::json!({
                "ok": true,
                "operation": "vault-init",
                "home_source": home_source,
                "vault_id": vault_id,
                "genesis_fingerprint": genesis_fingerprint,
                "owner_principal_id": owner_principal_id,
                "policy_sequence": 0,
                "item_count": 0,
                "local_state": local_state,
                "durability": durability,
                "backup_required": true,
                "maturity": "pre-alpha"
            }),
            Self::VaultStatus {
                operation,
                home_source,
                format_version,
                suite,
                vault_id,
                genesis_fingerprint,
                policy_sequence,
                current_revision,
                principal_count,
                owner_count,
                item_count,
                tombstone_count,
                item_revision_proof_count,
                artifact_bytes,
            } => serde_json::json!({
                "ok": true,
                "operation": operation,
                "home_source": home_source,
                "format_version": format_version,
                "suite_id": suite,
                "vault_id": vault_id,
                "genesis_fingerprint": genesis_fingerprint,
                "policy_sequence": policy_sequence,
                "current_revision": current_revision,
                "principal_count": principal_count,
                "owner_count": owner_count,
                "item_count": item_count,
                "tombstone_count": tombstone_count,
                "artifact_bytes": artifact_bytes,
                "capacity": {
                    "artifact_bytes": {"used": artifact_bytes, "maximum": MAX_VAULT_BYTES},
                    "policy_revisions": {"used": policy_sequence, "maximum": MAX_POLICY_REVISIONS},
                    "item_revision_proofs": {
                        "used": item_revision_proof_count,
                        "maximum": MAX_ITEM_REVISION_PROOFS
                    },
                    "items": {"used": item_count, "maximum": MAX_ITEMS},
                    "mutation_possible": *artifact_bytes < MAX_VAULT_BYTES
                        && *policy_sequence < MAX_POLICY_REVISIONS as u64
                        && *item_revision_proof_count < MAX_ITEM_REVISION_PROOFS
                },
                "cryptographic_scopes": true,
                "public_validation": "valid",
                "identity_unlocked": false,
                "maturity": "pre-alpha"
            }),
            Self::AuditVerified {
                vault_id,
                principal_id,
                event_count,
                latest_mac,
                audit_events_after_checkpoint,
            } => serde_json::json!({
                "ok": true,
                "operation": "vault-audit-verify",
                "vault_id": vault_id,
                "principal_id": principal_id,
                "evidence": "current-jury-v1-local",
                "event_count": event_count,
                "latest_mac": latest_mac,
                "audit_events_after_checkpoint": audit_events_after_checkpoint,
                "local_activity_only": true,
                "other_principals_verified": false,
                "remote_freshness_verified": false,
                "maturity": "pre-alpha"
            }),
            Self::Mutation {
                operation,
                item,
                item_id,
                previous_revision,
                current_revision,
                dry_run,
                committed,
                local_recovery_required,
                redistribution_recommended,
                pending_requests_invalidated,
                item_quorum_claim_suppressed,
                warnings,
            } => serde_json::json!({
                "ok": true,
                "operation": operation,
                "item": item,
                "item_id": item_id,
                "previous_revision": previous_revision,
                "current_revision": current_revision,
                "dry_run": dry_run,
                "vault_changed": committed,
                "committed": committed,
                "local_recovery_required": local_recovery_required,
                "redistribution_recommended": redistribution_recommended,
                "pending_requests_invalidated": pending_requests_invalidated,
                "item_quorum_claim_suppressed": item_quorum_claim_suppressed,
                "warnings": warnings,
                "delivery_claimed": false,
                "maturity": "pre-alpha"
            }),
            Self::FieldList { fields } => serde_json::json!({
                "ok": true,
                "operation": "field-list",
                "count": fields.len(),
                "fields": fields.iter().map(|field| serde_json::json!({
                    "item": field.item,
                    "item_id": field.item_id,
                    "field": field.field,
                    "kind": field.kind,
                    "updated_at_ms": field.updated_at_ms
                })).collect::<Vec<_>>(),
                "inaccessible_items_disclosed": false,
                "maturity": "pre-alpha"
            }),
            Self::PrivateOutput {
                operation,
                item,
                field,
                sink,
                durability,
            } => serde_json::json!({
                "ok": true,
                "operation": operation,
                "item": item,
                "field": field,
                "sink": sink,
                "durability": durability,
                "plaintext_in_structured_output": false,
                "maturity": "pre-alpha"
            }),
            Self::Execution {
                operation,
                manifest_digest,
                exit_code,
                exit_signal,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                streamed,
                protection_degraded,
                local_audit_recorded,
            } => serde_json::json!({
                "ok": exit_code == &Some(0) && exit_signal.is_none(),
                "operation": operation,
                "manifest_digest": manifest_digest,
                "exit_code": exit_code,
                "exit_signal": exit_signal,
                "stdout": String::from_utf8_lossy(stdout),
                "stderr": String::from_utf8_lossy(stderr),
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "streamed": streamed,
                "output_encoding": "utf8-lossy",
                "protection_degraded": protection_degraded,
                "local_audit_recorded": local_audit_recorded,
                "authorized_child_may_retain_plaintext": true,
                "maturity": "pre-alpha"
            }),
            Self::Silent => serde_json::json!({
                "ok": true,
                "operation": "private-output",
                "plaintext_in_structured_output": false,
                "maturity": "pre-alpha"
            }),
            Self::Safe {
                operation, fields, ..
            } => {
                let mut object = fields.as_object().cloned().unwrap_or_default();
                object.insert("ok".to_owned(), serde_json::Value::Bool(true));
                object.insert(
                    "operation".to_owned(),
                    serde_json::Value::String((*operation).to_owned()),
                );
                object.insert(
                    "maturity".to_owned(),
                    serde_json::Value::String("pre-alpha".to_owned()),
                );
                serde_json::Value::Object(object)
            }
        }
    }

    fn write_human(&self) {
        println!("{PRE_ALPHA_WARNING}");
        match self {
            Self::IdentityCreated {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                protection_degraded,
                durability,
            } => {
                println!("Identity created: {identity}");
                println!("Principal: {principal_id}");
                println!("Fingerprint: {}", grouped(fingerprint));
                println!("Kind: {kind}");
                println!("KDF profile: {kdf_profile}");
                println!("Protection degraded: {protection_degraded}");
                println!("Durability: {durability}");
            }
            Self::IdentityStatus {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                memory_kib,
                passes,
                lanes,
                stronger_profile_available,
            } => {
                println!("Identity: {identity}");
                println!("Principal: {principal_id}");
                println!("Fingerprint: {}", grouped(fingerprint));
                println!("Kind: {kind}");
                println!("KDF: {kdf_profile}; {memory_kib} KiB; {passes} passes; {lanes} lanes");
                println!("Stronger profile available: {stronger_profile_available}");
                println!("Public fields authenticated: false (unlock not performed)");
            }
            Self::IdentityList { identities } => {
                println!("Named identities: {}", identities.len());
                for identity in identities {
                    println!(
                        "{}: {} {} {} ({})",
                        identity.name,
                        identity.kind,
                        identity.principal_id,
                        grouped(&identity.fingerprint),
                        identity.kdf_profile
                    );
                }
                println!("Public fields authenticated: false (unlock not performed)");
            }
            Self::IdentityPassphraseChanged {
                identity,
                principal_id,
                fingerprint,
                kdf_profile,
                protection_degraded,
                durability,
            } => {
                println!("Identity passphrase changed: {identity}");
                println!("Principal: {principal_id}");
                println!("Fingerprint: {}", grouped(fingerprint));
                println!("KDF profile: {kdf_profile}");
                println!("Principal keys changed: false");
                println!("Protection degraded: {protection_degraded}");
                println!("Durability: {durability}");
            }
            Self::VaultCreated {
                home_source,
                vault_id,
                genesis_fingerprint,
                owner_principal_id,
                local_state,
                durability,
            } => {
                println!("Vault created ({home_source})");
                println!("Vault ID: {vault_id}");
                println!("Genesis fingerprint: {}", grouped(genesis_fingerprint));
                println!("Owner principal: {owner_principal_id}");
                println!("Local state: {local_state}");
                println!("Durability: {durability}");
                println!("Create an owner backup before storing any real data.");
            }
            Self::VaultStatus {
                operation,
                home_source,
                format_version,
                suite,
                vault_id,
                genesis_fingerprint,
                policy_sequence,
                current_revision,
                principal_count,
                owner_count,
                item_count,
                tombstone_count,
                item_revision_proof_count,
                artifact_bytes,
            } => {
                println!(
                    "{}: valid public state ({home_source})",
                    operation.replace('-', " ")
                );
                println!("Format: {format_version}; suite: {suite}");
                println!("Vault ID: {vault_id}");
                println!("Genesis fingerprint: {}", grouped(genesis_fingerprint));
                println!("Policy sequence: {policy_sequence}");
                println!("Current revision: {}", grouped(current_revision));
                println!(
                    "Principals: {principal_count}; owners: {owner_count}; items: {item_count}; tombstones: {tombstone_count}"
                );
                println!("Capacity: {artifact_bytes}/{MAX_VAULT_BYTES} artifact bytes");
                println!("Item proofs: {item_revision_proof_count}/{MAX_ITEM_REVISION_PROOFS}");
                println!("Cryptographic scopes: true");
                println!("Identity unlocked: false");
            }
            Self::AuditVerified {
                vault_id,
                principal_id,
                event_count,
                latest_mac,
                audit_events_after_checkpoint,
            } => {
                println!("Local Jury v1 audit evidence verified");
                println!("Vault ID: {vault_id}");
                println!("Principal: {principal_id}");
                println!("Events: {event_count}");
                println!("Latest MAC: {}", grouped(latest_mac));
                println!("Events after checkpoint: {audit_events_after_checkpoint}");
                println!(
                    "This verifies local activity only, not other principals or remote freshness."
                );
            }
            Self::Mutation {
                operation,
                item,
                item_id,
                previous_revision,
                current_revision,
                dry_run,
                committed,
                local_recovery_required,
                redistribution_recommended,
                pending_requests_invalidated,
                item_quorum_claim_suppressed,
                warnings,
            } => {
                println!("Operation: {operation}");
                if let Some(item) = item {
                    println!("Item: {item}");
                }
                if let Some(item_id) = item_id {
                    println!("Item ID: {item_id}");
                }
                println!("Previous revision: {}", grouped(previous_revision));
                println!("Current revision: {}", grouped(current_revision));
                println!("Dry run: {dry_run}");
                println!("Local vault changed: {committed}");
                println!("Local recovery required: {local_recovery_required}");
                println!("Redistribution recommended: {redistribution_recommended}");
                println!("Pending witnessed requests invalidated: {pending_requests_invalidated}");
                println!("Item quorum claim suppressed: {item_quorum_claim_suppressed}");
                for warning in warnings {
                    println!("Warning: {warning}");
                }
                println!("No delivery to another recipient is claimed.");
            }
            Self::FieldList { fields } => {
                println!("Accessible fields: {}", fields.len());
                for field in fields {
                    println!(
                        "{}.{} ({}, updated {})",
                        field.item, field.field, field.kind, field.updated_at_ms
                    );
                }
            }
            Self::PrivateOutput {
                operation,
                item,
                field,
                sink,
                durability,
            } => {
                println!("Operation: {operation}");
                if let Some(item) = item {
                    println!("Item: {item}");
                }
                if let Some(field) = field {
                    println!("Field: {field}");
                }
                println!("Private sink: {sink}");
                if let Some(durability) = durability {
                    println!("Durability: {durability}");
                }
            }
            Self::Execution {
                operation,
                manifest_digest,
                exit_code,
                exit_signal,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                protection_degraded,
                local_audit_recorded,
                ..
            } => {
                println!("Operation: {operation}");
                println!("Manifest digest: {}", grouped(manifest_digest));
                println!("Exit code: {exit_code:?}; signal: {exit_signal:?}");
                println!("Stdout truncated: {stdout_truncated}");
                println!("Stderr truncated: {stderr_truncated}");
                println!("Stdout: {}", String::from_utf8_lossy(stdout));
                println!("Stderr: {}", String::from_utf8_lossy(stderr));
                println!("Protection degraded: {protection_degraded}");
                println!("Local audit recorded: {local_audit_recorded}");
                println!("An authorized child may retain plaintext.");
            }
            Self::Silent => {}
            Self::Safe { lines, .. } => {
                for line in lines {
                    println!("{line}");
                }
            }
        }
    }

    #[must_use]
    pub fn exit_code(&self) -> u8 {
        let Self::Execution {
            exit_code,
            exit_signal,
            ..
        } = self
        else {
            return 0;
        };
        let portable =
            exit_code.unwrap_or_else(|| 128_i32.saturating_add(exit_signal.unwrap_or(0)));
        u8::try_from(portable).unwrap_or(1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliErrorKind {
    InvalidArguments,
    UnsupportedPlatform,
    NotFound,
    Conflict,
    InvalidIdentity,
    AuthenticationFailed,
    AccessDenied,
    InvalidVault,
    ProtectionUnavailable,
    Filesystem,
    LocalState,
    Process,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CliError {
    kind: CliErrorKind,
    code: &'static str,
    message: &'static str,
}

impl CliError {
    pub(super) const fn new(kind: CliErrorKind, code: &'static str, message: &'static str) -> Self {
        Self {
            kind,
            code,
            message,
        }
    }

    pub(super) const fn kind(self) -> CliErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self.kind {
            CliErrorKind::InvalidArguments | CliErrorKind::UnsupportedPlatform => 2,
            CliErrorKind::NotFound => 3,
            CliErrorKind::Conflict => 4,
            CliErrorKind::AuthenticationFailed => 5,
            CliErrorKind::AccessDenied => 6,
            CliErrorKind::InvalidIdentity
            | CliErrorKind::InvalidVault
            | CliErrorKind::ProtectionUnavailable
            | CliErrorKind::Filesystem
            | CliErrorKind::LocalState
            | CliErrorKind::Process => 1,
        }
    }

    pub fn write(self, json: bool) {
        if json {
            eprintln!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "error": {"code": self.code, "message": self.message},
                    "maturity": "pre-alpha"
                })
            );
        } else {
            eprintln!("jury: {} ({})", self.message, self.code);
        }
    }
}

impl fmt::Debug for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliError")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CliError {}

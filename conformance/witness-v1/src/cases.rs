use super::*;

pub fn protocol_case_result(case: &Value) -> &'static str {
    if case["kind"] == "owner-change" {
        return owner_change_case_result(case);
    }

    if case["kind"] == "global-checkpoint" {
        return checkpoint_case_result(case);
    }
    if case["known_version"].as_bool() != Some(true)
        || case["known_suite"].as_bool() != Some(true)
        || case["known_construction"].as_bool() != Some(true)
    {
        "unsupported-version"
    } else if case["within_bounds"].as_bool() != Some(true)
        || case["canonical"].as_bool() != Some(true)
    {
        "invalid"
    } else if case["signature_valid"].as_bool() != Some(true)
        || case["domain_valid"].as_bool() != Some(true)
    {
        "invalid-signature"
    } else if case["scope_equal"].as_bool() != Some(true) {
        "wrong-scope"
    } else if case["policy_current"].as_bool() != Some(true) {
        "stale-policy"
    } else if case["revision_current"].as_bool() != Some(true) {
        "wrong-scope"
    } else if case["time_valid"].as_bool() != Some(true) {
        "expired"
    } else if case["replay_consistent"].as_bool() != Some(true) {
        "replay-conflict"
    } else if case["actors_unique"].as_bool() != Some(true) {
        "invalid"
    } else if case["quorum_reached"].as_bool() != Some(true) {
        "insufficient-quorum"
    } else if case["anchor_consistent"].as_bool() != Some(true) {
        "anchor-conflict"
    } else if case["restored_state_safe"].as_bool() != Some(true) {
        "restored-state-unsafe"
    } else if case["explicit_witnessed_path"].as_bool() != Some(true) {
        "direct-downgrade"
    } else {
        "accepted"
    }
}

pub(super) fn protocol_case(name: &str, changed: Option<(&str, bool)>, expected: &str) -> Value {
    let mut case = json!({
        "name": name,
        "known_version": true,
        "known_suite": true,
        "known_construction": true,
        "within_bounds": true,
        "canonical": true,
        "signature_valid": true,
        "domain_valid": true,
        "scope_equal": true,
        "policy_current": true,
        "revision_current": true,
        "time_valid": true,
        "replay_consistent": true,
        "actors_unique": true,
        "quorum_reached": true,
        "anchor_consistent": true,
        "restored_state_safe": true,
        "explicit_witnessed_path": true,
        "expected": expected
    });
    if let Some((field, value)) = changed {
        case[field] = Value::Bool(value);
    }
    case
}

pub(super) fn build_scope_cases() -> Value {
    let request = make_scope("base");
    let mut cases = vec![json!({
        "name": "exact-equality",
        "request": request,
        "manifest": make_scope("base"),
        "request_signature_valid": true,
        "manifest_digest_valid": true,
        "expected": "accepted"
    })];
    for field in make_scope("base").keys() {
        let request = make_scope("base");
        let mut manifest = make_scope("base");
        manifest.insert(field.clone(), format!("mutated:{field}"));
        cases.push(json!({
            "name": format!("mismatch-{field}"),
            "mutated_field": field,
            "request": request,
            "manifest": manifest,
            "request_signature_valid": true,
            "manifest_digest_valid": true,
            "expected": "wrong-scope"
        }));
    }
    Value::Array(cases)
}

pub(super) fn build_presentation_cases() -> Value {
    let base = json!({
        "human": true,
        "empty_presentation": false,
        "complete": true,
        "digest_match": true,
        "lossless": true,
        "untruncated": true,
        "meaningful": true,
        "label_signature_valid": true,
        "label_current": true,
        "subject_binding_valid": true,
        "entitled": true
    });
    let mut cases = Vec::new();
    let mut positive = base.clone();
    positive["name"] = json!("human-complete");
    positive["expected"] = json!("accepted");
    cases.push(positive);
    for (name, field) in [
        ("missing", "complete"),
        ("digest-mismatched", "digest_match"),
        ("lossy", "lossless"),
        ("truncated", "untruncated"),
        ("opaque", "meaningful"),
        ("forged-label", "label_signature_valid"),
        ("stale-label", "label_current"),
        ("wrong-binding", "subject_binding_valid"),
        ("absent-entitlement", "entitled"),
    ] {
        let mut case = base.clone();
        case["name"] = json!(name);
        case[field] = Value::Bool(false);
        case["expected"] = json!("wrong-scope");
        cases.push(case);
    }
    let descriptor =
        json!({"item_id": "ExampleItem", "content_role": "descriptor", "field_id": null});
    let field =
        json!({"item_id": "ExampleItem", "content_role": "body", "field_id": "ExampleField"});
    let whole_body = json!({"item_id": "ExampleItem", "content_role": "body", "field_id": null});
    let other_field =
        json!({"item_id": "ExampleItem", "content_role": "body", "field_id": "ExampleOtherField"});
    let legacy = json!({"item_id": "ExampleItem", "field_id": null});
    for (name, allowed, requested, expected) in [
        (
            "automatic-exact-field",
            vec![field.clone()],
            vec![field.clone()],
            "accepted",
        ),
        (
            "automatic-exact-descriptor",
            vec![descriptor.clone()],
            vec![descriptor.clone()],
            "accepted",
        ),
        (
            "automatic-explicit-field-and-descriptor",
            vec![descriptor.clone(), field.clone()],
            vec![descriptor.clone()],
            "accepted",
        ),
        (
            "automatic-descriptor-cannot-read-body",
            vec![descriptor.clone()],
            vec![whole_body.clone()],
            "policy-denied",
        ),
        (
            "automatic-field-cannot-read-descriptor",
            vec![field.clone()],
            vec![descriptor.clone()],
            "policy-denied",
        ),
        (
            "automatic-field-cannot-read-other-field",
            vec![field.clone()],
            vec![other_field],
            "policy-denied",
        ),
        (
            "automatic-whole-body-rule-invalid",
            vec![whole_body.clone()],
            vec![whole_body],
            "policy-denied",
        ),
        (
            "automatic-old-role-implicit-rule-invalid",
            vec![legacy.clone()],
            vec![legacy],
            "policy-denied",
        ),
        (
            "automatic-empty-request-invalid",
            vec![descriptor],
            vec![],
            "policy-denied",
        ),
    ] {
        cases.push(
            json!({"name": name, "human": false, "automatic_targets": allowed,
            "manifest_targets": requested, "empty_presentation": true, "expected": expected}),
        );
    }
    Value::Array(cases)
}

pub(super) fn digest_list(value: &Value) -> Option<Vec<Vec<u8>>> {
    value
        .as_array()?
        .iter()
        .map(|v| {
            let bytes = hex::decode(v.as_str()?).ok()?;
            (bytes.len() == 32 && bytes.iter().any(|b| *b != 0)).then_some(bytes)
        })
        .collect()
}

pub(super) fn checkpoint_case_result(case: &Value) -> &'static str {
    let (Some(mut active), Some(committed), Some(member)) = (
        digest_list(&case["active_slot_policies"]),
        digest_list(&case["checkpoint_policy_digests"]),
        digest_list(&case["witness_policy_digests"]),
    ) else {
        return "invalid";
    };
    if committed.len() > 16_384 || committed.windows(2).any(|pair| pair[0] >= pair[1]) {
        return "invalid";
    }
    active.sort();
    active.dedup();
    if active != committed {
        return "checkpoint-fork";
    }
    match case["operation"].as_str() {
        Some("register") => {
            if active.iter().any(|d| member.contains(d)) {
                "accepted"
            } else {
                "policy-denied"
            }
        }
        Some("request") => {
            let Some(selected) = case["selected_policy_digest"]
                .as_str()
                .and_then(|v| hex::decode(v).ok())
            else {
                return "invalid";
            };
            if case["selected_policy_digest"] != case["slot_policy_digest"]
                || !active.contains(&selected)
            {
                "wrong-scope"
            } else if !member.contains(&selected) {
                "policy-denied"
            } else {
                "accepted"
            }
        }
        Some("advance") => {
            let old = &case["current"];
            let next = &case["candidate"];
            let (Some(old_sequence), Some(next_sequence), Some(old_time), Some(next_time)) = (
                old["sequence"].as_u64(),
                next["sequence"].as_u64(),
                old["issued_at_ms"].as_u64(),
                next["issued_at_ms"].as_u64(),
            ) else {
                return "invalid";
            };
            if old == next {
                "accepted"
            } else if next_sequence < old_sequence {
                "stale-policy"
            } else if next_sequence == old_sequence {
                "checkpoint-fork"
            } else if old_sequence.checked_add(1) != Some(next_sequence) {
                "witness-behind"
            } else if next["predecessor_digest"] != old["digest"] || next_time <= old_time {
                "checkpoint-fork"
            } else {
                "accepted"
            }
        }
        _ => "invalid",
    }
}

pub(super) fn owner_change_case_result(case: &Value) -> &'static str {
    let (Some(current), Some(next), Some(owners), Some(principals)) = (
        case["current_sequence"].as_u64(),
        case["next_sequence"].as_u64(),
        case["owners"].as_array(),
        case["principals"].as_array(),
    ) else {
        return "invalid";
    };
    if !matches!(case["change"].as_str(), Some("grant" | "revoke")) {
        return "invalid";
    }
    if case["operation"] != "administrative-rekey"
        || !matches!(case["content_role"].as_str(), Some("descriptor" | "body"))
        || case["field_id"] != Value::Null
        || case["target_item_id"] != case["item_id"]
        || case["output_sink"] != "none"
    {
        return "wrong-scope";
    }
    if current.checked_add(1) != Some(next) {
        return "wrong-scope";
    }
    if !owners.contains(&case["requester"])
        || !principals
            .iter()
            .any(|p| p["id"] == case["target"] && p["kind"] == "human")
    {
        return "policy-denied";
    }
    let target_is_owner = owners.contains(&case["target"]);
    if (case["change"] == "grant" && target_is_owner)
        || (case["change"] == "revoke"
            && (!target_is_owner || owners.len() <= 1 || case["requester"] == case["target"]))
    {
        return "policy-denied";
    }
    "accepted"
}

pub(super) fn build_owner_change_cases() -> Vec<Value> {
    let owner = hex_bytes(&id(0x09));
    let other = hex_bytes(&id(0x70));
    let target = hex_bytes(&id(0x71));
    let machine = hex_bytes(&id(0x72));
    let item = hex_bytes(&id(0x03));
    let base = json!({"kind":"owner-change", "operation":"administrative-rekey", "change":"grant",
        "requester":owner, "target":target, "owners":[owner,other],
        "principals":[{"id":owner,"kind":"human"},{"id":other,"kind":"human"},
            {"id":target,"kind":"human"},{"id":machine,"kind":"machine"}],
        "current_sequence":7, "next_sequence":8, "content_role":"body", "field_id":null,
        "item_id":item,"target_item_id":item,"output_sink":"none"});
    let mut cases = Vec::new();
    let mut add = |name: &str, changes: Value, expected: &str| {
        let mut case = base.clone();
        if let Some(changes) = changes.as_object() {
            for (key, value) in changes {
                case[key] = value.clone();
            }
        }
        case["name"] = json!(format!("owner-change-{name}"));
        case["expected"] = json!(expected);
        cases.push(case);
    };
    add("grant-body", json!({}), "accepted");
    add(
        "grant-descriptor",
        json!({"content_role":"descriptor"}),
        "accepted",
    );
    add(
        "revoke-owner",
        json!({"change":"revoke","target":other}),
        "accepted",
    );
    add(
        "grant-existing-owner",
        json!({"target":other}),
        "policy-denied",
    );
    add(
        "revoke-nonowner",
        json!({"change":"revoke"}),
        "policy-denied",
    );
    add(
        "self-revoke",
        json!({"change":"revoke","target":owner}),
        "policy-denied",
    );
    add(
        "last-owner",
        json!({"change":"revoke","target":owner,"owners":[owner]}),
        "policy-denied",
    );
    add(
        "unknown-principal",
        json!({"target":hex_bytes(&id(0x73))}),
        "policy-denied",
    );
    add(
        "machine-principal",
        json!({"target":machine}),
        "policy-denied",
    );
    add(
        "requester-not-owner",
        json!({"requester":target}),
        "policy-denied",
    );
    add("sequence-gap", json!({"next_sequence":9}), "wrong-scope");
    add(
        "sequence-overflow",
        json!({"current_sequence":u64::MAX,"next_sequence":0}),
        "wrong-scope",
    );
    add(
        "field-target",
        json!({"field_id":hex_bytes(&id(0x74))}),
        "wrong-scope",
    );
    add(
        "another-item",
        json!({"target_item_id":hex_bytes(&id(0x75))}),
        "wrong-scope",
    );
    add(
        "plaintext-sink",
        json!({"output_sink":"stdout"}),
        "wrong-scope",
    );
    add("unknown-change", json!({"change":"replace"}), "invalid");
    cases
}

pub(super) fn build_checkpoint_cases() -> Vec<Value> {
    let a = hex_bytes(&id(0xe1));
    let b = hex_bytes(&id(0xe2));
    let c = hex_bytes(&id(0xe3));
    let current = json!({"sequence":7,"digest":hex_bytes(&id(0xc1)),"predecessor_digest":hex_bytes(&id(0xc0)),"issued_at_ms":100});
    let base = json!({"kind":"global-checkpoint","operation":"request",
        "active_slot_policies":[a,b],"checkpoint_policy_digests":[a,b],
        "witness_policy_digests":[a,b],"selected_policy_digest":a,"slot_policy_digest":a,
        "current":current,"candidate":current});
    let mut cases = Vec::new();
    let mut add = |name: &str, changes: Value, expected: &str| {
        let mut case = base.clone();
        if let Some(changes) = changes.as_object() {
            for (key, value) in changes {
                case[key] = value.clone();
            }
        }
        case["name"] = json!(format!("global-checkpoint-{name}"));
        case["expected"] = json!(expected);
        cases.push(case);
    };
    add("first-policy", json!({}), "accepted");
    add(
        "second-policy-same-checkpoint",
        json!({"selected_policy_digest":b,"slot_policy_digest":b}),
        "accepted",
    );
    add(
        "shared-policy-deduplicated",
        json!({"active_slot_policies":[a,a,b]}),
        "accepted",
    );
    add(
        "historical-extra-policy",
        json!({"checkpoint_policy_digests":[a,b,c]}),
        "checkpoint-fork",
    );
    add(
        "omitted-active-policy",
        json!({"checkpoint_policy_digests":[a]}),
        "checkpoint-fork",
    );
    add(
        "unsorted-set",
        json!({"checkpoint_policy_digests":[b,a]}),
        "invalid",
    );
    add(
        "duplicate-set",
        json!({"checkpoint_policy_digests":[a,a,b]}),
        "invalid",
    );
    add(
        "zero-digest",
        json!({"checkpoint_policy_digests":[hex_bytes(&fixed(0,32)),a,b]}),
        "invalid",
    );
    add(
        "uncommitted-request-policy",
        json!({"selected_policy_digest":c,"slot_policy_digest":c}),
        "wrong-scope",
    );
    add(
        "wrong-slot-policy",
        json!({"selected_policy_digest":b}),
        "wrong-scope",
    );
    add(
        "other-policy-membership-is-not-authority",
        json!({"witness_policy_digests":[b]}),
        "policy-denied",
    );
    add(
        "registration-any-active-policy",
        json!({"operation":"register","witness_policy_digests":[b]}),
        "accepted",
    );
    add(
        "registration-historical-policy",
        json!({"operation":"register","witness_policy_digests":[c]}),
        "policy-denied",
    );
    add(
        "registration-empty-set",
        json!({"operation":"register","active_slot_policies":[],"checkpoint_policy_digests":[],"witness_policy_digests":[]}),
        "policy-denied",
    );
    add(
        "identical-checkpoint",
        json!({"operation":"advance"}),
        "accepted",
    );
    let successor = json!({"sequence":8,"digest":hex_bytes(&id(0xc2)),"predecessor_digest":hex_bytes(&id(0xc1)),"issued_at_ms":101});
    add(
        "strict-successor",
        json!({"operation":"advance","candidate":successor}),
        "accepted",
    );
    add(
        "remove-last-policy",
        json!({"operation":"advance","candidate":successor,"active_slot_policies":[],"checkpoint_policy_digests":[]}),
        "accepted",
    );
    let mut gap = successor.clone();
    gap["sequence"] = json!(9);
    add(
        "sequence-gap",
        json!({"operation":"advance","candidate":gap}),
        "witness-behind",
    );
    let mut old = successor.clone();
    old["sequence"] = json!(6);
    add(
        "rollback",
        json!({"operation":"advance","candidate":old}),
        "stale-policy",
    );
    let mut fork = successor.clone();
    fork["sequence"] = json!(7);
    add(
        "same-sequence-fork",
        json!({"operation":"advance","candidate":fork}),
        "checkpoint-fork",
    );
    let mut predecessor = successor.clone();
    predecessor["predecessor_digest"] = json!(hex_bytes(&id(0xca)));
    add(
        "wrong-predecessor",
        json!({"operation":"advance","candidate":predecessor}),
        "checkpoint-fork",
    );
    let mut clock = successor;
    clock["issued_at_ms"] = json!(100);
    add(
        "non-increasing-issuance",
        json!({"operation":"advance","candidate":clock}),
        "checkpoint-fork",
    );
    cases
}

pub(super) fn build_protocol_cases() -> Value {
    let mut cases = vec![
        protocol_case("accepted", None, "accepted"),
        protocol_case("identical-replay-idempotent", None, "accepted"),
        protocol_case("identical-duplicate-actor-counts-once", None, "accepted"),
        protocol_case(
            "unknown-version",
            Some(("known_version", false)),
            "unsupported-version",
        ),
        protocol_case(
            "unknown-algorithm",
            Some(("known_suite", false)),
            "unsupported-version",
        ),
        protocol_case(
            "unknown-construction",
            Some(("known_construction", false)),
            "unsupported-version",
        ),
        protocol_case("malformed-bound", Some(("within_bounds", false)), "invalid"),
        protocol_case("noncanonical", Some(("canonical", false)), "invalid"),
        protocol_case(
            "one-bit-signature",
            Some(("signature_valid", false)),
            "invalid-signature",
        ),
        protocol_case(
            "wrong-domain",
            Some(("domain_valid", false)),
            "invalid-signature",
        ),
        protocol_case(
            "cross-vault-item-role-revision-seal-session",
            Some(("scope_equal", false)),
            "wrong-scope",
        ),
        protocol_case(
            "stale-policy",
            Some(("policy_current", false)),
            "stale-policy",
        ),
        protocol_case(
            "stale-revision",
            Some(("revision_current", false)),
            "wrong-scope",
        ),
        protocol_case("expired", Some(("time_valid", false)), "expired"),
        protocol_case(
            "replay-changed-bytes",
            Some(("replay_consistent", false)),
            "replay-conflict",
        ),
        protocol_case("duplicate-actor", Some(("actors_unique", false)), "invalid"),
        protocol_case(
            "quorum-substitution",
            Some(("quorum_reached", false)),
            "insufficient-quorum",
        ),
        protocol_case(
            "anchor-rollback",
            Some(("anchor_consistent", false)),
            "anchor-conflict",
        ),
        protocol_case(
            "restored-witness",
            Some(("restored_state_safe", false)),
            "restored-state-unsafe",
        ),
        protocol_case(
            "implicit-direct-downgrade",
            Some(("explicit_witnessed_path", false)),
            "direct-downgrade",
        ),
    ];
    cases.extend(build_checkpoint_cases());
    cases.extend(build_owner_change_cases());
    Value::Array(cases)
}

pub(super) fn build_split_write_cases() -> Value {
    Value::Array(vec![
        json!({"name":"before-db-commit","database":"g","external":"g","pending":"none","output_escaped":false,"expected":"serve-base"}),
        json!({"name":"db-advanced-without-candidate","database":"g+1","external":"g","pending":"none","output_escaped":false,"expected":"anchor-conflict"}),
        json!({"name":"after-db-commit-before-cas","database":"g+1","external":"g","pending":"exact-candidate","output_escaped":false,"expected":"repeat-cas-readback"}),
        json!({"name":"after-cas-before-readback","database":"g+1","external":"candidate","pending":"exact-candidate","output_escaped":false,"expected":"mark-published"}),
        json!({"name":"after-readback-before-release","database":"g+1","external":"candidate","pending":"exact-candidate","output_escaped":false,"expected":"mark-published"}),
        json!({"name":"after-response-release","database":"g+1","external":"candidate","pending":"published","output_escaped":true,"expected":"serve-stable-output"}),
        json!({"name":"external-conflict","database":"g+1","external":"conflict","pending":"exact-candidate","output_escaped":false,"expected":"anchor-conflict"}),
        json!({"name":"multiple-candidates","database":"g+1","external":"g","pending":"multiple","output_escaped":false,"expected":"anchor-conflict"}),
        json!({"name":"output-before-anchor","database":"g+1","external":"g","pending":"exact-candidate","output_escaped":true,"expected":"anchor-conflict"}),
    ])
}

pub(super) fn build_byte_mutations(vectors: &Map<String, Value>) -> AnyResult<Value> {
    let mut mutations = Vec::new();
    for (name, vector) in vectors {
        let Some(signature_hex) = vector["signature_hex"].as_str() else {
            continue;
        };
        let mut signature =
            hex::decode(signature_hex).map_err(|error| format!("signature decode: {error}"))?;
        let first = signature
            .first_mut()
            .ok_or_else(|| format!("empty signature for {name}"))?;
        *first ^= 1;
        mutations.push(json!({
            "name": format!("{name}-signature-bit-0"),
            "source": name,
            "mutation": "signature bit 0 xor 1",
            "mutated_signature_hex": hex_bytes(&signature),
            "expected": "invalid-signature"
        }));
        mutations.push(json!({
            "name": format!("{name}-wrong-domain"),
            "source": name,
            "mutation": "prepend wrong-domain byte to signed preimage",
            "expected": "invalid-signature"
        }));
    }
    mutations.push(json!({
        "name": "capsule-ciphertext-bit-0",
        "source": "construction.capsules[0]",
        "mutation": "ciphertext bit 0 xor 1",
        "expected": "invalid-contribution"
    }));
    mutations.push(json!({
        "name": "witnessed-slot-context-bit-0",
        "source": "construction.witnessed_slot",
        "mutation": "context bit 0 xor 1",
        "expected": "wrong-scope"
    }));
    mutations.push(json!({
        "name": "witnessed-slot-set-bit-0",
        "source": "construction.witnessed_state_digest",
        "mutation": "digest bit 0 xor 1",
        "expected": "wrong-scope"
    }));
    mutations.push(json!({
        "name": "contribution-ciphertext-bit-0",
        "source": "construction.contributions[0]",
        "mutation": "ciphertext bit 0 xor 1",
        "expected": "invalid-contribution"
    }));
    Ok(Value::Array(mutations))
}

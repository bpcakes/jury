use super::*;

pub(super) struct PolicyActors {
    pub(super) approver_id: String,
    pub(super) witness_one_id: String,
    pub(super) witness_two_id: String,
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn initialize_policy_actors(
    repository: &Path,
    data: &Path,
    state: &Path,
    artifacts: &Path,
) -> TestResult<PolicyActors> {
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
        ],
        b"OwnerPassphrase1234\nOwnerPassphrase1234\n",
    )?)?;
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "init",
        ],
        b"OwnerPassphrase1234\n",
    )?)?;
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleWitnessedItem",
            "--allow-direct",
        ],
        b"OwnerPassphrase1234\n",
    )?)?;
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "set",
            "ExampleWitnessedItem",
            "ExampleField",
            "--unconcealed",
            "--value-stdin",
        ],
        b"OwnerPassphrase1234\nExampleFieldValue",
    )?)?;

    let approver = register_role_principal(
        repository,
        data,
        state,
        artifacts,
        "approver",
        "approver",
        None,
        "ApproverPass1234",
        "OwnerPassphrase1234",
    )?;
    let witness_one = register_role_principal(
        repository,
        data,
        state,
        artifacts,
        "witness-one",
        "witness",
        Some(2),
        "WitnessOnePass1234",
        "OwnerPassphrase1234",
    )?;
    let witness_two = register_role_principal(
        repository,
        data,
        state,
        artifacts,
        "witness-two",
        "witness",
        Some(31),
        "WitnessTwoPass1234",
        "OwnerPassphrase1234",
    )?;
    Ok(PolicyActors {
        approver_id: approver["principal_id"]
            .as_str()
            .ok_or("missing approver principal ID")?
            .to_owned(),
        witness_one_id: witness_one["principal_id"]
            .as_str()
            .ok_or("missing first witness principal ID")?
            .to_owned(),
        witness_two_id: witness_two["principal_id"]
            .as_str()
            .ok_or("missing second witness principal ID")?
            .to_owned(),
    })
}

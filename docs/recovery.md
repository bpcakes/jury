# Owner backup and recovery

> [!WARNING]
> Jury is externally unreviewed pre-alpha software. It does not yet protect
> secrets. Use only generic test data, never real credentials.

An owner backup is more sensitive than a transfer artifact. Anyone who knows
its backup passphrase can recover every included identity and every current
item for which the backed-up owner has direct access. It does not recover a
`juryd` deployment, witness replay state, external anchors, witness
availability, or quorum availability.

All paths below are illustrative absolute paths containing only generic test
data. Their parent directories must already exist and satisfy Jury's private
ownership and mode checks (use `0700` directories and `0600` private files).
Identity parent directories must be separate from the vault, backup input and
state paths; choosing different leaf names under a shared parent is insufficient.

## Create and verify a backup

Select the source vault and owner identity, then create a backup with a new,
independent backup passphrase:

```console
$ jury --home /absolute/source-vault/ExampleVault \
    --identity-file /absolute/source-identity/ExampleOwner.identity \
    backup create --out /absolute/offline/ExampleVault.backup
$ jury --home /absolute/source-vault/ExampleVault \
    --identity-file /absolute/source-identity/ExampleOwner.identity \
    backup verify --in /absolute/offline/ExampleVault.backup
$ jury --home /absolute/source-vault/ExampleVault \
    --identity-file /absolute/source-identity/ExampleOwner.identity \
    backup status
```

Creation first asks for the current identity passphrase, then captures and
confirms a separate backup passphrase. Automation may provide those exact
inputs through `JURY_IDENTITY_PASSPHRASE` and `JURY_BACKUP_PASSPHRASE`.
Restore and identity init use `JURY_NEW_PASSPHRASE` for a newly sealed identity.
Identity passphrase change authenticates with `JURY_IDENTITY_PASSPHRASE` and
seals with `JURY_NEW_PASSPHRASE`. Vault init, audit verify, identity public and
identity prove also accept `JURY_IDENTITY_PASSPHRASE`. Do not put a
passphrase on the command line. Explicit `--passphrase-stdin` overrides all
inherited passphrase variables: supply each requested passphrase line and
confirmation in prompt order. Without that flag, configured environment
sources do not consume stdin; field input then contains only the field bytes.
Do not mix those two input layouts. Deliberately reusing an identity passphrase
for the backup requires `--reuse-identity-passphrase` and reduces custody
independence.

For `--passphrase-stdin`, each entry below is one newline-terminated line.
Optional role lines appear only when that role is selected. In a terminal the
same sequence uses blocking hidden prompts, including when passphrase variables
are set. For unattended use, supply the complete stream through a pipe.

| Command | Input order |
| --- | --- |
| Field set | Identity passphrase, then exact field bytes (no confirmation) |
| Backup create | Owner passphrase; optional approver passphrase; optional witness passphrase; backup passphrase twice |
| Backup verify | Backup passphrase; owner passphrase |
| Backup restore with a new owner | Backup passphrase; new owner passphrase twice; optional new approver passphrase twice; optional new witness passphrase twice |
| Backup restore with `--reuse-identity` | Backup passphrase; existing owner passphrase once; optional new approver/witness passphrases twice each |
| Backup drill | Source owner passphrase; backup passphrase; new owner passphrase twice; optional new approver/witness passphrases twice each |

An interrupted or incomplete multi-role restore can leave the owner identity
and recovery marker published before a later role prompt fails. Keep those
matching outputs and retry the exact command with the complete input sequence;
the authenticated recovery marker supports resuming publication. Do not delete
the marker or treat partial output as a completed restore.

An explicitly selected approver identity or witness-client identity, together
with that principal's authenticated local state, can be included with
`--approver-identity-file` or `--witness-identity-file`. Creation prompts for
each identity separately. A restore of such an archive must provide the
matching `--approver-identity-out` or `--witness-identity-out` absent target.

Registration alone does not initialize a role's local recovery state. After
registration, export the current signed public vault and import it with each
selected role before creating a multi-role backup:

```sh
jury transfer export --out ./ExampleVault.transfer.json
jury --identity ExampleApprover --expected-genesis "$GENESIS" \
  transfer import --in ./ExampleVault.transfer.json
jury --identity ExampleWitnessOne --expected-genesis "$GENESIS" \
  transfer import --in ./ExampleVault.transfer.json
jury --identity ExampleApprover vault audit verify
jury --identity ExampleWitnessOne vault audit verify
```

Use the externally verified genesis fingerprint for `GENESIS`. A fresh
installation must contain the registered role's encrypted identity and the
signed transfer; no owner's private identity is needed there.
`--dry-run` previews an import without initializing state. An approver or witness
has no directly accessible items, so its first installation requires
`--allow-no-access`. Keep each role's state current by importing subsequent
signed transfers before backing it up.

An interrupted import can retain the authenticated incoming checkpoint before
publishing the public vault. Keep that transfer and retry it, or import its
owner-signed descendant. A different signed sibling is a fork and remains
refused even if the public vault still contains the earlier snapshot. Preserve
the local audit and checkpoint files; resolve the lineage with the owner
instead of deleting retained state to force an import.

`backup verify` fully decrypts and validates the archive without publishing a
restore. `backup status` reports authenticated local creation, verification,
and drill receipts. A receipt does not prove that the archive still exists or
is readable, so verify the specific retained file.

Backup receipts require complete authenticated coverage metadata. Local policy
catalogs require explicit registration-proof and review-label collections,
including when empty. Unreleased scratch files missing those fields are rejected;
archives embedding old receipts cannot be verified or restored. Version 1 remains
the unreleased format under development. There are no released vaults and no
compatibility or migration path; use freshly initialized synthetic test data.
Policy replay also requires complete owner slots, just as new policy writes do;
a signature does not exempt an old scratch revision from that requirement.

## Restore to an absent installation

Choose an absent detached vault home, an absent identity file, and a state root
that has no state for this vault lineage:

```console
$ jury --home /absolute/restored-vault/ExampleRestoredVault \
    --expected-genesis EXTERNALLY_VERIFIED_GENESIS \
    backup restore --in /absolute/offline/ExampleVault.backup \
    --identity-out /absolute/restored-identity/ExampleRestoredOwner.identity \
    --state-out /absolute/restored-state
```

For subsequent commands select the restored vault and identity, and retain its
state root, for example:

```console
$ JURY_STATE_HOME=/absolute/restored-state jury \
    --home /absolute/restored-vault/ExampleRestoredVault \
    --identity-file /absolute/restored-identity/ExampleRestoredOwner.identity \
    vault audit verify
```

The backup passphrase decrypts the archive. Jury then captures and confirms a
new identity passphrase and reseals the recovered identity with fresh salt,
nonces, and root material. A newly installed identity passphrase must differ
from the backup passphrase. To reuse an already installed exact identity, use
`--reuse-identity PATH` instead of `--identity-out`; Jury decrypts it and
compares its private material before publishing the vault.

Before the first restored file is published, Jury requires the recovered
genesis to match `--expected-genesis` or an exact interactive confirmation.
The expected value must come from an independent trusted record, not from the
backup being restored.

Restore never overwrites a vault or identity. Cross-directory publication uses
a private recovery marker beside the owner identity. If a later publication
step fails, leave the successfully published files and marker in place, correct
the reported environmental failure, and repeat the exact command. Jury accepts
only authenticated matching partial output and removes the marker after the
identity, vault, and local state are all durably published.

The destination filesystem must support atomic no-replace rename and directory
sync. Jury reports `filesystem-capability-unsupported` when it cannot preserve
that transaction contract; it does not substitute a hard-link sequence with a
second durable-name window. If final marker cleanup cannot be durably
confirmed, restore still reports the committed installation with
`transaction_marker_removed: false`; repeat the exact command to finish
cleanup.

Inside a Git worktree, omit `--home` while running the command from that
worktree. Restore publishes only `.jury/vault.json` and
`.jury/.gitattributes` there. Identity files, local state, and the recovery
marker stay outside Git, and Jury does not run a Git command.

## Run the `ExampleVault` recovery drill

Use separate, explicitly absent destinations. The drill calls the real restore
transaction and retains the restored copy for inspection:

```console
$ jury --home /absolute/source-vault/ExampleVault \
    --identity-file /absolute/source-identity/ExampleOwner.identity \
    backup drill --in /absolute/offline/ExampleVault.backup \
    --vault-out /absolute/drill-vault/ExampleVaultDrill \
    --identity-out /absolute/drill-identity/ExampleDrillOwner.identity \
    --state-out /absolute/drill-state
$ JURY_STATE_HOME=/absolute/drill-state jury --home /absolute/drill-vault/ExampleVaultDrill \
    --identity-file /absolute/drill-identity/ExampleDrillOwner.identity \
    vault status
$ JURY_STATE_HOME=/absolute/drill-state jury --home /absolute/drill-vault/ExampleVaultDrill \
    --identity-file /absolute/drill-identity/ExampleDrillOwner.identity \
    vault audit verify
```

The drill authenticates the selected source owner before it decrypts the
backup or accepts new identity passphrases. Therefore an unavailable or
mismatched source fails before any drill destination is published.

Confirm that the reported genesis fingerprint and owner principal match the
source. The drill opens and validates every restored direct descriptor. For a
generic direct test field such as `ExampleRecoveryItem.ExampleRecoveryField`,
also read it through a controlled private-file sink:

```console
$ JURY_STATE_HOME=/absolute/drill-state jury --home /absolute/drill-vault/ExampleVaultDrill \
    --identity-file /absolute/drill-identity/ExampleDrillOwner.identity \
    read ExampleRecoveryItem ExampleRecoveryField --direct \
    --out /absolute/drill-output/ExampleRecoveryValue.txt
```

The drill never opens a witnessed-only item. Recover its external witness
deployment and replay state separately, then use the normal approval and
witness-contribution quorum before claiming witnessed recovery. A client-side
backup cannot prove that external recovery succeeded.

Inspect the retained drill installation and controlled output. Delete them only
through an explicit operator-directed cleanup after that inspection; Jury does
not delete drill output automatically.

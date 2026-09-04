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
ownership and mode checks. Backup, identity, vault, and state destinations must
be separate.

## Create and verify a backup

Select the source vault and owner identity, then create a backup with a new,
independent backup passphrase:

```console
$ jury --home /absolute/private/ExampleVault \
    --identity-file /absolute/private/ExampleOwner.identity \
    backup create --out /absolute/offline/ExampleVault.backup
$ jury --home /absolute/private/ExampleVault \
    --identity-file /absolute/private/ExampleOwner.identity \
    backup verify --in /absolute/offline/ExampleVault.backup
$ jury --home /absolute/private/ExampleVault \
    --identity-file /absolute/private/ExampleOwner.identity \
    backup status
```

Creation first asks for the current identity passphrase, then captures and
confirms a separate backup passphrase. Automation may provide those exact
inputs through `JURY_IDENTITY_PASSPHRASE` and `JURY_BACKUP_PASSPHRASE`.
Restore uses `JURY_NEW_PASSPHRASE` for a newly sealed identity. Do not put a
passphrase on the command line. Deliberately reusing an identity passphrase for
the backup requires `--reuse-identity-passphrase` and reduces custody
independence.

An explicitly selected approver identity or witness-client identity, together
with that principal's authenticated local state, can be included with
`--approver-identity-file` or `--witness-identity-file`. Creation prompts for
each identity separately. A restore of such an archive must provide the
matching `--approver-identity-out` or `--witness-identity-out` absent target.

`backup verify` fully decrypts and validates the archive without publishing a
restore. `backup status` reports authenticated local creation, verification,
and drill receipts. A receipt does not prove that the archive still exists or
is readable, so verify the specific retained file. Authenticated receipts made
before coverage metadata was added remain readable; their coverage fields are
reported as unknown, and `backup status` recommends creating a fresh backup
instead of inferring which identities or items the older archive contains.

## Restore to an absent installation

Choose an absent detached vault home, an absent identity file, and a state root
that has no state for this vault lineage:

```console
$ jury --home /absolute/private/ExampleRestoredVault \
    --expected-genesis EXTERNALLY_VERIFIED_GENESIS \
    backup restore --in /absolute/offline/ExampleVault.backup \
    --identity-out /absolute/private/ExampleRestoredOwner.identity \
    --state-out /absolute/private/ExampleRestoredState
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
$ jury --home /absolute/private/ExampleVault \
    --identity-file /absolute/private/ExampleOwner.identity \
    backup drill --in /absolute/offline/ExampleVault.backup \
    --vault-out /absolute/private/ExampleVaultDrill \
    --identity-out /absolute/private/ExampleDrillOwner.identity \
    --state-out /absolute/private/ExampleDrillState
$ jury --home /absolute/private/ExampleVaultDrill \
    --identity-file /absolute/private/ExampleDrillOwner.identity \
    vault status
$ jury --home /absolute/private/ExampleVaultDrill \
    --identity-file /absolute/private/ExampleDrillOwner.identity \
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
$ jury --home /absolute/private/ExampleVaultDrill \
    --identity-file /absolute/private/ExampleDrillOwner.identity \
    read ExampleRecoveryItem ExampleRecoveryField --direct \
    --out /absolute/private/ExampleRecoveryValue.txt
```

The drill never opens a witnessed-only item. Recover its external witness
deployment and replay state separately, then use the normal approval and
witness-contribution quorum before claiming witnessed recovery. A client-side
backup cannot prove that external recovery succeeded.

Inspect the retained drill installation and controlled output. Delete them only
through an explicit operator-directed cleanup after that inspection; Jury does
not delete drill output automatically.

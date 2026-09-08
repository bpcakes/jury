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
For `backup drill`, the `--state-out` root must be absent and its existing
parent must also be separate from the source vault home or Git worktree.
For example, when `/absolute` contains the source, use
`/absolute/drill-state-parent/ExampleState` below a separate `0700` directory;
`/absolute/ExampleState` is refused even though that leaf does not exist.
For initial vault setup, use the repository README. For role registration and
fresh remote imports, follow the [operator walkthrough](witness-operator-walkthrough.md).
Service databases and external anchors have their own
[backup and restore procedure](self-hosting-juryd.md#backup-restore-and-rollback-behavior).

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
  transfer import --in ./ExampleVault.transfer.json --allow-no-access
jury --identity ExampleWitnessOne --expected-genesis "$GENESIS" \
  transfer import --in ./ExampleVault.transfer.json --allow-no-access
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
    --state-out /absolute/drill-state-parent/ExampleState
$ JURY_STATE_HOME=/absolute/drill-state-parent/ExampleState jury --home /absolute/drill-vault/ExampleVaultDrill \
    --identity-file /absolute/drill-identity/ExampleDrillOwner.identity \
    vault status
$ JURY_STATE_HOME=/absolute/drill-state-parent/ExampleState jury --home /absolute/drill-vault/ExampleVaultDrill \
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
$ JURY_STATE_HOME=/absolute/drill-state-parent/ExampleState jury --home /absolute/drill-vault/ExampleVaultDrill \
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

## Rollover and suite migration in the development checkout

Direct and governed rollover and suite migration are implemented in this
checkout, including exact-candidate recovery and retained bootstrap validation.
Native tests exercise source Recovery approvals, destination witnessed reads,
backup restoration and modeled interrupted publication states. A real TLS witness
and anchor test covers unavailable-anchor refusal, abrupt restarts and one-sided
SQLite restore refusal for one required endpoint. The complete quorum tests use
HTTP engines with in-memory stores. Jury remains externally unreviewed pre-alpha
and must not be used for real secrets.

An active owner can prepare a fresh lineage without appending to the source,
including when its policy history has reached the cap. Use an absent detached
home, an absent backup file in a separate existing private directory, and an
absent transfer file outside both. Keep every output outside the source
repository, identity storage and local-state storage. The destination home's
parent must also be an existing owner-only directory.

```console
$ jury vault rollover --out /absolute/destinations/ExampleVault \
    --backup-out /absolute/offline/ExampleVault.backup \
    --transfer-out /absolute/transfers/ExampleVault.transfer --dry-run
```

To migrate a suite-1 vault, replace `vault rollover` with
`vault migrate-suite --to 2`, keeping the same output, authorization and adoption
options. Suite 2 uses AES-256-GCM for HPKE; storage encryption and identity
protection retain their existing profiles. Migration re-encrypts every active
item and signs a record binding both suites and lineages. Only migration from
suite 1 to suite 2 is supported. Ordinary rollover preserves the source suite,
including suite 2; it does not implicitly migrate or downgrade.

For a direct-only source, dry-run performs the actual encryption, transfer and
backup preparation in memory. It publishes no destination. A subsequent real run generates a fresh
candidate and requires `--adopt-new-lineage` in place of `--dry-run`. That flag
explicitly trusts the generated genesis for the acting owner's local
installation. Each other installation must separately verify and trust the new
genesis when installing the transfer. The command records local backup and
export receipts; it does not claim recipient delivery or mutate Git.

Later destination rekeying, item deletion or role removal preserves the signed
first revision and its manifest. Transfer and backup retain the bootstrap's
registration proofs, witness policies and review labels even when those roles
or items are no longer active. Validation uses their original admission time;
it does not require an old challenge or label to remain unexpired today. Missing
historical evidence is refused. A subsequent rollover copies only active roles.
The destination's local policy catalog is recovery-critical: removing retained
bootstrap proofs or review-label sets prevents status, reads and backups, even
when the vault file itself is intact. Preserve the complete transfer and fresh
owner backup. Recover into a new local installation using that transfer or
backup; copying only the vault file does not restore the missing catalog.
New bootstraps use version 2, which preserves separate active revisions of the
same source witness policy as separate destination policies. Public references
to deleted items remain inactive; references to removed fields receive distinct
new scope IDs without recreating those fields. Version-1 artifacts remain
readable with their original encoding.
Public history validation authenticates the committed initial authority; it does
not prove equality of deleted plaintext or continuing endpoint availability.

The source bytes, old history and old backups remain available. Old copies
retain their original cryptography and recipient exposure. Verify and drill the
new backup using the procedures above with `--home` selecting the new lineage.

If publication is interrupted, retain the destination home and every file in
its private backup directory. Once `rollover.outputs.pending.json` is durable,
retry the same command against the unchanged source with `--resume` and
`--adopt-new-lineage`, using exactly the original output and local-state paths.
For migration, repeat `vault migrate-suite --to 2`; switching between migration
and rollover on retry is refused.
Supply the original backup passphrase after the owner identity passphrase.
Corrected endpoint credentials are allowed. Resume validates the saved candidate,
transfer, encrypted backup and authenticated local state; it reuses the exact
witness checkpoint without new source approvals or candidate challenges. It
refuses changed source bytes, mismatched paths, corrupted staging and conflicting
published outputs. KDF and passphrase-reuse options do not regenerate the backup.

The candidate lives in `rollover.pending.json`. The output marker records the
selected paths and saved output hashes. An owner-MAC audit event separately
binds those paths, source/destination bytes, backup, transfer and exact witness
checkpoint, so editing the marker cannot authorize a different intent. Its
encrypted backup and other payloads
live as owner-only `.jury-rollover-*` files beside the private backup, never as
identity material in the new vault home. Ordinary vault commands refuse either
pending marker or its cleanup counterpart. Resume republishes matching partial
outputs durably before cleaning up; a completed retry validates the installation
and confirms cleanup. Saved complete signed witness acknowledgements avoid
repeating registration only when the final vault was already published and
cleanup remains. If that vault is absent, resume contacts every required witness
again. A completed retry makes no claim of continuing global freshness.

A crash before the output marker is durable has not started external destination
registration and may leave an unrecoverable partial preparation. Use the
unchanged source and retain that preparation for explicit cleanup. Never remove
pending state to make an incomplete installation appear ready.

If waiting for role proofs ends before a destination candidate is saved, the
registration directory remains populated and cannot be resumed. Retain it for
explicit operator cleanup, select a new absent `--registration-dir`, and repeat
fresh preparation with new source approvals. A plain retry using the occupied
registration directory is refused; `--resume` requires the saved destination.

Governed rollover additionally needs `--registration-dir` naming an absent
private directory outside all source/output boundaries. The foreground process
retains protected staged content while candidates answer its published
`journal.json` and `<principal-id>.challenge.json` files. Each candidate selects
the unchanged source vault and its own identity, verifies the new fingerprint
through the owner's trusted channel, and runs:

```console
$ jury --identity ExampleWitness identity prove \
    --challenge /absolute/registration/PRINCIPAL_ID.challenge.json \
    --rollover-draft /absolute/registration/journal.json \
    --expected-rollover-genesis EXPECTED_NEW_GENESIS \
    --out /absolute/registration/PRINCIPAL_ID.proof.json
```

This proof authenticates the source owner, pinned destination genesis and role
admission. The draft contains policy-intent digests rather than full destination
policy templates, so the candidate command does not compare the
destination quorum and operation rules with the source. The owner's completion
path checks that equivalence before publication. Candidates must review the
completed public policy material before operating the new lineage; the draft
proof alone establishes neither its policy equivalence nor witness readiness.

Supply every active approver and witness proof before
`--registration-wait-seconds` expires. The same live process validates fresh
key-possession responses against its fixed candidate. Losing that process
before completion loses its protected staging; old responses cannot authorize a
replacement candidate.
The wait bound controls polling only. Challenges expire separately after 24
hours; an answer to an abandoned challenge cannot recover its lost staging or
authorize another candidate.
Copied review labels keep their original expiry. They must remain valid beyond
the full 24-hour registration deadline; short-lived labels are refused with
`rollover-review-label-lifetime` before source access. Challenge renewal after
source authorization checks that window again before candidates are asked for
proofs. Refresh source labels and their witness policies before preparation if
they expire too soon; rollover does not silently extend their authority.

For source items requiring witnesses, `--administrative-access FILE` supplies
version 1 JSON with `total_wait_seconds` (1–86400) and `entries`. Provide one
entry per descriptor and body with `item_id`, `content_role`, `checkpoint`,
`request_out`, `receipt`, `approvals`, `witnesses`, `wait_seconds` (0–900), and
optional `allow_insecure_loopback`. Request and receipt files must be absent.
The source policy must permit Recovery with whole-item human approval. The
review binds the destination vault path and preserves the item's access mode.
`--direct-source` explicitly selects an existing owner direct slot for mixed
items; it does not make a direct slot available for witnessed-only items.

Each active destination witness also needs `--destination-witness
ID,URL,PRIVATE_OPERATOR_TOKEN,CA_PEM`. These are operator credentials for initial
registration, distinct from the source request-client credentials. Loopback
HTTP requires `--allow-insecure-loopback`. The command retains exact public
registration inputs before contacting endpoints and verifies every required
signed checkpoint/anchor acknowledgement before publishing the destination.
It preserves the accepted initial checkpoint as `witness.checkpoint.json` and
per-witness acknowledgements in the new home. These describe the observed
registration outcome, not continuing global freshness.

Governed dry-run checks public source and Recovery request feasibility without
sending requests or creating a registration directory. Its output explicitly
leaves source access, fresh proofs, endpoint registration, backup and publication
pending. It is not a completed rollover or a witness-readiness check.

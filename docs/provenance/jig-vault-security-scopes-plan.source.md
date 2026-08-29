# Jig Vault v3: cryptographic item access scopes

Status: proposed implementation plan

Last grounded: 2026-08-28

Repository baseline: `0f38c15` (`master`)

Primary owners: `jig-vault`, `jig-sh`, and `jig-vault-tui`

Delivery tracker: Beads epic and child issues created from the specifications in
this document and kept synchronized through the review passes recorded near the
end.

## Progress

- [x] Ground the v3 design in the current repository and external primitive
  documentation.
- [x] Decompose the design into implementation Beads and synchronize their
  descriptions and dependency graph.
- [x] Revise the encryption model after review of grant-time backward secrecy,
  descriptor-length privacy, recipient proof, principal replacement, bounded
  history, provider behavior, and canonical preimages.
- [x] Resolve the remaining wire-freeze gaps around later recipient-key
  compromise, canonical X25519 descriptor keys, panic-free HPKE entropy, and an
  independent final protocol review.
- [x] Separate descriptor and body encryption keys by deriving both from the
  wrapped per-epoch item root key with domain-separated HKDF contexts.
- [x] Version exact portable/hardened Argon2id profiles and make owner backups
  use independent recovery credentials with fresh identity resealing.
- [x] Specify protected-memory/core-dump controls, additive hardware-bound
  identity unlock, authenticated body-size buckets, and honest cover reseals.
- [ ] Implement B01 through B20. No implementation work has started.

## Surprises & Discoveries

- Granting an existing item root key would let a newly authorized recipient
  decrypt any retained pre-grant ciphertext from the same epoch, so backward
  secrecy requires the same rotation transaction as revocation.
- Encrypting a variable-length item descriptor still exposes a useful oracle for
  small-dictionary item names; descriptor plaintext must have one fixed wire
  length.
- An Ed25519 descriptor self-signature proves control of only the signing key,
  not the separately generated HPKE private key.
- Permanent journals and proof chains need an explicit capacity exit before the
  hard caps become an operational dead end.
- HPKE Base mode with a long-lived recipient key does not provide forward secrecy
  after later recipient-private-key compromise; retained historical artifacts
  can become decryptable even if the key was compromised only after revocation.
- RFC 7748 requires the X25519 primitive to process several byte encodings of the
  same field element. Fingerprints and duplicate-key checks therefore need a
  stricter, single canonical Jig descriptor encoding above the primitive.
- The `hpke` crate's `getrandom` convenience surface can panic on OS-random
  failure. Merely promising not to call it is weaker than compiling it out and
  seeding a private infallible RNG only after Jig's fallible entropy boundary
  succeeds.
- Using one random item key directly for both descriptor and body AEAD leaves
  avoidable cross-purpose key reuse. One wrapped random item root key can instead
  derive independent descriptor and body keys without adding recipient slots.
- Once a backup uses an independent passphrase, embedding only the live encrypted
  identity file would still require the historical identity passphrase and would
  no longer be full-owner recovery. The backup must carry recovery-form private
  material and reseal it under a newly chosen identity credential.
- General-purpose allocators can copy or move a supposedly locked secret, while
  the 128–512 MiB Argon2 workspace commonly exceeds unprivileged `memlock`
  limits. Protected memory therefore needs a dedicated non-growing allocation
  boundary and must state that encrypted swap/hibernation remains an OS concern.
- A hardware protector is additive only if the identity file has no remaining
  passphrase-only unlock path. Recovery belongs in the independently encrypted
  owner backup rather than a bypass slot beside the device-bound slot.
- Ciphertext buckets hide exact logical body length, but no padding field can
  conceal a publicly signed revision or filesystem/network timing. An ordinary-
  looking signed reseal can add cover activity, with explicit limits and history
  cost, without claiming complete traffic-analysis resistance.

## Decision Log

The detailed decision record is maintained in section 28. Review rounds 7 and 8
add the decisions that reader-set changes rotate keys symmetrically, private
descriptors use fixed-size plaintext, onboarding proves both private keys, key
replacement is atomic, bounded histories exit through a signed new lineage,
X25519 descriptor keys have one canonical application encoding, HPKE's panic-on-
entropy-failure convenience surface is compiled out, later recipient-key
compromise is an explicit non-goal rather than an implied revocation guarantee,
and item root keys are never used directly for content encryption.
Decision D23 adds exact bounded KDF profiles, monotonic passphrase-change
upgrades, independent backup credentials, and recovery-time identity resealing.
Decisions D24–D26 add fail-closed compact-secret memory protection, additive
device-bound unlock providers, and authenticated size buckets plus optional
indistinguishable body reseals.

## Outcomes & Retrospective

The plan and tracker now describe the intended security model; implementation
and release evidence remain pending. The final retrospective will record what
shipped, the commands and fixtures that proved it, and any deliberate deviations
from this plan.

## 1. Executive decision

Jig Vault should add cryptographic access control at the canonical item boundary.

A canonical item is the first version of a security scope.

In the motivating example, the items are `Development`, `Staging`, and
`Production`.

The v3 vault remains one logical, portable `vault.json` artifact.

The artifact contains public, signed opaque item and access metadata plus
separately encrypted item descriptors and bodies.

Canonical item names are private by default.

The public policy identifies an item only by a random stable item ID.

A small descriptor encrypted under an item-specific derived descriptor key
contains the canonical item name, so a selected identity discovers names only
for items it may currently read.

Every item key epoch has one random 32-byte item root key. HKDF-SHA256 derives
independent descriptor and body encryption keys from that root, and the root is
never passed directly to an AEAD.

That item root key is wrapped independently to every human or machine principal
that may read the item.

There is no v3 passphrase that unlocks the whole vault for every recipient.

Every recipient instead owns an encrypted local identity with:

- an X25519 HPKE decryption key;
- an Ed25519 signing key;
- a local audit/checkpoint seed;
- a stable public principal descriptor.

The selected identity's passphrase unlocks only that local identity.

An owner grants `reader` or `writer` access to a principal for an item.

An owner has read/write/admin access to every item and therefore receives a key
slot for every active item.

Ordinary CLI and TUI inventory views show only named items accessible to the
selected identity.

The full artifact still reveals opaque item count, exact public artifact and
transfer length, encrypted-body size buckets, revision activity, principals,
and item/principal access relationships.

Every effective reader-set change rotates the affected item root key, derives a
fresh descriptor/body key pair, and reseals the current item descriptor and body.
A grant therefore excludes the new reader from retained pre-grant ciphertext,
while a revocation excludes the removed reader from future ciphertext.

Removing write access without removing read access is a signed policy change and
does not rotate the item root or derived keys.

Signed policy and item-revision chains make unauthorized edits rejectable by an
honest Jig client.

They do not stop an authorized reader from copying plaintext.

They do not make a revoked person forget data they already decrypted.

They do not provide forward secrecy for retained historical artifacts if a
recipient's HPKE private key is compromised later. Changing only the identity
passphrase preserves that HPKE key; principal replacement and item rekeying
protect later epochs, not earlier artifacts.

They do not provide authoritative global freshness when files are exchanged
offline.

Organizations that require immediate server-side revocation, SSO, just-in-time
access, approval workflows, or a central audit authority should use a hosted or
self-hosted secrets service for Production rather than treating offline Jig Vault
as an equivalent control plane.

## 2. Why this design

The current v2 envelope has one passphrase-derived wrapping key.

That key unwraps one vault-wide data-encryption key.

That data-encryption key decrypts one serialized state containing every field.

Anyone who can unlock the envelope can therefore decrypt Production, Staging,
Development, legacy values, and all field metadata.

Adding an ACL field inside that encrypted state would improve user experience but
would not create a security boundary.

The same vault-wide key would still be present on every authorized developer's
machine.

The client could be patched to ignore the ACL.

Splitting environments into separate v2 vault homes would create real key
separation, but it would abandon the requested single-vault distribution model,
duplicate lifecycle operations, and make canonical references depend on an
external scope selection.

The chosen design retains the single artifact and moves the key boundary inward
to the item.

The choice mirrors the useful part of several competitor models:

- Doppler assigns project roles and access to selected environments/configs.
- Infisical scopes roles by environment, path, secret name, and tags.
- HashiCorp Vault authorizes capabilities on secret paths and denies by default.
- Bitwarden Secrets Manager grants people, groups, and machine accounts read or
  read/write access to projects.
- 1Password normally uses separate vaults as the cryptographic sharing boundary,
  while documenting that some finer app permissions are only client-enforced.
- SOPS and age demonstrate recipient-wrapped file encryption, but their usual
  file boundary is coarser than the desired item boundary.

Jig's canonical `jig://ITEM/FIELD` reference already gives the product a natural
scope boundary without inventing environment routing syntax.

The item boundary also supports a direct migration from the v2 grouped field
model.

## 3. Product outcomes

The feature is complete when all of the following statements are true.

1. A developer granted Development and Staging can carry the same `vault.json`
   as an owner without decrypting or discovering Production's item name from the
   artifact or conforming UI.

2. A Production deploy identity can decrypt Production without receiving a
   reusable vault-wide passphrase.

3. An unauthorized principal cannot learn an item's canonical name or its field
   names, kinds, timestamps, lengths, or values.

4. Opaque item IDs, envelope count and sizes, principal labels, roles, and access
   relationships are explicitly documented metadata leaks.

5. A reader cannot publish an item mutation that another conforming Jig client
   accepts unless policy grants that principal writer or owner authority.

6. A non-owner cannot publish an access-policy mutation that another conforming
   Jig client accepts.

7. Adding or removing effective read access rotates the affected item root key,
   derives fresh descriptor/body keys, reseals both ciphertexts, and replaces
   the complete slot set.

8. The revocation output tells the owner to rotate the underlying external
   credentials when prior disclosure matters.

9. Existing `jig://ITEM/FIELD` references continue to identify fields without
   repository or vault routing in the reference.

10. Read, inject, exec, run, import, TUI, audit, backup, and restore flows have
    explicit v3 behavior and fail closed at access boundaries.

11. v1 and v2 vaults remain readable according to the existing compatibility
    rules.

12. Migration to v3 is explicit and one way.

13. Older binaries reject v3 rather than silently interpreting it.

14. A normal transfer contains no private identity, local operational audit,
    checkpoint, or local operation receipt.

15. An owner backup is clearly labeled as full recovery material and can restore
    both the vault and an owner identity.

16. Offline forks and rollbacks are detected whenever the receiving installation
    has a prior authenticated checkpoint that proves the conflict.

17. The documentation does not claim server-grade revocation, “use without
    view,” global freshness, or deletion resistance.

18. A selected principal can see its own accessible item/role matrix, explain or
    preflight a required capability without reading a field, and receive one
    uniform unavailable result for inaccessible and nonexistent item names.

19. An owner can register a principal and grant its initial exact item roles in
    one atomic policy revision, and can batch several exact grants for one
    principal without intermediate policy states.

20. Transfer inspection, import dry-run, and local export-status commands explain
    authenticated public deltas, conflicts, and accessible-name changes before
    mutation without disclosing inaccessible names.

21. Every shared-state mutation reports that redistribution is recommended, and
    local status distinguishes the current vault revision from the last revision
    exported on that installation without claiming delivery to anyone.

22. Policy-changing commands provide authenticated dry-run previews; revocation
    and owner removal show exact key rotations, affected opaque or accessible
    items, and external-credential warnings before commit.

23. Local identities have explicit names, can be listed without unlocking, and
    are selected by name or an unambiguous explicit file option without automatic
    key probing.

24. Interactive and scripted initialization can create several initial private-
    name items with the first owner and ends with fingerprint, recovery, and
    onboarding next steps.

25. Owner recovery status distinguishes identity coverage, captured vault
    revision, backup age, local verification state, and whether a real restore
    drill has been recorded, without pretending that an unobserved off-machine
    drill occurred.

26. The TUI provides accessible-only role filters, owner access-matrix editing,
    disabled-command reasons, exact committed-versus-retryable results, and
    copyable references only for item names the selected identity can decrypt.

27. A new recipient cannot decrypt retained item ciphertext created before its
    grant, even when that ciphertext came from the immediately preceding valid
    vault revision.

28. Before permanent policy or item-proof histories reach their hard caps, an
    owner can create a separately trusted, signed v3-to-v3 rollover lineage
    without overwriting or weakening the old lineage.

29. Fingerprints, duplicate-key rejection, registration proofs, and principal
    replacement operate on one canonical Jig encoding of each X25519 public key;
    alternate RFC 7748 encodings of the same field element cannot create a second
    apparent cryptographic identity.

30. Every new v3 identity/backup records one exact bounded Argon2id profile;
    passphrase change upgrades weak profiles, preserves stronger profiles by
    default, and hostile headers cannot request arbitrary pre-authentication
    memory.

31. A v3 owner backup uses an independently captured passphrase by default and
    can restore the same owner principal into a freshly sealed identity that no
    longer depends on the former live identity passphrase.

32. Before any private unlock, Jig disables process core dumps and prepares a
    page-dedicated protected-memory boundary; compact credentials and keys never
    silently fall back to ordinary pageable allocator storage.

33. An identity may require both its passphrase and one explicitly enrolled OS
    keychain, Secure Enclave, TPM 2.0, or FIDO2 protector, with no passphrase-only
    bypass slot and backup-based recovery onto replacement hardware.

34. Encrypted item bodies and encrypted backups expose only fixed size buckets
    rather than exact logical/recovery lengths, while optional signed cover reseals are
    indistinguishable from ordinary body updates in shared state and documentation
    states the remaining public-framing and timing/activity leaks.

## 4. Non-goals

The first v3 release does not attempt to provide:

- a hosted Jig secrets service;
- SSO, SCIM, OIDC, LDAP, or directory synchronization;
- just-in-time or expiring access grants;
- IP, device-posture, time, or network conditions;
- multi-party approval for each read or deployment;
- a remotely authoritative audit log;
- a remotely authoritative latest revision;
- secret leasing or dynamic credential generation;
- transparent rotation of credentials in third-party systems;
- prevention of screenshots, memory inspection, shell capture, or deliberate
  exfiltration by an authorized reader;
- cryptographic “execute but never reveal” semantics for a local child process;
- field-level ACLs inside an item;
- wildcard, tag, path-expression, or group grants in v3.0;
- automatic conflict resolution for concurrent writes to the same item;
- post-quantum recipients in the first wire suite;
- recipient forward secrecy or post-compromise secrecy for historical artifacts;
  later compromise of a long-lived HPKE private key can expose retained artifacts
  from epochs in which that principal had a slot;
- SSH-agent, age-plugin, or browser-extension identities;
- public discovery of item or field names inside an inaccessible item;
- concealment of opaque envelope count, exact revision sequence, principal
  descriptors, or public item/principal access relationships;
- complete traffic-analysis resistance: size buckets and optional cover reseals
  do not hide filesystem access, transport timing, policy changes, an absent
  cover schedule, or correlation by an observer with prior artifacts;
- protection against a privileged kernel/root attacker, live process memory
  inspection after unlock, suspend-to-disk without OS encryption, DMA, or
  physical acquisition; protected pages and disabled dumps narrow ordinary
  paging/crash exposure but are not a hardware isolation boundary;
- general access-request/invitation workflows or automatic distribution; the
  bounded owner-issued registration challenge and response exist only to prove
  control of both keys in a public principal descriptor;
- compatibility for writing v3 with an older binary;
- a down-migration from v3 to v2.

Direct principal grants are intentional for the first version.

The serialized subject shape must be versioned so a later release can add groups
without interpreting an unknown subject as a principal.

## 5. Threat model

### 5.1 Actors

The design distinguishes these actors.

`Owner`

An owner administers principals and item access.

An owner can read and write every item.

An owner signs policy revisions.

`Writer`

A writer can decrypt and mutate one granted item.

A writer signs item revisions.

A writer cannot change access policy.

`Reader`

A reader can decrypt one granted item.

A reader cannot publish an accepted mutation to that item.

`Machine`

A machine principal uses the same cryptographic identity shape as a person but is
marked as a machine in public policy.

A machine may be a reader or writer.

A machine may not be an owner in v3.0.

`Distributor`

A distributor can copy, truncate, replay, combine, or replace transfer files.

A distributor is not trusted with plaintext or signing authority.

`Revoked principal`

A revoked principal retains every file, key, plaintext, child-process copy, and
backup it obtained before revocation.

`Later-compromised recipient`

An attacker who later obtains a principal's static HPKE private key can open key
slots addressed to that key in retained historical artifacts. This remains true
when the compromise occurs after revocation or an identity passphrase change.
The attacker does not gain a later epoch created by principal replacement or
reader-set rekey unless it also compromises a then-authorized identity.

`Local attacker`

A different OS user may try to read or replace local files.

Existing private-directory, symlink, hard-link, atomic-write, and advisory-lock
protections remain in scope.

The threat also includes accidental or later collection of ordinary process core
dumps, crash bundles, and pageable secret buffers after Jig has released them.
Jig must disable its own dumpability before unlock and keep compact credentials
and keys in dedicated locked, dump-excluded pages. It does not claim protection
when a privileged kernel, debugger, or account controller reads live memory.

`Identity-file thief without enrolled hardware`

An attacker may copy a device-bound identity file and know or guess its
passphrase without possessing the enrolled keychain/Secure Enclave/TPM/FIDO2
protector. The identity remains locked because device-bound mode has no portable
passphrase-only slot. A thief controlling both the OS account and protector use
is outside this boundary.

An attacker with full control of the authorized user's process or account is out
of scope.

### 5.2 Protected assets

The design protects:

- canonical item names and deleted-item former names for inaccessible items;
- field values in inaccessible items;
- field names in inaccessible items;
- field kinds in inaccessible items;
- field timestamps in inaccessible items;
- field value lengths in inaccessible items;
- exact logical item-body and unpadded backup-recovery lengths beyond their
  public buckets;
- item root keys, derived descriptor/body keys, and HKDF intermediates;
- identity private encryption and signing keys;
- local audit/checkpoint authentication seeds;
- accepted policy authorship;
- accepted item-update authorship;
- known local revision freshness.

### 5.3 Intentionally public metadata

The shared vault exposes:

- vault ID and creation time;
- format and cryptographic suite identifiers;
- item stable IDs;
- active opaque item count;
- item tombstones containing opaque IDs and authenticated final hashes, but no
  former names;
- principal stable IDs;
- principal labels;
- whether a principal is human or machine;
- principal public encryption and verification keys;
- item roles and access relationships;
- policy revision counts and timestamps;
- item revision counts and timestamps;
- ciphertext body-size buckets, but not exact logical body lengths;
- exact total public artifact/transfer length and parseable public framing;
- the single fixed encrypted item-descriptor length;
- key-rotation epochs;
- signatures and hashes.

Canonical item names live only in per-item encrypted descriptors.

An artifact holder can still correlate opaque item IDs with principals, grants,
revision cadence, and size buckets and may infer a scope from external knowledge.

The UI and documentation must say that item-name confidentiality is not item-
existence, relationship, exact activity, or complete traffic-analysis
confidentiality.

### 5.4 Security claims

Given secure primitives and uncompromised private keys, a principal without a
current item key slot cannot recover that item's current root key or derive its
current descriptor or body encryption key.

The same principal cannot decrypt that item's descriptor and therefore cannot
recover its canonical name from the v3 artifact.

A conforming client rejects a policy revision not signed by an owner authorized
under the immediately preceding accepted policy state.

A conforming client rejects an item revision not signed by a writer or owner
authorized under the referenced policy state.

A conforming client rejects missing active items, duplicate IDs, duplicate slots,
unknown algorithms, malformed chains, unsupported subjects, stale local policy,
and stale local item revisions.

A local checkpoint makes a later rollback detectable on that installation.

A fresh installation cannot distinguish two otherwise valid offline forks without
an external trusted checkpoint.

### 5.5 Security limitations

A reader necessarily learns the item root key while unwrapping a slot and can
derive both content-encryption subkeys for that epoch.

That reader can copy plaintext or rewrap the item root key outside Jig.

Policy signatures stop honest recipients from accepting unauthorized changes;
they do not constrain a modified client on the reader's own machine.

Reader-set changes define a new key epoch. A grant protects retained earlier
ciphertext from the new reader, and a revocation protects later ciphertext from
the removed reader.

It cannot revoke earlier plaintext, a previously decrypted item name, or
ciphertext plus an earlier key.

HPKE Base mode does not provide recipient forward secrecy. Anyone who later
obtains a recipient's static HPKE private key can recover item root keys from that
recipient's slots in retained historical vault or transfer artifacts, derive the
matching descriptor/body keys, and decrypt the retained ciphertext. Identity
passphrase change only re-encrypts the same private key. Principal replacement
plus reader-set rekey excludes the old key from later epochs but cannot make
earlier artifacts safe.

If a Production credential might have been learned, the external Production
credential must be rotated after the Jig access revocation.

Local audit files can be deleted with the local account.

They are tamper-evident, not deletion-proof.

## 6. Current implementation map

The existing v2 format lives in `crates/jig-vault/src/format.rs`.

`VaultFile` currently contains:

- one authenticated header;
- one passphrase-wrapped vault data-encryption key;
- one encrypted state nonce;
- one encrypted state ciphertext.

`VaultState` is one `BTreeMap<String, SecretEntry>`.

`crates/jig-vault/src/vault/envelope.rs` derives one Argon2id wrapping key,
unwraps one data-encryption key, decrypts the complete state, and derives the
audit key from that vault-wide key.

`crates/jig-vault/src/vault.rs` keeps the complete `VaultFile`, plaintext
`VaultState`, data-encryption key, and audit key in one `OpenVault`.

Every public mutation currently serializes and reseals the complete state.

`VaultRevision` is an opaque pair derived from vault ID and state nonce.

`VaultSnapshot` exposes metadata for every field and every legacy secret after a
complete unlock.

`crates/jig-vault/src/audit.rs` maintains a local HMAC-SHA256 JSONL chain.

The HMAC key is derived from the vault-wide data-encryption key.

The chain detects edited records and broken links, but not deletion or rollback
without an external checkpoint.

`crates/jig-vault/src/store.rs` owns `vault.json`, `audit.jsonl`, `vault.lock`, a
16 MiB vault read limit, a 256 MiB audit read limit, private permissions,
symlink refusal, and atomic writes.

`crates/jig/src/runtime/vault.rs` selects repo, global, or explicit-home scope and
captures the passphrase.

Canonical references remain contextual to that selected scope.

`crates/jig-vault-tui` consumes metadata-only snapshots through a CLI-owned
backend and keeps one process-local credential.

The v3 implementation must preserve these hardened boundaries while replacing
the one-key/full-state assumption.

## 7. Competitor findings and implications

### 7.1 Doppler

Doppler exposes project roles and per-environment/config access.

Its advanced-permissions example explicitly supports write access to development
and CI, read-only access to staging, and visibility without secret access to
production.

Removing access is enforced by Doppler's service in dashboard and API requests.

Implication for Jig:

Use the environment-like item as the default scope and distinguish read and
write, but do not copy Doppler's server-backed “visible without secret access”
inventory behavior.

An offline Jig recipient should discover an item name only after its identity can
unwrap that item's root key and derive its descriptor key.

Do not copy the claim of immediate revocation because offline files lack a
continuously consulted authority.

### 7.2 Infisical

Infisical's RBAC assigns permissions to human and machine identities.

It can condition secret access on environments, paths, names, and tags.

Its roles are additive.

Implication for Jig:

Support both human and machine principals and default deny.

Start with exact item grants rather than prematurely adding a policy-expression
language.

### 7.3 HashiCorp Vault

HashiCorp Vault authenticates a client, associates policies with a token, and
authorizes capabilities against paths.

Policies are deny by default and separate read, create, update, delete, list, and
other capabilities.

The server also supplies the current policy and token authority.

Implication for Jig:

Separate read, write, and administer roles, and validate every operation against
the latest accepted signed policy.

Document that Jig does not have Vault's online token revocation or central
freshness.

### 7.4 1Password

1Password organizes sharing primarily by vault and assigns people and groups to
those vaults.

Its documentation distinguishes server-enforced access from client-enforced app
permissions and warns that a determined team member can bypass client-only
controls.

Implication for Jig:

Treat encryption keys, not UI affordances, as the read boundary.

Be candid that read/write separation is an acceptance rule once a reader already
has the item root key and can derive both symmetric content keys.

### 7.5 Bitwarden Secrets Manager

Bitwarden assigns people, groups, and machine accounts to projects with read or
read/write access.

Implication for Jig:

Use a compact reader/writer model for item data and a separate owner role for
policy administration.

Machine principals must be first-class, not a later token-shaped exception.

### 7.6 SOPS, age, and dotenvx

SOPS and age use recipient encryption for portable files.

dotenvx uses separate encrypted environment files and environment-specific keys.

These tools prove that offline recipients are practical, but their common
security boundary is a whole file.

Implication for Jig:

Use recipient wrapping, but apply it to each item root key inside one
authenticated vault artifact.

Avoid requiring one file per environment merely to gain key separation.

### 7.7 Product position

Jig v3 occupies a deliberate middle ground.

It is stronger than a shared encrypted dotenv or one-passphrase local vault
because recipients receive different cryptographic capabilities.

It remains an offline collaboration artifact, not a centralized secrets control
plane.

## 8. Terminology

`Vault artifact`

The portable, signed, encrypted `vault.json` file.

`Identity`

One local encrypted private-key file plus its public descriptor.

`Principal`

A policy entry representing a human or machine identity.

`Owner`

A human principal with global read, write, and policy-administration authority.

`Reader`

A principal allowed to unwrap and decrypt one item.

`Writer`

A principal allowed to read one item and publish signed item revisions.

`Item`

The canonical access-control and encryption compartment addressed by the first
segment of `jig://ITEM/FIELD`; its stable ID is public and its canonical name is
encrypted.

`Item descriptor`

A small encrypted record containing the canonical item name independently of the
larger encrypted field body.

`Item body`

The encrypted field map and field metadata for one item.

`Item root key`

A random 32-byte secret for one item key epoch. It is HPKE-wrapped to recipients
and used only as HKDF-SHA256 input, never directly as an AEAD key.

`Descriptor key`

A 32-byte XChaCha20-Poly1305 key derived from an item root key with the canonical
descriptor-key HKDF context.

`Body key`

A 32-byte XChaCha20-Poly1305 key derived from an item root key with the canonical
body-key HKDF context.

`Key slot`

An HPKE envelope containing an item root key for one principal.

`Policy revision`

An owner-signed, hash-linked atomic change set.

`Item revision`

A writer-signed, hash-linked encrypted item generation.

`Proof`

The metadata, ciphertext digest, author, parent hash, and signature of an older
item revision after its ciphertext has been discarded.

`Checkpoint`

Local authenticated state recording the highest policy and item revisions seen
by one identity on one installation.

`Transfer`

A vault-only package for collaboration that never contains private identity or
local audit material.

`Backup`

Owner-only encrypted recovery material that includes a complete vault, owner
identity, local audit, and checkpoint.

## 9. Access model

### 9.1 Principal kinds

The wire model supports exactly these v3 principal kinds:

- `human`;
- `machine`.

Unknown kinds fail closed.

A human may hold owner authority.

A machine cannot hold owner authority in v3.0.

The rule avoids unattended policy-admin credentials in the first release.

### 9.2 Item roles

The wire model supports exactly:

- `reader`;
- `writer`.

`writer` includes `reader`.

Absence of a grant means no access.

There is no explicit `deny` entry because v3.0 has direct grants only.

Owner authority is vault-global rather than another per-item role.

Every active owner is an effective writer and reader of every active item.

### 9.3 Effective access

For an item and principal:

1. If the principal is an active owner, effective access is owner.

2. Otherwise, use the exact active direct grant for that principal and item.

3. Otherwise, deny access.

The policy validator rejects duplicate grants.

The validator rejects a key slot without effective reader access.

The validator rejects missing key slots for any effective reader, writer, or
owner.

The validator rejects multiple current slots for the same item, key epoch, and
principal.

### 9.4 Administration rules

Only an active owner under the previous accepted policy state may sign the next
policy revision.

Genesis contains exactly one human owner.

At least one human owner must remain active.

Adding an owner rotates and reseals every active item once, replaces every slot
set, and adds that principal under the new epoch in the same atomic policy
transaction.

Removing an owner rotates every active item root key to which the removed owner
had access and derives fresh content keys.

Owner revocation must be executed by a different remaining owner.

The owner being removed cannot authorize the command with its own selected
identity in v3.0.

The remaining acting owner signs every replacement item revision under the new
policy sequence, where that acting owner still has authority.

Removing a principal is prohibited while any direct grant or current key slot
still refers to it.

Principal registration may be combined with exact initial item grants and their
reader-set rotations in one owner-signed policy revision.

The transaction resolves every requested name through the owner's decrypted
catalog and commits all grants or none.

The CLI may offer an explicit `--revoke-all` workflow that performs all required
rotations, but it must present the complete item count and require interactive
confirmation or an explicit automation flag.

### 9.5 Role changes

Reader to writer:

- append an owner-signed policy revision;
- retain the same item root, derived keys, and slot;
- allow future item signatures by that principal.

Writer to reader:

- append an owner-signed policy revision;
- retain the same item root, derived keys, and slot;
- reject future item signatures from that principal under the new policy.

No access to reader or writer, and reader or writer to no access, are effective
reader-set changes. For either direction:

- owner unwraps and decrypts the current descriptor and item body;
- generate a new random item root key and derive its descriptor/body keys;
- increment key epoch;
- increment descriptor revision and reseal descriptor and item body with
  independent fresh nonces;
- create slots only for the complete new effective reader set;
- append an owner-signed policy revision binding the new epoch, replacement
  descriptor metadata, and new current item revision hash;
- append a new owner-signed item revision;
- persist both changes atomically.

Initial readers supplied during item creation do not require an extra rotation
because no earlier item ciphertext exists. A repeated grant that leaves the
effective role unchanged is rejected as a no-op. Reader-to-writer and
writer-to-reader changes retain the item root key and derived keys because the
effective reader set is unchanged.

Reader or writer to no access is called read revocation. No access to reader or
writer is called a read grant. Both are reader-set changes.

### 9.6 Item creation and deletion

An owner creates an item.

Initial creation generates an opaque item ID, item root key, derived descriptor
and body keys, key epoch one, encrypted descriptor revision one, item revision
one, and slots for every owner plus explicitly granted principals.

The creator may grant initial readers and writers in the same policy revision.

An item name must satisfy the existing canonical `VaultItem` rules.

An active item name must be unique.

The acting owner proves uniqueness by decrypting the descriptors of every active
item before creation or rename.

Public validation can prove stable-ID uniqueness and descriptor authenticity but
cannot prove plaintext-name uniqueness without an owner session.

Item deletion is an owner policy operation.

Deletion leaves a signed public tombstone containing item ID, deletion policy
sequence, final descriptor digest, and final item revision hash.

The current descriptor ciphertext, body ciphertext, and key slots are removed
from the live artifact.

The tombstone prevents the same historical item from silently reappearing.

It does not revoke retained copies.

### 9.7 Item and field renames

An item rename is an owner policy change because canonical names affect reference
routing and global uniqueness even though names are encrypted.

It increments the descriptor revision and re-encrypts only the small descriptor
with a fresh nonce under the descriptor key derived from the same item root key.

It does not rotate the item root key, change either derived key, or reseal the
item body.

A field rename is a writer item mutation.

Field names remain inside the encrypted item body.

Existing compatibility rules about source and destination references remain.

## 10. Cryptographic suite

### 10.1 Suite identifiers

The first v3 suite is named:

`jig-vault-v3-x25519-hkdfsha256-chacha20poly1305-ed25519-xchacha20poly1305`

It consists of:

- HPKE Base mode from RFC 9180;
- DHKEM(X25519, HKDF-SHA256);
- HKDF-SHA256 for domain-separated item-root expansion;
- ChaCha20-Poly1305 inside HPKE key slots;
- Ed25519 signatures with strict verification;
- XChaCha20-Poly1305 for item bodies;
- SHA-256 for revision digests and fingerprints;
- Argon2id plus XChaCha20-Poly1305 for local identity-file encryption.

The suite identifier is authenticated.

Unknown suite identifiers fail before private-key operations.

### 10.2 Library decision

Use an RFC 9180 implementation rather than constructing ECIES-like wrapping from
raw X25519, HKDF, and AEAD calls.

The preferred implementation candidate is `hpke` 0.14 with default features
disabled and only `alloc`, `x25519` (which selects HKDF-SHA2), and `chacha`
enabled. Do not enable the crate's `getrandom` feature: it exposes convenience
key-generation and sender-setup paths that panic when `SysRng` fails.

Because that dependency disables `x25519-dalek` defaults, the selected feature
set must explicitly enable `x25519-dalek/zeroize` (directly or through audited
feature unification) and prove that the concrete HPKE secret-key type implements
drop zeroization. Key generation and encapsulation must first seed a private,
non-exhausting `CryptoRng` only after the existing fallible `getrandom::fill`
boundary succeeds, then call only the `hpke` `*_with_rng` paths. The adapter must
not be a finite buffer whose exhaustion can panic, and its seed/state must be
zeroized where the selected compatible RNG permits. Entropy failures become
typed, non-secret vault errors before HPKE produces any partial output; tests
must inject that failure.

The preferred signing implementation is `ed25519-dalek` 3 with zeroization kept
enabled, strict verification, and neither `legacy_compatibility` nor `hazmat`.

Do not enable age plugin or SSH recipient support.

The `age` crate is not the preferred embedded format because its pre-1.0 API is
explicitly described as beta, its file format does not directly solve signed
per-item authorization, and its plugin surface has had command-execution
advisories.

Before the v3 wire format is frozen, the first delivery bead must prove:

- Rust 1.88 compatibility;
- exact feature trees;
- no unwanted ML-KEM, plugin, SSH, PKCS#8, PEM, legacy, or hazmat surfaces;
- private-key zeroization behavior;
- RFC known-answer vectors;
- deterministic cross-process fixtures;
- license compatibility;
- current RustSec status;
- acceptable dependency duplication with the existing
  `chacha20poly1305` 0.10 stack, or a safe workspace upgrade plan.

Failure of those checks blocks wire-format implementation and requires a recorded
cryptographic dependency decision before substitution.

The suite itself remains RFC 9180 plus Ed25519 even if the concrete crate changes.

### 10.3 Key generation

Generate independent random private keys for HPKE and Ed25519.

Do not derive one private key from the other.

Do not derive principal private keys from a human passphrase.

The passphrase only protects random private keys at rest.

Generate every item root key independently with the OS random source.

Never use an item root key directly as an AEAD key. Derive descriptor and body
keys only through the typed HKDF-SHA256 construction in section 10.6.

Generate a fresh item body nonce on every seal.

Generate a fresh HPKE encapsulation for every key slot.

### 10.4 Key identifiers and fingerprints

Each principal gets a random ULID principal ID.

Jig public descriptors admit exactly one application-level encoding for an
X25519 public key: the 32-byte little-endian `u` coordinate emitted by deriving
the public key from the stored private key, with the top bit clear and the
integer strictly below `2^255 - 19`. Descriptor import rejects alternate RFC
7748 encodings before fingerprinting, self-signature verification, duplicate-key
comparison, registration proof, or policy insertion. This application-level
wire restriction does not replace the HPKE primitive's required X25519 input and
all-zero shared-secret validation.

The public descriptor also has a SHA-256 fingerprint over a canonical encoding of:

- descriptor format version;
- principal ID;
- principal kind;
- HPKE public key;
- Ed25519 verification key.

The HPKE public-key field in that preimage is the canonical Jig encoding above.
Public-key uniqueness compares the canonical HPKE bytes and strict canonical
Ed25519 verification-key bytes independently of principal ID and fingerprint, so
an alternate encoding cannot evade duplicate-key rejection or masquerade as a
fresh key during principal replacement.

The descriptor includes an Ed25519 self-signature over that same
domain-separated canonical descriptor, excluding the signature field itself.

That self-signature proves control of the signing key only. Before policy
addition, the acting owner issues a single-use registration challenge containing
a random 32-byte response encrypted to the descriptor's HPKE public key. The
candidate identity decrypts it and signs a response transcript that binds the
vault ID, issuing owner, challenge ID, descriptor fingerprint, HPKE
encapsulation/ciphertext digest, and recovered response. The owner verifies its
own challenge signature, the exact recovered response, and the candidate
signature before committing `principal_add`.

Challenge and response use dedicated HPKE `info`, AAD, and signature domains.
They are portable public artifacts, contain no identity private material, are
bound to one vault and descriptor, and are consumed by the successful add. The
shared policy stores the descriptor and owner-authorized addition, not the
off-policy random response. Duplicate-principal validation prevents replay after
addition. A core principal-add API must receive a successfully verified proof;
raw wire replay still treats the preceding owner's signature as the public
authorization boundary.

Display fingerprints in a grouped lowercase representation.

Machine-readable output uses the full lowercase hex digest.

Import never trusts a user-supplied fingerprint field without recomputing it.

### 10.5 Domain separation

Every signature, hash, KDF, HPKE `info`, HPKE AAD, and XChaCha20-Poly1305 AAD has
a distinct ASCII domain prefix.

The v3 implementation must provide one module of typed preimage builders.

Callers must not concatenate free-form strings ad hoc.

Every variable-length field is length-prefixed by its UTF-8 or byte length.

Every integer uses fixed-width big-endian encoding in cryptographic preimages.

Lists are encoded in validated canonical order.

JSON bytes are never signed directly.

This avoids dependence on serializer whitespace or object-key ordering.

Before the wire format freezes, `format_v3` must document the exact byte layout
for every preimage: domain-prefix bytes, discriminant/tag bytes, field order,
integer widths, length widths, optional-value encoding, and list ordering. A
checked-in generic vector corpus must contain exact hexadecimal preimages,
digests, item-subkey HKDF contexts and outputs, HPKE `info`/AAD, XChaCha AAD,
descriptor bytes, and strict Ed25519 signatures for every variant. Tests compare
production builders byte-for-byte with vectors produced by an independent
fixture encoder rather than round-tripping through the same builder.

### 10.6 Item descriptor and body encryption

Each item key epoch has one independently random 32-byte item root key. The root
is input keying material for HKDF-SHA256 and is never passed directly to
XChaCha20-Poly1305.

Derive the epoch pseudorandom key and two 32-byte AEAD keys as follows:

```text
item_prk = HKDF-Extract(salt = none, IKM = item_root_key)
descriptor_key = HKDF-Expand(item_prk, descriptor_key_context, 32)
body_key = HKDF-Expand(item_prk, body_key_context, 32)
```

`descriptor_key_context` is the canonical typed preimage containing:

- domain `jig-vault-v3-item-descriptor-key`;
- suite ID;
- vault ID;
- item ID;
- key epoch.

`body_key_context` has the same typed fields in the same order but uses domain
`jig-vault-v3-item-body-key`.

The contexts intentionally omit descriptor and item revision numbers so each
derived key remains stable within one key epoch. Every seal still requires a
fresh nonce. Reusing a nonce across descriptor and body domains does not reuse a
key. Policy replay rejects reuse of a descriptor nonce within the same item,
epoch, and descriptor-key domain; item-proof replay rejects reuse of a body nonce
within the same item, epoch, and body-key domain.

The implementation exposes distinct non-interchangeable root-key,
descriptor-key, and body-key types. Root and derived output keys use zeroizing
storage. The HKDF object remains in the shortest possible scope and is dropped
immediately; B01 must document whether the selected provider zeroizes its
internal PRK/HMAC state rather than claiming a guarantee the dependency does not
provide. A narrowly scoped mutation may retain the root only while it creates the
corresponding recipient slots.

Each item then has two independently nonced XChaCha20-Poly1305 ciphertexts:

- a small descriptor ciphertext containing `ItemDescriptorV1`, encrypted with
  `descriptor_key`;
- the existing field-body ciphertext containing `ItemStateV1`, encrypted with
  `body_key`.

`ItemDescriptorV1` has one canonical 256-byte binary plaintext encoding:

- byte 0 is descriptor schema version one;
- bytes 1 through 2 are the unsigned 16-bit big-endian UTF-8 name length;
- bytes 3 through 66 are a 64-byte name region containing the exact canonical
  item-name bytes followed by zero padding;
- bytes 67 through 255 are reserved zero bytes.

The decoder rejects a name length above 64, invalid UTF-8 or canonical item
syntax, a nonzero byte in either padding region, or any plaintext length other
than 256. Consequently every v3 descriptor ciphertext has the same length; the
public length is checked against that constant rather than treated as private
metadata.

Descriptor associated data binds:

- domain `jig-vault-v3-item-descriptor`;
- vault ID;
- item ID;
- key epoch;
- monotonically increasing descriptor revision;
- descriptor plaintext schema version.

Creation, rename, and every reader-set change use fresh descriptor nonces.

Rename increments the descriptor revision and replaces only descriptor
ciphertext.

Every reader-set change changes the item root key, derives a fresh subkey pair,
and therefore re-encrypts both descriptor and body under the next key epoch.

The owner-signed policy operation binds descriptor revision, nonce, ciphertext
length, and SHA-256 ciphertext digest.

Public validators authenticate those fields without learning the name.

Do not use a public hash, deterministic encryption, or name-derived item ID;
canonical environment names have a small guessable dictionary.

The item body uses XChaCha20-Poly1305 with a random 24-byte nonce and the derived
32-byte body key.

`ItemStateV1` is serialized as a four-byte big-endian logical-length prefix,
canonical body bytes, and zero padding to the smallest allowed plaintext bucket:
4 KiB, 8 KiB, 16 KiB, 32 KiB, 64 KiB, 128 KiB, 256 KiB, 512 KiB, 1 MiB, 2 MiB,
4 MiB, or 8 MiB. The decoder requires an exact bucket length, a representable
logical length, canonical body decoding within that prefix, and all-zero
remaining padding. No compression occurs before encryption.

The public envelope records the bucket ID and exact corresponding ciphertext
length, not the logical length. Capacity preflight includes base64/JSON overhead;
an item that cannot fit its next bucket under the 16 MiB artifact ceiling fails
before mutation. The 1 MiB per-field limit remains, while the 8 MiB padded-body
ceiling deliberately bounds aggregate fields in one item.

Its associated data binds:

- domain `jig-vault-v3-item-body`;
- vault ID;
- item ID;
- key epoch;
- item revision number;
- plaintext schema version.

It deliberately does not bind the encrypted mutable item name or descriptor
revision.

It deliberately does not bind the policy sequence because role-only policy
changes that preserve the effective reader set do not reseal unchanged item
content.

The signed item revision binds the policy sequence used to authorize the writer.

A writer may run `jig vault privacy cover --item ITEM`. It decrypts and
canonically reserializes the unchanged logical body, chooses the same bucket,
uses a fresh nonce, and publishes an otherwise ordinary signed item revision
with no public cover/no-op discriminator. Shared-state observers therefore
cannot distinguish that revision from a real same-bucket logical update by its
format. It still consumes one proof-history entry, changes the file, requires
redistribution, and records an explicit event only in the acting identity's
private local audit.

Cover reseals provide useful scheduled cover activity but do not conceal which
opaque item changed, policy mutations, artifact access/transport times, missed
schedule intervals, or comparisons with endpoints that know the plaintext.

### 10.7 Item key wrapping

Each key slot uses HPKE Base mode to encrypt exactly one 32-byte item root key to
one principal HPKE public key. Derived descriptor/body keys and the HKDF
intermediate are never stored in slots.

HPKE `info` binds:

- domain `jig-vault-v3-item-key-slot`;
- suite ID;
- vault ID;
- item ID;
- key epoch;
- recipient principal ID.

HPKE AAD binds:

- policy sequence that introduced the slot;
- recipient public-key fingerprint;
- exact role at that policy sequence.

Slots are contained in and authenticated by an owner-signed policy change.

Granting or revoking effective read access creates a new epoch and an entirely
new slot set. A new reader never receives the item root key used by any earlier
epoch.

### 10.8 Signatures

Policy revisions use Ed25519 signatures by an active owner.

Item revisions use Ed25519 signatures by a writer or owner authorized under the
referenced policy sequence.

Verification uses strict Ed25519 verification.

Reject non-canonical keys and signatures according to the selected library's
strict API.

Do not expose raw signing primitives.

### 10.9 Protected memory and dump exclusion

Private identity plaintext, item root keys, derived descriptor/body keys, HKDF
intermediates, decrypted item descriptors, canonical item names held by a
session, decrypted item bodies, serialized plaintext bodies, resolved field
values, signing keys, and HPKE secret keys must be held in zeroizing containers
wherever the Rust type system and selected dependencies allow.

Before passphrase capture, hardware-protector use, or any private-key operation,
the CLI/TUI process lowers `RLIMIT_CORE` to zero. Linux additionally sets
`PR_SET_DUMPABLE` to zero. Failure stops before unlock unless the operator uses
the explicit `--allow-unprotected-memory` emergency override and confirms the
degradation; non-interactive use additionally requires
`JIG_VAULT_ALLOW_UNPROTECTED_MEMORY=1`. This variable is removed before every
child process. Public validation/status commands do not need the override because
they never capture or derive secrets.

Add a page-dedicated, non-growing `ProtectedMemory` allocation owned by
`jig-vault`. Compact passphrases captured through Jig-owned input, Jig-generated
identity roots and private keys, signing keys, item roots, derived keys,
audit/checkpoint seeds, and RNG seeds enter it without a prior Jig-owned ordinary
`String`/`Vec` copy. External keychain, Secure Enclave, TPM, and FIDO APIs may
return short OS/library-owned buffers that Jig cannot allocate itself; copy those
immediately into `ProtectedMemory`, zero or release the source through the
provider API where supported, and record any unavoidable non-zeroizable provider
copy in that adapter's assurance documentation. No ordinary Jig-owned provider
copy may outlive the call. On Linux protected pages require
`mlock2(MLOCK_ONFAULT)` with a verified `mlock` fallback,
`MADV_DONTDUMP`, and `MADV_DONTFORK`; on macOS they require `mlock`, while the
process-wide zero core limit supplies the dump control. Guard pages and page-
rounded bounds prevent neighboring general allocations from being locked or
exposed. Setup is all-or-nothing and drop zeroizes before unlock/unmap. Linux
fork tests prove `MADV_DONTFORK` mappings are absent in the child. macOS code
must not execute user-controlled work between fork and exec; post-exec tests
prove the protected mappings are gone, while the zero core limit remains
inherited on both platforms.

If the supported OS cannot lock the compact protected allocation, unlock fails
closed unless the same explicit emergency override is active. JSON/human status
reports `required`, `active`, `degraded_by_override`, or `unsupported` without
addresses or secret-dependent detail. TUI sessions always keep their retained
identity material in protected pages and display persistent degraded state when
the override is used.

Bulk decrypted item bodies, serializer scratch, redaction copies, child-process
copies, and the 128–512 MiB Argon2 workspace remain short-lived zeroizing memory
but are not promised `mlock` coverage. Process-wide dump suppression covers
ordinary cores; encrypted swap/hibernation and privileged live-memory controls
remain deployment requirements. Documentation must not claim protection from
root, a debugger already controlling the process, suspend images, DMA, or an
authorized child that receives plaintext.

Public keys, opaque item IDs, hashes, signatures, and ciphertext need not be
zeroized.

Document unavoidable serializer and OS child-process copies just as the current
vault does.

Do not weaken `SecretBytes` non-growing allocation behavior.

## 11. Version 3 wire format

### 11.1 Top-level shape

The conceptual top-level structure is:

```text
VaultFileV3 {
  header: VaultHeaderV3,
  policy: PolicyJournalV1,
  items: map<ItemId, ItemEnvelopeV1>,
}
```

The actual persisted encoding remains pretty-printed JSON for operator
inspectability and continuity with v1/v2.

Secret-bearing and canonical item-name plaintext remains nested only inside item
ciphertext.

Serde types for v1, v2, and v3 must be separate.

Do not add a growing set of optional v3 fields to the v2 struct.

Parse the minimal discriminating header first, enforce the total byte limit, then
deserialize the version-specific body.

### 11.2 Header

`VaultHeaderV3` contains:

- `magic = "jig-vault"`;
- `version = 3`;
- `vault_id`;
- `created_at_ms`;
- `suite`;
- `policy_schema = 1`;
- `item_schema = 1`;
- `identity_schema = 1`;
- `genesis_fingerprint`.

The v3 header has no passphrase KDF, salt, wrapped vault DEK, or vault-wide state
nonce.

Those fields remain only in v1/v2 types.

`genesis_fingerprint` is the SHA-256 digest of the canonical signed genesis
record.

### 11.3 Policy genesis

`PolicyGenesisV1` contains:

- vault ID;
- policy sequence zero;
- creation timestamp;
- suite ID;
- exactly one human owner public descriptor;
- empty opaque item inventory;
- empty grants;
- zero previous-policy hash;
- genesis owner signature.

For a v2 migration only, genesis also contains an authenticated
`source_migration` attestation with source version, migration ID, SHA-256 digest
of the final preserved legacy audit bytes, and the verified terminal legacy
audit MAC.

For a v3 rollover only, genesis instead contains an authenticated
`source_rollover` attestation with the source vault ID, source genesis
fingerprint, terminal source vault revision, rollover ID, and the acting source
owner's signature over that complete bridge plus the destination vault ID and a
canonical unsigned bootstrap-manifest digest. The manifest commits the complete
destination principals, owners, grants, items, and ciphertext metadata created
by its first policy revision. It excludes all signatures and the genesis
fingerprint, avoiding a hash/signature cycle. New v3 vaults omit both
attestations, and a genesis containing both is invalid.

The owner self-signature provides integrity, not third-party identity proof.

The first import is trust on first use.

The CLI must show and optionally require the owner fingerprint during first
installation.

### 11.4 Policy journal

`PolicyJournalV1` contains genesis plus an ordered list of
`SignedPolicyRevisionV1`.

Every revision contains:

- monotonically increasing sequence;
- previous policy revision hash;
- timestamp;
- author principal ID;
- an ordered non-empty list of typed operations;
- resulting normalized policy-state hash;
- signature.

The validator replays the journal from genesis.

It checks author authority before applying each operation.

It computes the resulting normalized state and compares its hash.

It rejects sequence gaps, duplicate sequences, empty changes, unknown operations,
invalid transitions, and trailing unreferenced material.

### 11.5 Policy operations

The first schema supports these typed operations:

- `principal_add`;
- `principal_label_change`;
- `principal_remove`;
- `owner_grant`;
- `owner_revoke`;
- `item_create`;
- `item_rename`;
- `item_delete`;
- `item_role_change`;
- `item_reader_set_change`;
- `item_slots_replace`;
- `principal_replace`.

An API-level transaction may encode several operations in one revision.

`item_create` and `item_rename` bind the resulting descriptor revision, key
epoch, nonce, ciphertext length, and ciphertext digest.

`item_reader_set_change` represents any change to effective reader membership,
including item grant/revoke, owner grant/revoke, or the simultaneous old-key/
new-key substitution in `principal_replace`. It binds the exact prior and next
reader IDs, replacement descriptor metadata, and replacement current body
revision because both ciphertexts move to keys derived from the new item root.

`principal_replace` atomically substitutes a fresh principal descriptor for an
existing principal and copies its kind, label, direct grants, and owner status.
It must be paired with exactly one reader-set change and slot replacement for
every item the old principal could read, so old and new HPKE keys never share an
item epoch. The old principal is absent from the resulting normalized state.

The validator enforces legal combinations.

For example, `item_reader_set_change` must be paired with
`item_slots_replace` for the next epoch and must bind the replacement current
item revision hash. Neither operation is legal alone, and a reader-set change
may not retain the prior item root key or any prior-epoch slot.

Unknown operation names fail closed.

### 11.6 Normalized policy state

Journal replay produces:

- active principals by principal ID;
- active owners;
- active opaque items by item ID, kind, and authenticated descriptor metadata;
- item tombstones;
- direct item grants;
- current key epoch per item;
- current key slots per item and recipient;
- current item revision hash expected after policy-bound rotations.

All maps are deterministically ordered.

No plaintext item name or field metadata appears in normalized policy state.

### 11.7 Item envelope

`ItemEnvelopeV1` contains:

- stable item ID;
- current descriptor revision;
- current descriptor nonce;
- current descriptor ciphertext;
- zero or more prior revision proofs;
- exactly one current signed item revision;
- current item body nonce;
- current item ciphertext.

The public policy state contains only the expected descriptor metadata.

An authorized session unwraps the item root key, derives the descriptor key, and
decrypts the descriptor to obtain the canonical name. It discards the root,
HKDF intermediate, and descriptor key after catalog construction unless the
same narrowly scoped operation immediately needs the root for another authorized
purpose.

The item map key and all embedded IDs must agree with the envelope item ID.

The map key must equal the embedded item ID.

Every key slot also records the policy sequence and effective role under which it
was issued so its HPKE AAD remains reproducible after a later reader/writer role
change that intentionally retains the same slot.

### 11.8 Item revision

`SignedItemRevisionV1` contains:

- vault ID;
- item ID;
- monotonically increasing item revision number;
- one previous item revision hash, or the zero hash for creation;
- key epoch;
- policy sequence used for authorization;
- author principal ID;
- timestamp;
- item body nonce;
- ciphertext length;
- SHA-256 ciphertext digest;
- plaintext schema version;
- Ed25519 signature.

The ciphertext is stored beside the current revision rather than inside the
signed metadata.

The validator recomputes its digest and length.

### 11.9 Revision proofs

When an item is updated, the previous current revision becomes a proof.

A proof preserves the complete signed revision metadata and signature.

It discards the prior ciphertext bytes after retaining their digest and length in
signed metadata.

It retains the prior public nonce because that nonce is part of the signed
revision preimage.

Proofs form a complete chain from revision one to the parent of current.

This lets a fresh recipient validate authorship and ancestry without receiving
old secret ciphertext.

It also lets a transfer importer determine whether one branch is a strict
descendant of another.

The validator rejects missing proof links, duplicate revision numbers, parent
hash mismatches, policy references outside the validated journal, and authors who
lacked writer authority at their referenced policy sequence.

### 11.10 Item plaintext

`ItemStateV1` contains:

- plaintext schema version one;
- a deterministic map from field name to `ItemFieldV1`.

`ItemFieldV1` contains:

- base64 field value;
- exact decoded value length;
- field kind;
- creation timestamp;
- update timestamp.

The item ID and name are not duplicated in the field-body plaintext.

Field references are reconstructed from the decrypted current item descriptor
plus decrypted field name.

Decoded lengths and all existing concealed/text validation rules are rechecked
after decryption.

### 11.11 Legacy compartment

Unrepresentable legacy names migrate into one reserved owner-only compartment.

The compartment has a generated stable item ID and policy kind `legacy`.

It does not claim a canonical `VaultItem` name.

Its encrypted descriptor contains the reserved owner-visible display label
`(legacy)`.

Its body stores the existing legacy name map and metadata.

Only owners receive key slots.

The compatible `vault secret` commands route a representable legacy name to its
canonical item/field and enforce that item's role.

Only an unrepresentable name routes to this owner-only legacy compartment.

Conversion to a canonical field is one atomic owner operation touching the legacy
compartment, destination item, item revisions, and local audit.

### 11.12 Bounds

Retain the existing 16 MiB persistent `vault.json` read/write ceiling for the
first release.

Retain the 1 MiB per-field value limit and existing concealed minimum.

Retain the 1,024-field import limit.

Add explicit parse-time caps for:

- 256 active principals;
- 1,024 active plus tombstoned items;
- 16,384 active direct grants;
- 16,384 current key slots;
- 4,096 policy revisions;
- 65,536 item revision proofs across the artifact;
- 256 bytes per public label;
- exactly 256 plaintext bytes per encrypted item descriptor, retaining the
  existing 64-byte canonical item-segment limit;
- fixed encoded lengths for every key, nonce, digest, and signature.

The total 16 MiB limit remains authoritative even when individual count limits
would allow more. Public JSON framing is deliberately not padded: a parseable
padding field would reveal its own length and let an artifact holder recover the
unpadded public size. Exact public artifact/transfer length remains a documented
leak while encrypted item bodies hide their logical lengths within buckets.

Deserializers must reject oversized base64 text before decoding to avoid
allocation amplification.

The implementation may propose a larger file cap only with benchmark evidence,
documented backup implications, and an explicit plan amendment.

Every mutation preflight computes its resulting policy, item-proof, slot, item,
and total encoded-size counts before writing. A mutation that would cross a hard
cap fails with the typed `Capacity` error and an exact `jig vault history
rollover` next step; it never commits a state that cannot still be rolled over.
Rollover itself reads but does not grow the source and therefore remains
available at a source cap.

### 11.13 Authenticated history rollover

V3 does not prune or rewrite a vault's signed policy or item-proof ancestry in
place. An explicit owner-only rollover creates a new v3 lineage in an absent
vault home.

The rollover validates and checkpoints the source, decrypts its current logical
state as an owner, and creates a new vault ID, genesis fingerprint, item IDs,
item root keys, derived key pairs, nonces, ciphertexts, and revision-one chains.
It reproduces only active
principals, owners, direct roles, current item descriptors/bodies, and the
owner-only legacy compartment. Tombstones and prior policy/item proofs stay
available in the unchanged source rather than being copied as live history.

Current effective readers receive new-lineage slots; removed principals do not.
The new genesis carries the signed `source_rollover` bridge from section 11.3.
That bridge authenticates provenance but does not make the new vault the same
lineage: transfer merge rejects cross-lineage updates, and each installation
must explicitly trust/install the new genesis fingerprint.

Rollover writes only to hardened absent destinations, supports a complete
dry-run, never replaces or deletes the source, and emits exact backup,
redistribution, and old-lineage retention guidance. A fresh owner backup and
fresh local export receipt are required for the new lineage; an old backup does
not claim to cover it.

## 12. Identity lifecycle

### 12.1 Storage location

Private identities live outside every vault home.

The default identity root is independent from every vault base and home:

`~/.jig/vault-identities/`

`JIG_VAULT_IDENTITY_HOME` overrides that identity root.

It must not equal, contain, or be contained by the selected vault home.

In particular, identities cannot live below the legacy/global
`~/.jig/vault` home.

The default named identity file is:

`<identity-root>/default.identity.json`

An explicit `--identity NAME` resolves only the validated local name
`<identity-root>/<NAME>.identity.json`.

An explicit `--identity-file PATH` is the unambiguous path override.

`JIG_VAULT_IDENTITY` is the non-interactive name override.

`JIG_VAULT_IDENTITY_FILE` is the non-interactive path override.

The identity name, identity-file, and identity-home overrides are captured and
removed from child environments alongside reserved passphrase variables.

An explicit vault `--home` does not move the identity into that vault home.

### 12.2 Identity file

The public portion contains:

- magic and identity format version;
- principal ID;
- principal kind;
- HPKE public key;
- Ed25519 verification key;
- recomputable fingerprint;
- identity creation time;
- KDF profile ID, exact Argon2id version/parameters, and salt;
- protection mode and bounded provider metadata;
- identity-root wrap algorithm and nonce;
- private-payload AEAD algorithm and nonce.

The encrypted private payload contains:

- HPKE private key;
- Ed25519 signing key;
- random 32-byte local audit/checkpoint seed.

Generate a random 32-byte identity root. A domain-separated HKDF-SHA256 payload
key derived from that root encrypts the private payload with
XChaCha20-Poly1305. The passphrase/device unlock key wraps only the identity root
under a separate XChaCha20-Poly1305 nonce. Root and payload keys are distinct
non-interchangeable types.

Associated data binds every public identity-file field and a payload role.

The public header records a KDF profile ID, the exact Argon2id version and
parameters, and a 16-byte random salt. V3 admits only these exact profiles:

- `portable-v1`: Argon2id version 1.3, 131,072 KiB memory, three passes, four
  lanes, and a 32-byte output;
- `hardened-v1`: Argon2id version 1.3, 524,288 KiB memory, three passes, four
  lanes, and a 32-byte output.

`portable-v1` is the mandatory interoperable default and minimum for every new
v3 identity and backup. `hardened-v1` is an explicit operator choice using the
current implementation's maximum accepted memory. It is a Jig profile, not a
claim to implement RFC 9106's first recommended profile (2 GiB, one pass, four
lanes). Jig's portable profile already exceeds that RFC's memory-constrained
profile (64 MiB, three passes, four lanes) while retaining three passes. Raising
the pre-authentication memory ceiling requires supported-platform and peak-RSS
evidence plus a new profile ID; implementations never silently reinterpret an
existing profile.

Before allocating Argon2 memory or capturing a passphrase, decode bounded scalar
fields and require an exact recognized profile-ID/parameter tuple. A known ID
with changed parameters, an unknown ID, arbitrary in-range parameters, excessive
parallelism, or an over-ceiling memory request fails as a typed format error.
Legacy identity and backup versions retain their version-specific validation and
must not inherit broader v3 limits.

The 12-byte minimum passphrase remains an input floor, not an entropy claim.
Human guidance recommends generated multi-word passphrases and explains that KDF
cost cannot compensate for a guessable passphrase.

Changing the identity passphrase generates a new KDF salt, identity root, root-
wrap nonce, and payload nonce and re-encrypts the same private payload. It is
storage-credential rotation, not HPKE or Ed25519 key rotation, and it does not
prevent the unchanged HPKE private key from opening matching slots in retained
historical artifacts.

Passphrase change defaults to the stronger of the identity's recognized current
profile and `portable-v1`; it upgrades any supported legacy/weaker profile and
never silently downgrades `hardened-v1`. Operators may request
`--kdf-profile hardened`. A portability downgrade requires both
`--kdf-profile portable` and `--allow-kdf-downgrade`, plus an interactive warning
or the existing non-interactive confirmation contract. Reads report an available
profile upgrade but never rewrite an identity as a side effect.

#### Device-bound identity protection

Identity protection mode is exactly one of:

- `portable`: the profile-derived passphrase key is domain-separated with HKDF
  to form the identity-root wrap key;
- `device-bound`: unlock requires both the profile-derived passphrase key and one
  enrolled protector response. HKDF-Extract uses the passphrase key as salt and
  the normalized 32-byte protector response as input keying material, then an
  exact context binding identity format, principal ID, protection mode, provider
  kind, opaque credential ID, and provider challenge/salt derives the wrap key.

There is one active protection method and one wrapped identity root. A device-
bound identity never retains a passphrase-only recovery slot, cached protector
response, exported hardware private key, biometric data, PIN, or TPM/FIDO
authorization secret. Provider metadata is local identity-header data and never
enters shared vault policy, transfers, audit details, or child environments.

Support these versioned providers behind one typed `IdentityProtector` boundary:

- `keychain-v1`: a random 32-byte factor stored under application-scoped OS
  keychain access control. macOS Keychain and Linux Secret Service adapters are
  labeled `os-protected`, not automatically `hardware-backed`;
- `secure-enclave-p256-v1`: macOS Secure Enclave P-256 key agreement against an
  identity-bound peer public point, with the non-exportable private key stored by
  Keychain and user presence/verification required for human identities;
- `tpm2-sealed-v1`: a random 32-byte factor sealed and unsealed through a direct
  TPM 2.0 TSS API under a recorded bounded policy. The default binds to the TPM
  and object authorization, not volatile PCR values; a PCR-bound policy requires
  a separately versioned profile plus tested firmware-update and backup recovery.
  Jig never shells out to `tpm2-tools` with secret material;
- `fido2-hmac-secret-v1`: a credential-scoped CTAP2 `hmac-secret`/PRF response to
  the identity-bound 32-byte challenge, requiring user presence and verification
  for human identities.

The provider returns only a normalized factor into `ProtectedMemory`; it never
receives the passphrase, identity root, HPKE/signing private keys, or decrypted
item data. Status reports the provider kind, assurance class (`os-protected` or
`hardware-backed`), presence/verification policy, availability, and opaque
credential fingerprint without hardware serial numbers or attestation claims.
Unknown providers, algorithms, policy fields, response lengths, or credential
substitution fail before identity-root unwrap.

Each adapter must meet Rust 1.88, direct-API/no-secret-shellout, bounded
cancellation, temporary-buffer accounting, and real-device conformance
requirements. If an advertised adapter cannot meet them, implementation stops
and records that provider as unavailable; it must not silently substitute an OS
keychain or label software storage as hardware-backed. Removing a required
provider from the release needs an explicit plan amendment.

Enrollment, rebind, or removal first unlocks the existing method, verifies a
current owner-backup receipt or emits an explicit recovery warning, then creates
a fresh identity root/salt/nonces and atomically replaces the identity file.
Removing a protector requires `--allow-portable-downgrade` plus confirmation.
Provider cancellation, timeout, lockout, removal, or device loss never falls
back to passphrase-only unlock. Recovery decrypts an independent owner backup and
enrolls a replacement protection method while resealing the same principal keys.

Human FIDO2 and Secure Enclave modes require user presence/verification on every
unlock. Machine identities may use TPM2 or an explicitly non-interactive
keychain policy; status and documentation state the reduced physical-presence
property. No provider is silently selected from ambient devices.

### 12.3 Identity commands

Add:

```text
jig vault identity init [--name NAME] [--kind human|machine] [--label LABEL] \
  [--kdf-profile portable|hardened] \
  [--protection portable|keychain|secure-enclave|tpm2|fido2] \
  [--protector ID]
jig vault identity list
jig vault identity status [--name NAME]
jig vault identity public [--out FILE] [--overwrite]
jig vault identity prove --challenge CHALLENGE --out PROOF [--overwrite]
jig vault identity passphrase change [--kdf-profile portable|hardened] \
  [--allow-kdf-downgrade]
jig vault identity protection status
jig vault identity protection enroll --provider PROVIDER [--protector ID]
jig vault identity protection rebind [--protector ID]
jig vault identity protection remove --allow-portable-downgrade
```

`identity init` refuses an existing destination.

Identity names use a strict portable component grammar, never contain path
separators, and are not security identities.

It prompts twice or consumes the existing non-interactive new-passphrase policy.

It prints principal ID and fingerprint, never private keys.

`identity status` does not decrypt private keys. It reports the public header's
profile ID, exact parameters, and whether a stronger supported profile is
available, plus protection/provider metadata and local provider availability,
while marking file fields unauthenticated until a later unlock succeeds. Public-
header inspection never claims that the passphrase, hardware response, or private
payload is valid and never invokes a protector.

`identity list` scans only direct identity-root children matching the canonical
filename grammar, validates their public headers, and never unlocks or probes
private material.

Human output always identifies the selected vault, identity name, label, kind,
and grouped fingerprint before a protected mutation.

Labels are display-only and never resolve authorization targets.

`identity public` exports only a signed/self-consistent public descriptor through
the existing hardened private-file sink.

The public descriptor contains no claim that a label is verified identity.

`identity prove` validates the owner-signed, vault- and descriptor-bound
registration challenge, decrypts its HPKE payload with only the selected
identity, and writes the signed public proof through the same hardened sink. It
never emits the recovered response to terminal, JSON, audit, or diagnostics.

### 12.4 Principal key replacement

Principal public keys are immutable. Rotation creates a fresh identity with a
fresh principal ID and atomically replaces the old principal through the
`principal_replace` transaction; there is no in-place key edit.

The acting owner verifies a fresh registration proof for the new descriptor.
The transaction copies the old principal's kind, display label, direct roles,
and owner status, rotates every item readable by the old principal exactly once,
issues slots to the resulting reader set using only the new key, and removes the
old principal. Any partial copy or surviving old slot is invalid.

Replacement establishes post-compromise recovery only for the newly created item
epochs. Retained earlier vaults, transfers, backups, or ciphertext remain within
the old HPKE key's exposure and must not be described as revoked.

If the old principal is an owner, a different remaining owner must authorize the
replacement, and at least one such owner must remain. Operators should maintain
two human owners before a sole-owner key needs replacement; v3.0 has no
cryptographic way to distinguish a legitimate sole owner from an attacker who
already controls that owner's signing key.

### 12.5 Passphrase compatibility

For v1/v2, `JIG_VAULT_PASSPHRASE` unlocks the vault envelope as today.

For v3, `JIG_VAULT_PASSPHRASE` supplies the knowledge factor for the selected
local identity. A device-bound identity also invokes its exact recorded protector;
the environment variable alone is insufficient and no environment variable may
supply the provider response, PIN, biometric data, or presence assertion.

The CLI prompt changes from `Vault passphrase` to `Identity passphrase` after
detecting v3 from the public header.

`jig vault passphrase change` remains a compatibility alias.

On v3 it changes only the selected identity-file passphrase and returns explicit
JSON fields showing `target = "identity"`.

The preferred documented spelling becomes
`jig vault identity passphrase change`.

### 12.6 Multiple identities

The default release supports one explicitly named or explicitly pathed selected
identity per command and per TUI session.

It does not automatically try every identity file.

Automatic probing would leak membership through timing and multiply passphrase
prompts.

If the selected principal is absent from policy, return a safe principal-not-
registered error.

If it is registered but lacks an item slot, return item access denied.

There is no mutable project-local “current identity” pointer in v3.0.

Scripts and operators select a non-default identity explicitly, preventing a
checkout from silently switching a global identity.

### 12.7 Machine identities

Machine identities use encrypted identity files and the same passphrase capture
environment as humans.

They do not use bearer tokens in v3.0.

Automation supplies `JIG_VAULT_IDENTITY` or `JIG_VAULT_IDENTITY_FILE` plus
`JIG_VAULT_PASSPHRASE` through its own secret mechanism.

An explicitly enrolled TPM2 or non-interactive keychain protector may supply the
second factor. FIDO2 and human-presence policies are not suitable for unattended
automation and never downgrade themselves when no user is present.

Both variables are removed before child execution.

Machine identity documentation must emphasize filesystem permissions, CI secret
storage, and rotation.

### 12.8 Identity loss

Losing the only owner private identity without an owner backup makes policy
administration and owner-only item recovery impossible.

This is an intentional cryptographic property.

The CLI warns at vault creation and owner addition until a successful owner backup
has been created locally.

The warning state is local metadata, not a bypass.

## 13. Policy validation

### 13.1 Validation order

Opening a v3 vault performs these steps before item decryption:

1. Read `vault.json` under the existing total byte cap.

2. Parse and validate the minimal header.

3. Enforce suite and schema support.

4. Decode fixed-size public keys, hashes, and signatures with strict lengths.

5. Validate genesis self-signature and header fingerprint.

6. Replay every policy revision from genesis.

7. Validate normalized policy invariants.

8. Validate each item proof and current revision signature against historical
   policy authority.

9. Validate opaque inventory completeness, authenticated descriptor metadata,
   and tombstones without decrypting names.

10. Load and authenticate the selected local checkpoint.

11. Reject policy or item revisions older than the checkpoint.

12. Locate the selected principal and, when name routing or item inventory is
    requested, build an accessible catalog by unwrapping only that principal's
    granted item slots and decrypting only their small descriptors.

13. Discard catalog-build item roots, HKDF intermediates, and descriptor keys
    after descriptor decryption. If the same operation immediately opens that
    item body, retain only the derived body key required by the item guard.

14. Decrypt and validate only requested item bodies, except operations that
    explicitly require several items.

The accessible catalog maps canonical item names to stable item IDs and roles.

It rejects duplicate decrypted names within the selected principal's accessible
set.

An owner catalog covers every active item and is therefore the authority used to
enforce global name uniqueness before owner mutations.

The first v3 implementation intentionally chooses bounded descriptor scanning
over a duplicated per-principal encrypted index.

The descriptor scan touches only small ciphertexts and avoids catalog fan-out on
every grant, rename, and revoke; B18 must benchmark it at the declared item
scales.

### 13.2 Historical authority

An item revision references a policy sequence.

The validator checks writer authority in the replayed state at that exact
sequence.

An item revision may remain current after later role removal.

It does not become invalid merely because its author is no longer a writer.

A new item revision must reference the current accepted policy sequence.

This prevents a removed writer from authoring against an old policy after the
local client has accepted the removal.

### 13.3 Fork rules

Policy history must be linear.

Two policy journals that diverge after a common sequence are a policy fork.

No automatic merge is allowed.

Item history is linear per item.

Two revisions with the same parent are an item fork.

Different items may advance independently under the same policy and can be
merged.

The transfer importer accepts only strict ancestry or independent-item progress.

It rejects same-item and policy forks with metadata-only conflict details.

### 13.4 Local checkpoint

Each selected identity maintains a local authenticated checkpoint for each vault
ID.

The checkpoint records:

- highest accepted policy sequence and hash;
- highest accepted current revision number and hash for every active item;
- accepted tombstones;
- last successful transfer ID when applicable.

The checkpoint is authenticated with HMAC-SHA256 using a key derived by HKDF from
the identity's local seed and vault ID.

It lives under:

`<vault-home>/local/<principal-id>/checkpoint.json`

It contains no secret values.

The containing directory and file use existing private path protections.

Checkpoint update follows successful vault verification and, for mutation, the
atomic vault write.

A checkpoint write failure after a successful vault mutation is reported as a
committed-primary-action plus recovery warning, matching the TUI's existing
committed-action distinction.

The next open may safely advance a behind checkpoint after validating the vault's
chains.

It must never silently lower a checkpoint.

### 13.5 Fresh installation trust

Installing a transfer into an absent vault home has no local freshness history.

The importer validates all signatures and then presents:

- vault ID;
- genesis owner principal ID;
- genesis owner fingerprint;
- current policy sequence;
- selected principal's accessible decrypted item names and effective roles.

Interactive installation requires exact fingerprint confirmation.

Automation requires `--trust-genesis-fingerprint FULL_HEX`.

This is trust on first use.

Organizations needing stronger provenance must distribute the fingerprint through
an independent trusted channel.

## 14. Partial unlock and core API

### 14.1 Open states

Replace the single full-state `OpenVault` assumption with staged internal states:

```text
ParsedVault
  -> ValidatedPublicVault
  -> PrincipalVaultSession
  -> one or more UnlockedItem guards
```

`ValidatedPublicVault` contains only public policy, opaque item IDs, ciphertext,
hashes, and signatures.

`PrincipalVaultSession` holds the selected unlocked identity and an on-demand
accessible descriptor catalog containing only names that identity may decrypt.

`UnlockedItem` holds one derived body key and decrypted item body in zeroizing
storage. It does not retain the item root key.

Dropping an item guard wipes its derived body key and plaintext.

Do not decrypt any item body during ordinary open.

Name-based routing and item browsing may decrypt every accessible small
descriptor, but never an inaccessible descriptor or an untargeted item body.

An explicit aggregate snapshot or unfiltered field list may decrypt every
accessible item to produce its documented accessible field rows; that is a
bounded caller-requested multi-item operation, not an implicit session-open side
effect.

### 14.2 Snapshot contract

Evolve `VaultSnapshot` without exposing inaccessible field metadata.

Add an accessible item row shape containing:

- stable item ID;
- decrypted item name or legacy label;
- selected principal's effective role: `owner`, `writer`, or `reader`;
- key epoch;
- current item revision number;
- optional field count only when the caller explicitly decrypts that item body;
- optional updated timestamp only when the caller explicitly decrypts that item
  body.

The snapshot's accessible field records contain the existing metadata.

Inaccessible opaque envelopes contribute no item rows, names, counts, timestamps,
or `FieldRecord` values.

Legacy metadata is present only for owners who unlock the legacy compartment.

The existing `fields` projection remains for source compatibility where
possible, but callers must switch item browsing to the new item rows.

### 14.3 Revision contract

For v3, `VaultRevision` becomes an opaque digest of:

- vault ID;
- current policy hash;
- every active item ID and current item revision hash in sorted order;
- every tombstone in sorted order.

Do not expose the digest representation publicly.

Optimistic mutation and import preconditions continue to compare exact
authenticated state under the lock.

### 14.4 Error taxonomy

Add stable error kinds:

- `AccessDenied`;
- `Conflict`;
- `Capacity`;
- `Unsupported`.

Use `Authentication` for wrong identity passphrase or failure to unwrap a slot
that should belong to the selected principal.

Use `AccessDenied` when policy grants no item read or write authority.

Use `Conflict` for stale revisions, transfer forks, and checkpoint rollback.

Use `Capacity` when a valid current state cannot accept a requested mutation
without crossing a hard count or encoded-size cap. Report only safe counts and
the exact history-rollover next step.

Use `Serialization` or `Authentication` for malformed or invalidly signed shared
state according to whether structure or authenticity failed.

Use `Serialization` for duplicate canonical names discovered inside an
authenticated accessible descriptor set; never choose one ambiguous item.

Error messages must never confirm an item name or include a field name when the
selected identity cannot resolve that name through its accessible catalog.

For either an inaccessible item named `Production` or a nonexistent name supplied
by the caller, return the same `AccessDenied` kind and a message such as
`vault item 'Production' is unavailable for selected identity`.

The echoed name is caller input, not confirmation that the item exists.

Do not distinguish inaccessible from nonexistent item names or disclose whether
a requested field exists inside an inaccessible item.

### 14.5 Mutation authorization

Every core mutation method determines all touched items before decrypting or
writing.

It checks effective roles for all touched items.

It verifies current policy, item chains, local audit, and checkpoint under the
same vault edit lock.

It decrypts only touched items.

It appends local audit intent before saving new shared state.

It signs item or policy revisions as required.

It writes one complete `vault.json` atomically.

It advances the local checkpoint.

Crashes may leave local audit intent ahead of state as today.

State must not lead the authenticated item/policy signatures embedded in that
same state.

### 14.6 Multi-item operations

Legacy conversion, owner grant/revoke, principal revoke-all, and some transfer
merges touch multiple compartments.

They preflight every required item slot and body before the first durable write.

They retain all decrypted bodies in bounded zeroizing containers only for the
transaction lifetime.

If any item cannot be decrypted, authorized, validated, or resealed, no shared
state is written.

## 15. Local operational audit

### 15.1 Split authenticity from activity

The embedded policy and item signature chains are the portable authenticity
record.

The local audit remains an operational activity record for reads, injections,
execs, runs, imports, backups, identity actions, and failures.

Do not export local audit in a normal transfer.

### 15.2 Per-principal audit path

V3 audit events live at:

`<vault-home>/local/<principal-id>/audit.jsonl`

The HMAC key is derived from the selected identity's local seed and vault ID.

This avoids a new vault-wide audit key that every principal would need.

It also prevents two principals sharing one machine from accidentally treating
each other's local chain as their own.

### 15.3 Audit schema

Bump local audit event version for v3.

Every v3 event includes safe metadata for that selected principal:

- principal ID;
- vault ID;
- current policy sequence;
- operation ID;
- action;
- item ID and decrypted item name only when the selected principal already
  resolved that descriptor for the successful action;
- outcome or failure stage;
- previous MAC and MAC.

Never record field values.

Continue recording accessible field references where the selected principal
already decrypted the item and the action-specific projection permits it.

Do not record guessed item or field names when access fails at the item
boundary.

### 15.4 Audit verification

`vault audit verify` verifies the selected principal's local v3 log.

It also reports the presence and terminal MAC of a preserved v1/v2 audit when a
migration archive exists.

Because the v2 DEK-derived audit key is deliberately discarded after migration,
later verification recomputes the archive byte digest and compares it with the
owner-signed `source_migration` attestation.

The output labels this `migration-attested legacy archive`, not a freshly
recomputed v2 HMAC verification.

The command clearly labels each as local evidence.

It does not claim to verify other principals' activity.

### 15.5 Checkpoint relationship

Audit and checkpoint use separate HKDF subkeys from the local identity seed.

The checkpoint stores the latest local audit MAC.

The audit genesis stores the initial checkpoint digest.

This binds the two local files for ordinary tamper detection while retaining the
documented deletion/rollback limitation.

### 15.6 Audit scalability

Do not add audit rotation to this feature.

Preserve the existing 256 MiB cap and full-chain verification behavior unless a
separate concrete performance change is justified.

Benchmarks in the hardening bead must measure the added public-chain validation
cost separately from local audit cost.

### 15.7 Authenticated local operation receipts

V3 keeps bounded local-only operation evidence at:

`<vault-home>/local/<principal-id>/receipts.json`

The file is authenticated with a distinct HKDF-derived HMAC key from the selected
identity seed and vault ID.

It stores at most the latest successful:

- transfer export ID, vault revision, time, and output digest;
- owner backup ID, captured vault revision, time, and payload digest;
- verification for that backup ID and time;
- real restore drill for that backup ID and time.

It contains no passphrase, private key, item name, field metadata, value, or
trusted destination path.

Receipts do not participate in public policy, item validation, rollback maxima,
or remote freshness.

They are not included in normal transfer.

They may be included as prior local context in an owner backup, but backup
creation records its new receipt only after output commit and cannot claim that
the just-created receipt is inside the same backup.

A receipt-write failure after an export, backup, or drill primary commit returns
a committed-primary-action warning and exact local status limitation.

## 16. CLI contract

### 16.1 Command families

Add these command families:

```text
jig vault identity ...
jig vault principal ...
jig vault access ...
jig vault transfer ...
jig vault history ...
```

Keep existing field, secret, read, inject, exec, run, import, audit, backup,
passphrase, status, migrate, init, and TUI families.

### 16.2 Principal administration

Add:

```text
jig vault principal list
jig vault principal challenge --from PUBLIC_DESCRIPTOR --out CHALLENGE \
  [--overwrite]
jig vault principal add --from PUBLIC_DESCRIPTOR \
  --proof PROOF [--reader jig://ITEM]... [--writer jig://ITEM]... [--dry-run]
jig vault principal replace PRINCIPAL --from PUBLIC_DESCRIPTOR --proof PROOF \
  [--dry-run]
jig vault principal label PRINCIPAL --label LABEL
jig vault principal remove PRINCIPAL [--dry-run]
jig vault principal remove PRINCIPAL --revoke-all [--dry-run]
jig vault principal grant-owner PRINCIPAL [--dry-run]
jig vault principal revoke-owner PRINCIPAL [--dry-run]
```

All commands except list require selected owner identity.

`principal list` shows public principal metadata and opaque effective counts, not
inaccessible item names or field metadata.

`principal challenge` validates the descriptor self-signature and fingerprint,
refuses an already registered ID or key, encrypts a random response to the
candidate HPKE key, signs the bound challenge as the selected owner, and writes
only the public challenge artifact through a hardened sink.

`principal add` validates the matching registration proof and refuses duplicate
principal IDs or public keys. A descriptor or Ed25519 self-signature alone is
insufficient.

Adding a principal with no repeated role options grants no item access.

Adding a principal with initial `--reader`/`--writer` options resolves every name
through the owner's descriptor catalog, rotates and reseals each affected item,
and commits registration plus reader-set changes in one policy revision.

It preflights the complete batch before writing and rejects duplicate or
contradictory item arguments.

Successful human output prints the new principal's full ID, grouped fingerprint,
granted role summary, and exact next transfer-export command.

`principal replace` requires a new principal ID and keys, a fresh challenge and
proof, and the exact old principal ID rather than a label. Its dry-run lists all
roles copied, every item epoch rotated, old slots removed, and whether a second
owner is required. Commit is all-or-nothing.

Owner grant shows the number of item key epochs it will rotate and slot sets it
will replace.

Owner revoke shows the number of item root keys it will rotate.

It refuses self-revocation and instructs the operator to use a different
remaining owner identity.

Last-owner removal fails.

Machine owner grant fails.

### 16.3 Item access administration

Add:

```text
jig vault access list --me
jig vault access list jig://ITEM
jig vault access matrix
jig vault access explain jig://ITEM [--require read|write]
jig vault access check jig://ITEM --require read|write|owner
jig vault access grant jig://ITEM --principal PRINCIPAL --role reader|writer \
  [--dry-run]
jig vault access grant --principal PRINCIPAL \
  [--reader jig://ITEM]... [--writer jig://ITEM]... [--dry-run]
jig vault access change jig://ITEM --principal PRINCIPAL --role reader|writer \
  [--dry-run]
jig vault access revoke jig://ITEM --principal PRINCIPAL [--dry-run]
```

`access list --me` unlocks the selected identity and shows only decrypted
accessible item names, exact roles, and the capabilities each role implies.

`access list jig://ITEM` requires the selected identity to resolve that item name
or be an owner, then shows the public grant relationships for that resolved
opaque item ID.

`access matrix` is owner-only because only an owner can decrypt every item name.

It displays principals as labels plus grouped fingerprints but uses full
principal and item IDs in structured output and mutation requests.

`access explain` describes the selected principal's effective role and whether a
requested capability is present without reading a field.

`access check` performs the same authenticated capability preflight with stable
success/access-denied exit behavior for scripts.

Both commands return the identical unavailable result for an inaccessible and a
nonexistent caller-supplied item name.

Mutation commands require owner authority.

Granting reader or writer rotates the item root key, derives a fresh descriptor/
body key pair, reseals both ciphertexts with independent fresh nonces, and
replaces the complete slot set.

The repeated batch form applies all exact grants in one policy revision and
performs only one identity-passphrase capture.

Changing reader/writer role does not reseal.

Revoking performs the same rotation and reseal transaction for the smaller
reader set.

Grant and revoke output contains:

- item name;
- principal ID;
- prior role;
- old and new key epoch;
- resulting reader count;
- `backward_secrecy_established: true` for grants;
- `external_credential_rotation_required: true` for revokes in JSON;
- a human warning that grants cannot expose retained older ciphertext and
  revocation cannot erase retained plaintext or older keys.

### 16.4 Common policy preview and mutation results

Every principal, owner, item-policy, and access mutation accepts `--dry-run`.

A dry-run performs the same bounds, identity, public-chain, descriptor-catalog,
authorization, slot, body, and optimistic-revision preflight needed by the real
operation but writes no shared state, local audit intent, checkpoint, backup
receipt, or export receipt.

Preview output includes:

- acting vault and selected identity name, label, kind, and grouped fingerprint;
- current policy sequence and opaque vault revision;
- exact principal and role changes;
- accessible item names for the acting identity and opaque item IDs otherwise;
- item and descriptor key epochs before and after;
- number of descriptors and bodies that will be resealed;
- remaining recipient counts;
- whether external credential rotation may be required;
- whether redistribution will be recommended after commit.

The real command rechecks the exact preview revision under the edit lock and
fails with `Conflict` rather than applying a stale preview.

Interactive destructive commands require the existing exact-confirmation style.

Non-interactive automation must provide the command's explicit confirmation flag
and every required target; it never receives an implicit yes from `--json`.

Multi-item operations may report pre-commit progress on a terminal, but JSON and
non-terminal output remain deterministic.

Every successful shared-state mutation returns:

- previous and current opaque vault revisions;
- `vault_changed = true`;
- `redistribution_recommended = true`;
- `last_exported_revision` when known locally;
- an exact human next step using `jig vault transfer export`.

These fields mean only that the local artifact changed.

They never claim that another recipient received or accepted the revision.

### 16.5 Item creation and guided initialization

The first write to a missing canonical item remains able to create the item for
compatibility, but only for an owner.

A writer cannot create a new item merely by setting a field.

Add an explicit owner command:

```text
jig vault item create jig://ITEM
jig vault init [--item ITEM]...
```

It may accept repeated initial `--reader` and `--writer` principal IDs.

TUI item creation uses the same core transaction.

Repeated `vault init --item` arguments create private-name empty item
descriptors, epoch-one keys and bodies, and owner slots in the initial owner
policy transaction.

Interactive `vault init` creates the named owner identity first when it is absent,
clearly reports that an unused identity can remain if later vault creation fails,
offers repeated initial items, and ends with:

- vault ID and genesis fingerprint;
- selected owner identity name and fingerprint;
- created item names visible only to that owner until grants are added;
- owner-backup warning and exact backup command;
- exact principal-onboarding and transfer next steps.

There are no hard-coded semantics for `Development`, `Staging`, or `Production`.

### 16.6 Existing list and read commands

`vault field list` with no item returns fields only from decryptable items.

It does not return inaccessible item rows, names, or a locked-item count.

`vault field list jig://Production` returns the uniform item-unavailable
`AccessDenied` before attempting a field lookup when Production is inaccessible
or nonexistent.

`vault secret list` is a compatibility projection.

It returns canonical secret names from accessible items and unrepresentable names
from the legacy compartment only for owners.

Set/remove route representable names to the canonical item and enforce its role;
unrepresentable names require owner access.

`vault read` unwraps and decrypts only the addressed item.

Existing controlled sinks and reveal rules remain unchanged.

### 16.7 Inject

Template parsing still occurs before credential capture.

After public validation, collect every distinct referenced item.

Preflight read access to every referenced item.

If any item name is unavailable to the selected identity, fail before writing any
output.

Decrypt each accessible item at most once.

Do not disclose whether the item or field exists beyond the selected identity's
accessible catalog.

Continue exact output and audit lifecycle behavior.

### 16.8 Transparent exec

Restricted dotenv parsing remains before credential capture.

Collect every distinct referenced item and validate access before child spawn.

Resolve all referenced fields atomically from one authenticated vault revision.

If any access or field resolution fails, no child starts.

Continue stripping both passphrase variables and add
`JIG_VAULT_IDENTITY`, `JIG_VAULT_IDENTITY_FILE`, and
`JIG_VAULT_IDENTITY_HOME` to the stripped set.

Continue inherited stdin/environment, streaming independent redaction, and exact
child status.

Only concealed fields from accessible items become redaction needles.

### 16.9 Brokered run

The legacy-name broker first applies the existing exact, unambiguous
`SecretName`-to-`VaultReference` conversion.

A representable name resolves from its canonical item and uses that item's read
role.

An unrepresentable name resolves only from the owner-only legacy compartment.

Do not invent a more permissive fuzzy conversion.

All existing child-process containment, timeout, capture, cleanup, and redaction
invariants remain.

### 16.10 OnePassword import

The destination canonical item must already exist or be created by an owner in
the same transaction.

A writer may import into an existing item it can write.

Preview decrypts only destination item metadata.

An inaccessible or nonexistent destination fails with the uniform item-
unavailable result before revealing collision metadata.

All external values resolve before one atomic destination-item update.

The existing exact `IMPORT` and `IMPORT TEXT` confirmations remain.

### 16.11 Status

`vault status` remains non-creating and does not unlock an identity.

For v3 it reports safe public fields:

- format version;
- vault ID;
- suite ID;
- current policy sequence;
- active principal count;
- active item count;
- tombstone count;
- policy-revision and item-proof usage against each hard cap;
- encoded-size headroom and `rollover_recommended` without item names;
- `cryptographic_scopes = true`.

It may validate public signatures because no private key is needed.

If public validation fails, status reports a sanitized invalid-state error rather
than counts from untrusted structures.

It does not report selected-principal access without an identity unlock.

### 16.12 History rollover

Add:

```text
jig vault history status
jig vault history rollover --home ABSENT_HOME [--dry-run]
```

`history status` is the stable spelling for the public capacity fields also
shown by `vault status`. `history rollover` requires an owner identity, validates
the entire source and local checkpoint, applies the absent-home and alias checks
used by restore, and previews the new vault ID/fingerprint, active object counts,
fresh-encryption count, bridge digest, backup requirement, and trust/
redistribution steps. It never overwrites, truncates, or deletes the source.

### 16.13 JSON stability

Every new structured response has explicit tests in
`crates/jig/src/cli/output/vault.rs`, CLI parser tests, and consumer workflow
tests.

Never place private keys, item root keys, derived content keys, HKDF
intermediates, wrapped-key plaintext, field values, or raw decrypted bodies in
JSON.

Fingerprint, principal ID, role, opaque item ID, key epoch, revision, and public
counts are permitted.

An item name is permitted only in output produced after the selected identity has
decrypted that item's descriptor, or in owner-authorized output where the owner
has decrypted every relevant descriptor.

## 17. Transfer workflow

### 17.1 Purpose

Transfer distributes shared encrypted state between developers and machines.

It is not a backup.

It is not an invitation containing private credentials.

### 17.2 Commands

Add:

```text
jig vault transfer export --out FILE [--overwrite]
jig vault transfer inspect --in FILE [--against-current] [--me]
jig vault transfer import --in FILE [--dry-run]
jig vault transfer status
```

An owner uses principal and access commands before export when onboarding a new
recipient.

Any registered principal may export a validated current artifact.

Export never decrypts item descriptors or bodies.

After the output file commits successfully, export records the transfer ID,
current opaque vault revision, timestamp, and output digest in the selected
principal's authenticated local state.

It does not record or claim recipient delivery.

`transfer inspect` validates the transfer envelope and inner public chains before
displaying source vault, genesis and exporter fingerprints, policy ancestry,
opaque item/revision deltas, and predicted conflicts.

`--against-current` compares with the selected local home without mutating it.

`--me` additionally unlocks the selected identity and labels only item deltas
whose descriptors that identity can decrypt from the local or incoming accepted
state.

`transfer import --dry-run` executes the complete authenticated merge and
selected-identity preflight but writes no vault, audit, checkpoint, or export
receipt.

`transfer status` unlocks the selected identity, compares the current revision
with that installation's last successful export receipt, and reports `never
exported`, `matches last local export`, or `changed since last local export`.

It never reports `distributed`, `synchronized`, or an equivalent remote claim.

### 17.3 Transfer package

The transfer envelope contains:

- transfer magic and format version;
- transfer ID and creation timestamp;
- exact source vault ID;
- exact source v3 `vault.json` bytes;
- source public revision digest;
- exporting principal ID;
- exporter signature over envelope metadata and vault digest.

It contains no private identity.

It contains no local audit.

It contains no local checkpoint.

It contains no local operation receipts.

It contains no plaintext item names or field metadata.

The inner vault contains every opaque item envelope and its encrypted descriptor
and body, including items inaccessible to the exporter.

The 32 MiB maximum accommodates one maximum 16 MiB inner JSON vault plus
binary-envelope or base64 overhead while remaining a strictly bounded input.

The transfer's exact length and public metadata remain visible. Encrypted body
buckets prevent it from revealing exact logical body lengths, but public framing
can still be parsed and measured.

### 17.4 Absent-home import

Import into an absent home:

1. validates path and package bounds before passphrase capture;

2. validates exporter signature and complete inner v3 public state;

3. unlocks the selected local identity;

4. checks that its principal is registered;

5. requires at least one effective item access unless `--allow-no-access` is
   explicit;

6. decrypts only the selected identity's accessible item descriptors and shows
   their names and roles;

7. performs the trust-on-first-use fingerprint confirmation;

8. stages a private vault home;

9. installs `vault.json`, local audit genesis, and local checkpoint;

10. atomically publishes the absent home using the existing supported platform
   guarantees.

The first local audit event records transfer ID and exporter principal ID.

### 17.5 Existing-home import

Import into an existing home requires the same vault ID and genesis fingerprint.

The importer validates both local and incoming structures completely.

Policy journals must be equal or one must be a strict prefix of the other.

If incoming policy is behind, it cannot lower local policy.

If incoming policy is ahead and descends from local, it becomes the candidate
policy.

For every item:

- identical current revision is unchanged;
- incoming strict descendant advances local;
- local strict descendant remains local;
- independent progress on different items is merged;
- divergence for the same item is a conflict;
- missing active items are invalid;
- tombstones obey the selected descendant policy.

Current descriptor ciphertext and metadata must match the selected descendant
policy.

A descriptor change can advance only through its owner-signed policy branch; it
does not auto-merge independently of policy.

When an item branch advances concurrently with a policy branch, the importer
rechecks the advancing revision's author and key epoch against the selected
current policy.

It accepts the advance only if that author is still an effective writer/owner and
the revision epoch equals the selected current item epoch.

An unchanged historical current revision remains valid after its author is later
downgraded or removed; only a newly merged advance must pass this current-policy
check.

This allows unrelated policy changes plus an authorized item write to merge while
rejecting a stale removed writer and any pre-rotation item ciphertext.

The fully merged candidate is validated against the selected policy before one
atomic write.

No merge writes partially.

### 17.6 Fork recovery

V3.0 does not auto-merge two writes to the same item or two policy forks.

The conflict reports public policy metadata, opaque item IDs, and branch revision
hashes.

It may attach a decrypted item name only when the selected identity can resolve
that item in a locally accepted or fully validated incoming branch.

Recovery is explicit:

1. retain both transfer files;

2. open copies in separate explicit vault homes;

3. have an owner or authorized writer inspect the competing item values through
   controlled sinks;

4. choose one canonical branch;

5. reapply any desired values to that branch as a new signed revision;

6. redistribute the canonical artifact.

Do not add a `--force` overwrite that bypasses ancestry or checkpoint checks.

### 17.7 Raw copying

Users may still copy `vault.json` directly.

Opening a copied file validates its public chains and local checkpoint.

The supported transfer commands add provenance, merge rules, bounds, safe path
handling, and first-use fingerprint confirmation.

Documentation should recommend transfer commands rather than raw replacement.

## 18. Backup and recovery

### 18.1 Backup meaning

The v3 command surface includes:

```text
jig vault backup create --out FILE [--overwrite] \
  [--kdf-profile portable|hardened] [--reuse-identity-passphrase]
jig vault backup status
jig vault backup verify --in FILE
jig vault backup drill --in FILE --vault-out ABSENT_PATH \
  --identity-out ABSENT_PATH [--identity-kdf-profile portable|hardened] \
  [--identity-protection portable|keychain|secure-enclave|tpm2|fido2] \
  [--protector ID]
jig vault backup restore --in FILE --identity-out ABSENT_PATH \
  [--identity-kdf-profile portable|hardened] \
  [--identity-protection portable|keychain|secure-enclave|tpm2|fido2] \
  [--protector ID]
```

A v3 backup is full owner recovery material.

Anyone who has the backup passphrase can recover the included owner private
identity and therefore every item.

The CLI must state this before creation and in help text.

Backup is not the developer distribution path.

### 18.2 Authorization

Only an active owner may create a v3 backup.

The selected identity must have a valid current key slot for every active item.

Backup preflight verifies every item slot can be unwrapped, but it need not
decrypt every item body merely to copy authenticated ciphertext.

The owner identity public descriptor must match current policy.

Successful backup creation records an authenticated local recovery receipt with
backup ID, payload digest, captured vault revision, owner principal fingerprint,
creation time, and verification state.

The receipt stores no passphrase, private key, field value, item name, or trusted
destination path.

### 18.3 Backup envelope

Bump the backup envelope and payload versions.

The outer backup remains Argon2id plus XChaCha20-Poly1305 protected.

Its public header records and enforces the exact v3 KDF profiles from section
12.2 before Argon2 allocation. `portable-v1` is the default;
`--kdf-profile hardened` selects `hardened-v1`. Backup files are immutable, so a
profile change affects newly created backups rather than rewriting old ones.

Retain the existing 64 MiB total backup envelope ceiling. Before outer
encryption, pad the authenticated payload to the smallest exact 4, 8, 16, 32, or
64 MiB envelope target after accounting for framing, nonce, tag, and encoded
header. The target bucket ID is associated data; decrypted padding must be all
zero. A backup leaks only its target bucket, not its exact recovery-payload size.

If vault, identity, local audit, checkpoint, optional legacy audit, and framing do
not fit the bounded payload budget, backup creation fails before output commit and
reports which metadata class exceeded the budget without exposing event content.

For v3, backup creation first unlocks the selected owner identity, then captures
a separate backup passphrase twice. Interactive prompts say `Identity
passphrase` and `Backup passphrase` and never carry one response into the other.
Automation uses `JIG_VAULT_BACKUP_PASSPHRASE`; there is no fallback to
`JIG_VAULT_PASSPHRASE` or `JIG_VAULT_IDENTITY_PASSPHRASE`.

Deliberate reuse requires `--reuse-identity-passphrase`, an explicit full-owner-
recovery warning, and normal confirmation. Without that flag, an equal backup
and identity passphrase is rejected. The flag contains no secret and does not
place a passphrase on argv. All backup-capable child paths remove
`JIG_VAULT_BACKUP_PASSPHRASE` from descendant environments.

The encrypted payload contains:

- exact `vault.json` bytes;
- a canonical owner identity recovery payload containing the selected
  principal's HPKE private key, Ed25519 signing key, and local
  audit/checkpoint seed inside the outer encrypted payload;
- the matching public identity descriptor, but not an independently
  passphrase-encrypted copy of the live identity file;
- selected identity path metadata without trusted absolute-path installation;
- selected principal's local audit bytes;
- selected principal's checkpoint bytes;
- selected principal's prior authenticated local receipt bytes;
- the preserved legacy `audit.jsonl` archive when the v3 genesis contains a
  matching source-migration attestation;
- source vault ID and format version;
- source identity principal ID and fingerprint;
- backup creation metadata and payload digests.

Changing the live identity passphrase does not rewrite old backups.

`backup verify` decrypts and validates a specified backup, all embedded public
chains, private-to-public owner identity correspondence, local audit/checkpoint,
and the recovered owner's ability to unwrap every current item root key without
publishing a restore. Core archive verification requires the backup passphrase,
not the historical live identity passphrase; updating a local receipt also
unlocks the currently selected identity that authenticates that receipt.

After successful verification it updates the matching authenticated local
recovery receipt.

`backup status` unlocks the selected owner identity and reports:

- whether a successful backup receipt exists for this vault and identity;
- captured versus current vault revision;
- backup age and last full verification time;
- identity recovery coverage;
- whether a full restore drill has been recorded locally;
- exact next commands for create, verify, or drill.

The result says `unknown` when a backup or drill occurred elsewhere without a
local authenticated receipt.

It never infers that a file still exists or remains readable merely from a prior
creation receipt.

### 18.4 Restore destinations

V3 restore takes an absent vault home and either:

- an absent `--identity-out PATH`; or

- `--reuse-identity PATH` naming an existing identity whose decrypted public and
  private key material exactly matches the backed-up principal.

For an absent identity target, restore captures a new identity passphrase twice,
uses `portable-v1` by default or the explicit `--identity-kdf-profile`, and seals
the recovered private payload with a fresh identity root, salt, and nonces. It
uses portable protection by default or enrolls the explicit
`--identity-protection`/`--protector` through the normal provider boundary before
publishing either destination. The backup passphrase alone never becomes the
installed identity passphrase or hardware factor. Non-interactive restore uses
the existing command-scoped `JIG_VAULT_NEW_PASSPHRASE` contract for the new
identity credential; interactive hardware presence/verification cannot be
bypassed by an environment variable.

For `--reuse-identity`, restore unlocks that identity with its separate current
identity passphrase and proves private-key and seed correspondence. It neither
reseals nor overwrites the existing file.

Do not install an untrusted absolute path from backup metadata.

The default proposed identity output is under the identity root and must be shown
before mutation.

An existing nonmatching identity fails before vault-home publication.

### 18.5 Restore transaction

Cross-directory publication cannot be represented as one rename.

Use an explicit recoverable transaction:

1. validate source, vault target, identity target, parents, bounds, and platform
   support;

2. decrypt and validate the full backup in private staging;

3. verify inner vault signatures and backed-up checkpoint/audit;

4. verify recovered owner private/public correspondence and every required item
   slot, then either prepare a freshly sealed identity under the new identity
   passphrase or unlock and prove exact `--reuse-identity` correspondence;

5. create a private restore transaction marker in the verified identity-target
   parent, named `.jig-vault-restore-<transaction-id>.json`, containing only
   random ID, target paths, public IDs, payload digest, and publication state;

6. publish a new identity only if its target is absent;

7. publish the absent vault home atomically;

8. create a restore audit event and advance checkpoint in the installed home;

9. remove the transaction marker after both publications and syncs succeed.

If identity publication succeeds but vault publication fails, retain the valid
identity and marker and report an exact safe retry.

Never overwrite or delete a pre-existing identity.

Never report a partially published restore as rolled back unless exact inode and
ownership proofs make rollback safe.

### 18.6 Legacy backups

Continue decoding existing v1 backup envelopes and embedded v2 vaults.

Restoring a legacy backup yields its original v2 vault and audit.

The operator then runs explicit v2-to-v3 migration.

Do not rewrite legacy backup bytes in place.

### 18.7 Recovery drills

`backup drill` reuses the real restore transaction into explicitly absent vault
and identity destinations, opens the restored owner session, validates every
accessible encrypted descriptor, verifies every owner slot, audit, and
checkpoint, and only then records a successful drill receipt in the source
owner's authenticated local state.

It leaves the restored copy in place for operator inspection and never deletes
it automatically.

Failure after the restore's primary commit is reported as a committed restore
with an unrecorded source drill receipt, not as a safe automatic retry.

Documentation includes a generic `ExampleVault` recovery drill:

- create owner backup;
- restore to a new explicit home and identity path;
- confirm genesis fingerprint and owner principal;
- verify audit;
- read one generic test field through a controlled sink;
- delete the drill copy only through an explicitly operator-directed cleanup,
  outside automated tests.

## 19. Migration from v2

### 19.1 Eligibility

`jig vault migrate --to 3` accepts a valid v2 vault.

A v1 vault must first use the existing `--to 2` migration.

The command rejects v3 as already current and rejects unknown versions.

### 19.2 Identity choice

Migration requires a human identity that will become genesis owner.

If the selected identity does not exist, migration first creates one outside the
vault home using the normal identity flow.

If it exists, migration unlocks it separately.

Interactive prompts clearly distinguish:

- old vault passphrase;
- selected identity passphrase.

Automation uses:

- `JIG_VAULT_PASSPHRASE` for the v2 vault;
- `JIG_VAULT_IDENTITY_PASSPHRASE` for an existing selected identity.

When migration creates the identity, the existing vault passphrase may protect
the new identity only after explicit confirmation; scripts may instead provide
the identity passphrase variable.

All reserved variables are removed before child execution.

### 19.3 Data mapping

For every canonical v2 secret name:

1. parse its `jig://ITEM/FIELD` representation;

2. group it by canonical item name;

3. generate one stable item ID per group;

4. create item key epoch one with a fresh root and derived descriptor/body keys;

5. create descriptor revision one containing the canonical item name and encrypt
   it under the descriptor key derived from the new item root key with a fresh
   descriptor nonce;

6. preserve field value, kind, creation time, update time, and exact decoded
   length;

7. create item revision one signed by the genesis owner;

8. create an owner key slot.

Unrepresentable v2 names move into the reserved owner-only legacy compartment
with metadata preserved and its descriptor label encrypted like every other item
name.

Vault ID and vault creation timestamp remain unchanged.

The v3 genesis timestamp is the migration time and records the source format.

Migration dry-run reports only names visible through the v2 owner unlock and
writes no identity unless the operator proceeds to the real migration.

### 19.4 Audit bridge

Before mutation, verify the entire v2 audit using the v2 DEK-derived audit key.

Append the existing v2 migration intent event with a random migration ID.

Preserve `audit.jsonl` as the immutable legacy audit archive.

Hash its final bytes after appending the migration intent and bind that digest
plus verified terminal MAC into the owner-signed v3 source-migration attestation.

Create the v3 owner-local audit genesis referencing:

- migration ID;
- source format two;
- v2 terminal audit MAC;
- v3 genesis fingerprint;
- initial checkpoint digest.

Do not claim that the new identity can authenticate arbitrary historical v2
events without the preserved v2 archive and original verified bridge.

### 19.5 Atomicity and recovery

Hold the existing vault lock across v2 verification, transformation, v3 signing,
audit intent, and atomic `vault.json` replacement.

Identity creation occurs first and may leave an unused valid identity if later
migration fails.

V3 local audit/checkpoint staging occurs before the vault replacement when safe,
but the shared v3 file remains the primary commit point.

Use the migration ID to recognize these recoverable states:

- v2 vault plus v2 migration intent and staged v3 local files: retry may reuse or
  replace only matching staged files;
- v3 vault plus missing v3 local audit/checkpoint: rebuild them only from a valid
  matching v2 terminal intent and selected owner identity;
- v3 vault plus matching v3 local files: migration complete.

Never rerun item encryption with ambiguous identity or vault IDs.

### 19.6 Previously distributed copies

Every old v2 copy and backup still contains all old secrets under its shared
passphrase.

Migrating the live copy does not revoke them.

The migration success output and documentation instruct the owner to rotate
Production credentials if the old v2 artifact was distributed beyond the new
Production access set.

### 19.7 New vault cutover

After v3 ships, `vault init` creates v3 by default.

There is no feature flag that silently makes some new vaults v2.

Tests may retain explicit fixture constructors for v1/v2 compatibility.

## 20. TUI behavior

### 20.1 Session credential

For v3 the TUI retains one process-local unlocked identity credential or the
minimum encrypted credential state needed to reopen it per action.

It does not retain every item root or derived content key.

Lock, inactivity, authentication loss, audit failure, signal shutdown, and exit
drop identity material, snapshots, and protected inputs.

The retained identity root/private keys and passphrase/provider factors reside
only in `ProtectedMemory`. Before the first unlock the TUI disables core dumps;
protected-memory or provider degradation is a persistent header state rather
than a transient toast.

### 20.2 Item browser

The item list shows only items whose descriptors the selected identity can
decrypt.

Each row has a role badge:

- `OWNER`;
- `WRITE`;
- `READ`.

The browser provides `All accessible`, `Writable`, and `Readable` filters plus a
one-keystroke `Show my access` summary.

It never creates placeholder rows, locked counts, or guessed labels for opaque
inaccessible envelopes.

When a caller-supplied reference cannot be resolved through the accessible
catalog, the UI shows the uniform item-unavailable message without adding it to
history or confirming existence.

The persistent header shows selected vault, identity name, label, kind, grouped
fingerprint, and owner/registered state without private key material.

### 20.3 Command availability

Read/reveal/export commands require reader, writer, or owner.

Field mutation, rename, kind change, import, and item-content deletion require
writer or owner.

Item create, item rename, item delete, principal management, and access management
require owner.

Reader rows keep mutation commands disabled with a stable role-based reason.

Commands with no selected row explain the required role rather than silently
doing nothing.

Copy-reference is available only for decrypted accessible item names.

The UI model uses exact item IDs internally even when names change.

### 20.4 Access tools

Add owner-only Tools palette entries for:

- principals;
- item access;
- grant role;
- change role;
- revoke and rotate;
- replace principal keys;
- transfer export/import;
- owner backup;
- identity protection status/enroll/rebind/remove;
- body-size/privacy status and cover reseal;
- history status and rollover.

Principal onboarding is a guided challenge/proof/fingerprint/initial-role/review/
apply flow using one atomic policy mutation, followed by an explicit transfer-
export step.

The owner access view is a principal-by-item matrix built only after the owner
decrypts every descriptor.

Matrix edits are staged locally, reviewed as one diff, and committed as one
batch policy revision.

Transfer tools include inspect, dry-run import, local export status, and
accessible-name/public-opaque delta views.

Backup tools include recovery status, verify, and the explicit restore-drill
workflow.

Every protected mutation goes through the same single backend worker and joins
before terminal restoration.

Grant, revoke, principal replacement, and owner-change forms display accessible
names to the acting owner, affected item count, descriptor/body reseal counts,
key epochs, and the applicable backward-secrecy or external-credential warning.

After every shared-state mutation, a persistent result banner states that local
state changed and offers the exact transfer-export action.

### 20.5 Metadata boundary

Extend `VaultBackend`, `VaultAction`, `VaultActionResult`, and snapshot types with
metadata-only access records and committed-action results.

No item root key, derived content key, HKDF intermediate, private key, decrypted
body, or field value enters the Ratatui model.

Only names from descriptors decrypted for the selected identity may enter the
model, and lock/exit wipes the accessible catalog and rendered protected inputs.

Peek and export remain immediate controlled sinks.

Access-denied errors map to `VaultUiErrorKind::Unsupported` only if the running
backend lacks v3 support; ordinary policy denial gets a new `Access` kind.

Conflict errors remain non-authentication failures and do not automatically lock
the session unless public validation or checkpoint authenticity failed.

### 20.6 Responsive layouts and tests

Update wide and compact layouts.

Test accessible-only item discovery, mixed roles, filters, identity header, owner
matrix and onboarding tools, principal replacement, long safe labels, small
terminals, selection stability after rename, post-revoke row disappearance,
transfer/recovery/history status, rollover preview, redistribution banners,
committed-action refresh failure, lock wiping, and denied command availability.

Ratatui buffer tests assert that fixture secret values, private keys, and every
inaccessible fixture item name never appear.

## 21. Safety invariants

The following existing invariants remain binding.

- Vault references remain `jig://ITEM/FIELD` and never route scope.
- Raw values never pass through structured emitters, MCP, receipts, logs, or
  `Debug`.
- Existing pre-passphrase input and path validation remains.
- Reveal operations consume plaintext only in immediate selected sinks.
- Concealed and text values are encrypted identically.
- Only concealed values become output-redaction needles.
- Private filesystem permissions, no-follow reads, symlink refusal, hard-link
  alias checks, locks, atomic writes, and parent syncs remain.
- Mutations append local audit intent before shared state save.
- Transparent exec and brokered run retain their distinct process contracts.
- Backup restore never overwrites an existing vault home.
- `SecretBytes` does not reallocate while extending.
- Redaction remains a backup control, not the security boundary.

Add these v3 invariants.

- Private identity files never reside in a transfer package.
- A normal transfer never contains local audit or checkpoint files.
- A normal transfer never contains local operation receipts.
- A backup containing identity material is owner-only and clearly labeled.
- Public policy validates before any key unwrap.
- Public structures contain no canonical active or former item name, reversible
  name digest, or name-derived item ID.
- A selected identity decrypts descriptors only for item slots it currently
  holds; inaccessible descriptors never enter snapshots, JSON, TUI buffers,
  errors, audit events, or receipts.
- Name routing returns one result for inaccessible and nonexistent caller-
  supplied item names.
- Requested item access validates before field existence.
- Untargeted item bodies are never decrypted merely to build the accessible-name
  catalog.
- Every current effective reader has exactly one current key slot.
- Every current key slot belongs to an effective reader.
- Every effective reader-set change increments key epoch, changes the item root
  key, derives fresh descriptor/body keys, reseals both ciphertexts, and replaces
  every current slot.
- A read grant never wraps an item root key used by ciphertext from an earlier
  vault revision.
- Read revocation always increments key epoch and changes the item root key.
- Item root keys are never passed directly to an AEAD; descriptor and body keys
  are derived through the two exact, distinct HKDF contexts from section 10.6.
- Derived descriptor and body keys are unequal and non-interchangeable; nonce
  uniqueness is enforced independently within each encryption domain.
- Write-only role changes never claim cryptographic read revocation.
- Every decrypted item descriptor is exactly the canonical fixed-size encoding;
  descriptor ciphertext length never varies with the private item name.
- Principal addition and replacement require a verified vault- and descriptor-
  bound proof of both HPKE decryption and Ed25519 signing-key control.
- Every stored X25519 descriptor key uses the single canonical Jig encoding;
  fingerprints and duplicate-key checks never distinguish alternate encodings of
  the same X25519 field element as different keys.
- Principal public keys are immutable; replacement removes every old slot and
  rotates each inherited readable item exactly once.
- Identity passphrase change preserves principal keys. Principal replacement and
  reader-set rekey protect later epochs only and never claim recipient forward
  secrecy for retained historical artifacts.
- Every v3 identity and backup header names one exact allowlisted Argon2id
  profile; validation rejects profile/parameter mismatch and excessive resource
  requests before KDF allocation or passphrase capture.
- Identity passphrase change upgrades weak/legacy profiles, preserves an existing
  hardened profile by default, and never silently downgrades KDF cost.
- V3 owner backups use an independently captured passphrase by default and carry
  sufficient encrypted recovery material to reseal the owner identity under a
  newly selected identity passphrase.
- Private commands disable process core dumps before secret capture. Compact
  credentials, provider outputs, identity roots/private keys, item roots/derived
  keys, audit seeds, and RNG seeds use page-dedicated locked/dump-excluded memory
  or fail before unlock unless an explicit degraded-mode override is recorded.
- Device-bound identity unlock combines the passphrase-derived key with exactly
  one enrolled provider response; the identity file contains no portable bypass
  slot or cached provider secret.
- A provider receives no passphrase, identity/item root, principal private key,
  or plaintext vault data, and cancellation/loss never triggers fallback.
- Every item body plaintext and complete v3 artifact uses one exact allowed size
  bucket. Logical lengths and zero padding authenticate inside body AEAD; package
  padding is strictly bounded and transfer/backup framing binds its bucket.
- A cover reseal has the same shared item-revision form as a real body update,
  uses a fresh nonce, consumes history, and never claims to hide policy changes,
  opaque item identity, file access, transport timing, or missed cadence.
- Every policy mutation is signed by an owner authorized in the prior state.
- Every item mutation is signed by a writer authorized at its referenced policy
  state.
- Local checkpoints never move backward.
- Dry-run policy and transfer operations never mutate shared or local state.
- A local export receipt proves only which revision this installation exported,
  never delivery or remote acceptance.
- Identity labels never resolve authority, and identity selection never probes
  multiple private keys automatically.
- Transfer import never force-overwrites a fork.
- History rollover creates a distinct signed lineage in an absent home and never
  prunes, replaces, or relabels the source lineage.
- V3 readers reject unknown algorithms, schemas, operations, subject kinds, and
  roles.
- Older readers reject v3.

## 22. Validation and test strategy

### 22.1 Test layers

Each delivery bead adds tests with the implementation it changes.

The final hardening bead adds cross-cutting negative, fuzz, and performance
coverage; it does not postpone ordinary regression tests.

Use these layers:

- unit tests for canonical preimages and validators;
- RFC known-answer tests for HPKE and Ed25519;
- format fixtures for v1, v2, valid v3, and invalid v3;
- property tests for policy replay and revision chains;
- mutation tests for byte tampering and reordered structures;
- core API tests for partial unlock and authorization;
- CLI parser, output, help, and raw-output tests;
- TUI model/render/backend contract tests;
- end-to-end consumer workflows;
- platform-specific path and restore tests;
- size and latency benchmarks with declared fixtures.

### 22.2 Required principal matrix

Every relevant operation is tested as:

- owner;
- writer for target item;
- reader for target item;
- registered but no-access principal;
- unknown principal;
- removed principal;
- wrong identity passphrase;
- unavailable, cancelled, substituted, and successful device-bound protector;
- protected-memory/core-dump setup failure with and without explicit degraded
  override;
- valid identity with corrupted private payload.

### 22.3 Required item matrix

Exercise:

- Development accessible while the Production descriptor is inaccessible and
  its name is absent from snapshots, errors, JSON, and TUI buffers;
- Production readable but not writable;
- Production writable;
- empty item;
- concealed and text fields;
- maximum value;
- every body-size bucket boundary and a one-byte-over transition;
- same-bucket body mutations and unchanged-body cover reseal;
- multiple items in one inject/exec;
- legacy compartment;
- renamed item;
- deleted item tombstone;
- key epoch after grant;
- key epoch after revoke;
- retained pre-grant ciphertext rejected by the newly granted identity;
- owner addition and removal.

### 22.4 Negative crypto fixtures

Include fixtures for:

- wrong HPKE recipient;
- modified slot encapsulation;
- modified wrapped item root key;
- wrong slot AAD field;
- modified item nonce;
- modified ciphertext;
- modified ciphertext digest;
- body logical length outside its authenticated bucket, nonzero body padding,
  unknown body bucket, and one-byte-short/long bucket ciphertext;
- modified descriptor nonce;
- modified descriptor ciphertext;
- modified descriptor digest or length;
- variable-length, nonzero-padded, or otherwise noncanonical descriptor
  plaintext;
- descriptor metadata not matching the latest policy operation;
- duplicate decrypted accessible item name;
- public/name-derived item ID or plaintext item name fixture;
- invalid Ed25519 signature;
- non-canonical Ed25519 key/signature encoding;
- an X25519 descriptor key with its high bit set or integer encoding at or above
  `2^255 - 19`, including an alternate encoding of an already registered field
  element;
- X25519 recipient or encapsulated-key inputs that produce an all-zero shared
  secret;
- descriptor self-signature paired with an HPKE key whose private key the
  submitter does not control;
- registration response for the wrong vault, owner, challenge, descriptor, or
  HPKE ciphertext;
- replayed registration response;
- signature by a reader;
- signature by a removed writer against new policy;
- policy signature by a non-owner;
- policy sequence gap;
- policy parent mismatch;
- item proof gap;
- item parent mismatch;
- duplicate slot;
- slot for denied principal;
- missing owner slot;
- missing active item;
- reappearing tombstone;
- unknown suite/schema/role/subject/operation;
- unknown identity/backup KDF profile, known profile with altered Argon2
  version/memory/passes/lanes/output length, and over-ceiling pre-authentication
  memory or parallelism;
- unknown/substituted identity protector, changed provider challenge or opaque
  credential ID, short/long provider response, passphrase-only bypass slot, and
  provider fallback after cancellation/timeout;
- lowered local checkpoint;
- same-item fork;
- policy fork.
- principal replacement that retains one old key slot, misses one inherited
  role, or skips one required item rotation;
- rollover bridge with a changed source ID, genesis fingerprint, terminal
  revision, rollover ID, or owner signature.
- a retained historical artifact that remains decryptable after later compromise
  of its then-authorized recipient key, paired with an assertion that passphrase
  change does not alter that result and principal replacement protects only the
  new epoch.

Each test asserts stable error kind and absence of fixture secret bytes in display
and debug output.

### 22.5 Migration fixtures

Keep the checked-in generic v1 fixture.

Add a generic v2 fixture with:

- `Development` and `Production` canonical items;
- concealed and text fields;
- one unrepresentable legacy name;
- nontrivial timestamps;
- a valid audit chain.

Migration tests assert exact logical value and metadata preservation, new owner
access, fixed-size canonical item descriptors, item separation, legacy owner-only
behavior, audit bridge, retry states, and old-reader fail-closed behavior.

No fixture contains private project or customer identifiers.

### 22.6 Transfer tests

Test:

- absent-home trust-on-first-use install;
- wrong genesis fingerprint;
- recipient registered but no access;
- `--allow-no-access` install;
- inspect without identity shows only opaque deltas;
- inspect `--me` labels only decryptable descriptors;
- import dry-run predicts the exact merge and writes no local or shared state;
- transfer status distinguishes never exported, matching, and changed locally;
- export receipt never claims delivery;
- identical import no-op;
- incoming policy descendant;
- local policy descendant;
- independent changes to two items merge;
- same-item fork rejects;
- policy fork rejects;
- rollback below checkpoint rejects;
- exporter signature tamper rejects;
- transfer contains no identity/audit/checkpoint bytes;
- source and destination alias checks;
- interrupted install leaves documented recoverable state.

### 22.7 Backup tests

Test:

- owner backup and fresh restore;
- reader/writer backup rejection;
- wrong backup passphrase;
- independent identity and backup passphrases, rejected implicit reuse, and
  explicit warned reuse;
- portable and hardened backup profile round trips;
- hostile profile headers fail before Argon2 allocation or passphrase capture;
- identity mismatch;
- absent identity installation;
- absent identity recovery reseals the same principal keys and local seed under
  a new identity passphrase, salt, nonce, and selected profile;
- portable and each available device-bound restore enrollment; lost old hardware
  is not required and the restored identity has no portable bypass unless that
  mode was explicitly selected;
- exact existing identity reuse;
- nonmatching existing identity rejection;
- identity published then vault publication failure and safe retry;
- legacy backup restore compatibility;
- backup contains owner recovery capability;
- backup status before creation, after creation, after vault advance, and after
  verification;
- backup verify updates only authenticated local recovery status;
- real drill restores to absent targets, validates owner descriptors/slots, and
  records success without deleting the drill copy;
- drill receipt failure after restore reports committed restore;
- transfer cannot be decoded as backup and vice versa;
- exact backup envelope buckets and authenticated rejection of wrong bucket or
  nonzero padding;
- no private bytes in errors or structured output.

### 22.8 Child-process tests

For exec and run, test mixed accessible and denied references.

Assert no child marker is created when any reference is denied.

Assert all reserved credential environment variables are absent from the child.

Assert protected pages are absent or unreadable after fork, compact parent
secrets never enter argv/environment/pipes, and inherited core-size limits keep
secret-delivery children from producing ordinary cores.

Retain existing Unix process-tree, redaction, status, timeout, and output-cap
tests unchanged unless v3 data setup requires adapter changes.

### 22.9 Performance budgets

Measure rather than guess.

Record on a documented development machine:

- public validation time at 1, 50, and 256 principals;
- public validation time at 10, 100, and 1,000 items;
- policy replay at 1, 100, and 4,096 revisions;
- item proof validation at 1, 1,000, and 65,536 proofs;
- one item unlock;
- accessible descriptor catalog construction at 1, 10, 100, and 1,000 granted
  items;
- ten-item inject preflight;
- reader grant;
- read revocation and reseal at 1 KiB, 1 MiB, and near file cap;
- multi-item principal replacement;
- v3-to-v3 rollover at policy, proof, and total-file cap thresholds;
- transfer merge for independent items;
- transfer inspect and dry-run near the file cap;
- v2-to-v3 migration near file cap;
- portable and hardened identity/backup KDF wall time and measured peak RSS;
- rejected hostile KDF headers showing bounded pre-KDF work and no requested
  attacker-sized allocation;
- protected-memory allocation/lock/unlock/zeroize costs and minimum required
  locked-byte budget on Linux and macOS;
- each hardware provider's cold/warm unlock latency, cancellation/timeout, and
  concurrent-attempt behavior without fabricated availability targets;
- body/backup padding overhead at every bucket and proof-history growth under
  documented cover cadences.

The first release has no absolute latency SLO, but pathological superlinear
behavior outside the already documented local-audit verification cost blocks
release.

Outside an intentionally selected KDF invocation, peak memory must remain bounded
by the 16 MiB artifact cap plus explicitly bounded decrypted touched-item state,
not total unconstrained input. KDF benchmarks account separately for the exact
portable/hardened profile memory and concurrent transient buffers.

### 22.10 UX contract tests

Test:

- identity names resolve only inside the identity root and explicit identity-file
  selection is unambiguous;
- identity list reads public headers without private-key unlock or automatic
  probing;
- protected prompts and TUI headers identify the exact selected identity;
- `access list --me` and ordinary TUI snapshots contain only accessible names;
- `access explain` and `access check` prove capabilities without reading fields;
- inaccessible and nonexistent names have identical error kind, text shape, JSON
  shape, and exit behavior;
- principal add with initial grants is one policy revision or no change;
- principal add rejects a missing, mismatched, or replayed registration proof;
- principal replacement copies the exact authority set or changes nothing;
- repeated batch grants are atomic and reject duplicate/contradictory roles;
- every policy dry-run writes no shared or local bytes;
- a stale preview conflicts at commit;
- mutation output always includes local redistribution guidance;
- repeated init items create private descriptors and no public plaintext names;
- principal labels remain display-only and ambiguous labels never select an
  authorization target;
- human progress output is absent from JSON and non-terminal modes.

### 22.11 Commands

At minimum, relevant beads run:

```text
cargo test -p jig-vault
cargo test -p jig-vault-tui
cargo test -p jig-sh
cargo clippy -p jig-vault --all-targets -- -D warnings
cargo clippy -p jig-vault-tui --all-targets -- -D warnings
cargo clippy -p jig-sh --all-targets -- -D warnings
```

Before final integration:

```text
cargo build -p jig-sh --bin jig
JIG_DEV_BIN=target/debug/jig scripts/jig check test
JIG_DEV_BIN=target/debug/jig scripts/jig check fmt
JIG_DEV_BIN=target/debug/jig scripts/jig check clippy
JIG_DEV_BIN=target/debug/jig scripts/jig check contract
```

Run the workspace MSRV check at Rust 1.88 when dependency changes land.

## 23. Rollout and compatibility

### 23.1 Release shape

Deliver v3 in one release only after core, CLI, TUI, migration, transfer, backup,
documentation, and compatibility tests are complete.

Do not ship a writer before the supported reader and migration recovery exist.

Do not hide incomplete access enforcement behind a production feature flag.

Internal development may use test-only constructors and fixtures.

### 23.2 Read matrix

The new binary:

- reads v1 under existing rules;
- reads and writes v2 under existing rules;
- explicitly migrates v1 to v2;
- explicitly migrates v2 to v3;
- creates v3 by default;
- reads and writes v3 with a selected identity.

Old binaries:

- continue reading their supported old vaults;
- reject v3 version three.

### 23.3 Command compatibility

Keep canonical reference syntax.

Keep repo/global/explicit-home scope selection.

Keep raw-output safety flags and child-process behavior.

Keep `JIG_VAULT_PASSPHRASE`, with version-specific meaning documented.

Keep `vault passphrase change` as a v3 identity-passphrase alias.

Add named identity selection without changing repo/global/explicit vault-home
selection.

Existing field commands work when role permits.

Existing secret commands retain their compatibility projection on v3:
representable names use canonical item roles and only unrepresentable names use
owner-only legacy storage.

Existing backup command names remain, but v3 help clearly distinguishes owner
backup from transfer.

### 23.4 Documentation cutover

Update:

- `README.md`;
- `docs/configuration.md`;
- `docs/public-contract.md`;
- CLI long help and help snapshots;
- crate-level `AGENTS.md` invariants;
- `agent-map.md` only if ownership/entrypoints move;
- `CHANGELOG.md`.

Examples use `ExampleProject`, `ExampleVault`, Development, Staging, Production,
and generic principals only.

Documentation explicitly distinguishes private item names from the still-public
opaque envelope count, sizes, principals, grants, and revision activity.

It covers access-at-a-glance, capability checks, batch onboarding, policy
dry-runs, transfer inspection/status, redistribution reminders, named identities,
guided initialization, principal key replacement, capacity monitoring,
authenticated rollover, and recovery readiness as primary workflows rather than
advanced footnotes.

### 23.5 Operational guidance

Document onboarding:

1. developer initializes identity;

2. developer sends public descriptor through an authenticated channel;

3. owner verifies the fingerprint, creates a registration challenge, and sends
   it to the developer;

4. developer returns the identity-generated proof and the owner verifies it;

5. owner previews and applies one atomic principal-add plus initial Development/
   Staging reader-set rotations;

6. owner exports transfer;

7. developer verifies genesis fingerprint and imports;

8. developer confirms `access list --me` contains Development/Staging and no
   Production name;

9. developer checks a caller-supplied Production reference and receives the same
   unavailable result as a nonexistent item.

Document offboarding:

1. owner dry-runs each item revoke or explicit revoke-all and reviews descriptor/
   body rotations;

2. owner confirms and Jig rotates affected item roots and derived key pairs;

3. owner removes the principal;

4. owner rotates external credentials that may have been learned;

5. owner exports and redistributes new state, then checks only the local export
   revision rather than assuming delivery;

6. online services revoke their own tokens independently.

Document key replacement as a fresh identity plus challenge/proof followed by
one atomic `principal replace`; never advise editing keys inside a registered
descriptor. Owner replacement requires a different remaining owner.

Document capacity operations:

1. monitor the public policy, proof, and encoded-size headroom;

2. dry-run rollover before the warning threshold becomes a hard-cap failure;

3. create the new lineage in an absent home and verify its signed source bridge;

4. create and verify a new owner backup;

5. distribute the new lineage and require its new genesis fingerprint;

6. retain the old lineage and backups according to policy because rollover does
   not erase or revoke them.

### 23.6 Hosted-provider guidance

Add a decision guide:

Use Jig v3 when:

- offline portability is required;
- direct human/machine membership is manageable;
- delayed file distribution is acceptable;
- cryptographic separation of current item state is the goal.

Use a central secrets manager when:

- revocation must be immediate without redistributing a file;
- SSO/SCIM lifecycle is mandatory;
- access must expire;
- reads need central approval or audit;
- dynamic credentials or leasing are required;
- an authoritative latest state is required.

## 24. Implementation sequencing

The dependency graph is intentionally core-first and allows independent CLI,
process, transfer, backup, and TUI branches after the partial-unlock core exists.

No bead is created for planning, review, coordination, or status reporting.

Every child bead produces working code, tests, fixtures, or user documentation.

The final integration bead depends on every leaf and is the only release gate.

The graph is:

```text
B01 crypto suite proof
  -> B02 identity store
  -> B03 v3 format and canonical preimages

B03 -> B04 policy journal and access evaluator
B02 + B03 + B04 -> B05 item envelopes, signatures, and rekey engine
B02 + B03 -> B06 per-principal audit and checkpoint
B04 + B05 + B06 -> B07 partial-unlock vault session and snapshots
B07 -> B08 authorized atomic field/item/legacy mutations

B02 + B04 + B05 + B06 + B07 -> B09 v2-to-v3 migration
B02 + B04 + B07 -> B10 identity/principal/access CLI
B08 + B10 -> B11 field/read/inject command adaptation
B08 + B10 -> B12 exec/run adaptation
B08 + B10 -> B13 1Password import adaptation
B04 + B05 + B06 + B07 + B10 -> B14 transfer inspect/export/import, local export
status, and merge
B02 + B05 + B06 + B09 + B10 -> B15 owner backup/restore
B08 + B14 + B15 -> B20 capacity preflight and authenticated v3-to-v3 rollover
B11 + B13 + B14 + B15 + B20 -> B16 scoped TUI
B09 + B10 + B11 + B12 + B13 + B14 + B15 + B20 -> B17 config, status, docs,
contract
B09 + B11 + B12 + B13 + B14 + B15 + B20 -> B18 adversarial hardening and
benchmarks
B16 + B17 + B18 + B20 -> B19 release integration
```

The detailed bead specifications follow.

## 25. Delivery bead specifications

Each marked subsection is copied into one Beads child issue.

The issue description is self-contained enough for an implementation agent to
start from the named repository baseline, while this project plan remains the
authority for cross-cutting decisions.

When a bead proves more complex than its bounded changes, its implementer writes
a task-local ExecPlan under `.agent/plans/` according to `.agent/PLANS.md`.

That ExecPlan is an execution aid for the bead, not a replacement for this
project-level design.

### B01 — Add the vetted v3 cryptographic provider

<!-- BEAD:B01:BEGIN -->

#### Outcome

Add the production cryptographic provider used by all later v3 work and prove the
selected RFC suites at the repository's Rust 1.88 floor.

This is a code-and-test deliverable, not a research-only spike.

#### Context

Jig currently uses Argon2id, XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, and
SHA-256.

V3 needs recipient-specific public-key wrapping and signatures.

The project plan selects RFC 9180 HPKE Base mode with X25519/HKDF-SHA256/
ChaCha20-Poly1305 plus strict Ed25519.

The preferred crates are `hpke` 0.14 and `ed25519-dalek` 3, subject to the exact
feature and MSRV proof in this bead.

#### Scope

Edit:

- workspace `Cargo.toml` and `Cargo.lock`;
- `crates/jig-vault/Cargo.toml`;
- a focused `crates/jig-vault/src/crypto_v3.rs` or equivalent owned module;
- crate module wiring;
- checked-in generic known-answer fixtures if needed;
- crate-level dependency/security comments and invariants where warranted.

Provide typed wrappers for:

- HPKE encryption-key generation;
- HPKE item-root-key seal and open;
- HKDF-SHA256 item-root expansion into non-interchangeable descriptor and body
  key types using canonical contexts;
- Ed25519 signing-key generation;
- strict sign and verify;
- SHA-256 fingerprints and revision hashes;
- domain-separated, length-prefixed preimage construction;
- zeroizing private-key representations;
- a page-dedicated non-growing `ProtectedMemory` owner for compact credentials
  and keys, plus Linux/macOS dump-disable and page-protection adapters.

Do not expose raw hazmat signing or unauthenticated ad hoc key-wrap helpers.

Disable default HPKE features and enable only `alloc`, `x25519`, and `chacha`.
Do not enable HPKE's `getrandom` feature; Jig already owns the fallible
`getrandom::fill` boundary and the dependency's convenience surface can panic on
`SysRng` failure.

Explicitly enable `x25519-dalek/zeroize` despite disabled transitive defaults,
and keep Ed25519 zeroization enabled. Prove the concrete HPKE secret-key wrapper
zeroizes on drop.

After fallible entropy acquisition succeeds, seed a private non-exhausting
`CryptoRng` compatible with `hpke` 0.14 and call only its `*_with_rng` paths for
key generation and encapsulation. Do not use a finite byte-buffer adapter whose
exhaustion can panic. Preserve the current `getrandom::fill` error behavior,
zeroize RNG seed/state where supported, and map failures to a stable vault error
without key bytes or partial output. If no compatible RNG can meet the Rust 1.88,
feature, zeroization, and panic-free constraints, stop and record the provider
decision rather than enabling HPKE's `getrandom` feature.

Do not enable ML-KEM, NIST curves, SSH, PEM, PKCS#8, age plugins, legacy Ed25519
compatibility, or hazmat features.

If the preferred crate versions cannot meet Rust 1.88, zeroization, advisory, or
feature constraints, stop before introducing a different wire suite and record a
concrete dependency decision in the implementation change.

#### Required tests

- RFC 9180 known-answer vectors for the exact selected ciphersuite.
- RFC 8032 Ed25519 vectors or upstream-compatible fixed vectors.
- Cross-process deterministic fixtures for public-key and signature decoding.
- Wrong recipient, wrong `info`, wrong AAD, ciphertext tamper, and signature
  tamper failures.
- Exact HKDF-SHA256 vectors prove the same item root and context derive stable
  keys, descriptor and body domains derive unequal keys, and any vault ID, item
  ID, epoch, suite, or purpose change changes the derived key.
- Provider APIs do not accept an item root where an AEAD content key is required
  and do not interchange descriptor and body key types.
- Strict length rejection; strict Ed25519 encoding rejection; canonical Jig
  X25519 descriptor encoding; alternate RFC 7748 encodings and all-zero shared-
  secret inputs.
- Debug output contains no private-key, item-root, derived-key, or HKDF-
  intermediate bytes.
- Drop/zeroization behavior is exercised where observable without unsafe test
  hooks.
- Linux and macOS protected-memory tests cover page rounding, guard pages, lock
  success/failure, dump exclusion, fork exclusion where supported, zeroize-
  before-unmap, and explicit degraded-mode state without reading freed memory.
- Core-size/dumpability controls activate before injected passphrase/provider
  capture; setup failure prevents the callback unless the explicit override is
  present.
- The resolved HKDF implementation's PRK/HMAC-state drop behavior is inspected
  and documented; root/derived output types zeroize even if internal provider
  state cannot make the same guarantee.
- A type/feature assertion proves the X25519 secret representation has drop
  zeroization with the resolved feature graph.
- Injected entropy failure makes key generation and encapsulation return a
  classified error without panic or partial output.
- The resolved HPKE feature graph omits `hpke/getrandom`, and the selected seeded
  RNG has no input-exhaustion panic path.
- `cargo tree -e features` demonstrates the intended feature closure.
- RustSec/advisory check has no unacknowledged applicable advisory.
- Rust 1.88 check builds the affected workspace targets.

## Acceptance Criteria

The new provider can wrap and unwrap a 32-byte item root key for one X25519
recipient, derive distinct descriptor and body keys through the exact typed HKDF
contexts, sign and strictly verify a domain-separated digest, and reject every
negative fixture without exposing private material.

The exact algorithm IDs, crate versions, feature set, licenses, MSRV result, and
dependency duplication decision are documented beside the code or in a concise
repository decision record consumed by later format code.

The resolved feature proof explicitly shows `x25519-dalek/zeroize`, omits
`hpke/getrandom`, and demonstrates that no OS-random failure or RNG-adapter
exhaustion reachable through Jig's provider wrapper can panic.

Compact provider/key material can enter only the protected allocation or an
explicitly reported degraded override; ordinary bulk/KDF allocations retain the
documented narrower guarantee.

`cargo test -p jig-vault`, strict crate Clippy, and the Rust 1.88 affected-target
check pass.

#### Dependencies and unblocks

Depends on no child bead.

Unblocks B02 and B03.

<!-- BEAD:B01:END -->

### B02 — Implement encrypted human and machine identity storage

<!-- BEAD:B02:BEGIN -->

#### Outcome

Add the hardened local identity domain and encrypted identity store outside vault
homes.

#### Context

V3 has no shared vault passphrase.

Each user or deployer owns independent HPKE and signing private keys protected by
a local passphrase.

The selected identity also supplies a random local seed for per-vault audit and
checkpoint keys.

#### Scope

Add identity types and store code under `crates/jig-vault/src/identity/` or an
equally focused module boundary.

Implement:

- `PrincipalId` and validated human/machine kinds;
- public descriptor encode/decode, canonical Jig X25519 public-key validation,
  and recomputed fingerprint;
- public descriptor signing-key self-signature and strict verification;
- bounded owner registration-challenge and candidate proof artifacts that prove
  HPKE decryption and Ed25519 signing-key control together;
- independent HPKE and Ed25519 key generation through B01 wrappers;
- encrypted identity file version one;
- random identity root, typed HKDF-derived payload key, separately nonced private-
  payload encryption, and identity-root wrapping;
- exact allowlisted `portable-v1` (128 MiB, three passes, four lanes) and
  opt-in `hardened-v1` (512 MiB, three passes, four lanes) Argon2id profiles,
  recorded with their complete parameters and a 16-byte salt;
- bounded profile validation before allocation or passphrase capture, with the
  current 512 MiB ceiling unchanged for attacker-controlled headers;
- passphrase-change profile upgrades that never silently downgrade cost and use
  fresh salt/root/nonces while preserving principal keys;
- exact portable or additive device-bound protection with no passphrase-only
  bypass slot;
- typed OS keychain, macOS Secure Enclave P-256 key-agreement, TPM2 sealed-
  factor, and FIDO2 `hmac-secret` provider adapters, with direct APIs and bounded
  cancellation/timeouts;
- provider enrollment/rebind/removal, assurance reporting, explicit portable
  downgrade, and backup-based lost-device recovery;
- independent default identity-root resolution under
  `~/.jig/vault-identities` and `JIG_VAULT_IDENTITY_HOME`;
- strict portable identity-name grammar and canonical named-file resolution;
- unambiguous explicit identity-file resolution supplied by the CLI;
- public-header-only identity enumeration without private-key probing;
- no-follow bounded reads;
- private directory/file permissions;
- identity lock and atomic replace for passphrase changes;
- public descriptor export through an existing hardened output abstraction;
- registration-challenge open and signed proof export through that abstraction;
- protected-memory unlocked-identity guards and process dump suppression before
  passphrase/provider capture;
- local audit/checkpoint subkey derivation by vault ID and distinct HKDF labels.

The identity file must live outside the selected vault home.

Do not automatically scan or attempt every identity in the directory.

Listing validated public identity headers is allowed, but selection and unlock
always target exactly one name or explicit file.

Do not store raw private keys, recovery phrases, or passphrases in vault policy,
JSON output, errors, logs, audit details, or `Debug`.

The public label passed at identity creation is a local convenience only; the
owner chooses policy labels when adding a descriptor.

Identity creation derives and stores the canonical X25519 public key from the
generated private key. Descriptor import rejects a high-bit or out-of-field
X25519 alias before fingerprinting or proof verification. Passphrase change
re-encrypts the same private payload and must be documented and returned as
storage-credential rotation, not principal-key rotation or historical-artifact
revocation.

#### Required tests

- Human and machine identity creation.
- Independent encryption and signing keys.
- Correct descriptor fingerprint recomputation.
- Canonical generated X25519 public-key bytes, rejection of alternate encodings
  of the same field element, and semantic duplicate-key comparison.
- Descriptor self-signature succeeds only for the bundled signing key.
- Registration proof succeeds only when the selected identity controls both the
  descriptor's HPKE and Ed25519 private keys.
- Wrong vault, issuing owner, challenge ID, descriptor fingerprint,
  encapsulation/ciphertext digest, or recovered response rejects.
- Wrong passphrase and modified public/private fields fail authentication.
- Portable and every available provider-backed identity round-trip; the same
  passphrase without the enrolled factor fails, provider/credential/challenge
  substitution fails, and cancellation/timeout/device loss never falls back.
- Providers never receive or log passphrase, identity root/private payload, item
  keys, or plaintext data. Their normalized outputs are copied immediately into
  protected memory; tests account for and minimize any unavoidable short-lived
  OS/library-owned source buffer and forbid a lingering ordinary Jig-owned copy.
- Enrollment/rebind/removal rotates identity root/salt/nonces atomically,
  requires old-method unlock, and explicit removal downgrade cannot bypass its
  warning/confirmation.
- Portable and hardened profile known-answer/round-trip fixtures use their exact
  recorded tuples; unknown IDs, ID/tuple mismatch, and over-ceiling parameters
  fail before Argon2 allocation or passphrase capture.
- Passphrase change upgrades a weaker supported fixture to portable, preserves a
  hardened identity by default, upgrades portable to hardened on request, and
  requires the explicit downgrade flag to move hardened to portable.
- Unsupported identity version/algorithm fails closed.
- Existing identity refuses initialization.
- Named identity creation/listing and canonical filename rejection.
- Passphrase change preserves principal ID and both public keys.
- An artifact addressed to the preserved HPKE key remains openable after
  passphrase change; only principal replacement plus item rekey excludes it from
  later epochs.
- Failed atomic write leaves one complete old or new identity.
- Named/explicit/default identity roots and files never equal, contain, or sit below a
  selected vault home.
- Symlinked identity root/file and permissive Unix modes reject or tighten under
  the existing path policy.
- Bounded input prevents allocation amplification.
- Debug/error scans contain no fixture private bytes.
- Distinct vault IDs and HKDF purposes yield distinct local subkeys.

## Acceptance Criteria

The core crate can create, inspect publicly, unlock, export publicly, and
passphrase-rotate a generic human or machine identity without a vault.

All private material remains encrypted at rest and zeroizing in the owned core
types.

Compact identity credentials and keys are locked/dump-excluded by default, and
device-bound identities require both factors without a recovery bypass in the
identity file.

Public descriptors have one canonical X25519 representation, and passphrase
rotation never claims to rotate principal keys or revoke retained artifacts.

New identities default to the exact portable profile, can explicitly select the
bounded hardened profile, and retain enough authenticated profile metadata for
deterministic unlock and explicit future upgrade.

The default and explicit path rules match section 12 of the project plan.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B01.

Unblocks B03, B05, B06, B07, B09, B10, and B15.

<!-- BEAD:B02:END -->

### B03 — Add the bounded v3 wire model and canonical cryptographic preimages

<!-- BEAD:B03:BEGIN -->

#### Outcome

Add separate v3 serialization types, strict structural validation, canonical
preimage builders, and generic compatibility fixtures without yet implementing
policy semantics or item decryption.

#### Context

The current `VaultFile` struct directly represents v1/v2's one wrapped key and
one state ciphertext.

V3 needs a header, signed policy journal, opaque item envelope map, encrypted
item descriptors, proof chains, and current ciphertexts.

JSON remains the persisted transport, but signatures use deterministic typed
binary preimages rather than JSON bytes.

#### Scope

Refactor `crates/jig-vault/src/format.rs` into explicit versioned representations
or focused submodules while preserving byte-compatible v1/v2 reads.

Add wire newtypes and serde models for all section 11 structures:

- `VaultHeaderV3`;
- policy genesis and signed revision records;
- typed policy operations;
- public descriptors and direct grants;
- key slots;
- item envelopes;
- encrypted item-descriptor metadata and ciphertext;
- current item revisions and prior proofs;
- encrypted item-body fields;
- exact item-body size-bucket IDs;
- tombstones;
- registration challenge/proof artifacts;
- principal-replacement and source-rollover records;
- suite/schema identifiers.

Implement:

- minimal header discrimination before full version-specific parse;
- strict fixed-size base64 decoding;
- canonical application-level X25519 descriptor-key validation before
  fingerprinting, signature checking, or policy semantics;
- total/count/label bounds from section 11.12;
- duplicate-key and ID consistency checks that do not require policy replay;
- canonical preimage encoders for fingerprints, policy hashes/signatures, item
  hashes/signatures, item descriptor/body HKDF contexts, item-descriptor AAD,
  item-body AAD, and key-slot HPKE contexts;
- the exact fixed 256-byte binary `ItemDescriptorV1` encoding from section 10.6;
- exact canonical `ItemStateV1` logical-length/padding encoding for every 4 KiB
  through 8 MiB power-of-two bucket;
- a checked-in generic canonical-vector corpus plus an independent fixture
  encoder for every cryptographic preimage variant;
- stable round-trip fixtures;
- redacted debug formatting.

Unknown suite, schema, role, principal kind, operation, or subject kind fails
closed.

Do not accept serde defaults for security-relevant v3 fields.

Do not change v1 AAD or v2 AAD bytes.

#### Required tests

- Existing checked-in v1 and generated v2 fixtures remain readable.
- Old-version serializers remain byte/AAD compatible where asserted today.
- Valid generic v3 fixture round trips.
- Reordered JSON object keys preserve semantic validation and cryptographic
  preimages.
- Reordered lists that are required canonical reject.
- Every fixed-size field rejects short, long, and malformed base64.
- X25519 descriptor keys reject the high-bit and `u >= 2^255 - 19` aliases,
  including byte strings that the RFC 7748 primitive would process as the same
  field element as an already registered canonical key.
- Every count and byte cap has exact-boundary tests.
- Duplicate item/principal/slot/revision identifiers reject.
- Embedded/map item ID mismatch rejects.
- No valid v3 public structure contains a plaintext item name or name-derived ID.
- Descriptor nonce/digest/length fields have strict boundary and tamper fixtures.
- Every descriptor ciphertext has the one expected length regardless of a
  one-byte or 64-byte canonical name; wrong plaintext length, name length,
  UTF-8, canonical syntax, or nonzero padding rejects.
- Body fixtures at every bucket boundary round-trip; changed logical length,
  nonzero padding, wrong bucket ID, and short/long ciphertext reject after AEAD
  without exposing the logical size.
- Production preimage builders match exact checked-in hexadecimal bytes for
  every domain, tag, field order, integer/length width, optional value, and list
  variant without using production builders to generate expectations.
- Descriptor-key and body-key HKDF context vectors differ only in their required
  domain prefixes and both bind suite, vault ID, item ID, and key epoch exactly.
- Unknown enum strings reject.
- Debug formatting excludes ciphertext only where needed and always excludes any
  decrypted fixture bytes/private material.

## Acceptance Criteria

The crate can parse v1, v2, and structurally valid v3 through separate types;
reject malformed/oversized v3 before cryptography; and produce stable canonical
bytes consumed by B04 and B05.

Accepted item bodies expose only their validated bucket, not exact logical
length. Public artifact framing remains measurable and bounded.

Every accepted public descriptor has one X25519 wire representation, so
fingerprints and later duplicate-key checks are stable across processes.

No v3 public API claims policy or item authenticity until later validators run.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B01 and B02.

Unblocks B04, B05, and B06.

<!-- BEAD:B03:END -->

### B04 — Implement signed policy replay and exact access evaluation

<!-- BEAD:B04:BEGIN -->

#### Outcome

Turn a structurally valid v3 policy journal into a fully authenticated normalized
policy state and exact owner/reader/writer decisions.

#### Context

Policy is public shared state keyed only by opaque item IDs.

Genesis is trust-on-first-use, and every later revision is signed by an owner
authorized in the immediately previous state.

Direct principal grants are the only v3.0 subject form.

#### Scope

Add a focused policy domain under `crates/jig-vault/src/policy/` or equivalent.

Implement:

- genesis self-signature and header fingerprint validation;
- sequential previous-hash replay;
- historical owner authorization;
- typed operation application;
- normalized state hash computation;
- active principal and owner indexes;
- active opaque item/descriptor-metadata index and name-free tombstones;
- direct grant evaluation;
- key epoch and key-slot inventory;
- effective role computation with global owner implication;
- legal atomic-operation combination checks;
- at-least-one-human-owner invariant;
- machine-cannot-own invariant;
- exact duplicate and referential-integrity checks;
- public policy-diff metadata for transfer conflict reporting.
- capacity preflight for policy, proof, slot, item, and encoded-size limits;

Operations must implement the transitions in sections 9 and 11.

Policy replay never decrypts item descriptors or bodies.

Duplicate HPKE-key checks consume only B03-validated canonical Jig encodings and
compare the canonical key bytes independently of principal ID or descriptor
fingerprint. A principal add or replacement cannot treat an alternate X25519
encoding of an existing field element as a fresh key.

Item create/rename operations bind exact encrypted descriptor metadata.

A reader-set-change operation binds the next epoch, exact replacement descriptor
metadata, and exact replacement item revision hash, but B05 performs the item
cryptography. It covers item grant/revoke, owner grant/revoke, and the old-key/
new-key substitution in principal replacement, and is valid only with a complete
next-epoch slot replacement.

Implement `principal_replace` as one atomic normalized transition that copies
the exact old authority set to a fresh descriptor, requires rotations for every
readable item, and removes the old principal and all old slots. Owner replacement
requires authorization by a different remaining owner.

#### Required tests

- Valid genesis and multi-owner evolution.
- Non-owner policy signature rejection.
- Removed owner cannot sign a later sequence.
- Last owner cannot be removed.
- Machine cannot become owner.
- Principal cannot be removed with grants or slots.
- Duplicate key/fingerprint/principal/grant/slot rejection.
- Exact and alternate-encoding reuse of an existing X25519 key rejects before
  policy mutation; principal replacement requires genuinely distinct canonical
  HPKE and Ed25519 public keys.
- Reader/writer/owner/denied effective roles by opaque item ID.
- Grant/rotate, role change, revoke/rotate, principal replacement, create,
  rename, delete, and tombstone replay.
- Descriptor nonce reuse within the same item root epoch rejects during policy
  replay; reuse of the same nonce value after root rotation is a distinct key
  domain and remains structurally valid.
- A grant that retains the old epoch/root key or adds only a slot rejects.
- Principal replacement with missing/copied-extra authority, a surviving old
  slot, skipped/double rotation, or self-authorized owner replacement rejects.
- Missing/extra slot relative to effective readers rejects.
- Sequence gap, parent mismatch, resulting-state hash mismatch, and fork metadata.
- Historical states remain queryable for B05 signature validation without
  unbounded duplicate copies beyond the journal's existing cap.
- Property tests generate legal operation sequences and mutate one invariant at a
  time.

## Acceptance Criteria

Given a generic v3 journal, the policy module either returns one authenticated
normalized current state plus bounded historical authorization lookup or a stable
classified error.

It answers exact effective access without item decryption and enforces every
administration invariant in section 9.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B03.

Unblocks B05, B07, B09, B10, and B14.

<!-- BEAD:B04:END -->

### B05 — Implement item envelopes, signed revisions, grants, and cryptographic rekey

<!-- BEAD:B05:BEGIN -->

#### Outcome

Implement independently encrypted item descriptors and bodies, HPKE recipient
slots, complete signed proof chains, and the cryptographic primitives for grant
and revocation.

#### Context

An item is the v3 confidentiality boundary for both its canonical name and field
state.

Grant and revocation both generate a new item root key, derive a fresh descriptor/
body key pair, reseal content, replace root-key slots, advance key epoch, and bind
policy plus item revision atomically at the caller layer. This gives a new reader
no root or derived key for retained pre-grant ciphertext and a removed reader no
key for later ciphertext.

This is epoch separation, not recipient forward secrecy. Later compromise of a
static recipient HPKE key can still open that recipient's slots in retained
historical artifacts. Principal replacement and rekey protect only the epochs
created after replacement.

#### Scope

Add focused envelope/item code under `crates/jig-vault/src/item/` or equivalent.

Implement:

- item plaintext serialization and validation;
- exact fixed-size descriptor plaintext serialization, zero-padding validation,
  and canonical-name validation;
- item creation with a random root key, independently derived descriptor/body
  keys, epoch one, and revision one;
- XChaCha20-Poly1305 descriptor seal/open with the derived descriptor key, exact
  AAD, and an independent nonce;
- XChaCha20-Poly1305 item-body seal/open with the derived body key and exact AAD;
- canonical body logical-length encoding, authenticated zero padding, and exact
  4 KiB through 8 MiB bucket selection/validation;
- unchanged-body cover reseal as an ordinary signed revision with fresh nonce
  and no public no-op discriminator;
- HPKE root-key-slot create/open with exact `info` and AAD;
- current item revision signing and strict verification;
- proof-chain validation from revision one to current;
- demotion of prior current revision to ciphertext-free proof;
- writer authorization at referenced historical policy sequence;
- grant rekey/reseal using a fresh item root, newly derived key pair, and complete
  next-reader slot set;
- role-only change with no cryptographic rewrite;
- descriptor-only rename with new descriptor revision/nonce and unchanged body;
- revoke/rekey/reseal with new root and derived keys, epoch, descriptor/body
  nonces, slots, and item revision;
- owner-add rekey helpers for every active item;
- owner-remove rekey helpers for every active item;
- atomic old-to-new principal rekey helpers for every inherited readable item;
- deletion final-hash/tombstone helpers;
- protected-memory item-root/derived-key guards plus zeroizing HKDF-intermediate,
  decrypted-descriptor, accessible-name, and decrypted-body guards.

Use stable item IDs in cryptographic contexts, never mutable item names.

Never retain old ciphertext when converting a current revision to a proof.

Never return an item root key or derived content key through a public API.

#### Required tests

- Two items with different item roots, derived key pairs, and ciphertexts.
- One item's descriptor and body derivations are stable for the same root and
  epoch but unequal to each other; cross-using either key fails authentication.
- Reusing the same nonce value in the descriptor and body test domains still
  produces distinct ciphertext key streams; nonce reuse inside either domain is
  rejected by construction or an explicit invariant test.
- Authorized principal opens only its slotted descriptor/body and cannot recover
  the other item's name.
- Grant changes the item root, both derived keys, descriptor/body nonces and
  ciphertexts, epoch, current revision, and the complete slot set.
- A newly granted identity cannot open retained ciphertext from the immediately
  preceding epoch or any earlier epoch.
- Reader-to-writer and writer-to-reader do not change key epoch or body.
- Every body bucket boundary and one-byte transition authenticates; logical-
  length, bucket-ID, padding, and ciphertext-length tampering rejects.
- Cover reseal preserves canonical logical bytes and bucket, changes nonce/hash/
  revision, verifies as a normal writer revision, and consumes exactly one proof
  entry without a public cover marker.
- Revoke changes the item root, both derived keys, nonces, ciphertexts, epoch,
  current revision, and slots.
- Rename changes descriptor revision/nonce/ciphertext without changing the item
  root, either derived key, epoch, or body ciphertext.
- Revoked identity cannot open the new slot/body.
- Remaining identities can open and logical field values are preserved.
- Principal replacement preserves exact roles for the new identity, removes all
  old slots, rotates every affected item once, and leaves the old identity unable
  to open the new epoch.
- A retained old artifact remains openable by its then-authorized HPKE key after
  passphrase change or later private-key compromise, while that key cannot open
  the post-replacement epoch; output and docs classify this as the expected lack
  of recipient forward secrecy.
- Old current ciphertext is absent after update/revoke while signed proof remains.
- Reader-authored revision rejects; historical writer-authored revision remains
  valid after later downgrade/removal.
- Writer cannot mutate another item.
- Tampered AAD fields, slots, descriptors, bodies, proofs, parents, authors, and
  policy sequences reject.
- Body nonce reuse within the same item root epoch rejects across the retained
  item-proof chain; reuse of the same nonce value after root rotation is a
  distinct key domain and remains structurally valid.
- Concealed/text rules and metadata preservation match v2 semantics.
- Boundary tests approach the total artifact cap without unbounded allocation.
- Secret bytes do not appear in errors, debug, or serialized public structures.

## Acceptance Criteria

The core item module demonstrates Development/Staging discovery and access
without Production-name or body decryption in one parsed vault model and
performs real key rotation and reseal on both read grant and read revoke.

The module's guarantees are explicitly epoch-bounded and do not imply that
identity passphrase change or later principal replacement protects retained
historical ciphertext.

Public item bodies reveal only their authenticated size bucket, and an artifact
observer cannot distinguish a valid cover reseal from a real same-bucket update
without external timing/plaintext knowledge.

All current and historical signatures validate against B04 policy states.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B02, B03, and B04.

Unblocks B07, B09, B14, and B15.

<!-- BEAD:B05:END -->

### B06 — Add per-principal local audit and rollback checkpoints

<!-- BEAD:B06:BEGIN -->

#### Outcome

Separate portable signed state authenticity from per-principal local activity,
add authenticated last-seen checkpoints for rollback detection, and provide a
bounded local receipt substrate for honest export/recovery status.

#### Context

V2 derives one audit key from the vault-wide DEK.

V3 has no vault-wide secret shared by every principal.

Each identity has a random local seed from which distinct audit and checkpoint
keys are derived per vault.

#### Scope

Refactor `crates/jig-vault/src/audit.rs` and `store.rs` with explicit v1/v2 versus
v3 paths.

Implement:

- `<vault-home>/local/<principal-id>/audit.jsonl`;
- `<vault-home>/local/<principal-id>/checkpoint.json`;
- `<vault-home>/local/<principal-id>/receipts.json`;
- private path preparation and no-follow bounded access;
- v3 audit event schema and safe activity projection;
- independent HKDF-derived audit and checkpoint HMAC keys;
- checkpoint current policy/item/tombstone maxima;
- distinct HKDF-derived receipt authentication and bounded latest successful
  transfer-export/owner-recovery records without remote-delivery claims;
- checkpoint-to-latest-audit binding;
- fail-closed rollback comparison;
- safe behind-checkpoint advancement after full public chain validation;
- committed-primary-action reporting when checkpoint refresh fails after shared
  state save;
- preservation/inspection hooks for legacy `audit.jsonl` during migration;
- missing/torn/tampered local file recovery rules from sections 13 and 15.

Do not export these files through normal transfer APIs.

Do not accept another principal's directory as the selected identity's local
state.

#### Required tests

- Separate principals get distinct audit/checkpoint keys and paths.
- V3 audit append/verify and safe activity projection.
- Existing v1/v2 audit tests remain valid.
- Changed event, link, checkpoint, item maximum, policy maximum, or latest MAC
  rejects.
- Torn audit tail behavior remains explicit and recoverable.
- Behind checkpoint advances only after valid signed-chain proof.
- Lower policy or item revision rejects as conflict.
- Missing checkpoint on fresh install is initialized only through an explicit
  trusted install/migration path.
- Symlink, traversal, malformed principal ID, and permissive path tests.
- Transfer payload fixture scan contains neither local file.
- Local export/recovery receipt tamper rejects and never changes rollback maxima.
- Failed receipt update after a committed primary action has a distinct recovery
  result.
- No protected values or private seeds in audit/debug/error output.

## Acceptance Criteria

V3 operations can append and verify selected-principal activity and local
operation receipts independently of other principals, and an installation that
has seen a newer signed state rejects a rolled-back artifact.

The code and docs retain the limitation that deletion/rollback of both local
files by the same account is not externally detectable.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B02 and B03.

Unblocks B07, B09, B14, and B15.

<!-- BEAD:B06:END -->

### B07 — Introduce partial-unlock vault sessions and scoped snapshots

<!-- BEAD:B07:BEGIN -->

#### Outcome

Replace the v3 full-state open model with validated public vault state, one
selected principal session, on-demand item guards, access-aware snapshots, and
stable access/conflict errors while preserving v1/v2 APIs.

#### Context

Current `OpenVault` holds the one vault DEK and complete plaintext state.

V3 must validate public chains once, discover only authorized encrypted names,
and decrypt only requested authorized item bodies.

CLI and TUI consumers must never receive rows or names for inaccessible opaque
items.

#### Scope

Refactor `crates/jig-vault/src/vault.rs`, `lib.rs`, and focused submodules.

Implement internal staged states from section 14:

- parsed/validated public vault;
- principal session using an unlocked B02 identity;
- process dump suppression and protected-memory retention of the compact
  identity/root/derived-key state;
- on-demand accessible descriptor catalog mapping decrypted canonical names to
  opaque item IDs and roles;
- on-demand unlocked item guard;
- effective access lookup;
- local checkpoint verification;
- v3 opaque revision digest;
- accessible-only snapshot item rows;
- accessible-only field and legacy projections;
- uniform inaccessible/nonexistent item-name behavior before field existence;
- `AccessDenied`, `Conflict`, `Capacity`, and `Unsupported` error kinds;
- v1/v2 compatibility dispatch behind the existing public `Vault` facade.

Keep the public API non-exhaustive where it already is.

Prefer adding credential/session types over forcing every caller to understand
wire models or private keys.

Do not decrypt any item body merely to open a session or route a name.

Descriptor catalog construction may unwrap each accessible item root and derive
only its descriptor key, must discard unneeded roots, HKDF intermediates, and
derived keys, and must reject noncanonical padding and duplicate accessible
names.

#### Required tests

- One vault snapshot shows Development/Staging and contains no Production name,
  row, count, or timestamp.
- Raw public parsing finds only Production's opaque ID/ciphertext metadata, not
  its canonical name.
- Accessing inaccessible Production and a nonexistent item returns identical
  item-unavailable behavior.
- Reader opens one item; writer and owner roles project correctly.
- Unknown and removed principals fail with stable safe kinds.
- Wrong identity passphrase remains authentication failure.
- Public signature/checkpoint tampering fails before item decrypt.
- Descriptor decrypt is limited to accessible slots; item-body decrypt occurs on
  demand and item/descriptor guard drop wipes owned protected state.
- Injected lock/dump setup failure prevents unlock by default; explicit degraded
  override is stable in API/JSON state and never disappears during a TUI session.
- V3 revision changes for policy or any current item change.
- Existing v1/v2 snapshot, revision, reveal, and list tests remain valid.
- Public `Debug` and errors contain no identity or item plaintext.

## Acceptance Criteria

Core callers can open v1/v2 with a passphrase and v3 with a selected identity
through a coherent facade.

V3 snapshots represent only accessible named items without leaking inaccessible
names or field metadata, and ordinary opens perform no bulk body decryption.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B04, B05, and B06.

Unblocks B08, B09, B10, B14, and B15.

<!-- BEAD:B07:END -->

### B08 — Port atomic field, item, batch, and legacy mutations to v3 roles

<!-- BEAD:B08:BEGIN -->

#### Outcome

Make the core's ordinary data-management operations work on v3 compartments with
exact authorization, signatures, audit intent, optimistic revision checks, and
one atomic shared-state write.

#### Context

Current mutations operate on one plaintext `VaultState` and reseal the whole v2
state.

V3 mutations touch one or a bounded set of decrypted item bodies and append item
revisions.

Opaque inventory and encrypted descriptor changes require owner policy revisions.

#### Scope

Adapt core methods and `VaultMutation` handling for:

- set/create/replace/remove field;
- change field kind;
- rename field within or across items;
- rename item;
- remove item;
- atomic field batch/import preconditions;
- legacy set/remove;
- legacy conversion into canonical item;
- explicit empty-item creation;
- removal of the last field without implicit item deletion;
- exact v3 `VaultRevision` preconditions.
- body-bucket recalculation and capacity preflight on every changed item;
- authorized `privacy cover --item` preparation as a normal unchanged-body
  revision with local-only cover audit classification;
- committed mutation results carrying previous/current opaque revisions and the
  local redistribution-recommended signal consumed by CLI/TUI adapters.

Authorization rules:

- field-body changes require writer or owner on every touched canonical item;
- moving a field across items requires write on both;
- item create/rename/delete and global name-uniqueness checks require owner;
- legacy operations require owner;
- a writer cannot create a missing item through first field set;
- the backward-compatible upsert may create a first field only when caller is
  owner or item already exists with writer access.

All touched item bodies must preflight, decrypt, validate, mutate, seal, sign, and
fit the persistent cap before audit intent or shared state commit where current
ordering permits; preserve the invariant that durable state never leads audit.
Return the typed `Capacity` error and rollover next step before a mutation would
cross any permanent-history or artifact cap.

#### Required tests

- Full owner/writer/reader/denied matrix for each operation class.
- Same-item and cross-item field renames.
- Writer cannot create, rename, or delete an item.
- Removing last field retains empty item and access policy.
- Item rename updates only encrypted descriptor metadata/ciphertext and references
  without body reseal/key epoch change.
- Item delete writes a name-free tombstone and removes current descriptor/body
  ciphertext and slots.
- Batch is all-or-nothing across access, conflict, validation, serialization, and
  write failures.
- Legacy compartment remains owner-only and conversion is atomic across two
  bodies.
- Existing timestamps, kinds, write modes, and stale-preview behavior remain.
- Audit intent may lead on injected state-write failure; state never leads.
- Checkpoint update failure returns committed-action recovery metadata.
- Every successful shared mutation result carries exact revision change and
  redistribution recommendation; no result claims delivery.
- V1/v2 mutation compatibility remains.
- Same-bucket field updates and cover reseals preserve public body length; body-
  bucket crossings and resulting total-cap checks are exact and deterministic.

## Acceptance Criteria

Every ordinary core data mutation has explicit v3 role enforcement and produces
valid signed item/policy state with no unauthorized or partial commit path.

Existing v1/v2 behavior and tests remain supported.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B07.

Unblocks B11, B12, B13, and B20.

<!-- BEAD:B08:END -->

### B09 — Implement explicit, recoverable v2-to-v3 migration

<!-- BEAD:B09:BEGIN -->

#### Outcome

Migrate a valid v2 vault into item-separated v3 state owned by one selected human
identity, preserving logical values/metadata and bridging the legacy audit.

#### Context

Every distributed v2 copy is a full-access artifact.

Migration creates future compartment separation but cannot revoke old copies.

V1 must continue to migrate to v2 first.

#### Scope

Implement the section 19 migration in core lifecycle code and generic fixtures.

Include:

- eligibility/version checks;
- separate v2 vault and selected identity credential handling;
- optional identity creation before migration;
- genesis owner creation using the selected descriptor;
- canonical field grouping by item;
- independent opaque item IDs, encrypted name descriptors, item root keys,
  derived key pairs, slots, epochs, and signed revision-one records;
- exact fixed-size canonical descriptor plaintext for every migrated item;
- smallest-fitting authenticated body bucket for every migrated item;
- owner-only legacy compartment mapping;
- vault ID, vault creation time, field values, kinds, lengths, and timestamps
  preservation;
- v2 audit full verification and migration-intent append;
- preserved legacy audit archive;
- v3 local audit/checkpoint genesis bridge;
- random migration ID and retry/recovery states;
- one atomic `vault.json` commit under the existing lock;
- authenticated dry-run with no identity or state creation;
- explicit warning/JSON flag about old copies and external credential rotation;
- successful migration result recommends initial transfer export without
  claiming distribution;
- old-reader fail-closed fixture.

Use only generic fixture identities and names.

Do not put identity private material inside the v3 shared vault.

Do not allow v1 direct-to-v3 in this bead.

#### Required tests

- Generic v2 Development/Production/legacy fixture migrates exactly.
- Resulting public JSON contains none of the canonical or legacy item names.
- One-byte and 64-byte migrated names produce equal-length descriptor
  ciphertext, and decoded padding is canonical.
- Owner catalog decrypts every migrated descriptor and reconstructs exact
  references.
- Independent owner slots, item roots, and derived key pairs per item.
- Value/kind/timestamp/length preservation.
- Legacy owner-only behavior.
- Existing identity and newly created identity paths.
- New-identity migration supports portable or explicitly enrolled device-bound
  protection; provider failure occurs before the v3 primary commit and never
  leaves a passphrase-only fallback identity.
- Migration preserves every logical value while body ciphertext exposes only the
  resulting bucket; a source that cannot fit after required padding fails dry-run
  with exact capacity guidance before durable writes.
- Migration dry-run creates no identity, audit, checkpoint, or shared-state bytes.
- Wrong old-vault passphrase versus wrong identity passphrase are distinguishable
  without leaks.
- V2 audit tamper blocks migration.
- Injected failures at identity creation, v2 intent, staging, vault write, v3
  local-state creation, and checkpoint update match documented retry states.
- Repeated retry never duplicates or changes accepted logical state ambiguously.
- V1 instructs migration to two first.
- V3 rejects repeated migration as already current.
- V2 fixture remains readable before migration.
- Old v2 reader rejects resulting version three.
- Successful migration emits current revision and local redistribution guidance.

## Acceptance Criteria

`jig-vault` core lifecycle can migrate a v2 vault to a fully valid v3 vault with
one owner identity and recover deterministically from every injected commit-edge
failure.

The result exposes no private identity in `vault.json` and warns that prior v2
copies remain full-access.

`cargo test -p jig-vault` and strict crate Clippy pass.

#### Dependencies and unblocks

Depends on B02, B04, B05, B06, and B07.

Unblocks B15, B17, and B18.

<!-- BEAD:B09:END -->

### B10 — Add identity, principal, item, and access CLI administration

<!-- BEAD:B10:BEGIN -->

#### Outcome

Expose the v3 identity and access lifecycle through typed CLI commands, safe
structured output, help, preflight, and end-to-end administrative tests.

#### Context

Core identity, policy, item-slot, and partial-session behavior exists from
B02/B04/B05/B07.

This bead supplies the operator workflows needed before ordinary data commands
can be exercised as different principals.

#### Scope

Update:

- `crates/jig/src/cli/vault.rs`;
- CLI conversion modules;
- `crates/jig/src/command/vault.rs`;
- `crates/jig/src/runtime/vault.rs` and focused modules;
- tool-definition constants;
- CLI output formatter/tests;
- help snapshots and consumer workflow tests.

Implement section 12 and 16 commands:

- named identity init/list/status/public/prove/passphrase change;
- identity protection status/enroll/rebind/remove and exact
  `portable|keychain|secure-enclave|tpm2|fido2` selection with opaque protector
  identifiers only;
- identity `--kdf-profile portable|hardened`, explicit downgrade gating, and
  public-header status that reports exact parameters and upgrade availability
  without unlocking or rewriting;
- exact one-identity selection through `--identity` or
  `JIG_VAULT_IDENTITY`, plus unambiguous `--identity-file` or
  `JIG_VAULT_IDENTITY_FILE`;
- principal challenge/add/replace/label/remove/grant-owner/revoke-owner with
  common dry-run;
- atomic principal add plus repeated initial reader/writer grants;
- access list `--me`, owner matrix, explain, check, singular grant/change/revoke,
  and repeated batch grant with common dry-run;
- explicit item create and repeated initial `vault init --item` flow;
- selected vault/identity/fingerprint headers on protected human interactions;
- dump/protected-memory setup before credential or protector prompts, persistent
  degraded-mode reporting, and the explicit emergency override contract;
- `privacy cover --item` with history/capacity/redistribution warnings;
- uniform inaccessible/nonexistent item-name result;
- stable access-check exit behavior;
- common authenticated mutation preview and stale-preview conflict;
- deterministic committed results with opaque revisions, redistribution
  recommendation, and exact transfer next step;
- `JIG_VAULT_IDENTITY_PASSPHRASE` migration plumbing where command conversion
  owns it;
- `JIG_VAULT_BACKUP_PASSPHRASE` capture/plumbing for B15 without fallback to an
  identity or legacy vault passphrase;
- credential-variable removal before child-capable flows;
- interactive confirmations for revoke-all and multi-item owner removal;
- capacity preflight errors with exact rollover next steps;
- JSON fields and human summaries.

Validate public descriptors, IDs, roles, identity names/files, caller-supplied
item references, paths, and overwrite preconditions before passphrase capture
wherever possible.

Resolve authorization and persisted policy subjects only by full IDs.

Labels and shortened fingerprints are display conveniences and never mutation
selectors.

Never accept passphrases or private keys on argv.

No administrative command may reveal field values.

#### Required tests

- Clap parsing and rejection for every command and invalid role/path/combination.
- Named identity list/selection and no automatic private-key probing.
- Protected human output identifies the exact vault and selected identity.
- Identity public export and no private byte inclusion.
- Identity init/passphrase-change profile parsing, hardened opt-in, rejected
  silent downgrade, and stable status fields for profile/parameters/upgrade.
- Protection-mode/provider parsing, assurance/availability status without device
  invocation, two-factor enrollment/rebind, explicit removal downgrade, provider
  cancellation, and no fallback or secret argv/environment fields.
- Cover command requires write authority, produces no field output or public
  cover discriminator, and reports proof/headroom/redistribution cost.
- Challenge/proof binds the vault, owner, descriptor, HPKE ciphertext, recovered
  response, and candidate signature; wrong/missing/replayed proof rejects.
- Add developer plus Development/Staging grants in one policy revision and verify
  the developer cannot discover Production's name or decrypt retained pre-grant
  Development/Staging ciphertext.
- Batch grant is all-or-nothing and uses one policy revision.
- `access list --me` shows only accessible items and exact role capabilities.
- Owner matrix shows all decrypted names; non-owner cannot request the matrix.
- Explain/check do not read fields and use stable access exit behavior.
- Inaccessible Production and a nonexistent name have identical error/JSON
  shapes.
- Grant/revoke both report descriptor/body reseal and key-epoch changes;
  reader/writer-only changes report no rekey.
- Policy dry-run writes no vault, audit, checkpoint, or receipt bytes.
- Stale preview conflicts before mutation.
- External-credential-rotation warning and JSON flag on read revoke.
- Principal replacement transfers the exact authority set, rotates all readable
  items, removes old slots, and requires a different owner for owner replacement.
- Last owner and machine owner failures.
- Principal removal with outstanding access fails; explicit revoke-all succeeds
  after confirmation.
- Reserved environment variables are captured/removed correctly.
- V1/v2 commands retain old passphrase behavior.
- V3 passphrase alias reports identity target.
- Human and JSON output contain only permitted metadata.
- Every shared-state mutation reports local redistribution guidance without a
  delivery claim.
- Repeated init items produce encrypted descriptors and no public plaintext
  names.
- End-to-end workflow uses only generic principal names and items.

## Acceptance Criteria

An operator can create/select named human or machine identities, exchange a
public descriptor plus proof of both private keys, atomically onboard or replace
principals with exact grants, inspect and check only authorized item names,
preview and batch policy changes, manage owners safely, initialize private-name
items, and receive exact redistribution guidance through stable CLI and JSON
contracts.

No value-bearing output path is introduced.

`cargo test -p jig-sh`, relevant `jig-vault` tests, and strict CLI Clippy pass.

#### Dependencies and unblocks

Depends on B02, B04, and B07.

Unblocks B11, B12, B13, B14, B15, and B17.

<!-- BEAD:B10:END -->

### B11 — Adapt field listing, controlled read, and template injection to scopes

<!-- BEAD:B11:BEGIN -->

#### Outcome

Make the existing field management, listing, controlled reveal, export, and
template injection CLI paths enforce v3 item access without changing their raw
output safety contracts.

#### Context

B08 provides authorized v3 mutations.

B10 provides selected identity and access administration.

This bead owns ordinary non-child data workflows and their structured metadata.

#### Scope

Adapt CLI/runtime paths for:

- field list/set/remove;
- compatible secret list/set/remove with exact canonical-name routing and
  owner-only fallback for unrepresentable legacy names;
- raw `vault read` stdout/private-file delivery;
- raw `vault inject` parsing, multi-item resolution, stdout/private-file delivery;
- accessible-descriptor catalog routing and accessible-only list JSON role
  metadata;
- v3 credential capture and selected identity resolution;
- access-aware audit events and safe failure stages.
- shared-mutation revision/redistribution results for field and compatible secret
  writes.

For injection, collect every distinct item and preflight access before resolving
any field or writing any byte.

Decrypt each referenced item at most once per authenticated operation.

Preserve:

- canonical reference syntax;
- pre-passphrase path/input validation;
- exact byte output with no newline;
- terminal `--reveal` requirement;
- hardened private-file sink rules;
- no structured raw-value output;
- concealed/text encryption and redaction meaning;
- operation lifecycle audit ordering.

#### Required tests

- Owner/writer can mutate an accessible item; reader/denied cannot.
- Inaccessible item contributes no list row, item name, count, timestamp, or field
  metadata.
- Item-specific list returns uniform unavailable before guessed field lookup.
- Read succeeds for reader/writer/owner and denies inaccessible/unknown/removed.
- Read error messages never confirm inaccessible item or field existence.
- Multi-item inject succeeds when all items are accessible.
- One denied item makes inject produce no stdout/file and no partial field
  resolution result.
- No list/read/inject JSON, audit, debug, or error contains the inaccessible
  Production fixture name.
- Repeated references decrypt one item once through an observable test seam that
  does not expose keys.
- Existing raw-output, symlink, hard-link, overwrite, terminal, size, and audit
  tests pass for v1/v2/v3.
- Secret commands enforce canonical item roles for representable names and owner
  access for unrepresentable legacy names.
- JSON/debug/error fixture scans contain no values or private material.
- Every successful field/secret mutation recommends local transfer export and no
  read-only operation does.

## Acceptance Criteria

All ordinary field/read/inject workflows behave correctly for mixed v3 item
access and retain their established output and filesystem hardening.

Existing v1/v2 consumer behavior remains covered.

`cargo test -p jig-sh`, relevant integration tests, `cargo test -p jig-vault`, and
strict affected-crate Clippy pass.

#### Dependencies and unblocks

Depends on B08 and B10.

Unblocks B16, B17, and B18.

<!-- BEAD:B11:END -->

### B12 — Adapt transparent exec and brokered run to scoped identities

<!-- BEAD:B12:BEGIN -->

#### Outcome

Make child-process secret delivery enforce v3 access atomically before spawn and
strip all v3 credential variables without weakening existing process ownership,
redaction, or status behavior.

#### Context

`vault exec` is transparent streaming process plumbing.

`vault run` is a constrained broker for legacy names.

Their contracts are intentionally different and must remain separate.

#### Scope

Adapt:

- restricted dotenv reference resolution for `vault exec`;
- multi-item access preflight and one-revision field resolution;
- concealed-value redaction needle construction;
- v3 operation audit start/finish/failure metadata;
- child environment stripping for `JIG_VAULT_PASSPHRASE`,
  `JIG_VAULT_NEW_PASSPHRASE`, `JIG_VAULT_IDENTITY_PASSPHRASE`,
  `JIG_VAULT_BACKUP_PASSPHRASE`,
  `JIG_VAULT_ALLOW_UNPROTECTED_MEMORY`,
  `JIG_VAULT_IDENTITY`, `JIG_VAULT_IDENTITY_FILE`, and the non-secret but
  authority-shaping `JIG_VAULT_IDENTITY_HOME`;
- core-dump disable before secret resolution, protected parent credential/key
  pages excluded from fork, and inherited zero core-size limit for a child that
  receives plaintext;
- `vault run` exact canonical-name routing plus owner-only unrepresentable legacy
  access on v3;
- generic end-to-end v3 child fixtures.

Do not move child-process implementation into the policy layer.

Do not change transparent exec into the broker or give broker constraints to
exec.

Every referenced item and field must resolve before spawn.

Any denial, missing accessible field, signature failure, checkpoint rollback, or
redaction setup failure means no child starts.

#### Required tests

- Exec with accessible Development and inaccessible Production starts no child,
  leaves an explicit marker absent, and does not confirm Production's existence.
- Exec with several accessible items injects exact values from one authenticated
  vault revision.
- Reader can exec; writer and owner can exec; denied cannot.
- Concealed accessible values redact; text accessible values do not become
  redaction needles.
- Every reserved credential environment variable is absent in child probes.
- Injected dump/lock setup failure starts no child without explicit degraded
  override. Linux protected parent pages are absent after fork; macOS executes
  no user-controlled code before exec and has no protected mapping after exec.
  A secret-delivery child cannot produce an ordinary core image on either
  supported platform.
- Raw stdout/stderr streaming, inherited stdin/environment, nonzero/signal status,
  and no timeout/cap remain for exec.
- V3 run permits canonical names according to the addressed item role and permits
  unrepresentable legacy names only for owners.
- Existing broker timeout, cap, process-tree cleanup, temp-file wiping, and
  cleaned-environment tests stay green.
- Denied and nonexistent item names have identical pre-spawn behavior.
- Denied and failure audit events contain no guessed inaccessible item/field
  name or value.

## Acceptance Criteria

No v3 child starts until every secret input is authorized and resolved, and every
credential-control environment variable is stripped.

Existing transparent and brokered process contracts remain byte/status compatible
apart from intentional v3 authorization failures.

`cargo test -p jig-sh` with vault exec/run integrations, `cargo test -p
jig-vault`, and strict affected-crate Clippy pass.

#### Dependencies and unblocks

Depends on B08 and B10.

Unblocks B17 and B18.

<!-- BEAD:B12:END -->

### B13 — Adapt 1Password import preview and commit to scoped items

<!-- BEAD:B13:BEGIN -->

#### Outcome

Make the one-time 1Password dotenv import operate against one authorized v3 item
with metadata-safe preview and one atomic signed item revision.

#### Context

The current importer parses and validates before passphrase capture, previews
authenticated field collisions, resolves every external value, commits one field
batch, and installs a private destination file.

V3 must preserve that lifecycle without revealing an inaccessible destination's
item name or collision metadata.

#### Scope

Adapt CLI/runtime/core integration for:

- selected v3 identity;
- destination item existence and effective write role;
- owner-only item creation in the same transaction when explicitly requested;
- accessible-only previous-kind preview;
- revision-bound commit token/precondition;
- one item-body decrypt, batch mutation, reseal, signed revision, audit, and
  checkpoint update;
- safe committed-vault/destination-installation recovery reporting;
- committed vault-import result with previous/current revision and redistribution
  guidance;
- TUI backend-compatible preview types used later by B16.

Keep external `op` execution, bounds, raw diagnostic suppression, source parsing,
destination preflight, exact confirmations, and private file installation rules.

Dry-run invokes no `op` and makes no mutation.

An inaccessible or nonexistent destination returns the uniform unavailable
result before revealing any field collision or kind.

#### Required tests

- Writer and owner import into existing accessible item.
- Reader and denied principal fail before `op` execution and collision metadata.
- Owner explicit create-and-import path.
- Writer cannot create missing item.
- Dry-run invokes no resolver and reports only authorized metadata.
- Preview becomes stale after policy, role, key epoch, or destination item
  revision change.
- All external values resolve before one atomic item update.
- One failed resolver leaves vault and destination unchanged.
- Destination install race after commit reports committed action and exact safe
  rerun without values.
- Concealed-to-text confirmation remains `IMPORT TEXT`.
- Existing v1/v2 importer behavior and path/output hardening remain.
- Successful v3 commit recommends redistribution; dry-run and failed resolver do
  not.

## Acceptance Criteria

OnePassword import is fully usable by authorized v3 writers, reveals no
inaccessible item name or metadata, and retains its all-or-nothing vault update
and explicit post-commit destination recovery semantics.

`cargo test -p jig-sh`, `cargo test -p jig-vault`, import integrations, and
strict affected-crate Clippy pass.

#### Dependencies and unblocks

Depends on B08 and B10.

Unblocks B16, B17, and B18.

<!-- BEAD:B13:END -->

### B14 — Implement authenticated vault-only transfer and ancestry merge

<!-- BEAD:B14:BEGIN -->

#### Outcome

Provide the supported developer/machine distribution path: signed vault-only
export, authenticated inspect/dry-run/status UX, trust-on-first-use absent
install, and safe same-vault ancestry merge with typed fork rejection.

#### Context

Transfer is not backup.

It contains the complete shared v3 ciphertext artifact, encrypted name
descriptors, and public opaque policy but no private identity, audit, or
checkpoint.

Independent item histories allow non-conflicting item progress to merge.

Policy forks and same-item forks do not auto-resolve.

#### Scope

Add a versioned bounded transfer codec in `jig-vault` plus CLI commands/runtime in
`jig-sh`.

Implement:

- transfer envelope magic/version, ID, timestamp, exporter, inner vault digest,
  public revision, and exporter signature;
- hardened output/input paths and total size cap;
- export from fully validated public v3 state without descriptor/body decryption;
- authenticated local export receipt after output commit;
- `transfer inspect` public delta/conflict output plus selected-identity
  accessible-name projection;
- `transfer import --dry-run` through the exact merge preflight with no writes;
- `transfer status` comparison of current versus last locally exported revision
  without delivery claims;
- absent-home import with selected identity membership check;
- default at-least-one-access requirement and explicit `--allow-no-access`;
- selected-identity accessible descriptor decrypt before first-use presentation;
- interactive genesis fingerprint confirmation;
- automation `--trust-genesis-fingerprint`;
- private absent-home staging/publication using existing supported guarantees;
- local audit/checkpoint initialization;
- existing-home same-vault import;
- policy equal/prefix/descendant checks;
- per-item equal/ancestor/descendant checks using complete proof chains;
- independent-item merge;
- tombstone handling under selected policy;
- selected-policy descriptor metadata/ciphertext validation and no independent
  descriptor merge outside its policy branch;
- one candidate validation and atomic write;
- redistribution recommendation when an existing-home merge produces a new local
  candidate not identical to the imported package;
- same-item/policy fork classified errors and recovery guidance;
- explicit rejection of a rollover lineage as a merge candidate for its source;
- transfer activity events.

Do not add `--force` or raw overwrite bypasses.

Do not trust package paths.

Do not include any `local/` file or selected identity bytes.

#### Required tests

- Exporter signature and vault digest verification.
- Package byte scan proves no identity private fixture, audit event, checkpoint,
  local receipt, plaintext item name, or plaintext value.
- Inspect without identity shows only opaque item deltas.
- Inspect with selected identity labels only descriptors it can decrypt.
- Dry-run predicts the same accepted merge/conflict as real import and writes no
  shared/local state.
- Export status covers never-exported, matching, and changed-since-local-export;
  no output claims distribution.
- Absent install with correct and incorrect genesis fingerprints.
- Selected registered/access/no-access/unknown principal cases.
- Identical existing import no-op.
- Incoming/local policy descendant cases.
- Independent Development and Staging updates merge.
- Unrelated policy advance plus still-authorized stale item writer merges.
- Concurrent advance by a writer removed in the selected policy rejects.
- Concurrent item advance from an older key epoch rejects after selected-policy
  rekey.
- Two Production children of one parent reject as same-item fork.
- Divergent policy journals reject.
- Local checkpoint prevents rollback.
- Different vault ID/genesis rejects.
- A valid signed rollover bridge does not make its new lineage mergeable with the
  source lineage.
- Malformed/oversized/aliased/symlinked input/output rejects before credential
  capture where applicable.
- Injected staging/publication failures preserve documented absent/retry states.
- A novel merged state recommends re-export; no-op and dry-run do not claim a
  mutation.
- Human/JSON output contains only public metadata plus names decrypted for the
  selected identity.

## Acceptance Criteria

Two generic developers can inspect and dry-run exchange of one v3 artifact,
merge independent item changes, track only local export freshness, and
cryptographically reject unauthorized, stale, or forked state when prior
checkpoints provide the evidence without disclosing inaccessible item names.

The transfer is demonstrably incapable of restoring a private identity by itself.

`cargo test -p jig-vault`, `cargo test -p jig-sh`, transfer integration tests,
and strict affected-crate Clippy pass.

#### Dependencies and unblocks

Depends on B04, B05, B06, B07, and B10.

Unblocks B16, B17, B18, and B20.

<!-- BEAD:B14:END -->

### B15 — Upgrade owner backup and restore for v3 identity recovery

<!-- BEAD:B15:BEGIN -->

#### Outcome

Extend encrypted backup/restore so a v3 owner can create, verify, inspect recovery
status, drill, and recover the shared vault, selected owner identity, local audit,
and checkpoint without confusing the result with a normal transfer.

#### Context

Current backup packages exact v2 vault and audit bytes under the current vault
passphrase and restores only into an absent home.

V3 backup must carry owner recovery authority and coordinate an identity target
outside the vault home.

Cross-directory publication requires explicit recoverable states.

#### Scope

Version the backup codec/payload and lifecycle code.

Implement:

- v3 owner-only authorization and every-active-item slot preflight;
- exact shared vault bytes;
- canonical owner identity recovery material inside the outer encrypted payload,
  including the private HPKE/signing keys and local audit/checkpoint seed plus a
  matching public descriptor, rather than a still-passphrase-encrypted copy of
  the live identity file;
- selected local audit and checkpoint bytes;
- matching preserved legacy audit bytes for migrated vaults;
- public source identity/vault metadata and authenticated payload digests;
- a separately captured backup passphrase by default, with
  `JIG_VAULT_BACKUP_PASSPHRASE` as its non-interactive source and no fallback to
  identity/vault passphrase variables;
- explicit warned `--reuse-identity-passphrase` opt-in and rejection of equal
  credentials without that opt-in;
- exact versioned portable/hardened Argon2id backup profiles and rejection of
  unknown, mismatched, or over-ceiling headers before KDF allocation;
- exact authenticated 4/8/16/32/64 MiB envelope targets with zero-padding
  validation and no unpadded recovery-size disclosure;
- absent `--identity-out` restore;
- fresh absent-identity resealing under a newly captured identity passphrase,
  fresh identity root/salt/nonces, selected portable/hardened profile, and
  portable or newly enrolled device-bound protector;
- exact matching `--reuse-identity` restore;
- rejection of nonmatching existing identity;
- untrusted backup path metadata never used as an install target;
- private staging and restore transaction marker;
- publish-identity-then-absent-vault ordering;
- safe retry when identity succeeds and vault publication fails;
- restore audit/checkpoint advancement;
- current legacy backup decode/restore compatibility;
- authenticated local recovery receipts for successful create, verify, and real
  restore drill;
- `backup status` with captured/current revision, age, identity coverage,
  verification, drill state, and honest unknown states;
- `backup verify` full cryptographic validation without publication;
- `backup drill` through the real absent-target restore path, restored owner
  descriptor/slot validation, source receipt update, and no automatic cleanup;
- explicit human and JSON warnings that backup grants full owner recovery;
- new-lineage detection that marks every old-lineage backup as not covering the
  rollover and requires a fresh backup/verification/drill lifecycle.

Keep existing path boundary, no-follow, private mode, size, sync, absent-home, and
Linux publication invariants unless the new identity target requires a precisely
documented extension.

Do not overwrite or delete an existing identity.

#### Required tests

- Owner creates and restores v3 backup to new vault/identity paths.
- Status covers no receipt, current backup, stale captured revision, verified
  backup, recorded drill, and unknown off-machine activity.
- Verify detects missing/tampered backup and updates only local authenticated
  recovery state after success.
- Drill uses real absent destinations, verifies all owner descriptors/slots,
  leaves the restored copy, and records success.
- Drill receipt failure after committed restore is reported as committed rather
  than safe to rerun blindly.
- Reader/writer backup creation rejects.
- Wrong outer passphrase and tampered payload reject.
- Independent identity/backup passphrases are captured and routed distinctly;
  equal values reject unless warned reuse is explicitly selected, and the backup
  credential is stripped from every descendant environment.
- Portable and hardened backup profiles round-trip at their exact recorded
  tuples; hostile profile headers reject before Argon2 allocation or passphrase
  capture.
- Every backup envelope target round-trips; bucket/AAD mismatch, nonzero padding,
  short/long envelope, and allocation amplification reject.
- Missing owner item slot blocks backup as inconsistent state.
- Fresh restore preserves principal keys and local seed but emits a newly sealed
  identity with fresh root/salt/nonces and the requested profile/protector;
  neither the old live identity passphrase nor backup passphrase unlocks it, and
  lost old hardware is unnecessary.
- Existing exact identity reuse succeeds after private-key correspondence proof.
- Existing same public descriptor with different private material rejects.
- Existing unrelated identity rejects.
- Identity publication then injected vault publication failure yields safe exact
  retry and no overwrite.
- Transaction marker tamper fails closed.
- Restore never installs path metadata embedded in backup.
- Local audit/checkpoint verify after restore.
- Legacy v1 backup and embedded v2 restore fixtures remain supported.
- Backup/transfer formats reject each other.
- A source-lineage backup never reports coverage for a rolled-over vault ID or
  genesis fingerprint.
- No private or field bytes in output, errors, logs, receipts, or debug.

## Acceptance Criteria

A v3 owner can see honest recovery readiness, verify and drill a tested full
recovery artifact, restore without overwriting an identity or vault home, and
handle every partial cross-directory state through an exact documented result.

The backup passphrase is an independent recovery boundary by default, while an
absent identity is re-credentialed without changing the recovered principal.

Legacy backup compatibility remains green.

`cargo test -p jig-vault`, `cargo test -p jig-sh`, platform restore integrations,
and strict affected-crate Clippy pass.

#### Dependencies and unblocks

Depends on B02, B05, B06, B09, and B10.

Unblocks B16, B17, B18, and B20.

<!-- BEAD:B15:END -->

### B16 — Add access-aware Vault TUI browsing and administration

<!-- BEAD:B16:BEGIN -->

#### Outcome

Make the keyboard-first Vault manager show only accessible read/write/owner item
names and safely expose identity, access, transfer, recovery, and batch
administration tools through its access-filtered backend.

#### Context

The TUI owns presentation and one-worker lifecycle.

The `jig-sh` adapter owns fixed scope, credential capture, external tools, paths,
and core calls.

No decrypted field value or private key may enter the Ratatui model or ordinary
action result; only item names decrypted for the selected identity may enter it.

#### Scope

Update `crates/jig-vault-tui` and `crates/jig/src/runtime/vault/tui.rs`.

Implement:

- accessible-only role-bearing item rows with All/Readable/Writable filters;
- no inaccessible placeholder rows, locked counts, or guessed item names;
- exact stable item-ID selection through name changes;
- command availability by effective role;
- new UI access error kind and conflict mapping;
- selected vault/identity name, label, kind, fingerprint, and state in the locked/
  unlocked header without private data;
- show-my-access summary and disabled-command reasons;
- owner-only principal onboarding wizard and access-matrix editor;
- registration challenge/proof exchange and atomic principal-replacement wizard;
- staged batch grant/change/revoke review and one-revision commit;
- policy dry-run and stale-preview presentation;
- affected-item and external-credential rotation warnings;
- grant-time backward-secrecy and principal-replacement rekey previews;
- post-mutation redistribution banner and exact export action;
- transfer inspect/export/dry-run import/status tools and first-use fingerprint
  confirmation;
- identity KDF profile status, hardened opt-in, upgrade, and warned downgrade;
- identity protector availability/assurance, enrollment/rebind/removal, user-
  presence/cancellation, and explicit no-fallback/device-loss recovery states;
- protected-memory/core-dump state in the persistent header and explicit
  degraded-mode confirmation;
- body-bucket status plus authorized cover reseal with history/capacity/
  redistribution cost;
- v3 owner backup status/create/verify/drill/restore identity-target flows with
  visibly distinct identity, backup, and new-identity credential prompts;
- public history-capacity status and owner rollover preview/absent-home flow;
- v2-to-v3 migration credential prompts and committed-action recovery states;
- access-aware 1Password preview/commit;
- v3 audit/activity selection;
- lock/inactivity/signal cleanup of identity credentials and protected forms;
- wide and compact rendering.

Keep Peek/export immediate controlled sinks and never return their plaintext in
action results.

Keep at most one backend worker and join non-cancellable mutations before
terminal restoration.

#### Required tests

- Mixed Development read and Staging write rows with no Production name or row.
- Raw TUI buffers/actions/errors never contain the inaccessible Production
  fixture name.
- Reader/writer/owner command palette availability and disabled reasons.
- Principal onboarding and access matrix validate IDs/roles without private data
  and commit one reviewed revision.
- Principal onboarding rejects a descriptor without a matching two-key proof;
  replacement removes old access and rotates every inherited readable item.
- Revoke confirmation and resulting item-row disappearance for the revoked
  selected principal.
- Item selection remains exact after rename and policy refresh.
- Transfer inspect/dry-run/status, fingerprint confirmation, accessible-name/
  opaque delta, and fork result presentation.
- Backup recovery status, verify, drill, and full-owner warning.
- Backup creation never reuses an identity credential implicitly; protected
  forms keep identity, backup, and restored-identity passphrases in separate
  zeroized fields and expose the portable/hardened cost choice.
- Portable and device-bound unlock/restore flows never put protector responses,
  PINs, biometric data, or provider secrets in the Ratatui model; cancellation
  never opens a portable fallback.
- Protected pages remain locked/dump-excluded for the session and are wiped on
  lock/exit; degraded override is continuously visible.
- Bucket transitions and cover reseals display capacity/history cost without
  claiming complete traffic-analysis confidentiality.
- History warning/rollover views distinguish the new lineage and never offer
  in-place pruning or source overwrite.
- Mutation result persistently recommends export without claiming distribution.
- Committed primary action plus refresh/checkpoint failure avoids unsafe retry
  suggestion.
- Authentication/tamper locks; ordinary access denial does not unnecessarily
  discard a healthy session.
- Five-minute inactivity and explicit lock wipe identity/protected inputs.
- Small terminal and long label layouts remain bounded.
- Ratatui buffers, debug, action results, and errors contain no inaccessible item
  name, fixture value, item root key, derived content key, private key, or
  passphrase.
- Existing v1/v2 TUI workflows remain supported.

## Acceptance Criteria

The TUI makes access boundaries understandable and enforceable without exposing
inaccessible item names or weakening its credential/worker/terminal lifecycle.

Owner administration, transfer, backup, migration, and import all use the same
core contracts as the CLI.

`cargo test -p jig-vault-tui`, `cargo test -p jig-sh` TUI integrations, and
strict affected-crate Clippy pass.

#### Dependencies and unblocks

Depends on B11, B13, B14, B15, and B20.

Unblocks B19.

<!-- BEAD:B16:END -->

### B17 — Complete configuration, status, public contract, and operator guidance

<!-- BEAD:B17:BEGIN -->

#### Outcome

Make v3's operational and compatibility contract explicit across configuration,
CLI help, structured status, repository guides, examples, changelog, and
consumer-facing tests.

#### Context

Security scope claims are dangerous when documentation blurs offline recipient
encryption with online authorization.

This bead must describe both the strengthened boundary and its limits precisely.

#### Scope

Update:

- `README.md`;
- `docs/configuration.md`;
- `docs/public-contract.md`;
- CLI long help and formatter text;
- `CHANGELOG.md`;
- relevant crate `AGENTS.md` invariants;
- `agent-map.md` if entrypoint ownership changed;
- generic consumer fixtures/tests;
- `.jig.toml` or template documentation only if selected identity configuration
  becomes persisted policy.

Document:

- item cryptographic boundary;
- wrapped per-epoch item roots and domain-separated HKDF-derived descriptor/body
  keys, including that roots are never used directly for AEAD;
- private item-name descriptors versus still-public opaque IDs/counts/sizes,
  principals, grants, and revision activity;
- named identity creation, listing, exact selection, and fingerprint exchange;
- guided initialization and developer/deployer challenge/proof onboarding;
- selected-principal access list, capability explain/check, and owner matrix;
- exact roles and default deny;
- grant/revoke symmetric reader-set rekey, downgrade, owner addition/removal,
  principal key replacement, policy dry-run, and stale preview behavior;
- lack of recipient forward secrecy for retained historical artifacts, the fact
  that identity passphrase change preserves principal keys, and the future-only
  protection supplied by principal replacement plus item rekey;
- external credential rotation after revocation;
- transfer inspect/dry-run/status, redistribution reminders, and the fact that a
  local export receipt is not delivery;
- transfer versus owner backup and recovery readiness/verify/drill;
- exact portable and opt-in hardened Argon2id profile costs, header resource
  limits, status/upgrade behavior, and the fact that passphrase entropy remains
  the likely human-controlled weakness;
- independent backup passphrases by default, explicit warned reuse, immutable
  old backup profiles, and fresh identity-passphrase selection on restore;
- protected-memory and process dump guarantees, explicit degraded override,
  Argon2/bulk-plaintext limits, and encrypted swap/hibernation requirements;
- portable versus keychain/Secure Enclave/TPM2/FIDO2 device-bound identity
  protection, assurance labels, two-factor/no-bypass semantics, device-loss
  backup recovery, and machine-presence tradeoffs;
- exact item-body and encrypted-backup size buckets, cover-reseal mechanics and
  history cost, and the public framing/filesystem/transport/activity correlation
  that remains;
- trust-on-first-use and independent fingerprint channel;
- forks/checkpoints and fresh-install limitations;
- v1/v2/v3 compatibility and migration;
- identity loss and recovery drill;
- hard-cap status and signed v3-to-v3 rollover as a distinct new lineage;
- machine identity environment handling;
- when to choose a centralized secrets manager;
- no “use without view” or immediate revocation claim.

Finish v3 `vault status` public validation and output if not completed in earlier
CLI beads.

All examples use unmistakably generic names.

#### Required tests

- Help snapshots for every new/changed command.
- JSON status fixture for absent, v1, v2, valid v3, and invalid v3.
- Public contract tests assert existing canonical reference and raw-output rules.
- Documentation command examples parse where practical.
- Consumer workflow demonstrates owner, developer, deploy machine, transfer,
  private inaccessible Production name, capability checks, atomic onboarding,
  two-key proof, dry-run, local export status, grant/revoke epoch changes,
  principal replacement, rollover, and backup readiness/drill distinction.
- Search-based public-artifact/output check finds no inaccessible item-name
  canary.
- Repository contract/guide/map checks pass.
- Search-based fixture hygiene finds no downstream/private identifier.
- Search-based wording check finds no unsupported immediate-revocation or
  use-without-view promise in v3 docs.
- Public-contract and help tests state that passphrase change is not key rotation
  and that later HPKE-key compromise can expose matching retained historical
  artifacts.
- Help/status/configuration tests state exact profile parameters, reject any
  implication of automatic KDF rewriting, and distinguish identity, backup, and
  restored-identity passphrase sources.
- Help/status/consumer tests cover protected-memory degradation, every available
  provider assurance/presence state, exact bucket reporting, cover-reseal limits,
  and contain no unsupported hardware-isolation or traffic-confidentiality claim.

## Acceptance Criteria

An operator can understand and execute the complete generic lifecycle from docs,
including the limitation that a removed reader may retain old secrets.

The operator guidance also distinguishes passphrase rotation, principal-key
replacement, epoch rekey, and the absence of recipient forward secrecy.

Structured status and public contracts are stable and tested.

Relevant docs checks, `cargo test -p jig-sh`, and repository contract checks pass.

#### Dependencies and unblocks

Depends on B09, B10, B11, B12, B13, B14, B15, and B20.

Unblocks B19.

<!-- BEAD:B17:END -->

### B18 — Add adversarial corpus, fuzz/property coverage, and bounded benchmarks

<!-- BEAD:B18:BEGIN -->

#### Outcome

Prove the integrated v3 boundary against malicious serialized state, unauthorized
roles, rollback/fork cases, secret-output regressions, allocation abuse, and
pathological validation cost using reproducible tests and measurements.

#### Context

Every feature bead already owns its direct tests.

This bead supplies cross-component attacks that only become meaningful after
migration, ordinary commands, child processes, transfer, and backup coexist.

It is a product hardening deliverable, not a review or certificate bead.

#### Scope

Add:

- a generic checked-in negative v3 corpus or deterministic generators;
- property tests for policy and item histories;
- mutation tests flipping each signed/AAD/bounded field;
- parser fuzz targets when the repository's dependency/tool policy permits them;
- secret-canary scans across errors, JSON, human output, logs, receipts, TUI
  buffers, transfer packages, and public fixtures;
- integration tests for access-denied-before-field-existence;
- integration tests for encrypted descriptor privacy, uniform unavailable-name
  behavior, and accessible-only snapshots;
- integration tests for fixed-size descriptor ciphertext, named identity
  selection, two-key onboarding, atomic batch onboarding, principal replacement,
  policy/transfer dry-runs, local export receipts, and recovery receipts;
- protected-memory/core-dump fault injection and fork/child isolation across CLI
  and TUI unlock lifetimes;
- provider conformance tests for keychain, Secure Enclave, TPM2, and FIDO2 using
  real supported hardware in gated CI plus deterministic protocol fakes that
  cannot satisfy the production capability check;
- body/backup bucket mutation/property tests and cover-reseal history/
  authorization/capacity scenarios;
- retained pre-grant ciphertext tests proving a newly granted identity cannot
  decrypt any prior epoch;
- exact item-subkey vector and cross-domain misuse tests proving roots are never
  direct AEAD keys, descriptor/body keys are distinct, and same-epoch nonce reuse
  is rejected independently in each domain;
- canonical X25519 descriptor-key alias tests and all-zero shared-secret tests;
- retained historical-artifact tests showing that passphrase change preserves
  the recipient key and that principal replacement protects only later epochs;
- exact portable/hardened identity and backup KDF vectors, profile-upgrade and
  explicit-downgrade transitions, and immutable old-backup behavior;
- hostile pre-authentication KDF headers covering unknown IDs, profile/tuple
  mismatch, excessive memory/lanes, allocation instrumentation, and passphrase-
  prompt suppression;
- integration tests proving no child or external resolver starts after denial;
- checkpoint rollback and transfer fork scenarios;
- migration/backup/restore interruption matrix;
- rollover bridge, cross-lineage rejection, and source/destination interruption
  matrix;
- count/byte boundary tests against allocation amplification;
- reproducible benchmarks listed in section 22.9;
- exact dependency feature/advisory recheck at the integrated lockfile.

Do not weaken caps, assertions, fixtures, or production KDF parameters merely to
make the suite faster.

Test-only low-cost KDF constructors remain explicit at call sites.

Benchmark reports must name fixture sizes, machine, build mode, and peak-memory
method.

#### Required tests

Cover every negative fixture listed in section 22.4 and every principal/item
matrix row in sections 22.2 and 22.3 that spans multiple subsystems.

At least one mutation must be applied independently to each:

- public policy operation;
- key slot;
- encrypted item descriptor metadata/ciphertext;
- item proof;
- current item header;
- ciphertext;
- transfer envelope;
- backup payload;
- local checkpoint;
- local audit link.

The corpus also mutates every field of both item-subkey HKDF contexts and tries
root-as-AEAD, descriptor-key-as-body-key, body-key-as-descriptor-key, and
same-epoch same-domain nonce reuse. Each case must fail through a stable typed or
authentication boundary without secret disclosure.

The KDF corpus mutates each public profile field independently and proves that
only exact allowlisted tuples reach Argon2. Rejected inputs must not allocate the
declared memory, capture a passphrase, panic, or weaken legacy-version bounds.

The memory/provider corpus injects every syscall/provider failure before and
after secret acquisition, proves compact secrets never silently enter long-lived
ordinary Jig-owned allocations, accounts for unavoidable provider-owned result
buffers, and proves no passphrase-only bypass survives device-bound mode.
The padding corpus mutates logical lengths, every encrypted zero region, bucket
IDs, backup AAD, and boundary sizes without creating an allocation oracle.

Assert stable classified failure, no panic, no unbounded allocation, no child or
external side effect where preflight should stop, and no canary disclosure.

## Acceptance Criteria

The integrated adversarial suite detects unauthorized Production-name/read/write
disclosure, pre-grant ciphertext recovery, policy forgery, descriptor/item
forgery, malformed key replacement/rollover, stale rollback, same-item fork,
transfer/backup confusion, false delivery/readiness claims, and disclosure
regressions.

It also detects non-canonical X25519 identity aliases and any false claim that
passphrase change or principal replacement retroactively protects retained
historical artifacts.

All bounded benchmarks complete and reveal no unexplained superlinear path beyond
the documented local-audit behavior.

The Rust 1.88 affected workspace and current advisory checks pass.

`cargo test --workspace` and strict workspace checks pass in the supported
environment.

#### Dependencies and unblocks

Depends on B09, B11, B12, B13, B14, B15, and B20.

Unblocks B19.

<!-- BEAD:B18:END -->

### B20 — Add capacity preflight and authenticated v3 history rollover

<!-- BEAD:B20:BEGIN -->

#### Outcome

Prevent permanent signed-history caps from becoming an operational dead end by
adding exact capacity preflight and an owner-only, authenticated v3-to-v3
rollover into a distinct new lineage.

#### Context

V3 intentionally retains complete signed policy and item-proof ancestry up to
hard parse limits. Deleting old proofs in place would break fresh-recipient
validation and transfer ancestry.

The safe exit is a new vault ID and genesis fingerprint whose owner-signed
genesis attests to the fully validated terminal source revision. The source
remains unchanged and independently verifiable.

#### Scope

Update focused v3 format, policy, item, vault lifecycle, store, transfer, backup-
status, CLI/runtime, and output modules.

Implement:

- exact pre-serialization capacity accounting for policy revisions, item proofs,
  principals, items/tombstones, grants, slots, padded bodies, and total encoded
  vault size;
- typed `Capacity` failures before any ordinary mutation would cross a hard cap,
  with safe public headroom fields and the exact rollover next step;
- `jig vault history status` and owner-only `jig vault history rollover --home
  ABSENT_HOME [--dry-run]`;
- full source public-chain, selected-owner, local-checkpoint, descriptor, body,
  role, and slot validation before preview or commit;
- a fresh vault ID, genesis fingerprint, item IDs, item root keys, derived key
  pairs, nonces, fixed-size descriptor ciphertexts, smallest-fitting padded body
  ciphertexts, revision-one item chains, and current-recipient slots;
- reproduction of active principals, owners, direct grants, current logical item
  state, and the owner-only legacy compartment, excluding tombstones and old
  policy/item proofs from the new live lineage;
- exactly one human owner in destination genesis followed by one bounded,
  owner-signed bootstrap policy revision that materializes the committed active
  principals, additional owners, items, grants, and slots;
- canonical `source_rollover` preimage and acting-owner signature binding source
  vault ID, source genesis fingerprint, exact terminal source revision, rollover
  ID, destination vault ID, and the unsigned destination bootstrap-manifest
  digest without binding the later genesis fingerprint or signatures;
- hardened absent-home, symlink, hard-link alias, mode, staging, atomic publish,
  directory-sync, and interrupted-publication behavior shared with restore;
- explicit cross-lineage transfer rejection even when the rollover bridge is
  valid;
- destination local-checkpoint initialization plus source-local audit/receipt
  evidence that claims creation only, never remote installation;
- backup status that treats all source-lineage backups as non-covering for the
  destination and emits an exact fresh backup/verify/drill next step;
- deterministic JSON/human results with new fingerprint trust, redistribution,
  old-lineage retention, and external-credential limitations.

Rollover never writes, truncates, relabels, or deletes the source. It never
claims that old artifacts, backups, plaintext, or keys were revoked. It remains
available when the source is already at a count cap because it does not append to
the shared source journal.

#### Required tests

- Exact-boundary and one-over tests for every count and byte cap.
- Every ordinary mutation fails before audit/shared writes when its resulting
  state would exceed a cap and reports deterministic headroom/rollover fields.
- Dry-run validates/decrypts the full source and predicts exact public counts and
  bridge inputs while creating no source or destination bytes.
- Rollover near policy, item-proof, and 16 MiB limits produces a valid bounded v3
  destination with fresh IDs, keys, nonces, and revision-one histories.
- Destination item bodies use the smallest fitting buckets; padding growth that
  cannot fit the total file cap fails in dry-run before source/destination
  mutation.
- Source and destination current logical values, metadata, principal kinds/
  labels, owners, grants, and effective roles match exactly.
- Newly generated fixed-size descriptors reveal no source item names publicly;
  revoked principals and source tombstones receive no destination slot/state.
- Source `vault.json`, vault revision, and checkpoint remain byte-for-byte
  unchanged; only an explicitly committed source-local audit/rollover receipt
  may advance after destination publication, without rewriting prior backup
  receipt fields.
- Tampering any source-bridge field or signature rejects; the new lineage cannot
  merge with its source through transfer import.
- Wrong/non-owner identity, stale preview, lowered checkpoint, source fork,
  destination alias, existing destination, symlink, hard link, and permissive
  path reject safely.
- Injected failures at staging, file sync, publication, checkpoint, audit, and
  receipt edges yield one documented absent, retryable, or committed result and
  never overwrite either lineage.
- Backup status requires a fresh destination backup; a source backup never
  reports destination coverage.
- Human/JSON/debug/error output contains no item name unavailable to the acting
  identity, field value, item root key, derived content key, HKDF intermediate,
  private key, challenge response, or passphrase.

## Acceptance Criteria

An owner can inspect exact v3 history headroom and, even at a source history cap,
create and verify a fresh bounded v3 lineage with authenticated source provenance
without modifying or weakening the source lineage.

The destination requires explicit new-fingerprint trust, fresh distribution, and
fresh owner recovery evidence, while all cross-lineage merge and false-revocation
claims fail closed.

`cargo test -p jig-vault`, `cargo test -p jig-sh`, focused rollover/path fault
integrations, and strict affected-crate Clippy pass.

#### Dependencies and unblocks

Depends on B08, B14, and B15.

Unblocks B16, B17, B18, and B19.

<!-- BEAD:B20:END -->

### B19 — Integrate, dogfood, and release the v3 security-scope cutover

<!-- BEAD:B19:BEGIN -->

#### Outcome

Ship one coherent v3 release after all implementation branches are integrated,
the dev binary is dogfooded through the Jig harness, required gates pass, and the
release surface contains no stale v2-only assumption.

#### Context

This repository is both Jig's source and an adopted Jig harness.

Runtime validation must build the current binary and set `JIG_DEV_BIN` so the
repo-local cached launcher cannot mask changes.

This bead is concrete release integration; it does not replace the tests owned by
earlier beads.

#### Scope

Integrate B01–B18 plus B20 and resolve only actual cross-branch/API drift.

Perform a full stale-assumption audit across:

- format-version constants and migration parser;
- one-vault-DEK and full-state-open assumptions;
- direct item-root AEAD use, shared descriptor/body keys, untyped content-key
  interchange, or missing canonical HKDF context vectors;
- passphrase wording and environment stripping;
- stale shared identity/backup passphrase reuse, arbitrary Argon2 parameter
  acceptance, automatic KDF downgrade, or KDF allocation before profile/bounds
  validation;
- ordinary allocator storage for compact keys, unlock before dump suppression,
  silent lock failure, missing child credential stripping, or claims that Argon2/
  bulk plaintext is fully locked;
- device-bound identities with a passphrase-only bypass, ambient provider
  selection, shell-based secret transport, missing presence verification, or
  fallback after provider loss/cancellation;
- unpadded item/backup lengths, noncanonical padding, or cover operations
  publicly distinguishable from ordinary body revisions;
- `audit.jsonl` path assumptions;
- backup equals distribution wording;
- snapshots that assume every item has fields;
- public item-name/name-index and locked-row assumptions;
- variable-length private descriptors or grant-without-rekey assumptions;
- signing-only descriptor possession checks and mutable principal-key assumptions;
- cryptographic preimages without exact independent byte vectors;
- X25519 descriptor keys without the canonical Jig representation or semantic
  duplicate-key enforcement;
- documentation or output that implies HPKE recipient forward secrecy,
  passphrase-driven key rotation, or retroactive protection from principal
  replacement;
- `VaultItem`/`VaultReference` comments or debug implementations that call item
  labels non-secret in v3 contexts;
- raw identity-path-only selection assumptions;
- mutation results without redistribution guidance;
- transfer output that conflates local export with delivery;
- owner backup output without recovery readiness/verification state;
- history caps without rollover guidance or rollover treated as an in-place
  continuation;
- TUI actions that assume v2 mutation availability;
- JSON/help snapshots fixed at format two;
- docs and crate invariants;
- fixture names and private-identifier hygiene.

Build the development binary and dogfood a generic workflow:

1. initialize a named owner identity and v3 ExampleVault with repeated
   Development, Staging, and Production private-name items; enroll an available
   human-presence device protector and prove the same passphrase cannot unlock a
   copied identity file without it;

2. prove the raw public artifact contains opaque item IDs and no plaintext item
   names or exact logical body lengths beyond the selected encrypted-body
   buckets, while reporting its measurable public framing honestly;

3. create/list named developer and deploy-machine identities and exchange their
   public descriptors, owner challenges, and identity-generated two-key proofs;

4. retain the pre-grant vault artifact, then dry-run and atomically add the
   developer with Development writer/Staging reader and the deploy machine with
   Production reader;

5. prove neither newly added identity can decrypt its retained pre-grant item
   ciphertext, that each grant rotated the item root and both derived keys
   exactly once, and that key slots contain only roots;

6. prove the owner matrix is complete while the developer's `access list --me`,
   snapshots, JSON, TUI, and errors never reveal Production's name;

7. prove capability explain/check and caller-supplied inaccessible/nonexistent
   names have the specified uniform behavior;

8. inspect, dry-run, export, import, and query local export status for a transfer
   without any delivery claim;

9. prove the deploy identity can inject Production into a child;

10. prove parent compact secrets occupy protected pages, dump setup precedes
    unlock, protected pages are not inherited, reserved overrides are stripped,
    and the secret-delivery child cannot produce an ordinary core;

11. replace the deploy identity through a fresh challenge/proof, prove exact role
    continuity, one Production rotation, and inability of the old key to decrypt
    the replacement epoch;

12. dry-run then revoke developer Staging, observe descriptor/body key-epoch
   rotation and redistribution guidance, and redistribute the new state;

13. publish an unchanged-body Staging cover reseal, prove it has the ordinary
    signed revision shape and same public bucket as a real same-size update, and
    account for its proof-history cost;

14. create an owner backup with an independent passphrase and hardened profile,
    status-check and verify it, then drill and restore to absent generic paths
    while resealing the same principal under a new portable-profile identity
    passphrase;

15. migrate a generic v2 fixture, verify fixed-size encrypted item names and the
    bridge, and confirm prior-copy warnings.

16. exercise capacity status, dry-run and create a signed rollover in an absent
    generic home, reject cross-lineage merge, and create fresh destination backup
    evidence without modifying the source lineage.

17. run real-hardware conformance for every provider claimed supported by the
    release, including user presence/verification, cancellation, timeout,
    unavailable-device no-fallback behavior, and backup recovery onto replacement
    hardware.

Use the repository's structured work/gate commands for the implementation branch
and capture evidence according to repository policy.

Do not modify append-only state to hide a failed gate.

#### Required verification

```text
cargo build -p jig-sh --bin jig
export JIG_DEV_BIN=target/debug/jig
scripts/jig work check --plan-id <implementation-plan-id>
scripts/jig work gates --plan-id <implementation-plan-id>
scripts/jig work evidence --plan-id <implementation-plan-id>
scripts/jig check test
scripts/jig check fmt
scripts/jig check clippy
scripts/jig check contract
```

Also run the Rust 1.88 CI-equivalent check and inspect the complete diff for
stale docs, policy drift, fixture hygiene, and accidental private material.

Before release, obtain an independent protocol review from a reviewer who did
not author the implementation. The review must cover the final canonical
preimages, item-root HKDF construction and typed key separation, X25519
application encoding, HPKE slot coverage by owner signatures, policy/item
authorization replay, reader-set rekey atomicity, transfer merge, checkpoint
rollback, principal replacement, exact KDF profile/resource validation,
independent backup recovery credentials and identity resealing, protected-memory/
dump behavior, hardware-provider factor composition/no-bypass recovery, size-
bucket framing and cover-reseal claims, and stated compromise limitations.
Record the reviewed commit and disposition of every material finding; unresolved
high-severity findings block release.

## Acceptance Criteria

Every B01–B18 and B20 acceptance criterion is present in the integrated revision.

The independent final protocol review is tied to the release commit, and every
material finding is resolved or explicitly accepted below high severity with a
documented rationale.

The generic dogfood lifecycle completes with private inaccessible Production
name/content, grant-time backward secrecy, successful deploy-machine Production
use and key replacement, real Staging descriptor/body key rotation, honest local
transfer freshness, atomic proof-backed onboarding and previews, authenticated
rollover, verified/drilled owner recovery, protected compact secrets,
device-bound no-fallback unlock/recovery, bucketed bodies/packages, honest cover
reseal, and valid private-name v2 migration.

All required gates are green or have exact repository-authorized
not-applicable evidence.

The changelog and public contract describe the cutover and limitations.

No required work remains behind a feature flag or follow-up placeholder.

#### Dependencies and unblocks

Depends on B16, B17, B18, and B20.

Completes the parent epic.

<!-- BEAD:B19:END -->

## 26. Parent epic specification

<!-- BEAD:EPIC:BEGIN -->

Deliver Jig Vault v3 cryptographic item access scopes.

The epic replaces v2's one-passphrase/one-DEK/full-state security boundary with a
single portable v3 vault artifact containing signed policy over opaque item IDs
plus separately encrypted private-name descriptors and item bodies.

Human and machine principals own encrypted local identities.

Owners administer exact reader/writer item grants.

Every effective reader-set change rotates the wrapped item root, derives fresh
descriptor/body keys, and reseals both ciphertexts; writer/reader role-only
changes use signed authorization without rekeying.

The release includes partial unlock, rollback checkpoints, named identities,
accessible-only inventory, atomic onboarding and batch grants, capability checks,
policy/transfer dry-runs, local export freshness and redistribution guidance,
guided initialization, ordinary CLI and child-process adaptation, migration,
vault-only transfer, two-key registration proof, atomic principal replacement,
versioned portable/hardened identity KDF profiles, independent backup
passphrases, protected memory/core-dump suppression, additive OS keychain/Secure
Enclave/TPM2/FIDO2 identity protection, authenticated body/backup size buckets,
optional cover reseals, owner recovery resealing/readiness/verification/drills,
signed history rollover, TUI support, adversarial coverage, and operator
documentation.

It explicitly does not claim immediate online revocation, use-without-view,
remote audit authority, recipient forward secrecy after later HPKE-key
compromise, or protection from a reader who retained earlier plaintext.

It protects canonical item names from principals without current item access but
explicitly still leaks opaque envelope count/sizes, principal descriptors,
grants, and revision activity through the one complete artifact.

## Success Criteria

Completion requires B01 through B20 and the final integration acceptance in this
plan.

<!-- BEAD:EPIC:END -->

## 27. Source references

Repository grounding:

- `crates/jig-vault/src/format.rs`
- `crates/jig-vault/src/vault/envelope.rs`
- `crates/jig-vault/src/vault.rs`
- `crates/jig-vault/src/audit.rs`
- `crates/jig-vault/src/store.rs`
- `crates/jig/src/runtime/vault.rs`
- `crates/jig/src/cli/vault.rs`
- `crates/jig-vault-tui/src/lib.rs`
- `crates/jig/src/runtime/vault/tui.rs`
- `docs/configuration.md`

Official competitor and cryptographic references consulted:

- Doppler project permissions:
  `https://docs.doppler.com/docs/project-permissions`
- Doppler advanced permissions:
  `https://docs.doppler.com/docs/advanced-permissions`
- Doppler custom roles:
  `https://docs.doppler.com/docs/custom-roles`
- Infisical permissions overview:
  `https://infisical.com/docs/internals/permissions/overview`
- Infisical RBAC:
  `https://infisical.com/docs/documentation/platform/access-controls/role-based-access-controls`
- HashiCorp Vault policies:
  `https://developer.hashicorp.com/vault/docs/concepts/policies`
- 1Password permission enforcement:
  `https://support.1password.com/permission-enforcement/`
- Bitwarden Secrets Manager organization access:
  `https://bitwarden.com/help/manage-your-secrets-org/`
- Bitwarden Secrets Manager projects:
  `https://bitwarden.com/help/projects/`
- RFC 9180:
  `https://www.rfc-editor.org/rfc/rfc9180`
- RFC 5869:
  `https://www.rfc-editor.org/rfc/rfc5869`
- RFC 9106:
  `https://www.rfc-editor.org/rfc/rfc9106`
- Linux `mlock(2)`, `madvise(2)`/`MADV_DONTDUMP`, and dumpability controls:
  `https://man7.org/linux/man-pages/man2/mlock.2.html`,
  `https://man7.org/linux/man-pages/man2/madvise.2.html`, and
  `https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html`
- Apple Keychain Services and Secure Enclave key agreement:
  `https://developer.apple.com/documentation/security/keychain-services`,
  `https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave`,
  and
  `https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement`
- FIDO2 CTAP `hmac-secret` specifications:
  `https://fidoalliance.org/specifications/download/`
- Trusted Computing Group TPM 2.0 library specification:
  `https://trustedcomputinggroup.org/resource/tpm-library-specification/`
- RFC 7748:
  `https://www.rfc-editor.org/rfc/rfc7748`
- `hpke` crate documentation:
  `https://docs.rs/hpke/0.14.0/hpke/`
- `hpke` 0.14 feature and system-RNG behavior:
  `https://docs.rs/crate/hpke/0.14.0/features` and
  `https://docs.rs/hpke/0.14.0/hpke/fn.setup_sender.html`
- `ed25519-dalek` crate documentation:
  `https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/`
- `age` crate documentation:
  `https://docs.rs/age/latest/age/`
- RustSec age plugin advisory:
  `https://rustsec.org/advisories/RUSTSEC-2024-0433.html`

These references inform the architecture.

The checked-in plan and repository tests, not mutable external documentation,
define Jig's delivery contract.

## 28. Decision register

### D01 — Scope at canonical item, not whole vault or field

Decision:

One item is one encryption and access-control compartment.

Why:

It maps directly to the existing `jig://ITEM/FIELD` model and the motivating
environment boundary.

A whole-vault boundary reproduces v2's problem.

Field-level grants multiply key slots, policy edges, UI states, and atomic
cross-field behavior before a demonstrated need.

Rejected alternatives:

- ACL metadata inside the v2 ciphertext because every passphrase holder can
  bypass it.
- Separate vault homes per environment because the requested product is one
  distributed logical vault.
- Field-level ACLs in v3.0 because their complexity is not needed to separate
  Production, Staging, and Development.

### D02 — Keep one full ciphertext artifact

Decision:

Every normal v3 transfer carries the complete shared `vault.json`, including
every opaque item envelope, encrypted descriptor/body ciphertext, and public
item/principal access metadata.

Why:

One artifact preserves opaque inventory completeness, signature validation,
ancestry, future grants, and the user's single-vault mental model.

Confidentiality of names and contents comes from per-item root keys, independently
derived descriptor/body keys, and recipient slots rather than hiding ciphertext
existence.

Rejected alternative:

Recipient-filtered vault fragments would require redacted inventory proofs,
partial policy histories, and a more complex merge protocol while still leaking
some existence metadata.

### D03 — Encrypt item names and field metadata; expose opaque access metadata

Decision:

Canonical item names are encrypted in a small per-item descriptor under the
descriptor key derived from the current item root. Its plaintext has one
canonical 256-byte encoding so ciphertext length does not reveal the item-name
length.

Field names, kinds, timestamps, lengths, and values remain encrypted in the
separate item body.

Random item IDs, opaque item count/sizes, principal descriptors, roles, access
relationships, epochs, revisions, descriptor/body ciphertexts, and hashes remain
public.

Why:

Names such as customers, regions, acquisitions, or regulated systems may be
sensitive even when their field values are protected.

Public validation requires stable opaque IDs and authenticated descriptor
metadata, not descriptor plaintext.

An authorized session can build its name-routing catalog by decrypting only the
small descriptors for its current slots while leaving untargeted item bodies
closed.

Field metadata often reveals infrastructure details and is not required to route
an item-level denial.

Rejected alternatives:

- Plaintext inventory labels and denial rows because they unnecessarily
  disclose the inventory to every artifact holder.
- UI-only filtering because raw `vault.json` inspection would still reveal names
  and the product could not claim item-name confidentiality.
- Public item-name hashes or name-derived IDs because environment names are
  guessable offline.
- A per-principal encrypted catalog because every grant, revoke, rename, and
  owner change would fan out duplicated catalog state and add consistency
  invariants; bounded accessible-descriptor scanning is simpler and benchmarked.
- Publishing field names because it would create an unnecessary metadata leak to
  developers denied Production.

### D04 — Use per-principal public-key identities, not more shared passphrases

Decision:

Each human or machine owns independent random HPKE and signing keys in an
encrypted local identity file.

Why:

Individual slots make different item access possible inside the same artifact and
allow adding/removing one recipient without distributing a new common secret.

Rejected alternatives:

- One passphrase per item because sharing, rotation, attribution, and automation
  still depend on common knowledge.
- A vault-wide shared passphrase plus client ACL because it is not a cryptographic
  boundary.

### D05 — Combine encryption with signed policy and item revisions

Decision:

HPKE slots control read capability; Ed25519 policy/item chains control which
changes conforming recipients accept.

Why:

An item-root holder can derive both symmetric content keys and construct
ciphertext, so encryption alone cannot express reader versus writer.

Owner and writer signatures give offline recipients an attributable acceptance
rule.

Rejected alternative:

Unsigned role metadata would again be client decoration that any file editor
could replace.

### D06 — Rotate on every reader-set change, not every role edit

Decision:

Adding or removing effective read access creates a new item root key, derived
descriptor/body key pair, epoch, ciphertexts, and complete slot set.
Reader-to-writer and writer-to-reader changes retain the current epoch.

Why:

Giving a new reader an existing item root key would also give it the ability to
derive the old content keys and decrypt retained ciphertext created before the
grant. A fresh epoch provides backward
secrecy for grants and forward exclusion for revocations, while role-only changes
do not change who can decrypt.

Rejected alternative:

Adding only a new slot on grant fails the plan's pre-grant confidentiality claim.
Rotating on reader/writer-only changes adds cost without changing the reader set.

### D07 — Keep complete signature proofs but discard old ciphertext

Decision:

Item history retains signed metadata, nonce, hashes, parents, authors, and
signatures, but only the current revision retains ciphertext.

Why:

Complete proofs let fresh recipients validate ancestry and transfer merges.

Discarding old ciphertext avoids turning the current artifact into a historical
secret archive and strengthens post-revoke distribution.

Rejected alternatives:

- Current-only revision loses verifiable ancestry and safe merge decisions.
- Full ciphertext history permanently republishes every old secret generation.

### D08 — Split transfer from owner backup

Decision:

Transfer contains shared ciphertext only.

Backup contains an owner identity and local recovery state inside an additional
passphrase-encrypted envelope.

Why:

Developer distribution and disaster recovery grant radically different
capabilities.

One ambiguous export format would make accidental owner-key disclosure likely.

Rejected alternative:

Reusing the current backup as sharing would either grant full owner recovery or
fail to give the recipient a usable independent identity.

### D09 — Use local checkpoints without claiming global freshness

Decision:

Each identity installation authenticates its highest seen policy/item revisions
locally.

First install uses independently confirmed genesis fingerprint trust on first
use.

Why:

This detects ordinary replay after an installation has seen newer state while
remaining compatible with offline files.

Rejected alternative:

Claiming authoritative freshness without an online or independently published
checkpoint would be false.

### D10 — Use standard HPKE and strict Ed25519 with a blocking provider proof

Decision:

The wire suite is RFC 9180 X25519/HKDF-SHA256/ChaCha20-Poly1305 plus strict
Ed25519 and existing XChaCha20-Poly1305 item bodies.

B01 must validate concrete Rust dependencies before the wire format freezes.
The provider boundary must keep X25519 secret-key drop zeroization enabled and
surface entropy failure without panic. B03 must freeze exact canonical bytes
against independently produced normative vectors.

Why:

A standard hybrid encryption construction reduces design risk compared with
hand-rolled X25519/HKDF/AEAD composition.

Strict signatures and explicit features reduce known misuse surfaces.

Rejected alternatives:

- Hand-rolled ECIES-like wrapping.
- Embedding the full age file/plugin/SSH surface when Jig needs signed per-item
  authorization and owns its wire format.
- Enabling a post-quantum default suite before its size and maturity fit are
  established.

### D11 — Use direct principal grants in v3.0

Decision:

V3.0 supports exact human/machine principals, reader/writer item roles, and human
owners, but no groups or policy-expression language.

Why:

Direct grants solve the stated access split and keep slot rotation semantics
auditable.

Groups require membership history, effective-access provenance, and coordinated
slot changes that deserve their own compatible extension.

Rejected alternative:

Copying competitor wildcard/tag/group languages into the first offline format
would expand the trusted validator substantially without a concrete requirement.

### D12 — Require explicit migration and candid old-copy rotation

Decision:

New vaults become v3, but v2-to-v3 is an explicit one-way command and v1 goes
through v2.

Migration warns that all old v2 copies still grant full access and recommends
external Production credential rotation.

Why:

Persisted encrypted state and recovery artifacts can straddle releases.

An explicit cutover gives audit bridging, identity selection, recovery, and
operator warning a safe boundary.

Rejected alternative:

Silent auto-migration during a read or deployment could strand identities,
partially update audit state, and obscure the old-copy exposure.

### D13 — Make the secure path the low-ceremony path

Decision:

V3.0 includes named identity selection, accessible-only self-service views,
capability explain/check, atomic onboarding and batch grants, common policy
dry-runs, guided initialization, role-aware TUI workflows, and exact
redistribution next steps.

Why:

Per-principal cryptography introduces unavoidable identity, fingerprint, policy,
and transfer steps.

Composing those existing security operations atomically and explaining their
effects reduces partial onboarding, repeated passphrase capture, wrong-identity
mistakes, stale previews, and forgotten redistribution without adding a network
authority or new access semantics.

Rejected alternatives:

- Requiring operators to manually sequence every primitive command because it
  creates avoidable intermediate states and policy revisions.
- Authorizing by labels because display names are mutable and ambiguous.
- Automatic identity probing or a repo-controlled global identity pointer
  because selection would become surprising and could multiply unlock attempts.
- Expanding the convenience work into groups, invitations, approvals, expiry,
  hosted sync, or keychain agents in v3.0.

### D14 — Track local export and recovery evidence without remote claims

Decision:

Each selected identity may authenticate local receipts for the last successfully
exported vault revision and for owner backup creation, verification, and restore
drills.

Mutation, transfer, and recovery UX reports those receipts as local evidence
only.

Why:

Offline portability means Jig cannot know whether another person received a
transfer or whether an off-machine backup still exists.

Local receipts still answer useful questions—whether this installation exported
its current revision and whether this owner recently created/verified/drilled
recovery material—while preserving the product's honest freshness boundary.

Rejected alternatives:

- Saying `synced`, `distributed`, or `recoverable` from an export/create event
  alone because those are unprovable remote-state claims.
- Omitting reminders and status entirely because forgotten redistribution and
  untested recovery are predictable local-first failure modes.
- Adding a server callback or central receipt authority because that would change
  Jig's product boundary.

### D15 — Fix descriptor plaintext at 256 bytes

Decision:

Encode every private item descriptor as one strict 256-byte binary plaintext
with a length-delimited canonical name and zero-filled reserved bytes.

Why:

Encryption hides contents but not plaintext-derived ciphertext length. Canonical
item names come from a small, guessable domain, so a variable descriptor length
would weaken the stated name-confidentiality boundary.

Rejected alternatives:

- Documenting name length as public because it is avoidable at negligible fixed
  cost.
- Maximum-size padding for every body because it adds prohibitive storage.
  D26 later adds bounded body buckets to reduce exact-size leakage without
  changing this descriptor-specific decision.

### D16 — Prove control of both principal private keys before addition

Decision:

Keep the descriptor's Ed25519 self-signature, and require an owner-issued,
vault-bound HPKE challenge plus candidate-signed response before principal add or
replacement.

Why:

The signing self-signature cannot prove control of the independently generated
HPKE private key. A challenge encrypted to that key and answered under the paired
signing key proves that the candidate controls both without publishing private
material.

Rejected alternative:

Treating the descriptor self-signature as proof for both keys could register an
undecryptable or attacker-substituted HPKE key and strand later grants.

### D17 — Replace principals atomically instead of mutating public keys

Decision:

Principal descriptors and keys are immutable. Key rotation creates a fresh
principal and atomically copies the old authority while rotating every inherited
readable item and removing the old principal and slots.

Why:

A stable principal ID with mutable key material makes historical fingerprints,
slot ownership, and signature authority ambiguous. Atomic replacement gives the
new key no earlier epoch and the old key no later epoch.

Rejected alternatives:

- In-place key edits that blur historical identity.
- Manual add/grant/revoke/remove sequences that expose partial authority states
  and can rotate the same item more than once.

### D18 — Exit history caps through a signed new lineage

Decision:

Never prune authenticated history in place. Create a fresh v3 lineage with new
IDs, keys, revision-one state, and an owner-signed attestation to the validated
terminal source revision; leave the source unchanged.

Why:

Fresh recipients need complete ancestry to validate the original lineage.
Re-genesis bounds future work without claiming that a truncated history is the
same vault or that old artifacts disappeared.

Rejected alternatives:

- Silent proof pruning because it breaks validation and merge guarantees.
- Reusing the source vault ID/genesis because that makes distinct histories look
  merge-compatible.
- Growing caps indefinitely because the artifact and validator need enforceable
  resource bounds.

### D19 — Canonicalize X25519 identity keys at the Jig wire boundary

Decision:

Public descriptors admit only the canonical 32-byte little-endian X25519 `u`
coordinate emitted from the stored private key, with the high bit clear and the
integer below `2^255 - 19`. Fingerprints, duplicate-key checks, registration
proofs, and principal replacement consume that representation.

Why:

The X25519 primitive must process several non-canonical RFC 7748 inputs as the
same field element. Hashing or comparing those raw aliases would let one
cryptographic key acquire multiple fingerprints and evade semantic duplicate-key
checks.

Rejected alternative:

Accepting every primitive-level encoding directly into the application wire
format because it makes identity and replacement equality representation-
dependent.

### D20 — Treat recipient forward secrecy as an explicit non-goal

Decision:

V3 states that later compromise of a static HPKE private key can decrypt matching
slots and ciphertext in retained historical artifacts. Identity passphrase
change preserves that key. Principal replacement and reader-set rekey protect
only later epochs.

Why:

RFC 9180 HPKE Base mode does not provide forward secrecy after recipient-key
compromise. Epoch rotation still gives the intended grant-time separation and
post-revocation exclusion for newly produced state, but it cannot retroactively
change copied artifacts.

Rejected alternative:

Describing revocation, passphrase change, or principal replacement as protecting
historical vaults without a forward-secure recipient protocol.

### D21 — Compile out HPKE's panic-on-entropy-failure convenience API

Decision:

Build `hpke` without its `getrandom` feature. Jig first crosses its existing
fallible `getrandom::fill` boundary, then seeds a private non-exhausting
`CryptoRng` and calls only `*_with_rng` provider APIs.

Why:

The dependency's system-random convenience paths panic on entropy failure, while
Jig's current cryptographic boundary returns a typed error. Compiling those paths
out makes the provider contract mechanically narrower than a call-site promise.

Rejected alternative:

- Enabling `hpke/getrandom` and relying only on review to prevent accidental use.
- Feeding `*_with_rng` from a finite buffer whose exhaustion introduces a new
  panic path.

### D22 — Derive separate descriptor and body keys from the wrapped item root

Decision:

Each item epoch has one random 32-byte item root key. HPKE slots wrap only that
root. HKDF-SHA256 with canonical, domain-separated contexts derives distinct
descriptor and body keys, and typed APIs prevent the root or either derived key
from being used in the wrong AEAD role.

Why:

Descriptor and body encryption have different plaintext schemas, lifecycles,
AAD, and nonce streams. Cryptographic key separation confines accidental nonce
collision or protocol misuse to one domain without multiplying recipient slots
or changing the reader-set rotation model.

Rejected alternatives:

- Using the wrapped root directly as both AEAD keys because distinct AAD and
  nonces do not provide key separation.
- Wrapping descriptor and body keys separately because it doubles every
  recipient slot and creates an unnecessary consistency invariant.
- Deriving keys with ad hoc string concatenation because canonical typed HKDF
  contexts and independent vectors already provide the wire-freeze discipline.

### D23 — Version exact KDF profiles and separate backup credentials

Decision:

V3 identity and backup headers admit exact `portable-v1` and `hardened-v1`
Argon2id tuples. Portable remains the 128 MiB/three-pass/four-lane default;
hardened explicitly selects the current safe 512 MiB ceiling. Passphrase change
upgrades weak profiles and preserves stronger ones unless the operator explicitly
confirms a downgrade.

Owner backups capture an independent passphrase by default. Their encrypted
payload contains canonical identity recovery material, and a fresh restore
reseals that material under a newly selected identity passphrase rather than
installing an identity that still depends on the historical live credential.

Why:

Named exact profiles make KDF cost inspectable and upgradeable without allowing
an attacker-controlled pre-authentication header to request arbitrary memory.
Separating the backup credential avoids making one guessed or disclosed human
secret the default key for both daily identity use and disaster recovery.
Recovery material must change form because an exact still-encrypted identity file
would require the old identity passphrase in addition to the independent backup
passphrase and would therefore contradict full-owner recovery.

Rejected alternatives:

- Accepting arbitrary stored Argon2 parameters within broad ranges because the
  header is untrusted until after the expensive KDF and AEAD authentication.
- Making RFC 9106's 2 GiB profile the current hardened setting without supported-
  platform peak-memory evidence or raising the existing allocation ceiling.
- Automatically lowering a hardened identity during passphrase change because a
  credential rotation must not silently weaken offline-guessing resistance.
- Reusing the live identity passphrase for backups by default because compromise
  of one human secret then exposes both daily and recovery copies.
- Keeping only the exact encrypted live identity file in the backup because an
  independent backup passphrase alone could not restore it.

### D24 — Fail closed on compact-secret paging and ordinary core dumps

Decision:

Private commands disable process core dumps before unlock and place compact
credentials, provider outputs, identity/item roots and private keys, derived
keys, audit seeds, and RNG seeds in page-dedicated locked/dump-excluded memory.
Failure is blocking unless the operator makes one explicit, persistently reported
emergency override. Bulk bodies, serializer copies, child copies, and the large
Argon2 workspace retain zeroization and dump suppression but not an `mlock`
guarantee.

Why:

Zeroization limits lifetime but does not stop a live buffer from entering swap or
an ordinary core. Locking only dedicated compact allocations is enforceable
under normal resource limits and avoids pinning unrelated allocator pages. The
Argon2 workspace is intentionally 128–512 MiB and cannot honestly be promised
locked on typical unprivileged systems.

Rejected alternatives:

- Treating `zeroize` as paging/core protection because it acts only when the
  buffer is wiped.
- Silent best-effort `mlock` because operators would believe a property that may
  have failed at runtime.
- `mlockall` or locking the full Argon2/body workspace because ordinary limits
  make that unreliable and it can damage system availability.
- Claiming protection from root, live debuggers, DMA, or unencrypted hibernation
  because these controls do not establish such a boundary.

### D25 — Compose passphrases with one non-bypassable device protector

Decision:

An identity may use portable passphrase protection or require the passphrase plus
exactly one OS keychain, Secure Enclave, TPM2, or FIDO2 factor. Device-bound mode
combines both inputs to wrap one random identity root and contains no portable
fallback slot. Hardware/provider loss recovers only through an independently
encrypted owner backup that enrolls replacement protection.

Why:

A second factor improves resistance to a copied identity file plus guessed or
disclosed passphrase only when possession remains mandatory. Keeping a
passphrase-only slot beside the hardware slot would preserve the original attack
path. Protecting a random identity root lets credential/protector rotation remain
separate from stable HPKE and signing identity.

Rejected alternatives:

- Alternative passphrase and hardware unlock slots because the weaker slot
  bypasses the stronger one.
- Hardware-only unlock because it removes the independent knowledge factor and
  makes unattended account/device compromise the sole gate.
- Moving Jig's principal HPKE/signing keys directly into every hardware backend
  because provider algorithm differences would fragment the public wire suite
  and complicate backup recovery.
- Shelling out to keychain/TPM/FIDO tools with secret argv/environment because it
  creates additional disclosure and parsing boundaries.

### D26 — Bucket sizes and make cover reseals look like ordinary updates

Decision:

V3 pads item bodies to fixed 4 KiB–8 MiB power-of-two buckets and encrypted
backups to 4–64 MiB targets. Logical length and body padding authenticate inside
AEAD; backup framing binds its target and padding. Public vault JSON and transfer
framing remain unpadded because a parseable public padding field exposes its own
length. An authorized optional cover command reseals unchanged body bytes as an
ordinary signed item revision with no public cover discriminator.

Why:

Exact ciphertext length can reveal field growth or distinguish small logical
states even when values are encrypted. Buckets materially reduce that signal
without making every item consume its maximum. An ordinary-form reseal gives
artifact observers plausible uncertainty about whether same-bucket plaintext
changed; marking it publicly as cover would defeat that purpose.

Rejected alternatives:

- No encrypted body/backup padding because exact secret-bearing length remains an
  avoidable oracle.
- Padding every item/backup to its maximum because a 1,024-item portable vault
  and routine recovery artifacts would become impractical.
- Adding a visible padding field to public JSON/transfer framing because its
  length lets any parser recover the unpadded public size.
- Compression before encryption because secret-dependent size reintroduces an
  oracle and increases parser complexity.
- Claiming full traffic confidentiality or adding a required online cover daemon
  because the offline signed artifact still exposes revisions, opaque item IDs,
  file access, missed cadence, and transport timing.

## 29. Review history

### Review round 1 — threat model and cryptographic consistency

Focus:

- recipient confidentiality;
- writer/owner authenticity;
- revocation semantics;
- signature preimages;
- historical validation.

Material findings incorporated:

- Prior item proofs must retain the signed public nonce while discarding only old
  ciphertext.
- Owner self-revocation would leave no authorized signer for replacement item
  revisions under the new policy, so a different remaining owner is required.
- Key slots need issuance policy sequence and role so their HPKE AAD remains
  reproducible after role-only changes.
- Public descriptors need a signing-key proof of possession, not only a
  recomputed fingerprint.

Result:

No unresolved cryptographic cycle remains between item revision hashes and the
policy rotations that bind them.

### Review round 2 — identity, migration, backup, and crash recovery

Focus:

- filesystem separation;
- migration audit continuity;
- absent-target publication;
- backup authority;
- partial failure states.

Material findings incorporated:

- An identity root under the vault base would fall inside the legacy/global vault
  home, so identity storage moved to independent
  `~/.jig/vault-identities`/`JIG_VAULT_IDENTITY_HOME` resolution.
- Migrated legacy audit bytes need an owner-signed digest/terminal-MAC attestation
  because the v2 DEK-derived verification key is discarded.
- Migrated owner backups must include the matching legacy audit archive.
- Transfer and backup caps are explicit at 32 MiB and the existing 64 MiB,
  respectively.
- Cross-directory restore markers have an exact private location and recovery
  role.

Result:

Every durable migration/restore edge has a named primary commit point or safe
retry state; no plan step claims atomicity across unrelated directories.

### Review round 3 — concurrent workflows and compatibility

Focus:

- owner/developer concurrent changes;
- stale authorization;
- legacy command behavior;
- partial-unlock caller semantics;
- bead dependency usefulness.

Material findings incorporated:

- Transfer merge must recheck an advancing stale branch's author and key epoch
  against the selected current policy, rejecting removed writers and old epochs
  while allowing unrelated policy changes.
- Existing unchanged item revisions remain historically valid after their author
  loses write authority.
- Compatible `vault secret` and `vault run` names must route exact representable
  names to canonical item roles; only unrepresentable names use the owner-only
  legacy compartment.
- Aggregate snapshots/lists are explicitly documented multi-item decrypt
  operations rather than implicit session-open behavior.

Result:

The onboarding, offline edit, owner policy update, merge, revoke, migration, and
recovery flows have consistent authorization and compatibility rules.

### Review round 4 — self-containment, terminology, and dependency steady state

Focus:

- all 19 child specifications;
- parent epic scope;
- exact acceptance sections;
- marker extraction;
- dependency cycles/orphans;
- stale contradictory terminology;
- decision rationale.

Checks performed:

- All B01–B19 begin/end markers occur exactly once.
- Every child contains one acceptance section and one dependency statement.
- `tsort` accepts the blocking graph and B19 is the unique terminal child.
- Searches found no TODO/TBD implementation placeholders.
- Searches found no obsolete identity-under-vault path or nonce-discard claim.
- Every child produces code, tests, fixtures, docs, or release behavior; none is a
  planning/review/status bead.
- The decision register records alternatives and reasons for more than five
  material choices.

Result:

Steady state reached.

No fourth-round architectural correction was required after the first three
rounds' changes.

The original scope was ready for its initial Beads conversion.

### Review round 5 — private item discovery and low-ceremony UX

Focus:

- whether inaccessible item names may appear in normal UI;
- the cryptographic and data-model cost of private names by default;
- developer onboarding, identity selection, transfer, and recovery ergonomics;
- honest reminders in an offline-first distribution model.

Material findings incorporated:

- Canonical item names moved from public policy metadata into independently
  encrypted per-item descriptors. Public policy, tombstones, and transfer
  inspection use opaque random item IDs and never name-derived identifiers.
- A selected session discovers only its accessible catalog by decrypting small
  descriptors for slots granted to that identity. Inaccessible and nonexistent
  caller-supplied names share one `AccessDenied` response shape.
- Rename re-encrypts only the descriptor, while read revocation rotates the item
  root, derives fresh descriptor/body keys, and re-encrypts both ciphertexts.
- Normal CLI and TUI surfaces omit inaccessible rows and counts. Raw artifacts
  still reveal opaque compartments, sizes, principals, grants, revisions, and
  activity; those residual leaks are explicit rather than implied away.
- Principal onboarding and batch grants became atomic single-revision
  operations with dry-run previews. Identity names, guided initialization,
  accessible-only filters, transfer inspection/status, and backup
  verify/drill/status flows were added.
- Shared-state mutations report local export state and recommend redistribution
  without claiming delivery. Authenticated local receipts record only local
  export and backup evidence and never participate in authorization or
  freshness.

Result:

Private item names are the v3 default. The additional descriptor scan, rename,
revocation, migration, fixture, and performance work is accepted as the right
tradeoff for not revealing environment or secret names to unauthorized
developers.

### Review round 6 — post-conversion synchronization and steady state

Focus:

- exact synchronization between this plan and the parent plus B01–B19 Beads;
- dependency changes introduced by local export/backup receipts;
- stale visible-name or locked-row assumptions;
- graph readiness and Beads lint.

Checks performed:

- Parent and child descriptions extracted from the marked plan blocks match the
  corresponding Beads records exactly.
- All B01–B19 begin/end markers still occur exactly once, and every child still
  has one acceptance section and one dependency statement.
- B14 now depends on B06 because transfer status consumes the local receipt
  substrate; the graph remains cycle-free with B01 as the sole ready child and
  B19 as the terminal child.
- Searches found no remaining contract that reveals inaccessible rows or names
  through policy, transfer inspection, or tombstones.
- Beads lint reports no malformed descriptions or dependency errors.

Result:

The privacy and quality-of-life expansion is fully represented in both the
implementation plan and its execution graph. No further structural correction
was required after the terminology and B14 dependency updates.

### Review round 7 — encryption-model closure and bounded lifecycle

Focus:

- retained pre-grant ciphertext;
- private descriptor length leakage;
- proof of independent HPKE-key control;
- principal-key replacement;
- permanent history caps;
- provider entropy/zeroization behavior;
- normative canonical bytes.

Material findings incorporated:

- Every effective reader-set change now rotates the item root key, derives a new
  descriptor/body key pair, reseals both ciphertexts, and replaces all slots.
  Role-only reader/writer changes remain cheap.
- `ItemDescriptorV1` now has an exact fixed 256-byte plaintext encoding, closing
  item-name length disclosure. General body padding remained out of scope in
  this round and was later addressed with bounded buckets in round 11.
- Principal addition/replacement now requires an owner challenge and candidate
  response that proves both HPKE decryption and Ed25519 signing-key control.
- Public keys are immutable; atomic principal replacement copies exact authority,
  rekeys inherited readable items once, and removes every old slot.
- New B20 owns exact capacity preflight and an owner-signed v3-to-v3 rollover into
  a distinct lineage without pruning or overwriting the source.
- B01 explicitly proves X25519 drop zeroization and fallible entropy behavior;
  B03 freezes every cryptographic preimage against independent exact-byte
  vectors.

Checks performed:

- All B01–B20 begin/end markers occur exactly once, including the new B20 block.
- Every child has one acceptance section and one dependency statement.
- The synchronized Beads dependency graph is cycle-free and keeps B19 as the
  unique terminal child.
- Searches find no active grant-without-reseal, variable descriptor-length, or
  signing-only possession claim outside superseded review-history prose.

Result:

The plan now covers confidentiality in both directions of membership change and
has explicit operational paths for key replacement and bounded history. The
remaining work is implementation through the synchronized delivery Beads.

### Review round 8 — recipient compromise and wire-key canonicality

Focus:

- later compromise of static HPKE recipient keys;
- the distinction between passphrase rotation and principal-key replacement;
- X25519 non-canonical field-element aliases at the descriptor boundary;
- elimination of the provider's panic-on-entropy-failure convenience surface;
- independent final protocol review before release.

Material findings incorporated:

- The threat model and public contract now state that HPKE Base mode provides no
  recipient forward secrecy for retained historical artifacts. Principal
  replacement and rekey protect later epochs only.
- Public descriptors now require one canonical Jig X25519 encoding before
  fingerprinting, self-signature verification, duplicate-key comparison, or
  registration proof. Negative tests cover aliases and all-zero shared secrets.
- B01 now compiles `hpke` without `getrandom`, seeds a non-exhausting private RNG
  only after Jig's fallible entropy boundary succeeds, and rejects finite-buffer
  adapters that can panic on exhaustion.
- B19 now requires an independent review of the final protocol implementation and
  blocks release on unresolved high-severity findings.
- The parent acceptance text now requires B01 through B20, matching the plan and
  dependency graph.

Checks performed:

- The current crate's `random_array` uses fallible `getrandom::fill`, providing
  the repository-owned entropy boundary referenced by B01.
- The current passphrase-change implementation preserves the underlying DEK,
  confirming the existing distinction between storage-credential rotation and
  cryptographic key rotation that v3 identity handling must retain explicitly.
- Marked Beads blocks were re-extracted after editing and synchronized through
  the configured `br` tracker.

Result:

The plan is ready for B01 without an unresolved encoding, entropy, or recipient-
compromise ambiguity. The remaining cryptographic assurance step is the
implementation-tied independent review required by B19.

### Review round 9 — item content-key separation

Focus:

- direct reuse of one item key across descriptor and body AEAD domains;
- exact HKDF context binding and independent vectors;
- root-key slot semantics and lifetime;
- same-epoch nonce uniqueness within each derived-key domain;
- propagation through migration, rollover, sessions, tests, and release review.

Material findings incorporated:

- The per-epoch random secret is now an item root key that is wrapped in HPKE
  slots but never passed directly to an AEAD.
- HKDF-SHA256 derives non-interchangeable descriptor and body keys from canonical
  contexts binding suite, vault, item, epoch, and purpose.
- Descriptor and body nonce reuse is rejected independently within each item
  root epoch; equal nonce bytes across the two domains do not imply key reuse.
- Catalog construction discards item roots, HKDF intermediates, and descriptor
  keys promptly, while an item guard retains only its derived body key.
- B01, B03, B04, B05, B07, B09, B16, B17, B18, B20, and B19 carry the provider,
  wire, replay, lifecycle, leakage, documentation, adversarial, rollover, and
  final-review acceptance needed to keep the invariant intact.

Checks performed:

- All 21 marked parent/child specifications match their Beads descriptions
  byte-for-byte after synchronization.
- Beads lint reports no template warnings and graph analysis reports no cycles.
- Searches find no active direct shared-DEK descriptor/body contract.
- The repository contract, Rust file-size gate, and whitespace diff check pass;
  Rust format, Clippy, and test gates are path-not-applicable because this round
  changes only the plan and tracker contract.

Result:

The v3 delivery contract now makes descriptor/body key separation a typed,
vector-tested cryptographic invariant without increasing slot count or changing
reader-set semantics.

### Review round 10 — password KDF and recovery credential separation

Focus:

- portable versus hardened offline-guessing cost;
- untrusted KDF-header resource allocation;
- deterministic passphrase-change upgrades and downgrade prevention;
- independent owner-backup credentials;
- full recovery after separating the live identity and backup passphrases.

Material findings incorporated:

- V3 now records exact named Argon2id tuples. Portable retains the production
  128 MiB/three-pass/four-lane setting; hardened opts into the current 512 MiB
  maximum rather than raising an attacker-influenced allocation ceiling without
  measurements.
- Profile ID and every parameter must match an allowlisted tuple before Argon2
  allocation or passphrase capture. Older formats keep their own validation.
- Passphrase change upgrades weaker profiles, preserves hardened cost by default,
  and requires an explicit warned portability downgrade.
- Backup creation captures a separate credential by default and strips its new
  environment variable from child processes. Deliberate equality with the
  identity passphrase is an explicit warned exception.
- The v3 backup payload now carries canonical identity recovery material inside
  its outer encryption. Fresh restore preserves the principal keys and local
  seed but reseals them with a new identity passphrase, salt, nonce, and profile.

Checks performed:

- Current `crypto.rs` production settings and 512 MiB accepted ceiling were
  confirmed before fixing the two profiles.
- The recovery flow was traced end to end to remove the previous contradiction
  where an independent backup credential would still leave the embedded identity
  locked under its old passphrase.
- B02, B10, B12, B15, B16, B17, B18, B19, and the parent epic carry the format,
  CLI, environment, restore, UX, documentation, adversarial, and release work.

Result:

The v3 contract strengthens offline guessing within a bounded resource model and
makes an independent backup passphrase sufficient to recover and re-credential
the owner identity. Weak human passphrases remain an explicit residual risk.

### Review round 11 — local-memory, device-bound identity, and size privacy

Focus:

- pageable compact secrets and ordinary process core dumps;
- hardware-backed unlock without a weaker recovery slot;
- provider capability, presence, cancellation, and loss behavior;
- exact encrypted-body/backup length leakage and measurable public framing;
- what cover activity can and cannot conceal in an offline signed artifact.

Material findings incorporated:

- Private operations now suppress ordinary cores before capture/unlock and use a
  page-dedicated protected allocation for compact credentials and keys. Lock
  failure is visible and fail-closed by default.
- The plan explicitly excludes bulk bodies and the 128–512 MiB Argon2 workspace
  from the lock guarantee, retains zeroization/dump suppression, and requires
  encrypted swap/hibernation rather than making an unsupported OS claim.
- Identity encryption now has one random root. Portable mode derives its wrap
  key from the passphrase; device-bound mode combines that key with exactly one
  keychain/Secure Enclave/TPM2/FIDO2 response and stores no portable bypass.
- Device cancellation/loss never falls back. Independent owner backup recovery
  enrolls replacement protection while preserving principal keys.
- Canonical item bodies and encrypted backups use exact bounded size buckets.
  Public vault/transfer framing remains measurably bounded rather than claiming
  ineffective padding; capacity effects, migration, rollover, and restore are
  part of the delivery Beads.
- A writer-authorized cover operation reseals unchanged content using the normal
  signed item-revision form. The plan retains explicit leakage of opaque item
  identity, revision sequence, filesystem/transport timing, and schedule gaps.

Checks performed:

- Existing one-megabyte per-field and 16 MiB vault limits were reconciled with
  the 4 KiB–8 MiB body buckets and their total-cap effects.
- Linux/macOS support boundaries and the existing Unix child-process lifecycle
  were traced before defining dump, fork, and inherited core-limit behavior.
- Apple Keychain/Secure Enclave, FIDO2 `hmac-secret`, TPM2, and Linux memory-
  protection specifications were added as implementation evidence; claimed
  provider support remains gated on real-hardware conformance.
- B01, B02, B03, B05, B07–B10, B12, B14–B20, and the parent epic carry the
  provider, format, lifecycle, UX, adversarial, rollover, and release work.

Result:

The v3 contract now narrows ordinary swap/core exposure for compact secrets,
supports additive device-bound identity protection without a bypass slot, and
reduces exact size leakage without overstating offline traffic confidentiality.

## Revision note — 2026-08-28

Strengthened the existing plan in place instead of replacing its history. The
revision closes six encryption-model gaps, hardens the selected provider
contract, adds B20 for rollover/capacity work, and preserves B19 as the terminal
integration gate.

The same revision now also versions bounded identity/backup KDF profiles and
separates backup recovery credentials while preserving full owner recovery
through fresh identity resealing.

It now additionally requires protected compact-secret memory and pre-unlock dump
suppression, additive keychain/Secure Enclave/TPM2/FIDO2 identity protection,
bounded body/backup size buckets, and honest ordinary-form cover reseals.

## Revision note — 2026-08-28 (review round 8)

Clarified the recipient-compromise boundary, distinguished passphrase rotation
from principal-key replacement, fixed X25519 application-wire canonicality and
semantic duplicate-key requirements, compiled the HPKE panic-prone randomness
surface out of B01's intended feature set, added corresponding adversarial and
documentation tests, and made an independent final protocol review a B19 release
gate. The parent completion text was corrected to include B20.

## Revision note — 2026-08-28 (review round 9)

Replaced direct descriptor/body use of one item DEK with a wrapped per-epoch item
root key and canonical HKDF-SHA256 derivation of independent descriptor and body
keys. Propagated the new key types, zeroization lifetime, nonce-domain checks,
vectors, migration/rollover behavior, adversarial coverage, documentation, and
independent-review requirements through the synchronized delivery plan.

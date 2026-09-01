# Initial architecture

This document records repository boundaries, not a finished security protocol.
Jury `0.x` is a pre-alpha witnessed-access experiment. It has no completed
independent professional security review and must not be used for real secrets.

The authoritative project sequence and protocol-design requirements are tracked
in [jury-v1-master-plan.md](jury-v1-master-plan.md). Jig compatibility is a
downstream concern documented separately in
[jig-cutover-plan.md](jig-cutover-plan.md).

## Product boundary

The active release owns the portable vault format, portable encrypted
identities, grants, direct and witnessed item access, approval workflows,
offline-verifiable decision receipts, the self-hostable witness service, and
the CLI on Linux. Jury has no dependency on Jig; consumers such as Jig integrate
through stable Jury interfaces. macOS, Windows, the TUI, hardware-backed
identity protectors, and managed-service topology are deferred.

```text
       +------------+
       |  jury CLI  |
       +------+-----+
              |
     stable use-case seams
              |
        +-----v------+
        | jury-core  |
        +------------+
              |
   bounded protocol contracts
              |
      +-------+-------+
      |               |
+-----v------+   +----v-------+
| jury client |  |   juryd    |
+-------------+  +------------+
```

The dependency graph must remain acyclic. Storage and CLI transport details
must not leak into `jury-core`. Protocol types cross boundaries through bounded,
versioned contracts; HTTP and database adapters do not enter the witness engine.

## Child-process containment boundary

`jury-process` owns the neutral child-process boundary used by later guarded
execution work. The active `0.x` contract supports Linux only. A provisional
macOS backend remains in source for deferred post-`0.x` work; it is not a
supported release surface, required CI evidence, or a shipped artifact. Targets
without an implemented containment guarantee reject the operation before
spawning a child instead of silently weakening cleanup. The crate has no Jig
dependency; its design was checked against
`jig-sh` revision `eed70cee337b0067ed92deb9fa05017b0b284605`, then implemented
with pinned `rustix` and `wait-timeout` providers rather than retaining the
`jig-owned-process` package identity, its unsafe libc boundary, or any Jig
runtime dependency. The pinned external providers report MIT/Apache-family
license options; Jury's own release license remains a separate J26 decision.
Provisional macOS-only `libproc` remains deferred with that backend.

Each child starts as leader of a new process group. Jury keeps the leader's
wait status unconsumed while it may still signal that numeric group, forwards
the supported portable signal set only after a fresh non-reaping identity
check, terminates the group on success and failure paths, proves two consecutive
quiescent group snapshots, and only then reaps the leader. The active Linux
membership proof requires readable `/proc` process metadata. The provisional
macOS path uses a native libproc process-group snapshot but contributes no
active release evidence. Failure to establish those guarantees is an explicit
cleanup error, not evidence that cleanup succeeded.

Captured stdout and stderr have separate configured retention bounds and are
drained with finite deadlines. A configured streaming redactor receives chunks
before observers or retained captures and maintains independent stream state.
Truncation can continue draining without retaining more bytes; a fatal overflow
instead initiates tree cleanup. Spawn failure, pre-spawn cancellation, runtime
cancellation, timeout, signal-forwarding failure, output failure, and cleanup
failure remain distinguishable outcomes. Exit status exposes both an ordinary
code and a terminating signal where the platform reports one.

The containment guarantee covers descendants that remain in the created
process group. A deliberately detached descendant that calls `setsid` or moves
to another group is outside that guarantee. If such a process retains an output
pipe, capture ends at its drain deadline and reports the stream incomplete;
Jury does not wait without bound or claim that the detached process was killed.
Callers must configure redaction before running commands that may emit sensitive
values. These are pre-alpha execution mechanics, not a claim that Jury protects
secrets.

Containment does not erase copies owned by the caller's `Command`, Rust's spawn
machinery, kernel pipe buffers, or the child address space. Its delivery caller
must therefore keep protected values out of argv and the ambient environment,
bind stdin or descriptor delivery, close every local pipe owner, and configure
streaming redaction before any output observer or capture sees bytes.

The J14 native adapter now supplies that direct-access delivery layer. It parses
all restricted environment inputs and resolves the working directory plus an
opened executable before private capture. It then authenticates every distinct
item against one parsed vault revision, copies only selected fields into
protected mappings, clears decrypted item bodies, builds redaction from
concealed fields, and prepares all delivery channels before child spawn. Field
values may enter only an explicitly mapped child environment variable,
protected stdin pipe, or sealed anonymous Linux `memfd`; they never enter child
arguments or a named plaintext file. A hidden helper re-enters the already
running Jury image through Linux `/proc/self/exe`, then marks every inherited
descriptor close-on-exec except the pinned executable and explicitly selected
anonymous files before replacing itself with that executable.

Transparent `jury exec` inherits ordinary stdin and environment, removes every
`JURY_*` variable, streams post-redaction stdout/stderr without a capture or
overall-runtime limit, and mirrors the exact
child status. Brokered `jury run` starts from a small allowlist, supplies EOF
unless stdin is mapped, and applies an explicit timeout and separate output
retention bounds. Both modes suppress ordinary core dumps before credential
capture and use the same complete process-group owner. Direct J14 records a
secret-free digest over the pinned executable's path and metadata, exact
argument bytes, working directory, typed destinations, and field references.
This is intentionally weaker than a content-stable executable identity: in-place
file mutation, script interpreters, and dynamic dependencies remain visible
platform limitations for the J22 action-manifest assurance level. J14 is not
witnessed authorization, and an authorized child may copy or retain plaintext.

## Git-backed storage boundary

Jury's native default inside a Git worktree is the committed portable
artifact at `<worktree-root>/.jury/vault.json`. Git is an untrusted transport
and history layer, not an authorization or integrity mechanism. Jury validates
the artifact's own vault identity, genesis, policy ancestry, item ancestry,
writer signatures, suites, bounds, and retained local checkpoint before private
work. Git authorship, commit signatures, pull-request approval, branch names,
and merge commits never substitute for Jury principal authority.

The repository contains only the portable shared artifact and public Git
integration metadata. Private identities live in the platform data directory.
Rollback checkpoints, local audit, locks, and recovery transaction state live
in a platform-local state root keyed by vault ID, genesis
fingerprint, and principal ID. Plaintext and private keys never enter the
worktree, Git index, objects, diffs, hooks, or filters.

Fresh clones have no retained rollback state. Human use therefore requires an
explicit genesis-fingerprint trust decision before private work; non-interactive
use requires the expected fingerprint from a trust source outside the cloned
repository. A fingerprint committed beside the artifact is discovery metadata,
not an independent trust anchor.

`vault.json` is an opaque Git artifact. Ordinary textual conflict resolution is
forbidden. The first `0.x` public verifier accepts only an identical artifact or
an authenticated strict descendant. Any divergence, including independent-item
progress, remains a conflict and requires explicit operator recovery; semantic
diff and merge are deferred. Checking out an older or divergent artifact is
evaluated against retained local state and never silently lowers it.

Mutation dry-runs produce the exact canonical artifact bytes later consumed by
commit; commit does not regenerate signatures, entropy, slots, or policy
operations. Git-backed commit holds one vault/genesis edit lock shared by all
principals and linked worktrees using the same state root, rechecks both the
artifact digest and an opaque digest of `HEAD`, its loose ref, `packed-refs`,
the worktree reflog, and index without invoking Git, and prepares every bounded
output before changing a durable destination. It then publishes the acting
principal's authenticated audit intent, atomically replaces only encrypted
`.jury/vault.json`, and advances the separate checkpoint. A failure after the
shared replacement is reported as committed with local recovery required;
retry reconciles the audit/checkpoint and never republishes the shared
mutation.

Detached and global homes remain supported for users who do not want the
documented public policy, principal/grant, size-bucket, and revision-activity
metadata in a repository.

The Linux CLI currently implements deterministic repository/global/explicit
home selection, portable identity initialization and public-header status, and
empty genesis-vault initialization/public status. Repository initialization
creates only the encrypted artifact plus the fixed `.gitattributes` rule;
identity and local checkpoint/audit/receipt files are created outside the
worktree. Administrative item, policy, read, inject, and witnessed workflows
remain incomplete and are not implied by this storage foundation.

## Intended access modes

Jury's defining `0.x` path is **witnessed open**. A request binds the exact vault,
item, content role, revision seal, policy checkpoint, action manifest, workload,
expiry, and request session. Current approvers sign that request only after a
meaningful verified rendering. Independent witnesses validate the request and
decisions, enforce replay and checkpoint rules, and return revision-scoped
contributions. The endpoint passes only the resulting protected revision secrets
through the guarded item-access operation.

An authorized endpoint may retain a revision it was allowed to open. The
witnessed claim is therefore fresh authorization for each later revision seal,
not use-without-view, forgetting, universal freshness, or retroactive
revocation.

Jury also supports explicit **direct** slots for recovery, bootstrap, and
low-assurance use. A direct recipient can open its item without witnesses and
has unilateral access. If an item carries any usable direct slot, Jury makes no
quorum or distributed-authority claim for that item. Direct and witnessed paths
share the same guarded use-case interface and cannot expose raw identity keys,
epoch roots, reusable witness contributions, or revision secrets to adapters.

## Non-negotiable seams

- Algorithm-tagged, versioned direct and witnessed recipient slots frozen in
  format v1 before implementation.
- An item-access interface independent of the CLI and transport. Direct and
  witnessed paths release only the exact descriptor/body secrets for one
  authenticated revision seal.
- One authenticated cryptographic suite per vault lineage, with no negotiation,
  fallback, or mixed active suites. The format reserves authenticated
  new-lineage migration records, but the first `0.x` has no runtime suite
  migration or rollover command.
- Signed, canonical public policy separated from encrypted item bodies.
- Per-item data-encryption keys and exact reader/writer grants.
- Explicit randomness, identity, filesystem, and process boundaries for testing.
- No secret values, private keys, decrypted payloads, or passphrases in logs,
  errors, test names, snapshots, receipts, or telemetry.

## Trust boundary

Every access mode intentionally trusts the authorized endpoint with plaintext
for the selected revision. Jury cannot make that endpoint forget it. A direct
recipient can also retain and open every direct capsule addressed to its
long-lived key. A witnessed endpoint may retain an already released revision,
but the accepted J19 construction must show that retained endpoint-visible state
cannot open a later revision seal without a fresh authorized quorum, absent an
explicit direct path or excluded compromise threshold. Fresh clones have no
authoritative latest-state signal beyond an external checkpoint supplied by the
operator.

## Implementation gate

No `0.x` build is production cryptography. Shared and direct cryptographic
implementation may land only after the repository contains:

- a reviewable threat model and explicit nonclaims;
- a versioned direct-slot, witnessed-slot, and storage specification;
- a minimal machine-validated gate manifest binding the exact J01A suite
  artifact and canonical shared/direct preimage corpus, provider revisions,
  specifications, and vectors;
- algorithm and encoding choices grounded in primary standards or explicitly
  pinned primary specifications whose non-standard status is disclosed;
- every positive or conditional security-property claim mapped to an exact
  security notion, attacker model, public analysis or proof pinned by revision
  and content hash when mutable, assumptions, and a complete construction-level
  composition argument; unsupported properties remain explicit nonclaims;
- deterministic cross-implementation test vectors;
- rollback, recovery, rekey, and revocation semantics;
- adversarial and failure-injection test plans.

J01A freezes the shared primitive suite, direct-slot construction, and every
canonical shared/direct cryptographic preimage. J01B proves the selected
providers and owns the minimal direct gate manifest. J05 may only embed those
locked direct preimages, plus the J19-owned witnessed preimages, into its outer
bounded storage format; it cannot redefine either construction. No provider
dependency or cryptographic adapter may land until J01A and J01B are accepted
and that gate passes, and no encrypted identity, item, or backup path may land
until the applicable J05 format is also accepted. This is a drift-prevention
control, not a security certification or substitute for independent review.

J01A also freezes the native-identifier generation contract. J02 owns the
fallible randomness seam, J03 owns the single shared generator and
representation, and creation tasks own only their scope-specific collision
checks and atomic publication. No global `VaultId` registry exists, so global
uniqueness remains an explicit probabilistic nonclaim.

Witnessed/distributed cryptographic implementation has one additional active
pre-implementation gate and one release-candidate verification step.
J19A selects the construction and threat model; J19B freezes protocol-v1
schemas and state machines; J19C publishes vectors and a bounded
endpoint-retention model; J19 binds those exact pre-implementation artifacts
plus provider versions in a machine-validated gate after a fresh solo
verification pass. J20-J23 and witnessed portions of J05/J07/J08/J10 cannot
claim implementation before that gate opens. After implementation and
adversarial testing, J26 binds the exact
security-critical implementation, minimal gate verifier, provider lock data,
build inputs, and release artifacts after J25 and a fresh solo
release-candidate verification pass. The release remains blocked rather than
substituting coordination, static share release, or a mock quorum for the
promised authority model.

J19R/J19D external construction review and J19E external implementation/build
review are deferred optional work. They do not gate the active `0.x` release and
may become gates only after an explicit scope revision names an available
qualified reviewer and budget. Self-review, automated tests, independent
implementations, AI/model or coding-agent analysis, and a clean rebuild are
useful evidence but are not independent security review. Every `0.x` release
must state that it is externally unreviewed, experimental, and unsuitable for
real secrets.

## Deferred research

Post-quantum migrations not selected by J01A/J19, FIPS-validated deployments,
hardware witness providers beyond the first narrow adapter, and transparency
systems beyond the J23 release profile remain outside the initial `0.x` cut.

FIPS-validated deployment is not a Jury `0.x` objective. An algorithm appearing in
a FIPS publication is not described as a validated deployment, and no provider,
module, platform, or operational FIPS claim is made.

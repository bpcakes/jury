# Linux 0.0.1 QA and UX audit

## Repair and renewed QA, 2026-09-06

**Final result: the repaired native implementation passed all ten packaged
Linux CLI journeys.** QA-14 through QA-19 are closed. The implementation and
records were committed as `16ab8991422114ca7047ab0ccf55ab40e8e0fc08` after the
2026-09-06 QA run. No remaining functional or UX blocker was reproduced in
those covered paths. Jury remains externally unreviewed pre-alpha software,
unsuitable for real secrets.

Publication remains held for a security-reporting channel, a signing identity,
and a final candidate built from the intended release source. Subsequent
source or documentation changes require a new artifact binding; this historical
pass does not authenticate a later package. See [Linux release preparation](linux-release.md).

This section supersedes the earlier failure recommendations below. It serves
the maintainer's repair-and-retest request; retain the history to explain the
observed wrong-field, input-source, terminal-echo and packaging defects. Retire
this record when a successor release replaces its source and artifact binding.

The shared CLI parser now uses `ITEM/FIELD` (and `{{ITEM/FIELD}}` in templates).
It retains unambiguous `ITEM.FIELD` shorthand and rejects multi-dot shorthand
before publishing output or starting a child. Stored names and crypto/protocol
formats are unchanged. Existing identity authentication consistently accepts
`JURY_IDENTITY_PASSPHRASE`; identity creation and passphrase replacement use
`JURY_NEW_PASSPHRASE`. Explicit stdin still owns every requested passphrase and
confirmation. Field entry at a terminal is hidden with or without
`--value-stdin`; Ctrl-D ends the value, Enter adds a newline, and handled
cancellation restores terminal settings before returning without a mutation.
Exec help now explicitly states its JSON restriction.

The new CI-wired [real CLI/PTY regression](../scripts/check-linux-input-surfaces)
passed against freshly built Linux release binaries. It exercises both
colliding dotted-name pairs plus a legacy shorthand control, exact template
output, and env/stdin/anonymous-file delivery through both exec and run. It
also checks environment-only identity init/public/prove, vault init/audit,
passphrase replacement and old-passphrase rejection, explicit stdin precedence,
wrong/absent input, hidden terminal entry with and without passphrase prompts,
long and multiline values, editing, EOF, binary pipes, size refusal, and
Ctrl-C/INT/TERM/HUP/QUIT/TSTP cancellation. Assertions compare private bytes
without printing them, check unchanged vault files after refusal/cancellation,
and compare restored terminal settings exactly.

All eight broader host release journeys passed: witness lifecycle, approval
review, descriptor access, role onboarding/recovery, shared and disjoint witness
policies, diagnostics/timeouts, and owner changes. The two prompt-driver
failures described below are retained in the first-run log and have separate
passing reruns. The existing three native passphrase-input regressions passed. Renewed
exploratory execution passed interactive initialization, exact binary private
output and mode 0600, overwrite refusal, explicit reveal, missing-field errors,
JSON restrictions, wrong authentication, child exit propagation, both-stream
redaction, template output, audit verification and field removal. The real
HTTPS lifecycle passed with an explicit synthetic CA on both the CLI-to-witness
and witness-to-anchor links, including restart, receipt and cancellation.
The untrusted TLS client was refused. All fixtures were synthetic.

The direct/witness construction gates passed unchanged. The alternate-provider
check passed 27 BoringSSL positive cases, 87 negative cases and two Argon2
positive cases; this is conformance, not independent review. The scoped
repository leak scan detected its seeded leak and found zero exact-needle hits
in the declared scan surfaces. The four bounded J25 fuzz targets passed after
updating the fuzz workspace's separate lockfile for the new pinned nix terminal
adapter. Release-verifier tests passed (9); witness-gate tests passed (4).

Validation corrections are retained explicitly: the first new input test used
a guessed error-code string, corrected to the existing exact contract. Two
PTY journeys initially waited for the old `Passphrase:` prompt and timed out;
the helper now waits for `Identity passphrase:` while retaining its echo,
confirmation, signed-output and scope assertions. Approval and descriptor
journeys then passed fresh reruns. No assertion, timeout, vector or golden was
weakened to obtain a pass.

### QA-18 — P2: missing self-hosting files in the native package

Tracked as `jury-qv4.6.3`. After all nine CLI journeys passed on the first
repaired package, a package-only documentation check found five broken links
from the self-hosting guide: the witness/anchor config examples, both systemd
units, and the deployment README were absent. Architecture and provider
reference links also pointed outside the included files. The recipe now ships
those exact files and referenced reading material, checks local links in owned
guides before archiving, and explains that container/conformance builds need
the full source archive. Upstream notices remain verbatim.

The new packaging regression uses the actual repository guides and configs,
checks exact copied setup bytes and JSON decoding, then removes the witness
example and verifies the link check fails. All nine release-helper tests pass.
Its initial fixture omitted the root license files that the recipe already
copies; adding those real prerequisites fixed the fixture without changing the
link assertion. The full workspace test pass, formatting and clippy had passed;
the ongoing redundant profile pass was cancelled when this packaging finding
required source changes. That interrupted gate is not reported as a pass.
A new candidate and complete final verification replace its source binding.

### QA-19 — P2: accepted public review labels cannot be referenced

Tracked as `jury-qv4.3.15`. Real witnessed exec probes against both the old
package and the first repaired package accepted creation of an item/field
policy with public labels containing spaces, then rejected the combined
reference before producing a request. Both parsers applied the native name
profile. This was initially described as a new regression before the old
parser and old binary were checked; that attribution was incorrect. The
limitation already existed and the reproduction confirmed it on both builds.

The shared parser now also accepts an exact two-string JSON array. It preserves
existing native shorthand while addressing every accepted public label without
separator ambiguity. JSON references are byte-bounded, enforce the existing
256-byte/control-byte label profile, and reject malformed or extra elements.
Template framing follows the JSON string boundaries, so quoted closing braces
inside a label cannot terminate a reference. Signed labels, request formats,
authority and native stored names are unchanged.

The new CI-wired [public-label journey](../scripts/check-linux-public-labels)
passed with real witnesses, an anchor, human approval PTYs, exact template and
child bytes, and offline receipt verification. It covers spaces, Unicode,
quotes, closing braces, dots, slashes and equals signs, an exact 256-byte item
label, two distinct fields, all delivery channels through exec and run, and
malformed-reference refusal before a child starts. The existing input/terminal
suite and unchanged construction gate passed again. The replacement package and
final gates subsequently passed as recorded below.

### Final verified candidate and results

The completed result is retained in the close event for
`plan_01M1W5EPXVEDDTYWFGYKJ8M6TC` in `.agent/state/plans.jsonl`, with supporting
receipts and runs in `.agent/state/`. Both clean offline builds reproduced:

| Artifact | SHA-256 |
| --- | --- |
| `jury` | `31f65eb8675ba83ccec6b642ed8574298e595efa54a9c76a578ddc32ebe10c35` |
| `juryd` | `26a6cb7b3e841a6a4f535543611251d92782a16bc5f93a78254fe1c196f3b26c` |
| `SHA256SUMS` | `532bcf01ce6c245599131ca853cc94b3babb00ff43d85ea50ef1f50bc007c4a4` |

These identify the **unsigned historical candidate**, built from the earlier
Git baseline plus the repaired working source. They are not signing credentials
or checksums for every build of version 0.0.1. The local candidate directory was
`target/linux-release/0.0.1-candidate-public-labels`; ignored local artifacts and
raw logs may be removed and are not distributed through Git.

The recorded final checks passed:

- Ten journeys as an unprivileged Debian 12 user: witness lifecycle, approval
  review, descriptor access, role onboarding/recovery, shared witness policies,
  disjoint witness policies, diagnostics, owner changes, input surfaces, and
  public-label references.
- Packaged installation, PATH lookup, version/help and removal; exact deployment
  files and shipped guide links; HTTPS on the client/witness and witness/anchor
  links, including untrusted-certificate refusal, receipts, restart and cancellation.
- All six required Jig gates: verification profile, contract, Rust LOC,
  formatting, Clippy and workspace tests, with fresh passing evidence at closure.
- Unchanged construction inputs, 46 current-source J25 measurement cases,
  four bounded fuzz targets, alternate-provider conformance, and a scoped leak
  scan whose seeded control was detected and whose actual exact-needle hits were zero.
- Advisory review of 348 dependencies with no vulnerabilities or warnings,
  using database commit `5a0ebedfe8bdd2e295b171f4162f8c977bcad9a5`.

These checks establish the stated local behavior and consistency. They are
neither exhaustive defect discovery nor independent security review. A fresh
release candidate must repeat the applicable checks; no signed publication is
claimed by this record.

## End-user audit before these repairs, 2026-09-06

**Historical recommendation before the repairs: hold Linux 0.0.1.**
Fresh native command execution found QA-14, QA-15 and QA-17 below. At that point
they blocked J26 in the local tracker. QA-16 is a smaller help/UX repair. The previously repaired journeys still pass; their
success does not cover the newly reproduced cases. No application code or
repository tests were changed in this audit.

This update serves the maintainer's explicit request for an end-user QA/UX
audit before releasing Linux 0.0.1. It gates that release because accepted
names can resolve inconsistently and automation ignores a configured input
source. Supersede this section when the repairs and replacement candidate
have been exercised. The historical audit and repair evidence follow below.

The tested source was `ea494154132dc3e10c6b1798d6c17114f2495f92` plus the
pre-existing uncommitted implementation. The package was
`target/linux-release/0.0.1-candidate-layout`; its verifier matched the native
source and artifacts before this report update. Its `SHA256SUMS` digest was
`ef97235639246648d1b6ba291223e43318bcf4aece1866e7808960bb2f1e71bb`.
This locally calculated digest establishes consistency, not publisher
authentication. Packaged binary SHA-256 values:

- `jury`: `cdaafaebf6740c6039a05b5f56759b76dfb8c70a6b12c801f90b3c4da75779d1`
- `juryd`: `347d2d61799d14bb0c91267156324d23f2ad3fb2652b981c588c5ada32784199`

Both report `0.0.1`. A fresh host release build reproduced QA-14 and QA-15.
The host was Linux x86_64 with glibc 2.39 and Rust 1.97.1; the packaged
journeys also ran as an unprivileged user inside the pinned Debian 12 build
image, with external networking disabled. All identities, passphrases,
values, certificates and service credentials were synthetic.

### QA-14 — P1: accepted dotted names cannot be addressed consistently

Tracked as `jury-qv4.3.12`. After synthetic identity/vault initialization:

```sh
jury item create Example.Group --allow-direct
jury vault field set Example.Group ExampleField --value-stdin
jury read --direct Example.Group ExampleField --out /absolute/private/ExampleRead
```

Field input was supplied privately. The read succeeds and returns the exact
bytes. A private template containing `{{Example.Group.ExampleField}}` instead
fails with exit **6**, `item-unavailable`. Both of these fail with exit **2**,
`invalid-execution-request`:

```sh
jury exec --direct --stdin Example.Group.ExampleField -- /bin/true
jury run --direct --env EXAMPLE_VALUE=Example.Group.ExampleField -- /bin/true
```

Next, create item `Example` and field `Group.ExampleField` with a different
synthetic value. The identical template now exits **0** and writes that other
value. Exact byte comparisons confirmed which field was selected; no field
contents were printed as evidence. Both items were accessible to the owner,
so this demonstrates ambiguous addressing, not an authorization bypass.

[Native names](naming.md) explicitly allow dots. The template parser in
`crates/jury/src/cli/template_commands.rs` splits at the first dot, while
`crates/jury/src/cli/execution_commands/support.rs` additionally rejects a
dot in the remaining field name. The same accepted names therefore have
different usability across public command surfaces.

**Repair:** provide an unambiguous way to reference every accepted item/field
name across templates and process bindings. Refuse ambiguous input before
publishing output or starting a child. Do not normalize names or simply
narrow the documented name profile to make existing tests pass. Cover both
colliding pairs with different values and exact native CLI output assertions.

### QA-15 — P2: some commands ignore the configured identity passphrase

Tracked as `jury-qv4.3.13`. With `JURY_IDENTITY_PASSPHRASE` configured for a
synthetic identity, item creation, field operations, injection and process
execution authenticate successfully without consuming stdin. With the same
environment and stdin closed, `jury --json vault init` and
`jury --json vault audit verify` instead return exit **2**,
`passphrase-input-opt-in-required`. Each succeeds when supplied the identical
passphrase through explicit `--passphrase-stdin`.

The two handlers in `crates/jury/src/cli/vault_commands.rs` use
`secret_input::capture`, which has no environment source, while other private
operations use the environment-aware loader. The global help/input guidance
does not explain this exception. Related identity handlers also use the
source-less helper; their environment behavior was not separately exercised.

**Repair:** make existing-identity input selection consistent and document
new-passphrase/confirmation sources explicitly. Preserve the repaired
explicit-stdin precedence and exact field/child input bytes. Verify both
environment-only success and wrong/absent-source failures through real CLI
processes, plus terminal input.

### QA-16 — P3: help promises input behavior the commands reject

Tracked as `jury-qv4.3.11`. `vault field set --help` says `--value-stdin` is
required for non-terminal use. An actual terminal invocation without it also
returns exit **2**, `field-input-opt-in-required`, before prompting. The field
remains unchanged. State that the flag is always required and explain terminal
EOF, or implement the advertised protected interactive path.

`exec --help` also displays the global `--json` option without mentioning that
`jury --json exec ...` returns `exec-json-unsupported`. Its error is clear, but
the exception should be discoverable before invocation.

### QA-17 — P2: terminal field entry echoes the value on screen

Tracked as `jury-qv4.3.14`. In a real controlling terminal, run
`jury vault field set ExampleItem ExampleField --value-stdin`, enter a
synthetic value, and finish with newline and EOF. The terminal's `ECHO` flag
remains enabled: the field bytes appear in the terminal transcript and the
command exits **0**, storing the exact supplied bytes. The command's metadata
does not itself print the value; the disclosure comes from terminal echo.

This was reproduced with both an inherited identity passphrase and a normal
hidden passphrase prompt. In the latter case, the passphrase was absent from
the transcript, but echo was restored before field input. Only boolean
presence/absence results were recorded; no private bytes were retained in
the audit logs. The relevant path is `field_set` in
`crates/jury/src/cli/item_commands.rs`, which reads standard input after the
passphrase's echo guard has ended.

**Repair:** provide protected terminal field entry and restore terminal state
on completion, errors and cancellation, while preserving exact piped input.
If the command is intentionally pipe-only, reject terminal input before
accepting bytes and make that limitation explicit. Merely describing the
input as protected does not prevent the visible echo. Cover both passphrase
sources with actual PTYs, transcript-absence assertions and exact retrieval.

### Commands and journeys exercised in this pass

The eight existing `scripts/check-linux-*` journeys all passed against the
packaged binaries on Debian 12: witness lifecycle, approval review, descriptor
access, role onboarding, shared policies, disjoint policies, diagnostics and
owner changes. These execute real CLI/daemon processes, SQLite databases,
anchor services and approval PTYs. They check exact reads/injection, child
status, denied-child non-execution, receipts, restart/replay/cancellation,
checkpoint advancement and multi-role backup/restore. This is one configured
loopback deployment, not independent authority or multi-host assurance.

Additional fresh-install probes passed hidden identity/vault prompts, exact
binary field storage and private-file permissions, overwrite/refusal behavior,
explicit stdin under an inherited passphrase, redaction on both child streams,
exact inherited child stdin, child exit propagation, timeout termination,
template output, and field removal. Ctrl-C at the passphrase prompt restored
the original terminal mode under interactive Bash.
All 91 recursively advertised help surfaces rendered successfully; this is
a discoverability check, not a claim of functional coverage for every command.

A further real lifecycle passed with HTTPS on both CLI-to-witness and
witness-to-anchor links, an explicit synthetic CA, and no insecure CLI flag.
An HTTPS client without that CA rejected the certificate. The successful TLS
journey also verified exact read bytes, receipts, restart/replay and cancellation.

The fresh release build, formatting and Clippy passed. Release-tool filesystem
tests, witness-gate regression tests, and the frozen direct/witness input checks
passed. A refreshed `cargo audit --json` found no vulnerabilities or warnings
in the 347-package lockfile; the advisory database revision was
`5a0ebedfe8bdd2e295b171f4162f8c977bcad9a5` (updated 2026-09-02).
The first full workspace run completed with Cargo exit 0 and no failing tests.
Jig nevertheless rejected its receipt because this audit's report/tracker
edits changed the worktree while a read-only check was running. That is an
audit sequencing mistake, not a clean Jig gate or a product-test failure.
Final verification is run after freezing these edits; its complete result is
retained in `target/qa-linux-0.0.1-do73vlcw/final-work-gates.log`. No test or
gate is weakened to accommodate the report edits.

Scratch reproductions and unabridged non-secret check logs are in
`target/qa-linux-0.0.1-do73vlcw/`. Early exploratory assertions guessed wrong
exit codes for missing resources/executables and attempted unsupported JSON
exec; these are harness mistakes, not extra product findings. The first
terminal-mode probe compared a terminal control sequence rather than the
`stty` result; its parser was corrected and the actual modes were rechecked.
The initial QA-17 tracker description prematurely claimed its second prompt
variant before that driver completed. A case-sensitive prompt match had timed
out. The tracker records the correction; a separate corrected run then
confirmed the second variant. The earlier claim is not used as evidence.
No repository assertion, fixture, golden, gate or implementation was altered
to obtain a green result.

Signing and private security reporting remain unconfigured according to the
release/security documents. No signature, release tag or publication was
attempted. This pass did not repeat clean reproducible compilation, fuzzing,
alternate-provider analysis, systemd boot integration or multi-host deployment.
It is functional engineering QA, not independent security review or a claim
that Jury protects secrets. This report edit changes source-archive contents;
the existing package is bound to the pre-report snapshot, not this changed
document or any future repair.

## Previous audit and repair record

**Recommendation: hold the release.** The original QA-01 through QA-12
findings have repairs with real Linux CLI verification and combined tests.
Witnessed owner changes (QA-13) are also repaired and verified. The 0.0.1
release package and J26 preparation remain in progress.
The reproductions below describe the original failures; follow-up sections
record their repair evidence.

Current audit: 2026-09-06, Europe/Prague. Source baseline:
`bab88dd971a64ec0838d07a485471e04daf8a706` plus the existing uncommitted QA-01,
QA-02, and QA-03 repairs. No application code was changed during this audit.
Host: Pop!_OS 24.04, Linux x86_64; Rust 1.97.1; glibc 2.39.
At the original audit, both freshly built binaries reported `0.1.0`. The
release-preparation change sets the workspace and both binaries to `0.0.1`.

This report's consumer is the maintainer deciding whether to release Linux
0.0.1. It gates that candidate because command execution exposed broken item
creation, ambiguous secret-input handling, and incomplete operator journeys.
Delete or supersede it once these findings have regression coverage and the
replacement candidate passes the affected journeys. This is a functional/UX
audit, not independent security review or evidence that Jury protects secrets.

## Original release blockers

### QA-08 — P1: witnessed-only items prevent creation of another item

**Reproduction:** initialize an owner and vault, register two witnesses, create
`ExampleFirst` with a field and `ExampleBefore`, then apply:

```console
jury policy require witnessed --item ExampleFirst \
  --witness WITNESS_ONE --witness WITNESS_TWO \
  --approvals 0 --witness-quorum 2 --operation read-stdout \
  --automatic-read ExampleField --request-lifetime 300
jury --json item create ExampleAfter --allow-direct
```

The create command returns exit **1**, `invalid-vault`, with the message
`the selected vault public state is invalid`. Yet `jury --json vault status`
reports `public_validation: valid`, two items, and `mutation_possible: true`.
Creating the second item before the policy change succeeds. Updating a field
on the existing direct item afterward also succeeds. Failed creation leaves
vault bytes unchanged.

Reproduced both in the full approved-access installation and a fresh fixture
with no daemon activity, backup, or restore. It is not caused by recovery.

The source explains the result: item creation checks duplicate names through
`all_admin_items` in [item_commands.rs](../crates/jury/src/cli/item_commands.rs).
That helper in [context.rs](../crates/jury/src/cli/context.rs) requires direct
item discovery to return every policy item. Direct discovery omits
witnessed-only descriptors, so the helper labels a valid vault invalid.

**Required repair:** provide a valid owner item-creation/name-checking path
when existing descriptors require witnessed access. Preserve descriptor
confidentiality and name uniqueness; adding a unilateral slot to the governed
item is not an acceptable repair. Cover this mixed-authority lifecycle through
the CLI. Other callers of the helper merit inspection, but their runtime
behavior is not claimed as verified here.

### QA-09 — P1: an inherited passphrase source silently changes stored field bytes

This promotes the input-source concern previously grouped under QA-06 after
an exact byte-level reproduction.

**Reproduction:** with `JURY_IDENTITY_PASSPHRASE` already set to the synthetic
owner passphrase, run:

```console
jury --json --passphrase-stdin vault field set \
  ExampleDirect ExampleMixed --value-stdin
```

Supply `passphrase + newline + intended field bytes` on stdin, following the
explicit flag's help. The command exits **0**. Reading the field into a private
file confirms that its stored bytes include the **passphrase and newline**
before the intended field value. With the environment variable absent, the
same stdin layout stores only the intended value.

[secret_input.rs](../crates/jury/src/secret_input.rs) returns the environment
value before reading stdin, even when the flag is explicit. The unconsumed
passphrase line becomes field input. This can disclose the identity passphrase
to a later authorized field consumer; it is more than a confusing diagnostic.
No passphrase or field value was printed as evidence. The affected synthetic
field was replaced and the comparison output removed after verification.

**Required repair:** make explicit stdin selection authoritative or reject
conflicting sources before mutation. Document one unambiguous stdin contract
and exercise inherited-environment cases with exact stored-byte assertions.

## Follow-up repair verification

The repair work is tracked in [the remaining-findings plan](../.agent/plans/plan_01M1TMEMBQ9AM6YQ08ZYZR58DY.md).
QA-09 now uses explicit stdin precedence and unbuffered passphrase reads. A real
PTY check and the exact child-stdin regression pass; final combined verification
is pending. QA-08 has an implementation under test, not a completed release gate.

### QA-10 — P1: optional role backup has no native state bootstrap

A follow-up real CLI test initialized `ExampleApprover`, exported its descriptor,
completed a registration challenge/proof, and added it to the vault. Owner
`backup create --approver-identity-file FILE` then returned `not-found`, despite
the identity existing and authenticating. The missing files are that approver's
authenticated local audit/checkpoint/receipt state. Registration does not create
them; `vault audit verify` only reads existing state. The backup's optional role
path needs that state before it can publish a backup.

Tracked as `jury-34k`. Provide a real, genesis-bound role-state bootstrap and
exercise multi-role backup/recovery through native commands. Existing unit
fixtures construct role state directly and do not prove this onboarding path.
Owner-only backup and recovery remain separate from this finding.

### QA-11 — P1: one witness pair cannot register two item policies in a vault

Fresh release binaries reproduced this: create two items before cutover, apply
separate human-approval policies using the same witness pair, export current
checkpoints for both, and register them with `/v1/operator/register`. The second
registration returns HTTP **422**, `checkpoint-fork`. No request is executed.
The witness stores one current checkpoint per vault, but each checkpoint binds
one witness-policy digest; requests must match that digest. A second checkpoint
at the same vault sequence is also not a valid checkpoint advancement.

This blocks the ordinary shared-pair, multi-item deployment. Using distinct
witness pairs for different item policies is being tested as a separate supported
shape, not counted as repairing this defect. Preserve monotonic/fork checks and
follow the applicable protocol gate for a repair; do not reset service state.

## Remaining UX findings

### QA-04 — P2: witnessed onboarding still requires implementation knowledge

The README explains the foreground request and separate approver terminals,
but the self-hosting guide does not provide a complete runnable policy
registration request. The audit assembled authenticated
`POST /v1/operator/register` calls using exported policy material, checkpoint,
and base64-encoded accepted principal proof by consulting the implementation
and lifecycle helper. A new operator should not have to infer this schema.

`jury read`, `inject`, `run`, and `exec` help still leave several witness options
without descriptions, including `--checkpoint`, `--approval`, `--request-out`,
`--receipt`, and `--witness`. The endpoint tuple is explained elsewhere but not
on those command surfaces. Detached request creation and foreground execution
also need a clear explanation: the latter must retain its fresh session key;
a saved detached request is not a resumable execution session.

**Repair:** publish and actually execute a synthetic start-to-finish operator
recipe, including registration and checkpoint propagation. Explain the files,
endpoint format, two-terminal handoff, waiting, and cancellation in CLI help.

### QA-05 — P2: approval buries the decision in protocol detail

Actual PTY approvals for read, reveal, injection, run, and exec produced
**201–265 lines**. The first `ExampleItem` label appeared at line **172–208**;
the private-file read had 220 lines, with its first item label at line 184.
The tested denial produced 283 lines. These counts describe the particular
synthetic actions, not a universal output size.

**Repair:** lead with an authenticated summary of requester, item, field,
action/sink, revision, expiry, and decision. Preserve the complete lossless
manifest and exact command-byte review. Do not truncate authorized behavior
to make the screen shorter.

### QA-06 — P2: refusals omit actionable constraints; run defaults conflict with policy

Freshly reproduced:

- A template with mode `0664` returns exit 1, `filesystem-error`, with no
  explanation of the writable-input constraint. The identical template at
  `0600` injects successfully and produces exact expected bytes.
- `juryd database init --config FILE` with an invalid configuration returns
  only `juryd: adapter configuration is invalid`.
- A witnessed `jury run` using its default 1,800-second child timeout fails
  before producing a request, with exit 5, `invalid-witness-request`. The
  CLI-created policy has `max_timeout_ms: 30000`. Setting `--timeout 5`
  allows the same missing-approval scenario to reach exit 4,
  `approval-pending`, without spawning the child. Approved bounded runs
  succeed. The default and error message do not help users discover this.

The earlier audit also found that recovery destinations need sufficiently
separate parent directories, not merely disjoint leaf names. The current
restore used dedicated parents and passed; the failing parent-layout variant
was not repeated in this pass.

**Repair:** report safe constraint categories and next actions without
reflecting private content. Align the witnessed run default with its policy,
or give a specific timeout/policy diagnostic before request construction.
Keep the filesystem and authorization checks intact.

### QA-07 — P2: JSON and maturity messaging are inconsistent

Freshly reproduced:

- `jury --json invalid` exits 2 with ordinary Clap text on stderr; a domain
  refusal exits 2 with a JSON error. The global flag promises stable JSON
  without explaining parser exceptions.
- A successful direct `jury exec` emits only
  `Authority: direct-unilateral` on stderr, without the maturity warning.
- Top-level help says native Linux/pre-alpha/no real secrets, but does not
  state externally unreviewed status.

The vault-init output implementation still says
`Create an owner backup before storing any real data.`, implying a route to
real-data use despite the pre-alpha prohibition.

**Repair:** define and honor the machine-error contract, keep child/plaintext
stdout clean, and put consistent maturity/authority messaging on the
appropriate diagnostic surface. Remove the misleading real-data suggestion.

## Working behavior verified on the current build

| Actual command journey | Observed result |
| --- | --- |
| Locked release build of `jury` and `juryd` | Passed |
| `cargo install --locked --path crates/jury --root PREFIX` | Passed; installed executable starts from `/` with minimal environment and no Jig on PATH |
| Interactive identity creation in a PTY | Passed; hidden passphrase and confirmation; no degraded-protection override |
| Default-concealed field passed to a real direct child | Both captured child streams are `[REDACTED]` |
| Three-byte default-concealed field | Exit 2, `concealed-field-too-short`, with explicit text-field next action |
| CLI approver/witness registration and witnessed-only policy | Passed |
| Two real witness/anchor pairs, SQLite and authenticated registration | Both returned durable database-and-anchor acknowledgements |
| `witness policy-status` on actual wrapped responses | `durably-accepted`, two acknowledged witnesses |
| Interactive approved witnessed read to private file | Exact bytes; mode `0600`; receipt verifies |
| Interactive approved witnessed reveal | Exact raw stdout; receipt verifies |
| Interactive approved template injection | Exact rendered private file; receipt verifies |
| Interactive approved witnessed `run` | Both child streams redacted; receipt verifies |
| Interactive approved witnessed `exec` | Both child streams redacted; exact child exit 7 preserved; receipt verifies |
| Signed denial of a child command | Exit 6, `request-denied`; marker proves child did not run; no success receipt |
| Missing approval with bounded child timeout | Exit 4, `approval-pending`; child marker and receipt absent |
| Completed request replay after both witness restarts | Exact stable response unchanged |
| Cancellation followed by both witness restarts | Both retain the stable `cancelled` refusal |
| Owner backup and restore into absent dedicated targets | Passed with a source-recorded genesis pin; unpinned attempt refused before publishing files |
| Newly approved witnessed read using restored owner and state | Exact bytes; receipt verifies against the original checkpoint |

The restored-owner journey used separately running original witnesses and the
original approver. It demonstrates owner recovery followed by witnessed
access; it does not demonstrate simultaneous recovery of every authority or
independent deployment administration.

## Previously repaired findings

QA-01 (nonempty replay persistence), QA-02 (acknowledgement parsing), and QA-03
(default field concealment) no longer block the exercised paths. This pass
uses the repaired release binaries and real daemon persistence, rather than
counting the earlier blocked operations as successes.

The separate repairs, regression coverage, review limitations, and completed
combined verification are recorded in
[the repair plan](../.agent/plans/plan_01M1SN2634GDJTX3SVGZ8PF38D.md). The latest
repair verification passed workspace tests and the Jig verify profile. Those
are supplemental evidence; the new findings above were discovered through
actual commands despite those checks passing. No full workspace test rerun
was needed for this report-only follow-up.

Earlier baseline audit evidence also covered direct CRUD, backup verification
and direct recovery drill, transfer export/import/divergence, local audit,
history, anchor outage, and daemon database backup/restore. Those broader
journeys were not all repeated here. The original pre-repair test run's Cargo
process passed, but its enclosing Jig receipt failed because the report was
edited during its read-only check; that old receipt is not represented as green.

## Linux release readiness and limits

- Set the requested version consistently to `0.0.1`. The workspace, installed
  package, `jury`, and `juryd` reported `0.1.0` at the original audit;
  release preparation now sets all three to `0.0.1`.
- Complete J26 (`jury-qv4.6.2`), which remains open: exact source/verifier/build
  binding, release artifacts/checksums, SBOM/provenance, signing procedures,
  and current dependency/advisory review. This audit does not satisfy or bypass
  that gate. No tag, commit, release, or publication was created.
- Declare and test an architecture/libc support baseline. This native `jury`
  references `GLIBC_2.39`; `juryd` references `GLIBC_2.38`. These host-built
  artifacts are not evidence of compatibility across Linux distributions.
- TLS deployment, systemd/container installation, other distributions or
  architectures, Rust 1.90 compatibility, dependency advisories, signing, and
  reproducible packaging were not validated in this functional audit.
- All live services were synthetic loopback fixtures on one host. Their
  success does not establish separate authorities or failure domains.
- The documented 64 MiB whole-snapshot limit and retention-related availability
  limits remain. No load, high-throughput, or production-safety claim is made.

The current private synthetic fixture is `/tmp/jury-current-ux-mi5lsyrj`;
all its daemon processes were stopped. The current terminal driver and recovery
continuation are `/tmp/jury-current-ux-audit.py` and
`/tmp/jury-current-ux-resume.py`; the final bounded pending-approval probe is
`/tmp/jury-current-ux-pending.py`. The fresh item-creation reproducer is
`/tmp/jury-after-policy-repro.py`, and direct error/input checks are in
`/tmp/jury-current-direct-errors.py`. These are local diagnostic scripts, not
new checked-in regression tests or independently reproducible release evidence.
Their iterations included corrected harness assumptions about run output,
denial exit codes, and genesis encoding; these were not product defects.

### QA-12 — P1: witnessed child stdin fails before publishing a request

The real release CLI with a human-approved `child-stdin` policy refused
`exec --stdin ExampleItem.ExampleField` as `invalid-witness-request`.
The CLI builder adds both item and field approval targets, while the frozen
protocol correctly requires exactly one stdin target. Repair the builder to
authenticate the single field target; keep the protocol check. A native PTY
regression must compare the child's exact stdin and verify the resulting receipt.
Tracked as `jury-wmo`; validation and separate review are in progress.


## Verified follow-up: descriptor authority and automatic request lifecycle

QA-08 is repaired through the unreleased-format hard cutover. Automatic field policy selection now grants two distinct targets: descriptor metadata and the exact body field. Old role-implicit targets and automatic whole-body permission are rejected. Real Linux CLI/daemon checks passed exact field output, refusal of an unselected field, subsequent item creation, unchanged governed envelopes, human approval/denial, duplicate-name refusal, dry run and receipt verification. Delaying a real witness response beyond the batch budget confirmed that no additional witness call starts and no vault mutation or success receipt occurs.

The final lifecycle run caught and repaired a QA-12 regression in automatic cancellation: supplementary human item labels are required only for human-reviewed requests. The rebuilt binaries passed read, receipt, stable replay, restart, cancellation and governed name checks. Focused automatic/human core tests, formatting and scoped Clippy passed. This is local verification after the two completed review rounds, not independent security review. QA-10 role onboarding, QA-11 shared-pair policies and release preparation remain open.


## Unreleased format cutover

The implementation now rejects legacy replay-map encoding, role-implicit
automatic read targets, backup receipts without coverage metadata, and policy
catalogs with omitted required collections. No migration or compatibility path
is provided. Receipts with current coverage retain the existing authenticated
encoding; a fixed independently calculated digest test guards that contract.

The separate receipt/catalog cleanup received Claude and Codex review. The
resulting test-fixture and documentation repairs passed local verification.
Real Linux backup/restore/drill and portable transfer/retry/rollback checks
passed, as did live automatic and human-approved witness journeys. Compatibility
and version-bump recommendations were declined because no format has been
released and the user explicitly required a hard cutover.


Policy replay now enforces complete owner slots on every signed revision, using
an indexed check after state-hash verification. Two Claude/Codex review rounds
completed. The real Linux lifecycle verifies direct owner grant and revoke,
exact field delivery, denied revoked-owner reads with no output file, and the
subsequent witnessed read/replay/restart/cancellation flow.

### QA-13 — P1: owner changes fail on witnessed-only vaults

After converting the item to witnessed-only authority, `principal grant-owner`
returns exit 1 with `invalid-vault`, even though the vault is valid and remains
unchanged. The administrative path requires all items to be directly openable.
This is reproduced in the live lifecycle driver and tracked as `jury-tsc`.
A real governed administrative path is still required; an asserted refusal is
not a fix. QA-10, QA-11, QA-13 and final release preparation remain open.


QA-10 is repaired. Registered approvers and witnesses initialize and update
authenticated local state through signed `transfer import`, including on a
fresh installation and over a pre-registration public snapshot. First install
requires explicit `--allow-no-access`. Real Linux commands passed separate-host
approval, exact witnessed output and receipt verification, role-specific
backup/restore, read-only previews, rejected owner commands and rollback
refusal with retained local state. Interrupted publication retains the accepted
lineage: an exact retry succeeds and a signed sibling remains rejected. Both
comprehensive review rounds are complete; final local follow-ups passed.
QA-11 shared-pair policies, QA-13 witnessed owner changes and release preparation
remain open.


## QA-11 follow-up: one global checkpoint

Two comprehensive review rounds are complete. Live Linux checks now pass shared
and disjoint witness groups across several item policies, including adding a
previously unused pair to an established checkpoint chain. Every policy uses
the same owner-signed global checkpoint; selected-policy authority remains
separate. Retry, restart, exact outputs and receipts, unique propagation counts,
empty-set refusal, sibling registration refusal and rollback are covered by
`scripts/check-linux-shared-policies` and its `--disjoint` mode.

The human descriptor driver also verifies ambiguous-label guidance and opaque-ID
selection when an unrelated local label set is missing. Core tests, Clippy,
formatting, file-size gate and the separate fuzz workspace tests pass. The final
combined test gate passed in 855.1 seconds. QA-11 is complete; QA-13 and
release preparation remain open.
No compatibility reader or migration path was added.


## QA-13 repair verification

Witnessed owner grants and revocations now use explicit, separately approved
descriptor/body requests for every witnessed-only item. The change rotates all
items in one signed policy revision, preserves witnessed authority, and creates
no direct slots on witnessed-only items. The real Linux driver covers pending,
denied, partial-denied and dry-run cases with unchanged vault bytes, successful
grant/revoke over two witnessed items and a direct item, fresh content sealing,
checkpoint advancement and daemon restart, exact retained-owner reads and
explicit revoked-owner refusal. See `scripts/check-linux-owner-changes` and
[the owner-change guide](owner-changes.md).

Both requested review rounds completed with Claude only; native Codex could
not start because of the agent-thread limit. Review repairs include witness-side
owner-intent enforcement, catalog batch atomicity, label-expiry diagnostics,
plaintext cleanup, and explicit content-disclosure wording. The final combined
`scripts/jig check test` passed in 844.4 seconds, including all review repairs
(run-plan SHA-256 `f603e63001a8460dc705691ae732c47c5d65dfacbf74ed8278b1b890adfcc154`).
No third review was run. This is engineering QA, not independent security review.


## Linux package verification

The release recipe builds `jury` and `juryd` as version 0.0.1 for Linux x86_64,
using the pinned Debian 12 image, and compares two clean offline builds. The
completed package candidate passed real installation, version/help commands,
role onboarding, descriptor access, approval terminals, shared/disjoint witness
policies, lifecycle, recovery, diagnostics and owner changes. Its binaries are
byte-identical to the preceding candidate used for those journeys. These are
local engineering results, not independent review or a published release.

Two packaging review rounds completed with Claude only; native Codex could not
start because of the agent-thread limit. Follow-ups require explicit checksum
expectations, compare builds with different job counts, retain exact license
paths for all 339 vendored packages, preserve upstream SBOM references and
publish the output directory only after successful local verification. Eight
filesystem regression tests pass. Fresh main-tree build and measured resource
results are recorded in the existing work plan after these repairs.

Bounded ASan fuzzing, alternate-provider conformance, the unchanged frozen
protocol gate and the repository lifecycle leak scan passed. The latter used
the installed package binary, detected its seeded leak and found no exact hits
in its named scan surfaces. The product lockfile audit found no vulnerabilities
or warnings in 347 packages. The separately installed SBOM tool warns about its
own locked, yanked `xml-rs` 0.8.19 dependency; that warning is retained.

Publication remains pending: no private reporting contact or release-signing
identity has been supplied, and GitHub private vulnerability reporting is
currently disabled. No candidate is signed, tagged, published, or claimed to
protect real secrets. Development state uses the new format directly; there is
no migration or compatibility path.

The final source-size check exposed oversized conformance and runtime files,
including files missed by earlier committed-diff selectors. Those files have
been split without changing protocol vectors or adding compatibility paths.
The gate now checks the complete bound conformance source inventory against
both disk and the pinned Git revision. The unchanged corpus passes from a
clean clone of the reachable input commits. Complete candidate size checks,
final layout review and renewed package verification are tracked in the
existing work plan; the preceding package is not a binding for changed source.

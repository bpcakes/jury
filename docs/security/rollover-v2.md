# Rollover bootstrap version 2

Status: frozen input extension, accepted for implementation only while
`scripts/check-rollover-inputs` passes for these exact version-1/version-2 inputs.
This extension accepts only cryptographic suite 1. It is not independent review
and does not establish that Jury protects secrets.

Consumer: J18 rollover. The observed defect is refusal of a valid source in
which one item has rotated to witness-policy revision 2 while another still uses
revision 1 of that policy ID. The source's signed item operations, full replay,
portable catalog and transfer all validate. Replace this input when the format
is superseded; retain its decoder while artifacts using it remain supported.

Version 1's specification and frozen positive vectors remain unchanged.
Version 2 uses the same cycle-free signing order, item and principal encodings,
policy-intent projection, freshness checks, retained evidence and external
registration requirements. Its differences are enumerated below. This is a
format extension, not a change to HPKE, storage encryption or identity keys.

## Encoding and source binding

The domain remains ASCII `jury-v1/rollover/bootstrap` followed by `00 00 01`.
The next fields are manifest version u16 (2), source suite u16 (1), destination
suite u16 (1), then the unchanged destination vault ID, timestamp, acting owner
and three lists. The source suite is mandatory and must equal the authenticated
source header and genesis. It is committed before destination genesis exists.
Other suite values remain unsupported until their own construction, provider
and witnessed-input gates pass. Encoding a version-2 source suite does not
authorize a migration or negotiate a cryptographic algorithm.

Each witness-policy entry is source policy ID, source policy revision u64,
destination policy ID, intent digest. The source revision is nonzero. Entries
are strictly ordered by `(source policy ID, source policy revision)`; duplicate
pairs are invalid. Destination IDs remain unique and distinct from every source
policy ID, including inactive historical policies. The source revision and ID
must select the exact policy digest referenced by the source item's authenticated
slots. Two source revisions map to two fresh destination policy IDs, each at
revision one. Membership, thresholds, operation rules and scopes are preserved
separately; combining their authority into one destination policy is invalid.

In JSON, `source_suite` appears immediately after `version`, and each policy's
`source_policy_revision` immediately after `source_policy_id`. These fields must
be absent in version 1 and present with valid values in version 2. JSON remains
storage only. The binary version distinguishes both interpretations. Reject
version substitution, omitted revisions, reordered entries, repeated pairs,
aliased destination IDs and unsupported suite fields before private-key work.

## Inactive public scopes

An automatic target or owner review label can refer to a deleted source item or
a removed field. Such a reference grants no access to an active value. Preserve
the rule and its limits instead of extending its scope to another live value.

An item ID absent from the active source item mapping remains unchanged as an
inert reference in the destination policy or label. Reserve every source public
scope item ID before generating destination item IDs. No such inactive reference
may equal an active destination item ID. The reference is bound to the new
genesis through the destination policy and newly signed label; it does not
create an item, restore deleted ciphertext or add a tombstone/history record.

For each active source item, rename every public field reference consistently,
including references to removed fields. Generate its new field ID separately
from all live destination fields and all other public field references in that
item. A removed field gets no destination plaintext field. A field reference on
an inactive item stays unchanged along with its inactive item ID. Preserve the
complete set of policy-revision/rule/label uses for each field; no field merging,
splitting, silent omission or authorization union is permitted. Public readers
can check this bijection of public uses but cannot prove private field contents.

Existing label signature, owner, scope and expiration checks still apply.
Reissuing an expired label with a later expiration is not a rollover operation.
Fresh labels preserve public display bytes, non-item commitments and expiration.

## Compatibility and validation

Version-1 artifacts retain their original canonical bytes and interpretation.
Version-1 readers may refuse version 2; they must not interpret it as version 1.
Current readers validate the first bootstrap after later mutations using the
same encoded version and retain its required admissions, policies and labels.
The source-aware verifier checks exact per-item source revision selection, and
uses that revision in public-scope comparison so two distinct policies cannot
accidentally share an authority token. Existing source-owner signature checks
and complete first-revision reconstruction remain mandatory.

Before runtime adoption, run the unchanged version-1 vectors, deterministic
version-2 encoders in Python and Rust, and negative controls against the actual
binding verifier. Then perform a fresh solo check of the exact specification,
inputs and compatibility results. This prevents input drift and is not an
independent security assessment.

The input gate supersedes manifest SHA-256
`36768074e446147b3b2e99d7d630d0b7e83a7b7c2b31f401071cdbf0f965548a`.
The old specification, encoder and two old vector files retain their exact
accepted hashes. A separate compatibility check rejects changing an old vector
even together with its gate binding. The three new vectors cover direct state,
one governed policy and two active revisions of one source policy. Rust checks
version/suite substitution, absent/zero/duplicate/reordered source revisions,
destination-ID aliasing and unknown fields. The new corpus is created once;
normal verification cannot overwrite it.

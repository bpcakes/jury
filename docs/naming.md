# Naming

Jury is the product and CLI name. The category descriptor is:

> Jury is a portable secrets vault with direct and quorum-controlled witnessed
> access paths.

The short positioning line is:

> Portable secrets with configurable distributed authority.

Never apply the quorum-controlled or distributed-authority claim to a direct
recipient slot. A direct recipient is intentionally able to open its authorized
item without a witness; only witnessed slots require the configured parties.
An item containing both slot families is mixed-mode and must not be described
as quorum-controlled as a whole.

The courtroom metaphor stops at the product name. Product and protocol language
must remain technically direct:

| Concept | Preferred term |
| --- | --- |
| Portable encrypted artifact | vault |
| Protected value | secret or item |
| Human or machine identity | principal |
| Authorization service | witness |
| Permission | grant |
| Authorization evidence | receipt |

Do not rename witnesses to jurors, requests to cases, or authorization outcomes
to verdicts in code or protocol schemas. Those metaphors obscure the security
model and make machine authorization sound human-only.

The executable is `jury`. The standalone witness daemon is `juryd`.

## Native identifier and name profile

Jury's native vault, principal, and item identifiers are distinct typed values
with the same wire profile: exactly 32 bytes, not all zero, encoded as 64
lowercase hexadecimal characters. Parsers reject uppercase, shortened, padded,
and all-zero encodings instead of normalizing them. The bytes, not a storage
path or external reference, are the stable identity used by later signed state.

Native item and field names are case-sensitive and use this version-independent
profile:

- 1 through 64 ASCII bytes;
- an ASCII letter or digit at each endpoint;
- only ASCII letters, digits, `-`, `.`, and `_` internally;
- no trimming, case folding, or Unicode normalization.

The deliberately narrow profile rejects separators, controls, bidirectional
formatting, normalization variants, and cross-script confusables. External
clients translate their own reference syntax into separate validated item and
field inputs. Combined URIs, filesystem paths, repository identity, and source
control authorship are never native names or identifiers.

The current Serde representations are bounded semantic transport forms, not
canonical signed encodings. J05 owns the versioned binary preimages used for
signatures. Item and field names may be serialized only inside encrypted
descriptor or body plaintext; public state uses opaque identifiers. A reader
must also cap the total encoded artifact before invoking a Serde parser because
escaped strings and streaming formats may allocate while decoding, before a
domain visitor can reject an overlong value.

These format rules are pre-alpha interface constraints, not a claim that Jury
protects secrets.

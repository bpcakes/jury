# Security policy

Jury is pre-alpha software. It contains experimental cryptographic and
witnessed-access implementations, but does not yet protect secrets and must
not be used to store, authorize, inject, or transfer real secrets.

No private vulnerability-reporting channel is documented yet. Do not submit
credentials, private data, or sensitive vulnerability details to public issues.
Public issues may be used for non-sensitive bugs with synthetic reproductions.
Any public `0.x` release remains experimental and must publish supported
versions, its threat
model, deterministic test vectors, and the explicit statement that it has not
received independent whole-product professional security review and is not
suitable for real secrets. The active solo release path does not require or
imply external review. J19R/J19D construction review and J19E
implementation/build review are deferred optional work; if funded later, each
must name its exact construction, implementation, build, and revision scope.

The project has a zero review budget. Self-review, automated tests, independent
implementations, and AI-assisted analysis are useful engineering evidence but
must never be described as an independent security audit. Another coding agent,
model, or clean builder is not an independent security reviewer.

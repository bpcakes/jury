# Open-source boundary

Jury's intended commercial model is open infrastructure with paid operation and
assurance.

## Intended public components

- Vault format and cryptographic core
- CLI for Linux and macOS
- Witness protocol, schemas, verifier, and test vectors
- Cryptographically relevant witness-server implementation
- Recovery, rekey, revocation, and receipt-verification logic
- Reproducible build configuration and deployment examples

If a defect could permit unauthorized decryption, witness-share release, policy
bypass, or forged evidence, the relevant implementation must be independently
inspectable and self-hostable.

## Intended commercial components

Possible later commercial work may provide operating assurance rather than
artificial captivity. None of these managed-service capabilities ships in the
first `0.x` release:

- highly available managed witnesses;
- regional placement and independent witness federation;
- signed builds, provenance, transparency, and long-term receipt retention;
- SSO, SCIM, SIEM, HSM, enclave, compliance, and governance integrations;
- support, migrations, service-level commitments, and dedicated deployments;
- billing and internal service operations.

## License decision still required

Before public release, choose explicit licenses with counsel. The current
working proposal is:

- Apache-2.0 or MIT/Apache-2.0 for `jury-core`, `jury-protocol`, and `jury`;
- the same or a separately reviewed compatible license for the deferred
  `jury-tui` if it is activated;
- AGPL-3.0-or-later for `jury-witness`;
- a separately governed trademark policy;
- private billing and internal operational systems.

The repository must not advertise itself as open source until those license
texts are committed.

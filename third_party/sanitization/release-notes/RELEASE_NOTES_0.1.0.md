# Release 0.1.0

- Initial unpublished crate layout.
- Added safe `no_std` fixed-size `SecretBytes<N>`.
- Added `alloc` heap containers `SecretVec` and `SecretString`.
- Added explicit `unsafe-wipe` volatile backend and `VolatileOnDrop<T>`.
- Added threat model, unsafe audit notes, CI, and local check script.

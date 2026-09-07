# Release 1.0.1

- Fixed a `SecretPool::try_allocate` error path in both native and WASM
  backends so random-canary initialization failure releases the slot bitmap
  exactly once through `SecretPoolSlot::drop`.
- Fixed random-canary failure handling in native `LockedSecretBytes<N>` and
  `GuardedSecretVec` constructors by generating canaries before creating locked
  or guarded mappings, preventing mapping and lock-quota leaks on CSPRNG
  failure.
- Documented deterministic canary disclosure limits more explicitly and steered
  canary-disclosure threat models toward `random-canary`.
- Added explicit safety comments for canary-failure clear paths that mutate
  owned secret storage through `&self` and rely on the types remaining `!Sync`.

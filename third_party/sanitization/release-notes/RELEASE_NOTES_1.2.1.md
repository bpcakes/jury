# Release 1.2.1

- Added in-place locked fill constructors and replacement APIs for
  `LockedSecretBytes<N>` and `LockedSecretVec`, allowing decoders, KDFs, RNGs,
  and protocol parsers to write directly into OS-locked memory without staging
  plaintext in an unlocked `Vec`.
- Added capacity-based `LockedSecretVec` fill APIs for decoders that know a
  maximum output size before decoding and return the actual initialized length
  afterwards. Over-reported lengths fail closed and clear the temporary locked
  mapping; spare payload bytes beyond the reported initialized length are
  volatile-cleared before exposure.
- Added `LockedSecretVecFillError<E>` for distinguishing memory-lock setup
  failures, fill closure failures, and invalid reported output lengths.
- Hardened locked fill error paths with explicit pre-return clearing, pre-fill
  compiler fences, canary integrity checks before fixed-size locked
  replacements, and release-build capacity assertions for dynamic locked and
  guarded storage initialization.

# libproc-region

Jury-maintained safe provider for the Darwin `PROC_PIDREGIONPATHINFO` query
missing from `libproc` 0.14.11. It returns owned values from the mapped vnode,
checks the exact response size, and never dereferences the header address
or reopens its returned path. It contains no Jury policy or protocol types.
The public query only identifies the current process’s main executable. Darwin’s
`_NSGetMachExecuteHeader` supplies its header address, independent of dynamic
library ordering and where this provider is linked. See Apple’s use in
[`getsectbyname`](https://github.com/apple-oss-distributions/cctools/blob/main/libmacho/getsecbyname.c).
The provider verifies that the returned region contains that address. The header
need not be executable memory. No caller-supplied PID or address is accepted.

The implementation follows Apple's
[`proc_pidregionpathinfo`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c)
and [`proc_info.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h).
The kernel acquires the region vnode by its identifier before filling metadata.
The path can change immediately afterwards; callers must not use the path as identity evidence or process-launch authority.

The build script is derived from MIT-licensed `libproc` 0.14.11, upstream
commit `9c5b669ca414918eadc81e70ec654505a0c8a93f`, with an allowlist for this
query and the main-header accessor, with SDK-generated layout assertions. Its license is retained.
See the repository's `NOTICE.md` for source and platform-specific binary attribution.
Build tracking includes the SDK selection environment, SDK settings and every
transitive header consumed by bindgen. Binding-generation errors fail the build.
This is an extension, not a full libproc fork. Existing Jury containment uses
the unchanged crates.io libproc provider. Remove this extension when a pinned,
maintained upstream provider supplies the same checked API and regressions.

Building for Darwin requires a native macOS host, its Apple SDK and libclang.
Cross-compiling from Linux is unsupported and fails with an explicit build error.
The current release packaging lane remains Linux-only; macOS packaging is M10. Run `cargo fmt`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test` with
`--manifest-path third_party/libproc-region/Cargo.toml`. Provider CI runs these
checks alongside native workspace Clippy, the filesystem/witness/process and
CLI unit tests, and the running-image and CLI integration regressions on both
Apple Silicon (`macos-15`) and Intel (`macos-15-intel`). A separate toolchain
matrix entry runs the provider's own tests and Clippy on its Rust 1.90 minimum;
the workspace uses its current pinned toolchain. Each job has a 30-minute limit.
There is no file-size exemption and no claim of independent security review.
Malformed-response tests exercise the decoder with synthetic structures;
the live main-image and executing-code tests check real kernel vnode metadata.

The CLI replacement tests require the platform C compiler, `/bin/cp`, and a
loader-injectable Cargo test binary. Copying runs in a separate process so
parallel test forks cannot inherit writable executable descriptors from the
runner. Missing prerequisites or an ineffective barrier are failures,
not skips: otherwise a loader regression would silently remove the test’s proof.
These are developer/CI prerequisites, not a requirement on installed Jury users.
The running-image suite also signs a copied test executable locally with
Hardened Runtime enabled and no exception entitlements, then captures its real
kernel identity without loader injection. This checks ad hoc signing, not
Developer ID signing or notarization. M10 must validate the final distributed
binary; its tests must not add DYLD or library-validation exceptions merely
to accommodate the developer-only replacement barrier.

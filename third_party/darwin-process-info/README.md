# darwin-process-info

Jury-maintained safe provider for checked Darwin running-image identity and
bounded process-group membership queries. Formerly `libproc-region`.

## Running-image identity

The `PROC_PIDREGIONPATHINFO` query is missing from `libproc` 0.14.11. It returns owned values from the mapped vnode,
checks the exact response size, and never dereferences the header address
or reopens its returned path. It contains no Jury policy or protocol types.
The image query only identifies the current process’s main executable. Darwin’s
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

## Process-group membership

`process_group_has_only_leader` calls `proc_listpids(PROC_PGRP_ONLY)` with two
stack-allocated PID slots. A single positive PID equal to the pinned leader
proves sole membership at that instant. Two distinct positive PIDs mean the
buffer is saturated and cannot prove quiescence. A positive non-leader
singleton also remains non-quiescent: the leader can leave its original group
while descendants remain. Empty, duplicate,
nonpositive, misaligned or oversized responses are errors. Repeated
saturated responses never become proof of completeness.

This replaces the crates.io `libproc` 0.14.11 count-then-allocate query, whose
returned vector does not expose completeness and whose allocation scales with
the system process count. This was a contract and resource-bound deficiency;
we did not reproduce a false sole-leader result in that implementation.

The implementation relies on XNU scanning live and zombie lists under
`proc_list_lock`, also used for process-group membership changes. Research is
pinned to XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`:
[`proc_listpids`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c)
and [group membership](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c).
For a non-null buffer, XNU returns bytes actually copied, not the size of the
full matching list. It stops when the supplied capacity is full; a three-member
group therefore fills two slots and returns eight bytes. Oversized responses
violate this contract and remain errors. The native consumer regression checks
three, then two, then one live members using descendant handshakes.

The [libproc wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.c)
maps syscall failure to zero, which is also a valid empty-list response. The
provider clears and captures thread-local errno around the call: zero with a
native error preserves that error; zero without one rejects the empty snapshot
without inventing an OS failure.

The fixed supplied buffer bounds native result allocation and copying; the
kernel still scans its process lists. Its synchronous allocation, lock wait,
and scan cannot be preempted by this API. Callers check an absolute deadline
before and after each query and reject late results. This is not a hard
wall-clock bound on a kernel call.

The caller must own the unconsumed direct-child wait status, observe exit with
`waitid(WNOWAIT)`, retain that ownership through numeric signaling, and require
consecutive complete proofs before reaping. Sole membership alone does not
prove a live leader quiescent or grant authority to signal it. Descendants that
leave the owned group remain outside the containment guarantee.
Darwin snapshots include zombies. A departed leader cannot provide the required
positive sole-leader proof, and an extra zombie retained by another parent can
prevent that proof until the deadline. These cases fail conservatively; Linux's
live-member scan can accept an empty group or ignore zombies. This provider
does not claim identical cleanup availability across the two platforms.

## Build and validation

The build script is derived from MIT-licensed `libproc` 0.14.11, upstream
commit `9c5b669ca414918eadc81e70ec654505a0c8a93f`, with an allowlist for this
region query, group query and main-header accessor, with SDK-generated layout assertions. Its license is retained.
See the repository's `NOTICE.md` for source and platform-specific binary attribution.
Build tracking includes the SDK selection environment, SDK settings and every
transitive header consumed by bindgen. Binding-generation errors fail the build.
This is a narrow provider, not a full libproc fork. Remove it when a pinned,
maintained upstream provider supplies both checked APIs and their regressions.

Jury targets Apple Silicon macOS only; Intel Macs are outside its support scope.
Building for Darwin requires a native macOS host, its Apple SDK and libclang.
Cross-compiling from Linux is unsupported and fails with an explicit build error.
The current release packaging lane remains Linux-only; macOS packaging is M10. Run `cargo fmt`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test` with
`--manifest-path third_party/darwin-process-info/Cargo.toml`. Provider CI runs these
checks alongside native workspace Clippy, the filesystem/witness/process and
CLI unit tests, and the running-image and CLI integration regressions on
Apple Silicon (`macos-15`, `macos-26`), using explicit labels from
[GitHub’s runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). A separate toolchain
matrix entry runs the provider's own tests and Clippy on its Rust 1.90 minimum;
the workspace uses its current pinned toolchain. Each job has a 30-minute limit.
There is no file-size exemption and no claim of independent security review.
Malformed-response tests exercise the decoder with synthetic structures;
the live main-image and executing-code tests check real kernel vnode metadata.
The consumer containment tests use native children, descendant-ready handshakes,
positive controls, consumed wait statuses and cancellation of actively spawning
groups. A separate controlled-churn regression drives the production confirmation
loop and native signal/proof functions: prestarted children join from outside
the target group after a signal, between proofs. Two acknowledged members
saturate the query, reset an earlier successful proof, and must be killed by
the next signal before two new consecutive proofs succeed. The external test
controller survives group signals and reaps every injected member; successful
cleanup cannot be credited to fixture expiry or fallback cleanup. This verifies
membership changes between snapshots, not an ability to prevent outside
processes joining after cleanup has finished.
M04 native acceptance passed on Apple Silicon macOS 15.7.9 and 26.6.2 in
[CI run 34501541365](https://github.com/bpcakes/jury/actions/runs/34501541365),
for implementation commit `362b209`. Each current-toolchain job passed ten
provider tests, 54 process tests and eight running-image tests; the provider's
Rust 1.90 lane also passed on macOS 15. This is containment acceptance, not
full macOS CLI integration or release acceptance.

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

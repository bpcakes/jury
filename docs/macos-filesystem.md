# Native macOS filesystem boundary

Jury remains pre-alpha and must not be used for real secrets. This M02
implementation does not establish full native CLI or macOS release support.

`jury-filesystem` retains directory and file descriptors as authority. On
macOS it publishes only to APFS, including case-sensitive APFS. Volume type
is checked through `fstatfs` on the retained descriptor before writing.
Other filesystem types return `FilesystemErrorKind::Unsupported`.

Private roots require effective-user ownership, no group/world mode bits,
and an empty extended ACL. Every freshly created temporary file is validated
through its descriptor before protected exposure or any write. Existing
private reads, previews, locks, and publication also inspect descriptor ACLs.
The policy deliberately refuses every nonempty extended ACL, including
harmless deny entries, without changing an existing tree or resolving ACL
principals. Encrypted public artifacts retain their separate visibility API;
their files and publication parents must also have empty extended ACLs.
Errors expose neither paths nor ACL identities.

The safe ACL provider is pinned `calcifer-macos-acl` 0.1.0 (MIT), package
revision `24a15cc4f7c46802d93d2f9cc93e45e1d5a5313e`. Its borrowed-descriptor
API uses Darwin `acl_get_fd_np` and bounded native ACL decoding, preserving
unknown policy bits. Its omitted workspace license is retained under
`licenses/vendor-supplements`. This small upstream dependency has not received
independent security review. See the [provider API](https://docs.rs/calcifer-macos-acl/0.1.0/calcifer_macos_acl/)
and [Apple descriptor ACL semantics](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get_fd.3.html).

Create-new publication uses pinned rustix 1.1.4's Apple `RenameFlags::NOREPLACE`,
which maps to `RENAME_EXCL`. Competing publishers cannot overwrite the winner.
Existing-destination and unsupported-operation errors remain typed. Destination
ACL inspection opens with no-follow and nonblocking flags, then validates type
and identity; replacing a regular leaf with a FIFO cannot block that inspection.

Darwin file and parent synchronization use rustix `fcntl_fullfsync`, requesting
`F_FULLFSYNC` without falling back to ordinary `fsync`. File-sync failure occurs
before publication. A parent-sync failure after rename returns
`PublishedButParentUnsynced`; callers must reconcile the committed destination
instead of treating it as absent. Linux retains ordinary file/parent sync.
[Apple's sync documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
distinguishes the drive-cache flush request from ordinary `fsync`. Successful
calls and process-restart tests are not proof of survival of physical power loss.

Prepared files retain their open descriptor through publication or cleanup.
Publication compares the original contents/metadata snapshot; cleanup compares
the held inode identity so a rejected ACL or mode change cannot strand the
original private temporary file. A substituted pathname is preserved. The
existing quarantine/reconciliation rules for authenticated restore markers,
fixed system aliases, Git discovery, and linked worktrees remain in force.

Run the native boundary tests with:

```sh
cargo clippy --locked -p jury-filesystem --all-targets -- -D warnings
cargo test --locked -p jury-filesystem --all-targets -- --test-threads=1
scripts/test-macos-filesystem
```

The image runner creates and detaches only owned synthetic 128 MiB images. It
runs the complete filesystem suite on both APFS case modes and invokes the
otherwise ignored non-APFS refusal test on HFS+. The deliberately ignored
publication subprocess probe is invoked by its parent kill/restart test. The
suite covers inherited allow/deny ACL rejection before writing, competing
publishers, Unicode/case aliases, temporary replacement and cleanup, retained
parent renames, file/parent sync failures, and before/after-rename restart cases.
Use synthetic fixtures only. The current host run does not establish macOS 15
Apple Silicon acceptance; that native release lane belongs to subsequent macOS
integration/release work. M03 supplies native non-child CLI compilation and platform defaults; child
execution and full native release acceptance remain separate work.

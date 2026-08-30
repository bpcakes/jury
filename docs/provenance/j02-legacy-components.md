# J02 legacy-component provenance

Jury is pre-alpha and must not be used with real secrets. This record explains
the reviewed source ancestry for J02; it is not an independent security review
or certification.

## Source and history operation

- Canonical source: `https://github.com/bpcakes/jig-sh.git`
- Required source baseline: `eed70cee337b0067ed92deb9fa05017b0b284605`
- Filtered history tip: `7a6d648316afb5706d39b63b763f122528a426ce`
- Jury unrelated-history merge: `f3ffd877974c85d1dde32551aba01338bae7ed14`
- Disposable filter root during implementation:
  `/tmp/jury-j02-filter.JxmZ7U/source`

The exact baseline object and every named blob were obtained from a verified
sibling object store. `git filter-repo` ran only in the disposable clone. The
eight allowlisted paths were renamed into `jury-legacy-components/`, merged,
then moved and decoupled in Jury. No Jig crate is a runtime dependency.

The exact baseline is a merge commit which did not itself change an allowlisted
file, so filter-repo maps it to zero. The latest preceding source change,
`68856a09f5e976f499d86a8b86159ae57b62a393`, maps to the filtered tip. The
filter commit map remains in the disposable clone and is reproducible from the
source baseline and allowlist.

## Baseline blobs

Each row records the Git blob ID and SHA-256 of the bytes at the exact source
baseline.

| Source path | Git blob | SHA-256 |
| --- | --- | --- |
| `crates/jig-vault/src/secret.rs` | `e1622e8afd12ae9234638cc28298b100981fb626` | `ea0b575ea460d71690a873e0d7b77fd2077a3b0f89aa43a9714547e9d6ed3ea7` |
| `crates/jig-vault/src/redact.rs` | `bf8a79b694b7a5d4fad2a2e88907a16415477090` | `24233ae6d461057ccf9925789471c22bc03e1fe96161306bfeb2b69ea6d094e7` |
| `crates/jig-vault/src/exec_output.rs` | `53f230b99e7559d4029490256811d049c7d44756` | `50d6a36e4bdf85e8c6294bc1c9f1dc6b3faea0ab4c913e834b241310094bede2` |
| `crates/jig-vault/src/path_security.rs` | `a48ceec5c38d7423a4cc85ae057e2d80e81bd7ae` | `1064888bde5c93d391190491e917adb1b9b9c8751d136bc3e3832f6efa18429e` |
| `crates/jig-vault/src/output.rs` | `91d34ed647b0137a19a1b38077b392fefc5154ec` | `f589bf563b3beb389c81ff5725126831fbe1ddf3bf7151683b6a0d003d7d8bd0` |
| `crates/jig-vault/src/output/unix.rs` | `d66c50f29cade7d293e730177f6e09904c79aca7` | `acf4bcd4e4e9e0de83fb31f3571275332bf5a0c05cfbed7d820f52363141d3ae` |
| `crates/jig-vault/src/output/unix/error.rs` | `010f2fa01830969bc27b6a72f42abc46ceaec74e` | `96cd8c3e0b1db458ad8920f9fe2a91d01fd6094220cf36672f5f9869368d7e00` |
| `crates/jig-vault/src/output/unix/macos_path_tests.rs` | `88e8ef867a6664d83a8ff429861381e82bd1bb59` | `9da85fb18b178e77ee82a7e86eed356eb5588df1daf52f3c37c18933bbb61d02` |

## Disposition

| Imported behavior | Jury disposition |
| --- | --- |
| Non-growing `SecretBytes`, eager truncate/clear, redacted `Debug` | Retained in `jury-protected`; Jig/secrecy string conversions were removed because they transfer ownership through ordinary string storage. |
| Raw plus encoded redaction forms | Retained with Jury-neutral, value-free errors and bounded matcher construction. |
| Independent streaming stdout/stderr overlap state | Retained as public generic streaming redaction with leftmost-longest matching and fixed limits. |
| Absolute-path and verified macOS root-alias logic | Retained as input normalization only; replaced as authority by component-wise no-follow directory capabilities. |
| Unix path rechecks, private mode, create-new temporary, file sync, atomic publication, parent sync, and identity-safe cleanup | Ported through safe `cap-std`/`cap-fs-ext` APIs. The Jig implementation's ambient path operations, `libc` calls, vault facade, and path-bearing errors were rejected. |
| Jig output error classification | Replaced by stable operation/kind errors which do not retain private paths or values. |
| macOS path test | Its fixed-root-alias invariant remains platform-gated in the capability implementation; macOS runtime execution was not available in the Linux implementation session. |

The extracted output modules were deliberately deleted after their generic
invariants and adversarial cases moved into `jury-filesystem`; their original
history remains reachable through the provenance merge.

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_ROOT="$(mktemp -d)"

cleanup() {
  if [[ -n "$TEST_ROOT" && -d "$TEST_ROOT" ]]; then
    rm -rf -- "$TEST_ROOT"
  fi
}
trap cleanup EXIT

SOURCE_REPO="$TEST_ROOT/source"
CHECKOUT_REPO="$TEST_ROOT/source-checkout-1"
mkdir -p "$SOURCE_REPO/scripts" "$SOURCE_REPO/.github/workflows"
cp "$REPO_ROOT/scripts/new-checkout.sh" "$SOURCE_REPO/scripts/new-checkout.sh"
cp "$REPO_ROOT/scripts/check-ci-action-pins.sh" "$SOURCE_REPO/scripts/check-ci-action-pins.sh"
cp "$REPO_ROOT/scripts/test-ci-action-pins.sh" "$SOURCE_REPO/scripts/test-ci-action-pins.sh"
cp "$REPO_ROOT/scripts/test-new-checkout.sh" "$SOURCE_REPO/scripts/test-new-checkout.sh"
cp "$REPO_ROOT/.github/workflows/security-invariants.yml" "$SOURCE_REPO/.github/workflows/security-invariants.yml"
cp "$REPO_ROOT/.gitignore" "$SOURCE_REPO/.gitignore"
for workflow in agent-map-check.yml repo-policy.yml rust-tests.yml; do
  cp "$REPO_ROOT/.github/workflows/$workflow" "$SOURCE_REPO/.github/workflows/$workflow"
done
printf '%s\n' '[workspace]' >"$SOURCE_REPO/Cargo.toml"
mkdir "$SOURCE_REPO/web"
printf '%s' '' >"$SOURCE_REPO/web/.gitkeep"

cat >"$SOURCE_REPO/scripts/jig" <<'JIG'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "bootstrap" ]]; then
  exit 64
fi
if [[ -e .env ]]; then
  echo "bootstrap observed .env before trust was established" >&2
  exit 65
fi
if [[ "$(git remote get-url origin)" == *ExampleCredential* ]]; then
  echo "bootstrap observed the credential-bearing remote" >&2
  exit 66
fi
mkdir -p target/example web/node_modules/example
printf '%s\n' 'ExampleCache' >target/example/cache
printf '%s\n' 'ExamplePackage' >web/node_modules/example/package
if [[ "${EXAMPLE_CREATE_ENV_SYMLINK:-}" == 1 ]]; then
  ln -s -- "$EXAMPLE_SYMLINK_TARGET" .env
fi
if [[ "${EXAMPLE_MUTATE_TRACKED:-}" == 1 ]]; then
  printf '\n%s\n' '# Example unexpected bootstrap mutation' >>Cargo.toml
fi
if [[ "${EXAMPLE_HIDE_TRACKED_MUTATION:-}" == 1 ]]; then
  git update-index --assume-unchanged Cargo.toml
  printf '\n%s\n' '# Example hidden bootstrap mutation' >>Cargo.toml
fi
if [[ "${EXAMPLE_HARDLINK_TRACKED:-}" == 1 ]]; then
  rm -- scripts/test-ci-action-pins.sh
  ln -- "$EXAMPLE_HARDLINK_SOURCE" scripts/test-ci-action-pins.sh
fi
if [[ "${EXAMPLE_CREATE_CONTROL_FILE:-}" == 1 ]]; then
  mkdir .cargo
  printf '%s\n' '[build]' 'rustc-wrapper = "ExampleWrapper"' >.cargo/config.toml
fi
if [[ "${EXAMPLE_MUTATE_GIT_CONFIG:-}" == 1 ]]; then
  git config --local example.mutated true
fi
if [[ "${EXAMPLE_INSTALL_HOOK:-}" == 1 ]]; then
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >.git/jury-disabled-hooks/post-checkout
  chmod +x .git/jury-disabled-hooks/post-checkout
fi
if [[ "${EXAMPLE_SYMLINK_HOOK_DIR:-}" == 1 ]]; then
  rmdir .git/jury-disabled-hooks
  ln -s -- "$EXAMPLE_HOOK_TARGET" .git/jury-disabled-hooks
fi
JIG
chmod +x "$SOURCE_REPO/scripts/jig" "$SOURCE_REPO/scripts/new-checkout.sh" \
  "$SOURCE_REPO/scripts/check-ci-action-pins.sh" "$SOURCE_REPO/scripts/test-ci-action-pins.sh" \
  "$SOURCE_REPO/scripts/test-new-checkout.sh"

git -C "$SOURCE_REPO" init -q -b main
git -C "$SOURCE_REPO" config user.name ExamplePrincipal
git -C "$SOURCE_REPO" config user.email example@example.invalid
git -C "$SOURCE_REPO" add scripts .github .gitignore Cargo.toml web/.gitkeep
git -C "$SOURCE_REPO" commit -q -m "safe local revision"

REMOTE_URL="https://ExamplePrincipal:ExampleCredential@example.invalid/jury.git"
git -C "$SOURCE_REPO" remote add origin "$REMOTE_URL"
printf '%s\n' 'EXAMPLE_TOKEN=ExampleSecret' >"$SOURCE_REPO/.env"

OUTPUT="$(bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"

SOURCE_HEAD="$(git -C "$SOURCE_REPO" rev-parse HEAD)"
CHECKOUT_HEAD="$(git -C "$CHECKOUT_REPO" rev-parse HEAD)"
[[ "$CHECKOUT_HEAD" == "$SOURCE_HEAD" ]]
[[ "$(git -C "$CHECKOUT_REPO" remote get-url origin)" == "$REMOTE_URL" ]]
[[ "$(git -C "$CHECKOUT_REPO" rev-parse --abbrev-ref '@{upstream}')" == 'origin/main' ]]
if git -C "$CHECKOUT_REPO" config --local --get core.hooksPath >/dev/null; then
  echo "checkout helper left legitimate Git hooks disabled" >&2
  exit 66
fi
[[ "$(<"$CHECKOUT_REPO/.env")" == 'EXAMPLE_TOKEN=ExampleSecret' ]]
[[ "$(stat -c '%a' "$CHECKOUT_REPO/.env")" == "600" ]]

if [[ "$OUTPUT" == *ExampleCredential* ]]; then
  echo "checkout helper exposed credentials embedded in the remote URL" >&2
  exit 66
fi

TRACE_OUTPUT="$(bash -x "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"
if [[ "$TRACE_OUTPUT" == *ExampleCredential* ]]; then
  echo "checkout helper exposed credentials when shell tracing was requested" >&2
  exit 67
fi
[[ -f "$TEST_ROOT/source-checkout-2/.env" ]]

GIT_TRACE_OUTPUT="$(GIT_TRACE=1 bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"
if [[ "$GIT_TRACE_OUTPUT" == *ExampleCredential* ]]; then
  echo "checkout helper exposed credentials when Git tracing was requested" >&2
  exit 68
fi
[[ -f "$TEST_ROOT/source-checkout-3/.env" ]]

printf '%s\n' 'external target remains unchanged' >"$TEST_ROOT/external-target"
if SYMLINK_OUTPUT="$(EXAMPLE_CREATE_ENV_SYMLINK=1 EXAMPLE_SYMLINK_TARGET="$TEST_ROOT/external-target" bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted a bootstrap-created .env symlink" >&2
  exit 69
fi
[[ "$SYMLINK_OUTPUT" == *"Refusing to replace an .env path"* ]]
[[ "$SYMLINK_OUTPUT" != *ExampleCredential* ]]
[[ "$(<"$TEST_ROOT/external-target")" == 'external target remains unchanged' ]]

if MUTATION_OUTPUT="$(EXAMPLE_MUTATE_TRACKED=1 bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted a bootstrap-mutated tracked input" >&2
  exit 70
fi
[[ "$MUTATION_OUTPUT" == *"bootstrap changed tracked worktree content"* ]]
[[ "$MUTATION_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-5/.env" ]]

if HIDDEN_OUTPUT="$(EXAMPLE_HIDE_TRACKED_MUTATION=1 bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted an index-hidden tracked mutation" >&2
  exit 71
fi
[[ "$HIDDEN_OUTPUT" == *"bootstrap changed tracked worktree content"* ]]
[[ "$HIDDEN_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-6/.env" ]]

if CONTROL_OUTPUT="$(EXAMPLE_CREATE_CONTROL_FILE=1 bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted an untracked execution-control file" >&2
  exit 72
fi
[[ "$CONTROL_OUTPUT" == *"unexpected untracked or ignored output"* ]]
[[ "$CONTROL_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-7/.env" ]]

if CONFIG_OUTPUT="$(EXAMPLE_MUTATE_GIT_CONFIG=1 bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted changed local Git configuration" >&2
  exit 73
fi
[[ "$CONFIG_OUTPUT" == *"bootstrap changed local Git configuration"* ]]
[[ "$CONFIG_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-8/.env" ]]

if HOOK_OUTPUT="$(EXAMPLE_INSTALL_HOOK=1 bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted a bootstrap-installed Git hook" >&2
  exit 74
fi
[[ "$HOOK_OUTPUT" == *"bootstrap installed a Git hook"* ]]
[[ "$HOOK_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-9/.env" ]]

mkdir "$TEST_ROOT/hook-target"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$TEST_ROOT/hook-target/post-checkout"
chmod +x "$TEST_ROOT/hook-target/post-checkout"
if HOOK_SYMLINK_OUTPUT="$(EXAMPLE_SYMLINK_HOOK_DIR=1 EXAMPLE_HOOK_TARGET="$TEST_ROOT/hook-target" bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted a symlinked hook isolation directory" >&2
  exit 75
fi
[[ "$HOOK_SYMLINK_OUTPUT" == *"bootstrap installed a Git hook"* ]]
[[ "$HOOK_SYMLINK_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-10/.env" ]]

if HARDLINK_OUTPUT="$(EXAMPLE_HARDLINK_TRACKED=1 EXAMPLE_HARDLINK_SOURCE="$SOURCE_REPO/scripts/test-ci-action-pins.sh" bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted a hard-linked tracked file" >&2
  exit 76
fi
[[ "$HARDLINK_OUTPUT" == *"tracked file has multiple hard links"* ]]
[[ "$HARDLINK_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-11/.env" ]]

git -C "$SOURCE_REPO" checkout -q --detach
if DETACHED_OUTPUT="$(bash "$SOURCE_REPO/scripts/new-checkout.sh" 2>&1)"; then
  echo "checkout helper accepted a detached source revision" >&2
  exit 77
fi
[[ "$DETACHED_OUTPUT" == *"detached HEAD"* ]]
[[ "$DETACHED_OUTPUT" != *ExampleCredential* ]]
[[ ! -e "$TEST_ROOT/source-checkout-12" ]]

echo "new-checkout security regression test passed"

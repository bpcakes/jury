#!/usr/bin/env bash
set +x
unset GIT_TRACE GIT_TRACE2 GIT_TRACE2_EVENT GIT_TRACE2_PERF GIT_TRACE_CURL GIT_TRACE_CURL_NO_DATA GIT_CURL_VERBOSE
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PARENT_DIR="$(dirname "$REPO_ROOT")"
REPO_BASENAME="$(basename "$REPO_ROOT")"

REMOTE_URL="$(git -C "$REPO_ROOT" remote get-url origin)"
CURRENT_BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
LOCAL_HEAD="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')"

if [[ "$CURRENT_BRANCH" == "HEAD" ]]; then
  echo "Refusing to create a checkout from a detached HEAD." >&2
  exit 1
fi

n=1
while [[ -d "$PARENT_DIR/${REPO_BASENAME}-checkout-$n" ]]; do
  ((n++))
done

CHECKOUT_DIR="$PARENT_DIR/${REPO_BASENAME}-checkout-$n"

echo "==> Creating $CHECKOUT_DIR from exact local revision $LOCAL_HEAD"
git clone --no-checkout --no-hardlinks "$REPO_ROOT" "$CHECKOUT_DIR"
mkdir -m 700 "$CHECKOUT_DIR/.git/jury-disabled-hooks"
git -C "$CHECKOUT_DIR" config --local core.hooksPath .git/jury-disabled-hooks
git -C "$CHECKOUT_DIR" checkout -B "$CURRENT_BRANCH" "$LOCAL_HEAD"
git -C "$CHECKOUT_DIR" branch --set-upstream-to="origin/$CURRENT_BRANCH" "$CURRENT_BRANCH"

CHECKOUT_HEAD="$(git -C "$CHECKOUT_DIR" rev-parse --verify 'HEAD^{commit}')"
if [[ "$CHECKOUT_HEAD" != "$LOCAL_HEAD" ]]; then
  echo "Refusing to bootstrap checkout at unexpected revision $CHECKOUT_HEAD." >&2
  exit 1
fi

GIT_CONFIG_HASH="$(git hash-object --no-filters -- "$CHECKOUT_DIR/.git/config")"
GIT_HOOKS_HASH="$(tar -cf - -C "$CHECKOUT_DIR/.git" hooks | git hash-object --stdin)"
echo "==> Running scripts/jig bootstrap in $CHECKOUT_DIR"
(cd "$CHECKOUT_DIR" && scripts/jig bootstrap)

if [[ -f "$REPO_ROOT/.env" && ( -e "$CHECKOUT_DIR/.env" || -L "$CHECKOUT_DIR/.env" ) ]]; then
  echo "Refusing to replace an .env path created by checkout or bootstrap." >&2
  exit 1
fi
if [[ ! -f "$CHECKOUT_DIR/.git/config" || -L "$CHECKOUT_DIR/.git/config" \
  || -n "$(find "$CHECKOUT_DIR/.git/config" -maxdepth 0 -links +1 -print -quit)" \
  || "$(git hash-object --no-filters -- "$CHECKOUT_DIR/.git/config")" != "$GIT_CONFIG_HASH" ]]; then
  echo "Refusing checkout because bootstrap changed local Git configuration." >&2
  exit 1
fi
if [[ ! -d "$CHECKOUT_DIR/.git/jury-disabled-hooks" \
  || -L "$CHECKOUT_DIR/.git/jury-disabled-hooks" \
  || -n "$(find "$CHECKOUT_DIR/.git/jury-disabled-hooks" -mindepth 1 -print -quit)" ]]; then
  echo "Refusing checkout because bootstrap installed a Git hook." >&2
  exit 1
fi
if [[ "$(tar -cf - -C "$CHECKOUT_DIR/.git" hooks | git hash-object --stdin)" != "$GIT_HOOKS_HASH" ]]; then
  echo "Refusing checkout because bootstrap changed the Git hook tree." >&2
  exit 1
fi

git -C "$CHECKOUT_DIR" ls-files -z \
  | git -C "$CHECKOUT_DIR" update-index --no-assume-unchanged --no-skip-worktree \
      --no-fsmonitor-valid -z --stdin
if ! git -C "$CHECKOUT_DIR" -c core.fsmonitor=false -c core.ignorestat=false \
  update-index --really-refresh >/dev/null; then
  echo "Refusing checkout because bootstrap changed tracked worktree content." >&2
  exit 1
fi
if ! git -C "$CHECKOUT_DIR" diff --cached --quiet "$LOCAL_HEAD" -- \
  || ! git -C "$CHECKOUT_DIR" -c core.fsmonitor=false -c core.ignorestat=false \
    diff-files --quiet --; then
  echo "Refusing checkout because bootstrap changed the tracked tree or index." >&2
  exit 1
fi
while IFS= read -r -d '' path; do
  if [[ -f "$CHECKOUT_DIR/$path" && ! -L "$CHECKOUT_DIR/$path" \
    && -n "$(find "$CHECKOUT_DIR/$path" -maxdepth 0 -links +1 -print -quit)" ]]; then
    echo "Refusing checkout because a tracked file has multiple hard links: $path" >&2
    exit 1
  fi
done < <(git -C "$CHECKOUT_DIR" ls-files -z)
while IFS= read -r -d '' entry; do
  path="${entry:3}"
  case "$path" in
    .agent/.cache/ | .agent/.cache/* | .agent/tmp/ | .agent/tmp/* \
      | target/ | target/* | */target/ | */target/* \
      | node_modules/ | node_modules/* | */node_modules/ | */node_modules/*)
      ;;
    *)
      echo "Refusing checkout because bootstrap created unexpected untracked or ignored output." >&2
      exit 1
      ;;
  esac
done < <(git -C "$CHECKOUT_DIR" status --porcelain=v1 -z --ignored --untracked-files=normal)
bash "$CHECKOUT_DIR/scripts/check-ci-action-pins.sh" "$CHECKOUT_DIR/.github/workflows" "$CHECKOUT_DIR"
git -C "$CHECKOUT_DIR" config --local --unset core.hooksPath
rmdir -- "$CHECKOUT_DIR/.git/jury-disabled-hooks"

if [[ -f "$REPO_ROOT/.env" ]]; then
  ENV_STAGE_DIR="$(mktemp -d "$CHECKOUT_DIR/.env-stage.XXXXXXXX")"
  cleanup_env_stage() {
    rm -f -- "$ENV_STAGE_DIR/.env"
    rmdir -- "$ENV_STAGE_DIR" 2>/dev/null || true
  }
  trap cleanup_env_stage EXIT

  echo "==> Copying .env"
  (umask 077 && cp -- "$REPO_ROOT/.env" "$ENV_STAGE_DIR/.env" && chmod 600 "$ENV_STAGE_DIR/.env")
  mv -n -- "$ENV_STAGE_DIR/.env" "$CHECKOUT_DIR/.env"
  if [[ -e "$ENV_STAGE_DIR/.env" ]]; then
    echo "Refusing to replace an .env path created during publication." >&2
    exit 1
  fi
  rmdir -- "$ENV_STAGE_DIR"
  trap - EXIT
fi

git -C "$CHECKOUT_DIR" remote set-url origin "$REMOTE_URL"

echo
echo "Done! Checkout ready at: $CHECKOUT_DIR"

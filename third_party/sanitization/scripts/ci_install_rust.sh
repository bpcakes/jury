#!/usr/bin/env sh
set -eu

toolchain="$(
    sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml | sed -n '1p'
)"

if [ -z "$toolchain" ]; then
    echo "ci rust: rust-toolchain.toml is missing a channel" >&2
    exit 1
fi

add_cargo_path() {
    if [ -n "${GITHUB_PATH:-}" ]; then
        printf '%s\n' "$HOME/.cargo/bin" >> "$GITHUB_PATH"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
}

add_ci_cargo_wrapper() {
    if [ -z "${GITHUB_PATH:-}" ]; then
        return
    fi

    wrapper_dir="${RUNNER_TEMP:-/tmp}/sanitization-rust-bin"
    mkdir -p "$wrapper_dir"
    {
        printf '%s\n' '#!/usr/bin/env sh'
        printf '%s\n' 'case "${1:-}" in'
        printf '%s\n' '    +*)'
        printf '%s\n' '        toolchain="${1#+}"'
        printf '%s\n' '        shift'
        printf '%s\n' '        exec rustup run "$toolchain" cargo "$@"'
        printf '%s\n' '        ;;'
        printf '%s\n' 'esac'
        printf 'exec rustup run %s cargo "$@"\n' "$toolchain"
    } > "$wrapper_dir/cargo"
    chmod +x "$wrapper_dir/cargo"

    printf '%s\n' "$wrapper_dir" >> "$GITHUB_PATH"
    export PATH="$wrapper_dir:$PATH"
}

install_rustup() {
    rustup_init_version='1.28.2'

    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*)
            echo "ci rust: rustup/cargo is broken on Windows; use the runner Rust install" >&2
            exit 1
            ;;
        Linux)
            case "$(uname -m)" in
                x86_64 | amd64)
                    rustup_target='x86_64-unknown-linux-gnu'
                    rustup_sha256='20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c'
                    ;;
                aarch64 | arm64)
                    rustup_target='aarch64-unknown-linux-gnu'
                    rustup_sha256='e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c'
                    ;;
                *)
                    echo "ci rust: unsupported Linux architecture: $(uname -m)" >&2
                    exit 1
                    ;;
            esac
            ;;
        Darwin)
            case "$(uname -m)" in
                x86_64 | amd64)
                    rustup_target='x86_64-apple-darwin'
                    rustup_sha256='9c331076f62b4d0edeae63d9d1c9442d5fe39b37b05025ec8d41c5ed35486496'
                    ;;
                aarch64 | arm64)
                    rustup_target='aarch64-apple-darwin'
                    rustup_sha256='20ef5516c31b1ac2290084199ba77dbbcaa1406c45c1d978ca68558ef5964ef5'
                    ;;
                *)
                    echo "ci rust: unsupported macOS architecture: $(uname -m)" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "ci rust: unsupported installer platform: $(uname -s)" >&2
            exit 1
            ;;
    esac

    install_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sanitization-rustup.XXXXXX")"
    installer="$install_dir/rustup-init"
    installer_url="https://static.rust-lang.org/rustup/archive/$rustup_init_version/$rustup_target/rustup-init"

    echo "ci rust: installing pinned rustup $rustup_init_version for $rustup_target"
    curl --proto '=https' --tlsv1.2 -fsSL --output "$installer" "$installer_url"

    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s  %s\n' "$rustup_sha256" "$installer" | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
        actual_sha256="$(shasum -a 256 "$installer" | awk '{print $1}')"
        if [ "$actual_sha256" != "$rustup_sha256" ]; then
            echo "ci rust: rustup-init SHA-256 mismatch" >&2
            rm -rf "$install_dir"
            exit 1
        fi
    else
        echo "ci rust: no SHA-256 verifier is available" >&2
        rm -rf "$install_dir"
        exit 1
    fi

    chmod 755 "$installer"
    if "$installer" -y --profile minimal --default-toolchain none; then
        rm -rf "$install_dir"
    else
        status=$?
        rm -rf "$install_dir"
        return "$status"
    fi
    add_cargo_path
}

add_cargo_path

if ! command -v rustup >/dev/null 2>&1; then
    install_rustup
fi

if ! cargo --version >/dev/null 2>&1; then
    echo "ci rust: cargo proxy is not usable before toolchain setup; reinstalling rustup"
    install_rustup
fi

rustup set profile minimal
rustup toolchain install "$toolchain" --component clippy --component rustfmt
rustup default "$toolchain"
add_ci_cargo_wrapper

if ! cargo --version >/dev/null 2>&1; then
    echo "ci rust: cargo proxy is still not usable after toolchain setup" >&2
    exit 1
fi

rustup show
cargo --version
rustc --version

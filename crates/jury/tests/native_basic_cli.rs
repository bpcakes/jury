//! M03: real strict non-child workflows using each platform's default roots.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PASSPHRASE: &[u8] = b"ExamplePassphrase1234\n";

struct NativeHome {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    cwd: PathBuf,
}

impl NativeHome {
    fn new() -> TestResult<Self> {
        let temporary = tempfile::tempdir()?;
        let root = fs::canonicalize(temporary.path())?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let home = root.join("Example Home");
        let cwd = root.join("Example Working Directory");
        for path in [&home, &cwd] {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            _temporary: temporary,
            root,
            home,
            cwd,
        })
    }

    fn data(&self) -> PathBuf {
        self.home.join(if cfg!(target_os = "macos") {
            "Library/Application Support/Jury"
        } else {
            ".local/share/jury"
        })
    }

    fn state(&self) -> PathBuf {
        self.home.join(if cfg!(target_os = "macos") {
            "Library/Application Support/Jury/state/vaults"
        } else {
            ".local/state/jury/vaults"
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_jury"));
        command
            // Start above every possible temporary Git worktree so this fixture
            // exercises the platform default, regardless of TMPDIR.
            .current_dir("/")
            .env_clear()
            .env("HOME", &self.home);
        command
    }

    fn run(&self, arguments: &[&str], input: &[u8]) -> TestResult<Value> {
        run_json(self.command(), arguments, input)
    }

    fn initialize(&self) -> TestResult<Value> {
        let identity = self.run(
            &["identity", "init"],
            b"ExamplePassphrase1234\nExamplePassphrase1234\n",
        )?;
        assert_eq!(identity["operation"], "identity-init");
        assert!(
            self.data()
                .join("identities/default.identity.json")
                .is_file()
        );
        let vault = self.run(&["init"], PASSPHRASE)?;
        assert_eq!(vault["operation"], "vault-init");
        assert!(self.data().join("vaults/default/vault.json").is_file());
        assert!(self.state().is_dir());
        assert!(!self.cwd.join(".jury").exists());
        Ok(vault)
    }
}

fn run_json(mut command: Command, arguments: &[&str], input: &[u8]) -> TestResult<Value> {
    let mut child = command
        .args(["--json", "--passphrase-stdin"])
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let write = child.stdin.take().ok_or("missing stdin")?.write_all(input);
    let output = child.wait_with_output()?;
    // Reap even when input delivery fails. Never print private input or output.
    write?;
    success(output)
}

fn success(output: Output) -> TestResult<Value> {
    if !output.status.success() {
        return Err(format!(
            "CLI failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout)?;
    assert!(!value.to_string().contains("ExampleSecret"));
    Ok(value)
}

fn text(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or_else(|| "non-UTF-8 fixture path".into())
}

fn create_field(home: &NativeHome) -> TestResult {
    home.run(
        &["item", "create", "ExampleItem", "--allow-direct"],
        PASSPHRASE,
    )?;
    home.run(
        &[
            "vault",
            "field",
            "set",
            "ExampleItem",
            "ExampleField",
            "--value-stdin",
        ],
        b"ExamplePassphrase1234\nExampleSecret",
    )?;
    Ok(())
}

#[test]
fn strict_default_home_read_inject_transfer_and_absent_restore() -> TestResult {
    let native = NativeHome::new()?;
    let vault = native.initialize()?;
    create_field(&native)?;
    let output = native.cwd.join("read.txt");
    let read = native.run(
        &[
            "read",
            "ExampleItem",
            "ExampleField",
            "--direct",
            "--out",
            text(&output)?,
        ],
        PASSPHRASE,
    )?;
    assert_eq!(read["operation"], "field-read");
    assert_eq!(read["authority"], "direct-unilateral");
    assert!(fs::read(&output)? == b"ExampleSecret");
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);
    let template = native.cwd.join("template.txt");
    fs::write(&template, b"prefix={{ExampleItem.ExampleField}}")?;
    let injected = native.cwd.join("injected.txt");
    let result = native.run(
        &[
            "inject",
            "--direct",
            "--template",
            text(&template)?,
            "--out",
            text(&injected)?,
        ],
        PASSPHRASE,
    )?;
    assert_eq!(result["operation"], "template-inject");
    assert!(fs::read(&injected)? == b"prefix=ExampleSecret");

    let exported = native.cwd.join("ExampleVault.transfer");
    let source_bytes = fs::read(native.data().join("vaults/default/vault.json"))?;
    native.run(
        &["transfer", "export", "--out", text(&exported)?],
        PASSPHRASE,
    )?;
    let imported_home = native.root.join("Example Imported Vault");
    let imported = native.run(
        &[
            "--home",
            text(&imported_home)?,
            "--expected-genesis",
            vault["genesis_fingerprint"]
                .as_str()
                .ok_or("missing genesis")?,
            "transfer",
            "import",
            "--in",
            text(&exported)?,
            "--allow-no-access",
        ],
        PASSPHRASE,
    )?;
    assert_eq!(imported["operation"], "transfer-import");
    assert_eq!(fs::read(imported_home.join("vault.json"))?, source_bytes);
    let imported_read = native.cwd.join("imported-read.txt");
    native.run(
        &[
            "--home",
            text(&imported_home)?,
            "read",
            "ExampleItem",
            "ExampleField",
            "--direct",
            "--out",
            text(&imported_read)?,
        ],
        PASSPHRASE,
    )?;
    assert!(fs::read(imported_read)? == b"ExampleSecret");
    exercise_restore(&native, &vault).map_err(|error| format!("restore fixture: {error}"))?;
    Ok(())
}

fn exercise_restore(native: &NativeHome, vault: &Value) -> TestResult {
    let backup = native.cwd.join("ExampleVault.backup");
    native.run(
        &["backup", "create", "--out", text(&backup)?],
        b"ExamplePassphrase1234\nExampleBackupPassphrase\nExampleBackupPassphrase\n",
    )?;
    let restored_home = native.root.join("Example Restored Vault");
    let identity_parent = native.root.join("Example Restored Identities");
    fs::create_dir(&identity_parent)?;
    fs::set_permissions(&identity_parent, fs::Permissions::from_mode(0o700))?;
    let restored_identity = identity_parent.join("ExampleRestored.identity");
    let restored_state = native.root.join("Example Restored State");
    let restored = native.run(
        &[
            "--home",
            text(&restored_home)?,
            "--expected-genesis",
            vault["genesis_fingerprint"]
                .as_str()
                .ok_or("missing genesis")?,
            "backup",
            "restore",
            "--in",
            text(&backup)?,
            "--identity-out",
            text(&restored_identity)?,
            "--state-out",
            text(&restored_state)?,
        ],
        b"ExampleBackupPassphrase\nExampleRestoredPassphrase\nExampleRestoredPassphrase\n",
    )?;
    assert_eq!(restored["details"]["committed"], true);
    assert_eq!(restored["details"]["transaction_marker_removed"], true);
    assert_eq!(restored["details"]["protection_degraded"], false);
    assert_eq!(
        restored["genesis_fingerprint"],
        vault["genesis_fingerprint"]
    );
    let output = native.cwd.join("restored-read.txt");
    let mut command = native.command();
    command.env("JURY_STATE_HOME", &restored_state);
    run_json(
        command,
        &[
            "--home",
            text(&restored_home)?,
            "--identity-file",
            text(&restored_identity)?,
            "read",
            "ExampleItem",
            "ExampleField",
            "--direct",
            "--out",
            text(&output)?,
        ],
        b"ExampleRestoredPassphrase\n",
    )?;
    assert!(fs::read(output)? == b"ExampleSecret");
    Ok(())
}

#[cfg(target_os = "macos")]
#[path = "native_basic_cli/preflight.rs"]
mod preflight;

#[path = "native_basic_cli/selection.rs"]
mod selection;

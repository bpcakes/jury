use std::fmt;
use std::io::{self, IsTerminal as _, Write as _};
use std::{env, ffi::OsString};

use jury_protected::{
    ProtectedMemory, ProtectionPolicy, ProtectionStatus, capture_after_process_protection,
};
use zeroize::Zeroize as _;
use zeroize::Zeroizing;

const MAX_PASSPHRASE_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretInputError {
    NonInteractiveRequiresOptIn,
    InputUnavailable,
    InputTooLong,
    ProtectionUnavailable,
    ConfirmationMismatch,
    TerminalUnavailable,
}

impl fmt::Display for SecretInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonInteractiveRequiresOptIn => {
                "non-terminal passphrase input requires --passphrase-stdin"
            }
            Self::InputUnavailable => "passphrase input is unavailable",
            Self::InputTooLong => "passphrase input exceeds its byte bound",
            Self::ProtectionUnavailable => "protected passphrase memory is unavailable",
            Self::ConfirmationMismatch => "passphrase confirmation differs",
            Self::TerminalUnavailable => "terminal echo protection is unavailable",
        })
    }
}

impl std::error::Error for SecretInputError {}

pub struct CapturedPassphrase {
    memory: ProtectedMemory,
    process_status: ProtectionStatus,
}

#[derive(Clone, Copy)]
pub struct SecretInputSource<'a> {
    provided: Option<&'a [u8]>,
    environment_name: Option<&'static str>,
}

impl<'a> SecretInputSource<'a> {
    pub(crate) const fn process_environment(name: &'static str) -> Self {
        Self {
            provided: None,
            environment_name: Some(name),
        }
    }

    #[cfg(test)]
    pub(crate) const fn provided(value: &'a [u8]) -> Self {
        Self {
            provided: Some(value),
            environment_name: None,
        }
    }
}

impl CapturedPassphrase {
    #[must_use]
    pub const fn memory(&self) -> &ProtectedMemory {
        &self.memory
    }

    #[must_use]
    pub fn protection_degraded(&self) -> bool {
        self.process_status.is_degraded() || self.memory.status().is_degraded()
    }

    pub fn matches(&self, other: &Self) -> Result<bool, SecretInputError> {
        secrets_match(&self.memory, &other.memory)
    }
}

pub fn capture(
    policy: ProtectionPolicy,
    passphrase_stdin: bool,
    confirmation: bool,
) -> Result<CapturedPassphrase, SecretInputError> {
    capture_named(policy, passphrase_stdin, confirmation, "Passphrase")
}

pub fn capture_named(
    policy: ProtectionPolicy,
    passphrase_stdin: bool,
    confirmation: bool,
    label: &str,
) -> Result<CapturedPassphrase, SecretInputError> {
    capture_named_or_environment(policy, passphrase_stdin, confirmation, label, None)
}

pub fn capture_named_or_environment(
    policy: ProtectionPolicy,
    passphrase_stdin: bool,
    confirmation: bool,
    label: &str,
    source: Option<SecretInputSource<'_>>,
) -> Result<CapturedPassphrase, SecretInputError> {
    let stdin = io::stdin();
    let terminal = stdin.is_terminal();
    if source.is_none() && !terminal && !passphrase_stdin {
        return Err(SecretInputError::NonInteractiveRequiresOptIn);
    }

    // Establish dump suppression and the requested memory controls before the
    // first secret byte is accepted from the terminal or pipe.
    let process_status = establish_process_protection(policy)?;

    if let Some(source) = source {
        if let Some(value) = source.provided {
            return capture_provided(policy, value, process_status);
        }
        if let Some(name) = source.environment_name
            && let Some(value) = env::var_os(name).and_then(secret_environment)
        {
            return capture_provided(policy, &value, process_status);
        }
    }
    if !terminal && !passphrase_stdin {
        return Err(SecretInputError::NonInteractiveRequiresOptIn);
    }

    let first_prompt = format!("{label}: ");
    let first = read_one(&stdin, terminal, &first_prompt, policy)?;
    if !confirmation {
        return Ok(CapturedPassphrase {
            memory: first,
            process_status,
        });
    }
    let second_prompt = format!("Confirm {label}: ");
    let second = read_one(&stdin, terminal, &second_prompt, policy)?;
    if secrets_match(&first, &second)? {
        Ok(CapturedPassphrase {
            memory: first,
            process_status,
        })
    } else {
        Err(SecretInputError::ConfirmationMismatch)
    }
}

fn capture_provided(
    policy: ProtectionPolicy,
    value: &[u8],
    process_status: ProtectionStatus,
) -> Result<CapturedPassphrase, SecretInputError> {
    if value.len() > MAX_PASSPHRASE_BYTES {
        return Err(SecretInputError::InputTooLong);
    }
    let capacity = value.len().max(1);
    let memory = ProtectedMemory::initialize(capacity, policy, |destination| {
        destination[..value.len()].copy_from_slice(value);
        Ok::<usize, ()>(value.len())
    })
    .map_err(|_| SecretInputError::ProtectionUnavailable)?;
    Ok(CapturedPassphrase {
        memory,
        process_status,
    })
}

fn secret_environment(value: OsString) -> Option<Zeroizing<Vec<u8>>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;
        Some(Zeroizing::new(value.into_vec()))
    }
    #[cfg(not(unix))]
    {
        Some(Zeroizing::new(value.to_string_lossy().as_bytes().to_vec()))
    }
}

fn establish_process_protection(
    policy: ProtectionPolicy,
) -> Result<ProtectionStatus, SecretInputError> {
    let sentinel = ProtectedMemory::initialize(1, policy, |destination| {
        destination[0] = 0;
        Ok::<usize, ()>(1)
    })
    .map_err(|_| SecretInputError::ProtectionUnavailable)?;
    Ok(
        capture_after_process_protection(policy, sentinel.status().clone(), || ())
            .map_err(|_| SecretInputError::ProtectionUnavailable)?
            .status,
    )
}

fn read_one(
    stdin: &io::Stdin,
    terminal: bool,
    prompt: &str,
    policy: ProtectionPolicy,
) -> Result<ProtectedMemory, SecretInputError> {
    let echo = terminal.then(|| EchoGuard::disable(stdin)).transpose()?;
    if terminal {
        eprint!("{prompt}");
        io::stderr()
            .flush()
            .map_err(|_| SecretInputError::InputUnavailable)?;
    }
    let result = read_secret_line(&mut stdin.lock(), policy);
    drop(echo);
    if terminal {
        eprintln!();
    }
    result
}

fn read_secret_line(
    reader: &mut impl io::Read,
    policy: ProtectionPolicy,
) -> Result<ProtectedMemory, SecretInputError> {
    let mut input = StackSecret::new();
    let mut overflow = false;
    loop {
        let mut byte = [0_u8; 1];
        match reader.read(&mut byte) {
            Ok(0) if input.len == 0 => return Err(SecretInputError::InputUnavailable),
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if input.len < MAX_PASSPHRASE_BYTES => {
                input.bytes[input.len] = byte[0];
                input.len += 1;
            }
            Ok(_) => overflow = true,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(SecretInputError::InputUnavailable),
        }
    }
    if overflow {
        return Err(SecretInputError::InputTooLong);
    }
    let capacity = input.len.max(1);
    ProtectedMemory::initialize(capacity, policy, |destination| {
        destination[..input.len].copy_from_slice(&input.bytes[..input.len]);
        Ok::<usize, ()>(input.len)
    })
    .map_err(|_| SecretInputError::ProtectionUnavailable)
}

fn secrets_match(
    left: &ProtectedMemory,
    right: &ProtectedMemory,
) -> Result<bool, SecretInputError> {
    left.expose(|left_bytes| {
        right.expose(|right_bytes| {
            let mut difference = left_bytes.len() ^ right_bytes.len();
            for index in 0..left_bytes.len().max(right_bytes.len()) {
                difference |= usize::from(
                    left_bytes.get(index).copied().unwrap_or(0)
                        ^ right_bytes.get(index).copied().unwrap_or(0),
                );
            }
            difference == 0
        })
    })
    .map_err(|_| SecretInputError::ProtectionUnavailable)?
    .map_err(|_| SecretInputError::ProtectionUnavailable)
}

struct StackSecret {
    bytes: [u8; MAX_PASSPHRASE_BYTES],
    len: usize,
}

impl StackSecret {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_PASSPHRASE_BYTES],
            len: 0,
        }
    }
}

impl Drop for StackSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len.zeroize();
    }
}

#[cfg(unix)]
struct EchoGuard<'a> {
    terminal: &'a io::Stdin,
    original: rustix::termios::Termios,
}

#[cfg(unix)]
impl<'a> EchoGuard<'a> {
    fn disable(terminal: &'a io::Stdin) -> Result<Self, SecretInputError> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

        let original = tcgetattr(terminal).map_err(|_| SecretInputError::TerminalUnavailable)?;
        let mut private = original.clone();
        private.local_modes.remove(LocalModes::ECHO);
        tcsetattr(terminal, OptionalActions::Flush, &private)
            .map_err(|_| SecretInputError::TerminalUnavailable)?;
        Ok(Self { terminal, original })
    }
}

#[cfg(unix)]
impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            self.terminal,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
    }
}

#[cfg(not(unix))]
struct EchoGuard;

#[cfg(not(unix))]
impl EchoGuard {
    fn disable(_: &io::Stdin) -> Result<Self, SecretInputError> {
        Err(SecretInputError::TerminalUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn strict_capture_reports_established_protection() -> Result<(), Box<dyn std::error::Error>> {
        let captured = capture_named_or_environment(
            ProtectionPolicy::Strict,
            false,
            true,
            "Example passphrase",
            Some(SecretInputSource::provided(b"ExamplePass1234")),
        )?;
        assert!(!captured.protection_degraded());
        assert!(
            captured
                .memory()
                .expose(|bytes| bytes == b"ExamplePass1234")?
        );
        Ok(())
    }

    #[test]
    fn bounded_reader_preserves_exact_bytes_and_rejects_overflow()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = ProtectionPolicy::EmergencyAllowDegraded;
        let mut input = io::Cursor::new(b"ExamplePass1234\nremaining");
        let secret = read_secret_line(&mut input, policy)?;
        assert!(secret.expose(|bytes| bytes == b"ExamplePass1234")?);

        let mut oversized = vec![b'x'; MAX_PASSPHRASE_BYTES + 1];
        oversized.push(b'\n');
        assert!(matches!(
            read_secret_line(&mut io::Cursor::new(oversized), policy),
            Err(SecretInputError::InputTooLong)
        ));
        Ok(())
    }

    #[test]
    fn comparison_is_exact() -> Result<(), Box<dyn std::error::Error>> {
        let policy = ProtectionPolicy::EmergencyAllowDegraded;
        let secret = |bytes: &'static [u8]| {
            ProtectedMemory::initialize(bytes.len(), policy, |destination| {
                destination.copy_from_slice(bytes);
                Ok::<usize, ()>(bytes.len())
            })
        };
        assert!(secrets_match(
            &secret(b"ExamplePass1234")?,
            &secret(b"ExamplePass1234")?
        )?);
        assert!(!secrets_match(
            &secret(b"ExamplePass1234")?,
            &secret(b"ExamplePass1235")?
        )?);
        assert!(!secrets_match(
            &secret(b"ExamplePass1234")?,
            &secret(b"ExamplePass12345")?
        )?);
        Ok(())
    }

    #[test]
    fn late_bound_sources_preserve_exact_bytes_bounds_and_missing_environment_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = "Exact-例-Backup-Passphrase".as_bytes();
        let captured = capture_named_or_environment(
            ProtectionPolicy::EmergencyAllowDegraded,
            false,
            true,
            "Backup passphrase",
            Some(SecretInputSource::provided(value)),
        )?;
        assert!(captured.memory().expose(|bytes| bytes == value)?);

        let maximum = vec![b'x'; 1_024];
        let captured = capture_named_or_environment(
            ProtectionPolicy::EmergencyAllowDegraded,
            false,
            true,
            "Backup passphrase",
            Some(SecretInputSource::provided(&maximum)),
        )?;
        assert_eq!(captured.memory().len(), 1_024);
        let oversized = vec![b'x'; 1_025];
        assert!(matches!(
            capture_named_or_environment(
                ProtectionPolicy::EmergencyAllowDegraded,
                false,
                true,
                "Backup passphrase",
                Some(SecretInputSource::provided(&oversized)),
            ),
            Err(SecretInputError::InputTooLong)
        ));
        assert!(matches!(
            capture_named_or_environment(
                ProtectionPolicy::EmergencyAllowDegraded,
                false,
                false,
                "Backup passphrase",
                Some(SecretInputSource::process_environment(
                    "JURY_TEST_INTENTIONALLY_MISSING_PASSPHRASE",
                )),
            ),
            Err(SecretInputError::NonInteractiveRequiresOptIn)
        ));
        Ok(())
    }
}

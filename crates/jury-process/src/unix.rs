use std::os::fd::BorrowedFd;
#[cfg(target_os = "linux")]
use std::{fmt, time::Instant};

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProcessGroupId(Pid);

impl ProcessGroupId {
    pub(crate) fn new(raw: i32) -> std::io::Result<Self> {
        if raw <= 0 {
            return Err(std::io::Error::other(
                "process-group identity must be positive",
            ));
        }
        Pid::from_raw(raw)
            .map(Self)
            .ok_or_else(|| std::io::Error::other("process-group identity must be positive"))
    }

    pub(crate) const fn as_raw(self) -> i32 {
        self.0.as_raw_pid()
    }

    const fn as_pid(self) -> Pid {
        self.0
    }
}

impl TryFrom<u32> for ProcessGroupId {
    type Error = std::io::Error;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        let raw = i32::try_from(raw)
            .map_err(|_| std::io::Error::other("process identifier is not representable"))?;
        Self::new(raw)
    }
}

pub(crate) fn set_nonblocking(descriptor: BorrowedFd<'_>) -> std::io::Result<()> {
    let flags = fcntl_getfl(descriptor).map_err(std::io::Error::from)?;
    fcntl_setfl(descriptor, flags | OFlags::NONBLOCK).map_err(std::io::Error::from)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnreapedChildObservation {
    Running,
    Exited,
}

pub(crate) fn observe_unreaped_child(
    process_group: ProcessGroupId,
) -> std::io::Result<UnreapedChildObservation> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    match rustix::process::waitid(WaitId::Pid(process_group.as_pid()), options)
        .map_err(std::io::Error::from)?
    {
        None => Ok(UnreapedChildObservation::Running),
        Some(status) if status.exited() || status.killed() || status.dumped() => {
            Ok(UnreapedChildObservation::Exited)
        }
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "waitid returned an unrecognized owned-child state",
        )),
    }
}

pub(crate) fn signal_process_group(
    process_group: ProcessGroupId,
    signal: Signal,
) -> std::io::Result<()> {
    rustix::process::kill_process_group(process_group.as_pid(), signal)
        .map_err(std::io::Error::from)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_process_group_has_live_members(
    process_group: ProcessGroupId,
    deadline: Instant,
) -> std::io::Result<bool> {
    ensure_scan_budget(process_group, deadline)?;
    let entries = std::fs::read_dir("/proc").map_err(|error| {
        process_scan_error(
            error,
            format!(
                "failed to enumerate /proc while scanning Linux process group {}",
                process_group.as_raw()
            ),
        )
    })?;

    for entry in entries {
        ensure_scan_budget(process_group, deadline)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(process_scan_error(
                    error,
                    format!(
                        "failed to enumerate /proc entry while scanning Linux process group {}",
                        process_group.as_raw()
                    ),
                ));
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .filter(|pid| *pid > 0)
        else {
            continue;
        };
        ensure_scan_budget(process_group, deadline)?;
        let observation = std::fs::read(format!("/proc/{pid}/stat"))
            .and_then(|stat| parse_linux_process_stat(pid, &stat));
        ensure_scan_budget(process_group, deadline)?;
        let observation = match observation {
            Ok(observation) => observation,
            Err(stat_error) => {
                let Some(pid) = Pid::from_raw(pid) else {
                    continue;
                };
                let observed_group = rustix::process::getpgid(Some(pid));
                ensure_scan_budget(process_group, deadline)?;
                match observed_group {
                    Err(rustix::io::Errno::SRCH) => continue,
                    Ok(other_group) if other_group.as_raw_pid() != process_group.as_raw() => {
                        continue;
                    }
                    Ok(_) => {
                        return Err(process_scan_error(
                            stat_error,
                            format!(
                                "could not inspect process {pid}, which belongs to Linux process group {}",
                                process_group.as_raw()
                            ),
                        ));
                    }
                    Err(group_error) => {
                        return Err(process_scan_error(
                            stat_error,
                            format!(
                                "could not inspect process {pid} or prove it is outside Linux process group {}: {group_error}",
                                process_group.as_raw()
                            ),
                        ));
                    }
                }
            }
        };
        if observation.process_group == process_group.as_raw() && observation.live {
            ensure_scan_budget(process_group, deadline)?;
            return Ok(true);
        }
    }
    ensure_scan_budget(process_group, deadline)?;
    Ok(false)
}

#[cfg(target_os = "linux")]
fn ensure_scan_budget(process_group: ProcessGroupId, deadline: Instant) -> std::io::Result<()> {
    if deadline
        .checked_duration_since(Instant::now())
        .is_some_and(|remaining| !remaining.is_zero())
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Linux process group {} cleanup scan exceeded its deadline",
                process_group.as_raw()
            ),
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxProcessObservation {
    process_group: i32,
    live: bool,
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_process_stat(
    expected_pid: i32,
    stat: &[u8],
) -> std::io::Result<LinuxProcessObservation> {
    let expected_prefix = format!("{expected_pid} (");
    if expected_pid <= 0 || !stat.starts_with(expected_prefix.as_bytes()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Linux process stat did not begin with the expected process identifier",
        ));
    }
    let command_end = stat
        .windows(2)
        .rposition(|window| window == b") ")
        .filter(|command_end| *command_end >= expected_prefix.len())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing Linux process stat command field",
            )
        })?;
    let fields = std::str::from_utf8(&stat[command_end + 2..]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Linux process stat fields are not valid UTF-8",
        )
    })?;
    let mut fields = fields.split_whitespace();
    let state = fields.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing process state")
    })?;
    let process_group = fields
        .nth(1)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing process group")
        })?
        .parse::<i32>()
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid process group")
        })?;
    Ok(LinuxProcessObservation {
        process_group,
        live: !matches!(state, "Z" | "X" | "x"),
    })
}

#[cfg(target_os = "linux")]
fn process_scan_error(error: std::io::Error, message: String) -> std::io::Error {
    let kind = error.kind();
    std::io::Error::new(kind, ProcessScanContext { message, error })
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ProcessScanContext {
    message: String,
    error: std::io::Error,
}

#[cfg(target_os = "linux")]
impl fmt::Display for ProcessScanContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.message, self.error)
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for ProcessScanContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_process_group_contains_only_pinned_leader(
    process_group: ProcessGroupId,
) -> std::io::Result<bool> {
    use libproc::processes::{ProcFilter, pids_by_type};

    let raw_group = u32::try_from(process_group.as_raw())
        .map_err(|_| std::io::Error::other("macOS process-group identity was invalid"))?;
    let members = pids_by_type(ProcFilter::ByProgramGroup { pgrpid: raw_group })?;
    classify_macos_process_group_snapshot(process_group, &members)
}

#[cfg(any(target_os = "macos", test))]
fn classify_macos_process_group_snapshot(
    process_group: ProcessGroupId,
    members: &[u32],
) -> std::io::Result<bool> {
    let raw_group = u32::try_from(process_group.as_raw())
        .map_err(|_| std::io::Error::other("macOS process-group identity was invalid"))?;
    if members.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "macOS process-group snapshot omitted the pinned leader",
        ));
    }
    if members.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "macOS process-group snapshot returned a non-positive member identifier",
        ));
    }
    if members.len() == 1 && members[0] == raw_group {
        return Ok(true);
    }
    if members.contains(&raw_group) {
        return Ok(false);
    }
    // XNU may list live members ahead of the zombie leader. A non-empty
    // snapshot without the leader therefore proves only that the group is not
    // quiescent; the retained wait status still pins the numeric generation.
    Ok(false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConsecutiveQuiescence {
    required: u8,
    observed: u8,
}

impl ConsecutiveQuiescence {
    pub(crate) fn new(required: u8) -> std::io::Result<Self> {
        if required == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "process-group confirmation requires at least one proof",
            ));
        }
        Ok(Self {
            required,
            observed: 0,
        })
    }

    pub(crate) fn observe(&mut self, quiescent: bool) -> bool {
        if quiescent {
            self.observed = self.observed.saturating_add(1).min(self.required);
        } else {
            self.observed = 0;
        }
        self.observed == self.required
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_group_id_accepts_only_positive_representable_values() -> std::io::Result<()> {
        assert_eq!(ProcessGroupId::new(73)?.as_raw(), 73);
        assert!(ProcessGroupId::new(0).is_err());
        assert!(ProcessGroupId::new(-1).is_err());
        assert!(ProcessGroupId::try_from(u32::MAX).is_err());
        Ok(())
    }

    #[test]
    fn macos_snapshot_requires_the_exact_sole_pinned_leader() -> std::io::Result<()> {
        let process_group = ProcessGroupId::new(73)?;
        assert!(classify_macos_process_group_snapshot(process_group, &[73])?);
        for members in [&[73, 74][..], &[74, 73], &[74, 75], &[73, 73]] {
            assert!(!classify_macos_process_group_snapshot(
                process_group,
                members
            )?);
        }
        assert!(classify_macos_process_group_snapshot(process_group, &[]).is_err());
        assert!(classify_macos_process_group_snapshot(process_group, &[0]).is_err());
        Ok(())
    }

    #[test]
    fn nonblocking_setup_preserves_descriptor_status_flags() -> std::io::Result<()> {
        use std::os::fd::AsFd;

        let temporary = tempfile::NamedTempFile::new()?;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(temporary.path())?;
        let before = fcntl_getfl(file.as_fd()).map_err(std::io::Error::from)?;
        assert!(before.contains(OFlags::APPEND));

        set_nonblocking(file.as_fd())?;

        let after = fcntl_getfl(file.as_fd()).map_err(std::io::Error::from)?;
        assert!(after.contains(before));
        assert!(after.contains(OFlags::NONBLOCK));
        Ok(())
    }

    #[test]
    fn linux_stat_parser_handles_spaces_parentheses_and_zombies() -> std::io::Result<()> {
        assert_eq!(
            parse_linux_process_stat(73, b"73 (strange ) name) R 12 73 0 0")?,
            LinuxProcessObservation {
                process_group: 73,
                live: true,
            }
        );
        assert_eq!(
            parse_linux_process_stat(73, b"73 (worker) Z 12 73 0 0")?,
            LinuxProcessObservation {
                process_group: 73,
                live: false,
            }
        );
        assert!(parse_linux_process_stat(74, b"73 (worker) R 12 73 0 0").is_err());
        Ok(())
    }

    #[test]
    fn quiescence_requires_consecutive_proofs() -> std::io::Result<()> {
        let mut quiescence = ConsecutiveQuiescence::new(2)?;
        assert!(!quiescence.observe(true));
        assert!(!quiescence.observe(false));
        assert!(!quiescence.observe(true));
        assert!(quiescence.observe(true));
        Ok(())
    }
}

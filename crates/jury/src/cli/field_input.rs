use super::{CliError, CliErrorKind, read_bounded_standard_input};
use std::io::{self, IsTerminal as _};
use zeroize::Zeroizing;

pub(super) fn capture(maximum: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if !io::stdin().is_terminal() {
        return read_bounded_standard_input(maximum);
    }
    #[cfg(target_os = "linux")]
    return terminal::capture(maximum);
    #[cfg(not(target_os = "linux"))]
    Err(unavailable())
}

fn unavailable() -> CliError {
    CliError::new(
        CliErrorKind::Filesystem,
        "field-input-unavailable",
        "hidden field input is unavailable",
    )
}

#[cfg(target_os = "linux")]
mod terminal {
    use super::*;
    use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
    use nix::sys::signalfd::{SfdFlags, SignalFd};
    use rustix::event::{PollFd, PollFlags, poll};
    use rustix::termios::{
        LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr,
    };
    use std::io::Write as _;
    use std::marker::PhantomData;
    use std::rc::Rc;
    use zeroize::Zeroize as _;

    // Field mutations run on the CLI's initial thread, without a runtime or
    // workers. Block cancellation only on that thread and read it via signalfd;
    // unlike temporary signal-hook registrations, this leaves signal handlers
    // unchanged for subsequent work. The guard cannot move to another thread.
    struct TerminalInput {
        stdin: io::Stdin,
        original: Termios,
        previous_mask: SigSet,
        signals: SignalFd,
        restored: bool,
        _same_thread: PhantomData<Rc<()>>,
    }

    impl TerminalInput {
        fn open() -> Result<Self, CliError> {
            let stdin = io::stdin();
            let original = tcgetattr(&stdin).map_err(|_| unavailable())?;
            let mut mask = SigSet::empty();
            for signal in [
                Signal::SIGHUP,
                Signal::SIGINT,
                Signal::SIGQUIT,
                Signal::SIGTERM,
                Signal::SIGTSTP,
            ] {
                mask.add(signal);
            }
            let signals =
                SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
                    .map_err(|_| unavailable())?;
            let mut previous_mask = SigSet::empty();
            pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut previous_mask))
                .map_err(|_| unavailable())?;
            let guard = Self {
                stdin,
                original,
                previous_mask,
                signals,
                restored: false,
                _same_thread: PhantomData,
            };
            let mut private = guard.original.clone();
            // Canonical mode silently truncates long lines. Read bounded bytes
            // ourselves, retaining terminal CR-to-LF translation and signals.
            private
                .local_modes
                .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON);
            private.special_codes[SpecialCodeIndex::VMIN] = 0;
            private.special_codes[SpecialCodeIndex::VTIME] = 1;
            tcsetattr(&guard.stdin, OptionalActions::Now, &private).map_err(|_| unavailable())?;
            Ok(guard)
        }

        fn check_cancelled(&self) -> Result<(), CliError> {
            if let Some(signal) = self.signals.read_signal().map_err(|_| unavailable())? {
                let number = u8::try_from(signal.ssi_signo).map_err(|_| unavailable())?;
                return Err(CliError::new(
                    CliErrorKind::Interrupted(number),
                    "field-input-cancelled",
                    "field input cancelled; no value saved",
                ));
            }
            Ok(())
        }

        fn restore(&mut self) -> Result<(), CliError> {
            // Discard unread terminal input before re-enabling echo; it may
            // contain a cancelled value that must never reach the shell.
            let terminal = tcsetattr(&self.stdin, OptionalActions::Flush, &self.original);
            let signals = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&self.previous_mask), None);
            self.restored = true;
            terminal.map_err(|_| unavailable())?;
            signals.map_err(|_| unavailable())?;
            Ok(())
        }

        fn read(&self, maximum: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
            let mut value = Zeroizing::new(Vec::new());
            value
                .try_reserve_exact(maximum)
                .map_err(|_| unavailable())?;
            let mut byte = Zeroizing::new([0_u8; 1]);
            let codes = &self.original.special_codes;
            loop {
                self.check_cancelled()?;
                let mut ready = [
                    PollFd::new(&self.stdin, PollFlags::IN),
                    PollFd::new(&self.signals, PollFlags::IN),
                ];
                match poll(&mut ready, None) {
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => return Err(unavailable()),
                    Ok(_) => {}
                }
                self.check_cancelled()?;
                if ready[0]
                    .revents()
                    .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
                {
                    return Err(unavailable());
                }
                match rustix::io::read(&self.stdin, byte.as_mut_slice()) {
                    Ok(0) | Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => return Err(unavailable()),
                    Ok(_) => {}
                }
                let code = byte[0];
                if code != 0 && code == codes[SpecialCodeIndex::VEOF] {
                    self.check_cancelled()?;
                    return Ok(value);
                }
                if code != 0 && code == codes[SpecialCodeIndex::VERASE] {
                    if let Some(last) = value.last_mut().filter(|last| **last != b'\n') {
                        last.zeroize();
                        let length = value.len() - 1;
                        value.truncate(length);
                    }
                } else if code != 0 && code == codes[SpecialCodeIndex::VKILL] {
                    let start = value
                        .iter()
                        .rposition(|byte| *byte == b'\n')
                        .map_or(0, |index| index + 1);
                    value[start..].zeroize();
                    value.truncate(start);
                } else {
                    if value.len() == maximum {
                        return Err(CliError::new(
                            CliErrorKind::InvalidArguments,
                            "protected-input-too-large",
                            "protected input exceeds the active bound",
                        ));
                    }
                    value.push(code);
                }
            }
        }
    }

    impl Drop for TerminalInput {
        fn drop(&mut self) {
            if !self.restored {
                let _ = self.restore();
            }
        }
    }

    pub(super) fn capture(maximum: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let mut terminal = TerminalInput::open()?;
        eprintln!("Field value (hidden): Ctrl-D finishes; Enter adds a newline; Ctrl-C cancels.");
        io::stderr().flush().map_err(|_| unavailable())?;
        let value = terminal.read(maximum);
        terminal.restore()?;
        value
    }
}

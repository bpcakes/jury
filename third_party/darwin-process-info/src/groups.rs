use std::io;
use std::mem::size_of;

/// Whether a native process-group snapshot contains exactly its leader.
///
/// The caller must retain the leader's wait status to pin the PID generation
/// and separately establish that it has exited. This query does not establish
/// ownership, signal any process, or claim that a live leader is quiescent.
///
/// Two PID slots suffice: one exact leader is complete, whereas a full buffer
/// proves only that other members exist. No allocation or count-then-fill race
/// is needed. XNU scans both live and zombie lists under its process-list lock.
/// One synchronous kernel call may outlast a caller's deadline; callers must
/// check their absolute deadline before and after the call, not accept a late
/// result, and must not describe this API as preemptible.
///
/// # Errors
/// Returns an error for an invalid group, native query failure, an empty or
/// malformed response. A valid non-leader member is non-quiescent, not an error.
pub fn process_group_has_only_leader(group: u32) -> io::Result<bool> {
    if group == 0 || group > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process group",
        ));
    }
    let mut members = [0_i32; 2];
    // SAFETY: the initialized, correctly aligned array has exactly the byte
    // capacity supplied to libproc. No returned size controls memory access.
    // The fixed filter only queries IDs; it cannot signal or modify processes.
    // Darwin __error returns a valid pointer to this thread's errno storage;
    // the pointer is used only here and never escapes.
    let (bytes, errno) = unsafe {
        // Darwin's wrapper maps syscall failure to zero, also the valid empty
        // result. Clear and capture this thread's errno around the call to
        // distinguish both without reporting a stale earlier OS error.
        let errno = crate::bindings::__error();
        *errno = 0;
        let bytes = crate::bindings::proc_listpids(
            crate::bindings::PROC_PGRP_ONLY,
            group,
            members.as_mut_ptr().cast(),
            size_of::<[i32; 2]>() as i32,
        );
        (bytes, *errno)
    };
    classify_result(group, members, bytes, errno)
}

fn classify_result(group: u32, members: [i32; 2], bytes: i32, errno: i32) -> io::Result<bool> {
    if bytes == 0 && errno != 0 {
        return Err(io::Error::from_raw_os_error(errno));
    }
    classify(group, members, bytes)
}

fn classify(group: u32, members: [i32; 2], bytes: i32) -> io::Result<bool> {
    let count = match bytes {
        4 => 1,
        8 => 2,
        _ => return Err(invalid_snapshot()),
    };
    if members[..count].iter().any(|pid| *pid <= 0) {
        return Err(invalid_snapshot());
    }
    if count == 2 {
        if members[0] == members[1] {
            return Err(invalid_snapshot());
        }
        // Saturation is NOT a complete snapshot. It cannot prove quiescence,
        // even if the pinned leader is present or a subsequent query is full.
        return Ok(false);
    }
    // A leader may join another group before exiting. Its unconsumed wait
    // status still pins the original numeric group, and any remaining member
    // requires continued signaling rather than aborting cleanup.
    Ok(members[0] as u32 == group)
}

fn invalid_snapshot() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid process-group snapshot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_complete_exact_singleton_is_a_sole_leader() -> io::Result<()> {
        assert!(classify(73, [73, 0], 4)?);
        for members in [[73, 74], [74, 73], [74, 75]] {
            assert!(!classify(73, members, 8)?);
        }
        assert!(!classify(73, [74, 0], 4)?);
        Ok(())
    }

    #[test]
    fn malformed_or_potentially_truncated_responses_cannot_prove_quiescence() {
        for bytes in [-1, 0, 1, 3, 5, 7, 9, 12, 16, i32::MAX] {
            assert!(classify(73, [73, 74], bytes).is_err());
        }
        for members in [[0, 73], [73, 0], [-1, 73], [73, 73]] {
            assert!(classify(73, members, 8).is_err());
        }
        for member in [0, -1] {
            assert!(classify(73, [member, 0], 4).is_err());
        }
    }

    #[test]
    fn zero_return_preserves_native_failure_without_inventing_one_for_empty_results() {
        for errno in [1, 12, 22] {
            let error = classify_result(73, [0, 0], 0, errno).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
        }
        let empty = classify_result(73, [0, 0], 0, 0).unwrap_err();
        assert_eq!(empty.kind(), io::ErrorKind::InvalidData);
        assert_eq!(empty.raw_os_error(), None);
        assert!(classify_result(73, [73, 0], 4, 1).unwrap());
    }

    #[test]
    fn invalid_groups_fail_before_query() {
        for group in [0, u32::MAX] {
            assert_eq!(
                process_group_has_only_leader(group).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}

use super::*;

#[test]
fn destination_acl_open_refuses_fifo_substitution_without_waiting_for_a_writer()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::mpsc;
    let temporary = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temporary.path().join("state"), &[])?;
    state.root.dir.write("ExampleSecret", b"ExampleSecret")?;
    let metadata = state.root.dir.symlink_metadata("ExampleSecret")?;
    let snapshot = RegularFileSnapshot::from_metadata(&metadata);
    state.root.dir.remove_file("ExampleSecret")?;
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(temporary.path().join("state/ExampleSecret"))
        .status()?;
    assert!(status.success(), "synthetic FIFO creation failed");
    let directory = state.root.dir.try_clone()?;
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = validate_destination_acl(
            &directory,
            OsStr::new("ExampleSecret"),
            snapshot,
            FilesystemOperation::Preview,
        );
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(std::time::Duration::from_secs(2));
    if result.is_err() {
        // A regressed blocking reader is released before joining the worker.
        let _writer = rustix::fs::openat(
            &state.root.dir,
            "ExampleSecret",
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )?;
        worker.join().map_err(|_| "ACL worker panicked")?;
        return Err("ACL inspection blocked on FIFO substitution".into());
    }
    worker.join().map_err(|_| "ACL worker panicked")?;
    assert_eq!(
        result?.err().ok_or("expected FIFO refusal")?.kind(),
        FilesystemErrorKind::IdentityChanged
    );
    Ok(())
}

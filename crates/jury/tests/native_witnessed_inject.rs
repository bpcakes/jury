//! Native regression using real CLI/approval/engine operations and the shared
//! in-memory witness adapter fixture. Not juryd persistence or TLS acceptance.
#![cfg(target_os = "macos")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use jury_core::witness_receipt::ReceiptPolicyMaterialV1;
use support::*;

#[path = "native_cli/policy_actors.rs"]
mod native_cli_additional;
#[path = "native_cli/support.rs"]
mod support;

mod witnessed {
    include!("native_cli/witnessed/engine.rs");
    include!("native_cli/witnessed/injection.rs");
    include!("native_cli/witnessed/fixture.rs");
    include!("native_cli/witnessed/renderer_replacement.rs");

    #[test]
    fn native_witnessed_read_and_inject_complete_after_approval() -> TestResult {
        with_witnessed_workflow(|workflow, _, endpoints| {
            let read_receipt = exercise_witnessed_read(workflow)?;
            let inject_receipt = exercise_witnessed_injection(workflow)?;
            verify_receipts(
                workflow.approval.repository,
                workflow.approval.data,
                workflow.approval.state,
                &[&read_receipt, &inject_receipt],
            )?;
            assert_protected_value_not_persisted([
                workflow.approval.repository,
                workflow.approval.data,
                workflow.approval.state,
                workflow.artifacts,
            ])?;
            for endpoint in endpoints {
                assert!(endpoint.request_counts().1 >= 2);
            }
            Ok(())
        })
    }
}

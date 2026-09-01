use super::*;

pub(super) fn confirm_expected_genesis(cli: &Cli, vault: &VaultFileV1) -> Result<(), CliError> {
    let expected = hex(vault.header.genesis_fingerprint.as_bytes());
    if let Some(provided) = &cli.expected_genesis {
        if decode_presented_hex_32(provided).as_ref()
            != Some(vault.header.genesis_fingerprint.as_bytes())
        {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "genesis-fingerprint-mismatch",
                "the externally expected genesis differs from the selected vault",
            ));
        }
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "expected-genesis-required",
            "first private use requires an externally supplied expected genesis",
        ));
    }
    eprintln!("First private use of this vault requires explicit trust.");
    eprintln!("Genesis fingerprint: {}", grouped(&expected));
    eprint!("Enter the complete genesis fingerprint to continue: ");
    std::io::stderr().flush().map_err(|_| filesystem_error())?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .map_err(|_| filesystem_error())?;
    if decode_presented_hex_32(&confirmation).as_ref()
        != Some(vault.header.genesis_fingerprint.as_bytes())
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "genesis-confirmation-failed",
            "the vault genesis was not explicitly confirmed",
        ));
    }
    Ok(())
}

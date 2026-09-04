use std::env;
use std::ffi::OsString;
use zeroize::Zeroizing;

pub(super) struct Environment {
    pub(super) jury_home: Option<OsString>,
    pub(super) jury_identity_home: Option<OsString>,
    pub(super) jury_identity: Option<OsString>,
    pub(super) jury_identity_file: Option<OsString>,
    pub(super) jury_state_home: Option<OsString>,
    pub(super) xdg_data_home: Option<OsString>,
    pub(super) xdg_state_home: Option<OsString>,
    pub(super) user_home: Option<OsString>,
    pub(super) jury_identity_passphrase: Option<Zeroizing<Vec<u8>>>,
    pub(super) jury_backup_passphrase: Option<Zeroizing<Vec<u8>>>,
    pub(super) jury_new_passphrase: Option<Zeroizing<Vec<u8>>>,
}

impl Environment {
    pub(super) fn capture() -> Self {
        Self {
            jury_home: env::var_os("JURY_HOME"),
            jury_identity_home: env::var_os("JURY_IDENTITY_HOME"),
            jury_identity: env::var_os("JURY_IDENTITY"),
            jury_identity_file: env::var_os("JURY_IDENTITY_FILE"),
            jury_state_home: env::var_os("JURY_STATE_HOME"),
            xdg_data_home: env::var_os("XDG_DATA_HOME"),
            xdg_state_home: env::var_os("XDG_STATE_HOME"),
            user_home: env::var_os("HOME"),
            jury_identity_passphrase: secret_environment("JURY_IDENTITY_PASSPHRASE"),
            jury_backup_passphrase: secret_environment("JURY_BACKUP_PASSPHRASE"),
            jury_new_passphrase: secret_environment("JURY_NEW_PASSPHRASE"),
        }
    }
}

fn secret_environment(name: &str) -> Option<Zeroizing<Vec<u8>>> {
    let value = env::var_os(name)?;
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

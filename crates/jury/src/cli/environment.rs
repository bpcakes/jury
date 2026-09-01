use std::env;
use std::ffi::OsString;

pub(super) struct Environment {
    pub(super) jury_home: Option<OsString>,
    pub(super) jury_identity_home: Option<OsString>,
    pub(super) jury_identity: Option<OsString>,
    pub(super) jury_identity_file: Option<OsString>,
    pub(super) jury_state_home: Option<OsString>,
    pub(super) xdg_data_home: Option<OsString>,
    pub(super) xdg_state_home: Option<OsString>,
    pub(super) user_home: Option<OsString>,
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
        }
    }
}

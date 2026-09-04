use std::env;
use std::ffi::OsString;
#[cfg(test)]
use zeroize::Zeroizing;

use crate::secret_input::SecretInputSource;

pub(super) struct Environment {
    pub(super) jury_home: Option<OsString>,
    pub(super) jury_identity_home: Option<OsString>,
    pub(super) jury_identity: Option<OsString>,
    pub(super) jury_identity_file: Option<OsString>,
    pub(super) jury_state_home: Option<OsString>,
    pub(super) xdg_data_home: Option<OsString>,
    pub(super) xdg_state_home: Option<OsString>,
    pub(super) user_home: Option<OsString>,
    #[cfg(test)]
    pub(super) jury_identity_passphrase: Option<Zeroizing<Vec<u8>>>,
    #[cfg(test)]
    pub(super) jury_backup_passphrase: Option<Zeroizing<Vec<u8>>>,
    #[cfg(test)]
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
            #[cfg(test)]
            jury_identity_passphrase: None,
            #[cfg(test)]
            jury_backup_passphrase: None,
            #[cfg(test)]
            jury_new_passphrase: None,
        }
    }

    pub(super) fn identity_passphrase(&self) -> Option<SecretInputSource<'_>> {
        #[cfg(test)]
        {
            self.jury_identity_passphrase
                .as_ref()
                .map(|value| SecretInputSource::provided(value.as_slice()))
        }
        #[cfg(not(test))]
        {
            Some(SecretInputSource::process_environment(
                "JURY_IDENTITY_PASSPHRASE",
            ))
        }
    }

    pub(super) fn backup_passphrase(&self) -> Option<SecretInputSource<'_>> {
        #[cfg(test)]
        {
            self.jury_backup_passphrase
                .as_ref()
                .map(|value| SecretInputSource::provided(value.as_slice()))
        }
        #[cfg(not(test))]
        {
            Some(SecretInputSource::process_environment(
                "JURY_BACKUP_PASSPHRASE",
            ))
        }
    }

    pub(super) fn new_passphrase(&self) -> Option<SecretInputSource<'_>> {
        #[cfg(test)]
        {
            self.jury_new_passphrase
                .as_ref()
                .map(|value| SecretInputSource::provided(value.as_slice()))
        }
        #[cfg(not(test))]
        {
            Some(SecretInputSource::process_environment(
                "JURY_NEW_PASSPHRASE",
            ))
        }
    }
}

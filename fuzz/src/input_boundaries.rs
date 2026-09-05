use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

use clap::Parser as _;
use jury::cli::Cli;
use jury_core::domain::{
    FieldNameInput, FieldSelector, ItemId, ItemNameInput, ItemSelector, PrincipalId, VaultId,
};
use jury_filesystem::IdentityName;
use jury_witness::config::{AnchorServiceConfig, WitnessServiceConfig};

const MAX_INPUT_BYTES: usize = 512 * 1024;
const MAX_ARGUMENTS: usize = 128;
#[cfg(test)]
pub(crate) const ALL_ACCEPTED_PATHS: u16 = (1 << 11) - 1;

/// Exercises bounded CLI, selector, identity-name, and service-config input
/// decoding without touching files named by an input.
pub fn exercise(data: &[u8]) -> usize {
    coverage(data).count_ones() as usize
}

pub(crate) fn coverage(data: &[u8]) -> u16 {
    if data.len() > MAX_INPUT_BYTES {
        return 0;
    }
    let mut accepted = 0;
    let mut arguments = vec![OsString::from("jury")];
    arguments.extend(
        data.split(|byte| *byte == 0)
            .take(MAX_ARGUMENTS)
            .map(|argument| OsString::from_vec(argument.to_vec())),
    );
    if Cli::try_parse_from(arguments).is_ok() {
        accepted |= 1 << 0;
    }
    if let Ok(value) = std::str::from_utf8(data) {
        if IdentityName::parse(value).is_ok() {
            accepted |= 1 << 1;
        }
        if ItemSelector::parse(value).is_ok() {
            accepted |= 1 << 2;
        }
        if let Some((item, field)) = value.split_once('\0')
            && FieldSelector::parse(item, field).is_ok()
        {
            accepted |= 1 << 3;
        }
        if ItemNameInput::parse(value).is_ok() {
            accepted |= 1 << 6;
        }
        if FieldNameInput::parse(value).is_ok() {
            accepted |= 1 << 7;
        }
        if value.parse::<VaultId>().is_ok() {
            accepted |= 1 << 8;
        }
        if value.parse::<PrincipalId>().is_ok() {
            accepted |= 1 << 9;
        }
        if value.parse::<ItemId>().is_ok() {
            accepted |= 1 << 10;
        }
    }
    if serde_json::from_slice::<WitnessServiceConfig>(data).is_ok() {
        accepted |= 1 << 4;
    }
    if serde_json::from_slice::<AnchorServiceConfig>(data).is_ok() {
        accepted |= 1 << 5;
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_seeds_reach_each_input_family() {
        assert!(exercise(b"identity\0list") >= 1);
        assert!(exercise(b"ExampleSecret") >= 2);
        assert!(exercise(b"ExampleSecret\0token") >= 1);
        assert!(exercise(b"0101010101010101010101010101010101010101010101010101010101010101") >= 3);
        assert!(exercise(include_bytes!("../../deploy/juryd/witness.example.json")) >= 1);
        assert!(exercise(include_bytes!("../../deploy/juryd/anchor.example.json")) >= 1);
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        assert_eq!(exercise(&vec![b'a'; MAX_INPUT_BYTES + 1]), 0);
    }
}

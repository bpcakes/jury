use clap::ValueEnum;

use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum PrincipalKindArg {
    #[default]
    Human,
    Machine,
    Approver,
    Witness,
}

impl From<PrincipalKindArg> for PrincipalKind {
    fn from(value: PrincipalKindArg) -> Self {
        match value {
            PrincipalKindArg::Human => Self::Human,
            PrincipalKindArg::Machine => Self::Machine,
            PrincipalKindArg::Approver => Self::Approver,
            PrincipalKindArg::Witness => Self::Witness,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum KdfProfileArg {
    #[default]
    Portable,
    Hardened,
}

impl From<KdfProfileArg> for KdfProfile {
    fn from(value: KdfProfileArg) -> Self {
        match value {
            KdfProfileArg::Portable => Self::PortableV1,
            KdfProfileArg::Hardened => Self::HardenedV1,
        }
    }
}

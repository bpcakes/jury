use jury_protocol::witness_v1::{ApprovalModeV1, PlatformAssuranceV1, WitnessOperationV1};

use super::{ApprovalMode, PlatformAssurance, WitnessOperation};

pub(crate) const fn protocol_approval_mode(mode: ApprovalMode) -> ApprovalModeV1 {
    match mode {
        ApprovalMode::Human => ApprovalModeV1::Human,
        ApprovalMode::Automatic => ApprovalModeV1::Automatic,
    }
}

pub(crate) const fn approval_mode_tag(mode: ApprovalMode) -> u8 {
    protocol_approval_mode(mode).tag()
}

pub(crate) const fn protocol_platform_assurance(
    assurance: PlatformAssurance,
) -> PlatformAssuranceV1 {
    match assurance {
        PlatformAssurance::NormalizedPathOnly => PlatformAssuranceV1::NormalizedPathOnly,
        PlatformAssurance::StableExecutableIdentity => {
            PlatformAssuranceV1::StableExecutableIdentity
        }
    }
}

pub(crate) const fn platform_assurance_tag(assurance: PlatformAssurance) -> u8 {
    protocol_platform_assurance(assurance).tag()
}

pub(crate) const fn protocol_operation(operation: WitnessOperation) -> WitnessOperationV1 {
    match operation {
        WitnessOperation::ReadStdout => WitnessOperationV1::ReadStdout,
        WitnessOperation::WritePrivateFile => WitnessOperationV1::WritePrivateFile,
        WitnessOperation::TemplateInjection => WitnessOperationV1::TemplateInjection,
        WitnessOperation::ChildEnvironment => WitnessOperationV1::ChildEnvironment,
        WitnessOperation::ChildStdin => WitnessOperationV1::ChildStdin,
        WitnessOperation::ItemMutation => WitnessOperationV1::ItemMutation,
        WitnessOperation::Backup => WitnessOperationV1::Backup,
        WitnessOperation::Recovery => WitnessOperationV1::Recovery,
        WitnessOperation::AdministrativeRekey => WitnessOperationV1::AdministrativeRekey,
    }
}

pub(crate) const fn core_operation(operation: WitnessOperationV1) -> WitnessOperation {
    match operation {
        WitnessOperationV1::ReadStdout => WitnessOperation::ReadStdout,
        WitnessOperationV1::WritePrivateFile => WitnessOperation::WritePrivateFile,
        WitnessOperationV1::TemplateInjection => WitnessOperation::TemplateInjection,
        WitnessOperationV1::ChildEnvironment => WitnessOperation::ChildEnvironment,
        WitnessOperationV1::ChildStdin => WitnessOperation::ChildStdin,
        WitnessOperationV1::ItemMutation => WitnessOperation::ItemMutation,
        WitnessOperationV1::Backup => WitnessOperation::Backup,
        WitnessOperationV1::Recovery => WitnessOperation::Recovery,
        WitnessOperationV1::AdministrativeRekey => WitnessOperation::AdministrativeRekey,
    }
}

pub(crate) const fn operation_tag(operation: WitnessOperation) -> u8 {
    protocol_operation(operation).tag()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_domain_variant_matches_its_witness_v1_tag_and_json_label()
    -> Result<(), serde_json::Error> {
        for domain in [ApprovalMode::Human, ApprovalMode::Automatic] {
            let protocol = protocol_approval_mode(domain);
            assert_eq!(
                serde_json::to_value(domain)?,
                serde_json::to_value(protocol)?
            );
        }

        for domain in [
            PlatformAssurance::NormalizedPathOnly,
            PlatformAssurance::StableExecutableIdentity,
        ] {
            let protocol = protocol_platform_assurance(domain);
            assert_eq!(
                serde_json::to_value(domain)?,
                serde_json::to_value(protocol)?
            );
            assert_eq!(platform_assurance_tag(domain), protocol.tag());
        }

        for domain in [
            WitnessOperation::ReadStdout,
            WitnessOperation::WritePrivateFile,
            WitnessOperation::TemplateInjection,
            WitnessOperation::ChildEnvironment,
            WitnessOperation::ChildStdin,
            WitnessOperation::ItemMutation,
            WitnessOperation::Backup,
            WitnessOperation::Recovery,
            WitnessOperation::AdministrativeRekey,
        ] {
            let protocol = protocol_operation(domain);
            assert_eq!(core_operation(protocol), domain);
            assert_eq!(
                serde_json::to_value(domain)?,
                serde_json::to_value(protocol)?
            );
            assert_eq!(operation_tag(domain), protocol.tag());
        }
        Ok(())
    }
}

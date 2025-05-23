//! General purpose bpf_loader_upgradeable utility functions

use {
    crate::{
        error::GovernanceError,
        state::p_bpf_loader_upgradeable::{
            SetUpgradeAuthority, UpgradeableLoaderState, BPF_LOADER_UPGRADEABLE_PUBKEY,
        },
    },
    pinocchio::{
        account_info::AccountInfo,
        program_error::ProgramError,
        pubkey::{find_program_address, Pubkey},
        ProgramResult,
    },
};

/// Returns ProgramData account address for the given Program
pub fn get_program_data_address(program: &Pubkey) -> Pubkey {
    find_program_address(&[program.as_ref()], &BPF_LOADER_UPGRADEABLE_PUBKEY).0
}

/// Returns upgrade_authority from the given Upgradable Loader Account
pub fn get_program_upgrade_authority(
    upgradable_loader_state: &UpgradeableLoaderState,
) -> Result<Option<Pubkey>, ProgramError> {
    let upgrade_authority = match upgradable_loader_state {
        UpgradeableLoaderState::ProgramData {
            slot: _,
            upgrade_authority_address,
        } => *upgrade_authority_address,
        _ => return Err(ProgramError::InvalidAccountData),
    };

    Ok(upgrade_authority)
}

/// Sets new upgrade authority for the given upgradable program
pub fn set_program_upgrade_authority(
    program_address: &Pubkey,
    program_data_info: &AccountInfo,
    program_upgrade_authority_info: &AccountInfo,
    new_authority_info: &AccountInfo,
    bpf_upgrade_loader_info: &AccountInfo,
) -> ProgramResult {
    SetUpgradeAuthority {
        program_data: program_data_info,
        current_authority: program_upgrade_authority_info,
        new_upgrade_authority: new_authority_info,
    }
    .invoke()
}

/// Asserts the program  is upgradable and its upgrade authority is a signer of
/// the transaction
pub fn assert_program_upgrade_authority_is_signer(
    program_address: &Pubkey,
    program_data_info: &AccountInfo,
    program_upgrade_authority_info: &AccountInfo,
) -> Result<(), ProgramError> {
    let program_data_info_owner: Pubkey = unsafe { *program_data_info.owner() };
    if program_data_info_owner != BPF_LOADER_UPGRADEABLE_PUBKEY {
        return Err(ProgramError::IncorrectProgramId);
    }
    let program_data_address = get_program_data_address(program_address);

    if program_data_address != *program_data_info.key() {
        return Err(GovernanceError::InvalidProgramDataAccountAddress.into());
    }
    let program_data_data: &[u8] = unsafe { &program_data_info.borrow_data_unchecked() };
    let upgrade_authority = if let UpgradeableLoaderState::ProgramData {
        slot: _,
        upgrade_authority_address,
    } = UpgradeableLoaderState::from_bytes(program_data_data)
        .ok_or(GovernanceError::InvalidProgramDataAccountData)?
    {
        upgrade_authority_address
    } else {
        None
    };

    let upgrade_authority = upgrade_authority.ok_or(GovernanceError::ProgramNotUpgradable)?;

    if upgrade_authority != *program_upgrade_authority_info.key() {
        return Err(GovernanceError::InvalidUpgradeAuthority.into());
    }
    if !program_upgrade_authority_info.is_signer() {
        return Err(GovernanceError::UpgradeAuthorityMustSign.into());
    }

    Ok(())
}

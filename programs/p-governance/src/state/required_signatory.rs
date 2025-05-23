//! RequiredSignatory account
use {
    crate::{error::GovernanceError, state::enums::GovernanceAccountType},
    
    p_spl_governance_tools::account::{
        get_account_data, AccountMaxSize, DataLen, IsInitialized
    },
    pinocchio::{
        account_info::AccountInfo,
        program_error::ProgramError,
        pubkey::{find_program_address, Pubkey}
    },
};

/// Required signatory
#[derive(Clone, Debug, PartialEq, Copy)]
pub struct RequiredSignatory {
    /// Account type
    pub account_type: GovernanceAccountType,

    /// Account version
    pub account_version: u8,

    /// Governance this required signatory belongs to
    pub governance: Pubkey,

    /// Address of required signatory
    pub signatory: Pubkey,
}

impl AccountMaxSize for RequiredSignatory {}

impl IsInitialized for RequiredSignatory {
    fn is_initialized(&self) -> bool {
        self.account_type == GovernanceAccountType::RequiredSignatory
    }
}

impl DataLen for RequiredSignatory {
    const LEN: usize = core::mem::size_of::<RequiredSignatory>();
}

/// Deserializes RequiredSignatory account, checks the owner program, and
/// asserts that required signatory belongs to the given governance
pub fn get_required_signatory_data_for_governance(
    program_id: &Pubkey,
    required_signatory_info: &AccountInfo,
    governance: &Pubkey,
) -> Result<RequiredSignatory, ProgramError> {
    let required_signatory_data =
        get_account_data::<RequiredSignatory>(program_id, required_signatory_info)?;

    if required_signatory_data.governance != *governance {
        return Err(GovernanceError::InvalidGovernanceForRequiredSignatory.into());
    }

    Ok(required_signatory_data)
}

/// Returns RequiredSignatory PDA seeds
pub fn get_required_signatory_address_seeds<'a>(
    governance: &'a Pubkey,
    signatory: &'a Pubkey,
) -> [&'a [u8]; 3] {
    [
        b"required-signatory".as_ref(),
        governance.as_ref(),
        signatory.as_ref(),
    ]
}

/// Returns RequiredSignatory PDA address
pub fn get_required_signatory_address<'a>(
    program_id: &Pubkey,
    governance: &'a Pubkey,
    signatory: &'a Pubkey,
) -> Pubkey {
    find_program_address(
        &get_required_signatory_address_seeds(governance, signatory),
        program_id,
    )
    .0
}

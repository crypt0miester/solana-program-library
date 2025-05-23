use {
    crate::{
        error::GovernanceError,
        state::{
            governance::get_governance_data,
            required_signatory::get_required_signatory_data_for_governance,
        },
        tools::next_account_info,
    },
    p_spl_governance_tools::account::dispose_account,
    pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult},
};

pub fn process_remove_required_signatory(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let governance_info = next_account_info(account_info_iter)?; // 0
    let required_signatory_info = next_account_info(account_info_iter)?; // 1
    let beneficiary_info = next_account_info(account_info_iter)?; // 2

    if !governance_info.is_signer() {
        return Err(GovernanceError::GovernancePdaMustSign.into());
    };

    let mut governance_data = get_governance_data(program_id, governance_info)?;

    get_required_signatory_data_for_governance(
        program_id,
        required_signatory_info,
        governance_info.key(),
    )?;

    governance_data.required_signatories_count = governance_data
        .required_signatories_count
        .checked_sub(1)
        .unwrap();
    let governance_info_data = unsafe { governance_info.borrow_mut_data_unchecked() };
    governance_data.serialize(governance_info_data)?;

    dispose_account(required_signatory_info, beneficiary_info)?;

    Ok(())
}

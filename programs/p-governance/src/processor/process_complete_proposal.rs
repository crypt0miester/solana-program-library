//! Program state processor

use {
    crate::state::{
        enums::ProposalState, proposal::get_proposal_data,
        token_owner_record::get_token_owner_record_data_for_proposal_owner,
    },
    crate::tools::next_account_info,
    pinocchio::{account_info::AccountInfo, 
        sysvars::{clock::Clock, Sysvar}, pubkey::Pubkey, ProgramResult},
};

/// Processes CompleteProposal instruction
pub fn process_complete_proposal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let proposal_info = next_account_info(account_info_iter)?; // 0
    let token_owner_record_info = next_account_info(account_info_iter)?; // 1
    let complete_proposal_authority_info = next_account_info(account_info_iter)?; // 2

    let mut proposal_data = get_proposal_data(program_id, proposal_info)?;
    proposal_data.assert_can_complete()?;

    let token_owner_record_data = get_token_owner_record_data_for_proposal_owner(
        program_id,
        token_owner_record_info,
        &proposal_data.token_owner_record,
    )?;
    token_owner_record_data
        .assert_token_owner_or_delegate_is_signer(complete_proposal_authority_info)?;

    let clock = Clock::get()?;
    proposal_data.closed_at = Some(clock.unix_timestamp);
    proposal_data.state = ProposalState::Completed;

    let proposal_info_info_data = unsafe { proposal_info.borrow_mut_data_unchecked() };
    proposal_data.serialize(proposal_info_info_data)?;
    Ok(())
}

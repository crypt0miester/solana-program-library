//! Program state processor

use {
    crate::state::{
        enums::ProposalState, governance::get_governance_data_for_realm,
        proposal::get_proposal_data_for_governance, realm::assert_is_valid_realm,
        token_owner_record::get_token_owner_record_data_for_proposal_owner,
    },
    crate::tools::next_account_info,
    pinocchio::{account_info::AccountInfo, pubkey::Pubkey, sysvars::{Sysvar, clock::Clock}, ProgramResult},
};

/// Processes CancelProposal instruction
pub fn process_cancel_proposal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let realm_info = next_account_info(account_info_iter)?; // 0
    let governance_info = next_account_info(account_info_iter)?; // 1
    let proposal_info = next_account_info(account_info_iter)?; // 2
    let proposal_owner_record_info = next_account_info(account_info_iter)?; // 3
    let governance_authority_info = next_account_info(account_info_iter)?; // 4

    let clock = Clock::get()?;

    assert_is_valid_realm(program_id, realm_info)?;

    let mut governance_data =
        get_governance_data_for_realm(program_id, governance_info, realm_info.key())?;

    let mut proposal_data =
        get_proposal_data_for_governance(program_id, proposal_info, governance_info.key())?;
    proposal_data.assert_can_cancel(&governance_data.config, clock.unix_timestamp)?;

    let mut proposal_owner_record_data = get_token_owner_record_data_for_proposal_owner(
        program_id,
        proposal_owner_record_info,
        &proposal_data.token_owner_record,
    )?;

    proposal_owner_record_data
        .assert_token_owner_or_delegate_is_signer(governance_authority_info)?;

    proposal_owner_record_data.decrease_outstanding_proposal_count();
    let proposal_owner_record_info_data =
        unsafe { proposal_owner_record_info.borrow_mut_data_unchecked() };
    proposal_owner_record_data.serialize(proposal_owner_record_info_data)?;
    proposal_data.state = ProposalState::Cancelled;
    proposal_data.closed_at = Some(clock.unix_timestamp);

    let proposal_info_data = unsafe { proposal_info.borrow_mut_data_unchecked() };
    proposal_data.serialize(proposal_info_data)?;

    // Update  Governance active_proposal_count
    governance_data.active_proposal_count = governance_data.active_proposal_count.saturating_sub(1);
    let governance_info_data = unsafe { governance_info.borrow_mut_data_unchecked() };
    governance_data.serialize(governance_info_data)?;

    Ok(())
}

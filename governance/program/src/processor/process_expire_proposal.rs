//! Program state processor

use {
    crate::state::{
        enums::ProposalState, governance::get_governance_data_for_realm,
        proposal::get_proposal_data_for_governance, realm::assert_is_valid_realm,
        token_owner_record::get_token_owner_record_data_for_proposal_owner,
    },
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        clock::Clock,
        entrypoint::ProgramResult,
        pubkey::Pubkey,
        sysvar::Sysvar,
    },
};

/// Processes ExpireProposal instruction
pub fn process_expire_proposal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let realm_info = next_account_info(account_info_iter)?; // 0
    let governance_info = next_account_info(account_info_iter)?; // 1
    let proposal_info = next_account_info(account_info_iter)?; // 2
    let proposal_owner_record_info = next_account_info(account_info_iter)?; // 3

    let clock = Clock::get()?;

    assert_is_valid_realm(program_id, realm_info)?;

    let mut governance_data =
        get_governance_data_for_realm(program_id, governance_info, realm_info.key)?;

    let mut proposal_data =
        get_proposal_data_for_governance(program_id, proposal_info, governance_info.key)?;
    proposal_data.assert_can_expire(&governance_data.config, clock.unix_timestamp)?;

    let mut proposal_owner_record_data = get_token_owner_record_data_for_proposal_owner(
        program_id,
        proposal_owner_record_info,
        &proposal_data.token_owner_record,
    )?;

    proposal_owner_record_data.decrease_outstanding_proposal_count();
    proposal_owner_record_data.serialize(&mut proposal_owner_record_info.data.borrow_mut()[..])?;

    proposal_data.state = ProposalState::Expired;
    proposal_data.closed_at = Some(clock.unix_timestamp);

    proposal_data.serialize(&mut proposal_info.data.borrow_mut()[..])?;

    // Update Governance active_proposal_count
    governance_data.active_proposal_count = governance_data.active_proposal_count.saturating_sub(1);
    governance_data.serialize(&mut governance_info.data.borrow_mut()[..])?;

    Ok(())
}

//! Program state processor

use {
    crate::{
        error::GovernanceError,
        state::{
            governance::get_governance_data, proposal::get_proposal_data_for_governance, proposal_transaction_buffer::{
                get_proposal_transaction_buffer_address, get_proposal_transaction_buffer_data_for_proposal
            }
        },
    },
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        pubkey::Pubkey,
    },
};

/// Processes ExtendTransactionBuffer instruction
pub fn process_extend_transaction_buffer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    // Index of the buffer account to seed the account derivation
    buffer_index: u8,
    buffer: Vec<u8>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let governance_info = next_account_info(account_info_iter)?; // 0
    let proposal_info = next_account_info(account_info_iter)?; // 1

    let proposal_transaction_buffer_info = next_account_info(account_info_iter)?; // 2

    let creator_info = next_account_info(account_info_iter)?; // 3

    // proposal transaction buffer has to be created first
    if proposal_transaction_buffer_info.data_is_empty() {
        return Err(GovernanceError::TransactionBufferAlreadyExists.into());
    }

    // Governance account is no longer used and it's deserialized only to validate
    // the provided account
    let _governance_data = get_governance_data(program_id, governance_info)?;
    
    let proposal_data =
        get_proposal_data_for_governance(program_id, proposal_info, governance_info.key)?;
    proposal_data.assert_can_edit_instructions()?;

    let mut proposal_transaction_buffer_data = get_proposal_transaction_buffer_data_for_proposal(
        program_id,
        proposal_transaction_buffer_info,
        proposal_info.key,
    )?;

    // validations
    let proposal_transaction_buffer_address = get_proposal_transaction_buffer_address(
        program_id,
        proposal_info.key,
        creator_info.key,
        &buffer_index.to_le_bytes(),
    );
    if proposal_transaction_buffer_address != *proposal_transaction_buffer_info.key {
        return Err(GovernanceError::InvalidAccountFound.into());
    }
    let current_buffer_size = proposal_transaction_buffer_data.buffer.len() as u16;
    let remaining_space = proposal_transaction_buffer_data
        .final_buffer_size
        .checked_sub(current_buffer_size)
        .unwrap();

    // Check if the new data exceeds the remaining space
    let new_data_size = buffer.len() as u16;

    if new_data_size > remaining_space {
        return Err(GovernanceError::FinalBufferSizeExceeded.into());
    }
    
    if proposal_transaction_buffer_data.creator != *creator_info.key {
        return Err(GovernanceError::TransactionBufferUnauthorizedExtension.into());
    }

    let buffer_slice_extension = buffer;
    // Extend the buffer, log if it panics
    proposal_transaction_buffer_data
        .buffer
        .extend_from_slice(&buffer_slice_extension);

    proposal_transaction_buffer_data.invariant()?;
    
    // Serialize the modified transaction buffer back to account data
    proposal_transaction_buffer_data
        .serialize(&mut proposal_transaction_buffer_info.data.borrow_mut()[..])?;

    Ok(())
}

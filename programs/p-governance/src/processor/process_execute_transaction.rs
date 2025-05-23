//! Program state processor

use {
    crate::{
        state::{
            enums::{ProposalState, TransactionExecutionStatus},
            governance::get_governance_data,
            native_treasury::get_native_treasury_address_seeds,
            proposal::{get_proposal_data_for_governance, OptionVoteResult},
            proposal_transaction::get_proposal_transaction_data_for_proposal,
        },
        tools::next_account_info,
    },
    pinocchio::{
        account_info::AccountInfo,
        cpi::slice_invoke_signed,
        instruction::{AccountMeta, Instruction, Seed, Signer},
        pubkey::{find_program_address, Pubkey},
        sysvars::{clock::Clock, Sysvar},
        ProgramResult,
    },
};

/// Processes ExecuteTransaction instruction
pub fn process_execute_transaction(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let governance_info = next_account_info(account_info_iter)?; // 0
    let proposal_info = next_account_info(account_info_iter)?; // 1
    let proposal_transaction_info = next_account_info(account_info_iter)?; // 2

    let clock = Clock::get()?;

    let governance_data = get_governance_data(program_id, governance_info)?;

    let mut proposal_data =
        get_proposal_data_for_governance(program_id, proposal_info, governance_info.key())?;

    let mut proposal_transaction_data = get_proposal_transaction_data_for_proposal(
        program_id,
        proposal_transaction_info,
        proposal_info.key(),
    )?;

    proposal_data
        .assert_can_execute_transaction(&proposal_transaction_data, clock.unix_timestamp)?;

    // Execute instruction with Governance PDA as signer
    let instructions = proposal_transaction_data.instructions.clone();

    // In the current implementation accounts for all instructions are passed to
    // each instruction invocation. This is an overhead but shouldn't be a
    // showstopper because if we can invoke the parent instruction with that many
    // accounts then we should also be able to invoke all the nested ones
    // TODO: Optimize the invocation to split the provided accounts for each
    // individual instruction
    let instruction_account_infos = account_info_iter.as_slice();

    // Sign the transaction using the governance PDA

    let governance_seeds = governance_data.get_governance_address_seeds()?;
    let (_, bump_seed) = find_program_address(&governance_seeds, program_id);
    let gov_bump = &[bump_seed];

    let mut signer_seeds_raw: Vec<Seed> = governance_seeds
        .iter()
        .map(|s| Seed::from(*s))
        .collect::<Vec<_>>();

    signer_seeds_raw.push(Seed::from(gov_bump));
    // Sign the transaction using the governance treasury PDA if required by the
    // instruction
    let treasury_seeds = get_native_treasury_address_seeds(governance_info.key());
    let (treasury_address, treasury_bump_seed) = find_program_address(&treasury_seeds, program_id);
    let treasury_bump = &[treasury_bump_seed];
    if instruction_account_infos
        .iter()
        .any(|a| a.key() == &treasury_address)
    {
        let treasury_seeds_raw: Vec<Seed> = treasury_seeds
            .iter()
            .map(|s| Seed::from(*s))
            .collect::<Vec<_>>();
        signer_seeds_raw.extend(treasury_seeds_raw);
        signer_seeds_raw.push(Seed::from(treasury_bump));
    }

    let signers = [Signer::from(&signer_seeds_raw[..])];
    for instruction in instructions {
        let instruction_fixed = Instruction {
            program_id: &instruction.program_id,
            accounts: &instruction
                .accounts
                .iter()
                .map(|meta| AccountMeta {
                    pubkey: &meta.pubkey,
                    is_signer: meta.is_signer,
                    is_writable: meta.is_writable,
                })
                .collect::<Vec<_>>(),
            data: &instruction.data.clone(),
        };
        slice_invoke_signed(
            &instruction_fixed,
            &instruction_account_infos.iter().collect::<Vec<_>>(),
            &signers[..],
        )?;
    }

    // Update proposal and instruction accounts
    if proposal_data.state == ProposalState::Succeeded {
        proposal_data.executing_at = Some(clock.unix_timestamp);
        proposal_data.state = ProposalState::Executing;
    }

    let option = &mut proposal_data.options[proposal_transaction_data.option_index as usize];
    option.transactions_executed_count = option.transactions_executed_count.checked_add(1).unwrap();

    // Checking for Executing and ExecutingWithErrors states because instruction can
    // still be executed after being flagged with error The check for
    // instructions_executed_count ensures Proposal can't be transitioned to
    // Completed state from ExecutingWithErrors
    if (proposal_data.state == ProposalState::Executing
        || proposal_data.state == ProposalState::ExecutingWithErrors)
        && proposal_data
            .options
            .iter()
            .filter(|o| o.vote_result == OptionVoteResult::Succeeded)
            .all(|o| o.transactions_executed_count == o.transactions_count)
    {
        proposal_data.closed_at = Some(clock.unix_timestamp);
        proposal_data.state = ProposalState::Completed;
    }

    let proposal_info_data = unsafe { proposal_info.borrow_mut_data_unchecked() };
    proposal_data.serialize(proposal_info_data)?;

    proposal_transaction_data.executed_at = Some(clock.unix_timestamp);
    proposal_transaction_data.execution_status = TransactionExecutionStatus::Success;
    let proposal_transaction_info_data =
        unsafe { proposal_transaction_info.borrow_mut_data_unchecked() };
    proposal_transaction_data.serialize(proposal_transaction_info_data)?;

    Ok(())
}

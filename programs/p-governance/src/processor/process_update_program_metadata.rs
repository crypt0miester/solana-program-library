//! Program state processor

use {
    crate::{
        state::{
            enums::GovernanceAccountType,
            program_metadata::{
                get_program_metadata_data, get_program_metadata_seeds, ProgramMetadata,
            },
        },
        tools::next_account_info,
    },
    p_spl_governance_tools::account::{create_and_serialize_account_signed, to_bytes_with_len},
    pinocchio::{
        account_info::AccountInfo, memory::sol_memcpy, pubkey::Pubkey, sysvars::{clock::Clock, rent::Rent, Sysvar}, ProgramResult
    },
    pinocchio_log::log
};

/// Processes UpdateProgramMetadata instruction
pub fn process_update_program_metadata(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let program_metadata_info = next_account_info(account_info_iter)?; // 0
    let payer_info = next_account_info(account_info_iter)?; // 1
    let system_info = next_account_info(account_info_iter)?; // 2

    let rent = Rent::get()?;
    let updated_at = Clock::get()?.slot;

    const VERSION: &str = env!("CARGO_PKG_VERSION");

    // Put the metadata info into the logs to make it possible to extract it using
    // Tx simulation
    log!("PROGRAM-VERSION:{}", VERSION);

    if program_metadata_info.data_is_empty() {
        let program_metadata_data = ProgramMetadata {
            account_type: GovernanceAccountType::ProgramMetadata,
            updated_at,
            version: VERSION.to_string(),
            reserved: [0; 64],
        };

        create_and_serialize_account_signed(
            payer_info,
            program_metadata_info,
            &program_metadata_data,
            &get_program_metadata_seeds(),
            program_id,
            system_info,
            &rent,
            0,
        )?;
    } else {
        let mut program_metadata_data =
            get_program_metadata_data(program_id, program_metadata_info)?;

        program_metadata_data.version = VERSION.to_string();
        program_metadata_data.updated_at = updated_at;

        let program_metadata_info_mut = unsafe { program_metadata_info.borrow_mut_data_unchecked() };
        let data_len = program_metadata_info.data_len();
        unsafe {
            sol_memcpy(
                program_metadata_info_mut,
                to_bytes_with_len(&program_metadata_data, data_len),
                data_len,
            );
        }
    }

    Ok(())
}

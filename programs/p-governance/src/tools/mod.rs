//! Utility functions

use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

pub mod spl_token;

pub mod bpf_loader_upgradeable;

pub mod structs;

pub mod ephermal_signers;

pub mod executable_transaction_message;

pub mod transaction_message;


pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a AccountInfo>>(
    iter: &mut I,
) -> Result<I::Item, ProgramError> {
    iter.next().ok_or(ProgramError::NotEnoughAccountKeys)
}
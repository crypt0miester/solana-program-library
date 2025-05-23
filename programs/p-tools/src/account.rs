//! General purpose account utility functions

use {
    crate::error::GovernanceToolsError,
    pinocchio::{
        account_info::AccountInfo,
        instruction::{Seed, Signer},
        memory::sol_memcpy,
        msg,
        program_error::ProgramError,
        pubkey::{self, find_program_address, Pubkey},
        sysvars::{rent::Rent, Sysvar},
    },
    pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer},
};

/// Trait for accounts to return their max size
pub trait AccountMaxSize {
    /// Returns max account size or None if max size is not known and actual
    /// instance size should be used
    fn get_max_size(&self) -> Option<usize> {
        None
    }
}

pub trait IsInitialized {
    fn is_initialized(&self) -> bool;
}

/// Trait for accounts to return their size
/// This trait is used to determine the size of the account data
pub trait DataLen {
    const LEN: usize;
}

/// Creates a new account and serializes data into it using AccountMaxSize to
/// determine the account's size
pub fn create_and_serialize_account<'a, T: AccountMaxSize>(
    payer_info: &AccountInfo,
    account_info: &AccountInfo,
    account_data: &T,
    program_id: &Pubkey,
    _system_info: &AccountInfo,
) -> Result<(), ProgramError> {
    // Get raw account_info owner
    let account_info_owner: &Pubkey = unsafe { account_info.owner() };
    // Assert the account is not initialized yet
    if !(account_info.data_is_empty() && *account_info_owner == pinocchio_system::id()) {
        return Err(GovernanceToolsError::AccountAlreadyInitialized.into());
    }

    let (serialized_data, account_size) = if let Some(max_size) = account_data.get_max_size() {
        (None, max_size)
    } else {
        // SAFETY: single immutable borrow of `account` account data.
        let serialized_data = unsafe { account_info.borrow_data_unchecked() };
        let account_size = serialized_data.len();
        (Some(serialized_data), account_size)
    };

    let rent = Rent::get()?;

    CreateAccount {
        from: payer_info,
        to: account_info,
        space: account_size as u64,
        owner: &program_id,
        lamports: rent.minimum_balance(account_size),
    }
    .invoke()?;

    // SAFETY: single mutable borrow of `account_info` account data. There are no other borrows active.
    let data = unsafe { account_info.borrow_mut_data_unchecked() };

    unsafe {
        if let Some(serialized_data) = serialized_data {
            sol_memcpy(data, serialized_data, account_size);
        } else {
            sol_memcpy(data, to_bytes_with_len(account_data, account_size), account_size);
        }
    }

    Ok(())
}

/// Creates a new account and serializes data into it using the provided seeds
/// to invoke signed CPI call The owner of the account is set to the PDA program
/// Note: This functions also checks the provided account PDA matches the
/// supplied seeds
#[allow(clippy::too_many_arguments)]
pub fn create_and_serialize_account_signed<T: AccountMaxSize>(
    payer_info: &AccountInfo,
    account_info: &AccountInfo,
    account_data: &T,
    account_address_seeds: &[&[u8]],
    program_id: &Pubkey,
    system_info: &AccountInfo,
    rent: &Rent,
    extra_lamports: u64, // Extra lamports added on top of the rent exempt amount
) -> Result<(), ProgramError> {
    create_and_serialize_account_with_owner_signed(
        payer_info,
        account_info,
        account_data,
        account_address_seeds,
        program_id,
        program_id, // By default use PDA program_id as the owner of the account
        system_info,
        rent,
        extra_lamports,
    )
}

/// Creates a new account and serializes data into it using the provided seeds
/// to invoke signed CPI call Note: This functions also checks the provided
/// account PDA matches the supplied seeds
#[allow(clippy::too_many_arguments)]
pub fn create_and_serialize_account_with_owner_signed<'a, T: AccountMaxSize>(
    payer_info: &AccountInfo,
    account_info: &AccountInfo,
    account_data: &T,
    account_address_seeds: &[&[u8]],
    program_id: &Pubkey,
    owner_program_id: &Pubkey,
    _system_info: &AccountInfo,
    rent: &Rent,
    extra_lamports: u64, // Extra lamports added on top of the rent exempt amount
) -> Result<(), ProgramError> {
    // Get PDA and assert it's the same as the requested account address
    let (account_address, bump_seed) = find_program_address(account_address_seeds, program_id);

    if account_address != *account_info.key() {
        msg!("Create account with PDA:");
        pubkey::log(account_info.key());
        msg!("was requested while PDA:");
        pubkey::log(&account_address);
        msg!("was expected");
        return Err(ProgramError::InvalidSeeds);
    }

    let (serialized_data, account_size) = if let Some(max_size) = account_data.get_max_size() {
        (None, max_size)
    } else {
        let serialized_data = unsafe { account_info.borrow_data_unchecked() };
        let account_size = serialized_data.len();
        (Some(serialized_data), account_size)
    };
    let account_address_seeds_vec: Vec<u8> = account_address_seeds
        .into_iter()
        .flat_map(|slice| slice.to_vec())
        .collect();
    let account_address_seeds_raw: &[u8] = account_address_seeds_vec.as_ref();
    let bump = &[bump_seed];
    let signer_seeds: &[Seed] = &[Seed::from(account_address_seeds_raw), Seed::from(bump)];
    let rent_exempt_lamports = rent.minimum_balance(account_size);
    let total_lamports = rent_exempt_lamports.checked_add(extra_lamports).unwrap();

    // If the account has some lamports already it can't be created using
    // create_account instruction.
    // Anybody can send lamports to a PDA and by doing so create the account
    // and perform DoS attack by blocking create_account
    if account_info.lamports() > 0 {
        let top_up_lamports = total_lamports.saturating_sub(account_info.lamports());

        if top_up_lamports > 0 {
            Transfer {
                from: payer_info,
                to: account_info,
                lamports: top_up_lamports,
            }
            .invoke()?;
        }
        Allocate {
            account: account_info,
            space: account_size as u64,
        }
        .invoke_signed(&[Signer::from(signer_seeds)])?;
        Assign {
            account: account_info,
            owner: owner_program_id,
        }
        .invoke_signed(&[Signer::from(signer_seeds)])?;
    } else {
        // If the PDA doesn't exist use create_account to use lower compute budget
        CreateAccount {
            from: payer_info,
            to: account_info,
            space: account_size as u64,
            owner: owner_program_id,
            lamports: total_lamports,
        }
        .invoke_signed(&[Signer::from(signer_seeds)])?;
    }

    // SAFETY: single mutable borrow of `account_info` account data. There are no other borrows active.
    let data = unsafe { account_info.borrow_mut_data_unchecked() };

    unsafe {
        if let Some(serialized_data) = serialized_data {
            sol_memcpy(data, serialized_data, account_size);
        } else {
            sol_memcpy(data, to_bytes_with_len(account_data, account_size), account_size);
        }
    }

    Ok(())
}

/// Deserializes account and checks it's initialized and owned by the specified
/// program
pub fn get_account_data<T: Copy + DataLen + IsInitialized>(
    owner_program_id: &Pubkey,
    account_info: &AccountInfo,
) -> Result<T, ProgramError> {
    if account_info.data_is_empty() {
        return Err(GovernanceToolsError::AccountDoesNotExist.into());
    }
    // Get raw account_info owner
    let account_info_owner: &Pubkey = unsafe { account_info.owner() };

    if account_info_owner != owner_program_id {
        return Err(GovernanceToolsError::InvalidAccountOwner.into());
    }

    let account = unsafe { load_acc_unchecked::<T>(&account_info.borrow_data_unchecked())? };
    if !account.is_initialized() {
        Err(ProgramError::UninitializedAccount)
    } else {
        Ok(account)
    }
}


pub fn get_account_data_borrowed<'a, T: DataLen + IsInitialized>(
    owner_program_id: &'a Pubkey,
    account_info: &'a AccountInfo,
) -> Result<&'a T, ProgramError> {
    if account_info.data_is_empty() {
        return Err(GovernanceToolsError::AccountDoesNotExist.into());
    }
    // Get raw account_info owner
    let account_info_owner: &Pubkey = unsafe { account_info.owner() };

    if account_info_owner != owner_program_id {
        return Err(GovernanceToolsError::InvalidAccountOwner.into());
    }

    let account = unsafe { load_acc_unchecked_borrowed::<T>(&account_info.borrow_data_unchecked())? };
    if !account.is_initialized() {
        Err(ProgramError::UninitializedAccount)
    } else {
        Ok(account)
    }
}


pub unsafe fn load_acc_unchecked<T: Copy + DataLen>(bytes: &[u8]) -> Result<T, ProgramError> {
    // Check if bytes is large enough for T
    if bytes.len() == T::LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    // Check alignment (optional, but recommended for safety)
    if bytes.as_ptr() as usize % std::mem::align_of::<T>() != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Safe because we checked size and alignment, and T: Copy
    let account_type = unsafe { *(bytes.as_ptr() as *const T) };
    Ok(account_type)
}

pub unsafe fn load_acc_unchecked_borrowed<T: DataLen>(bytes: &[u8]) -> Result<&T, ProgramError> {
    // Check if bytes is large enough for T
    if bytes.len() == T::LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    // Check alignment (optional, but recommended for safety)
    if bytes.as_ptr() as usize % std::mem::align_of::<T>() != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Safe because we checked size and alignment, and T: Copy
    
    Ok(&*(bytes.as_ptr() as *const T))
}

#[inline(always)]
pub unsafe fn load_data_unchecked<T: DataLen>(bytes: &[u8]) -> Result<&T, ProgramError> {
    if bytes.len() != T::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(&*(bytes.as_ptr() as *const T))
}

/// Deserializes account type and checks if the given account_info is owned by
/// owner_program_id
pub fn get_account_type<T: Copy + DataLen>(
    owner_program_id: &Pubkey,
    account_info: &AccountInfo,
) -> Result<T, ProgramError> {
    if account_info.data_is_empty() {
        return Err(GovernanceToolsError::AccountDoesNotExist.into());
    }

    // Get raw account_info owner
    let account_info_owner: &Pubkey = unsafe { account_info.owner() };

    if account_info_owner != owner_program_id {
        return Err(GovernanceToolsError::InvalidAccountOwner.into());
    }

    let account_type = unsafe { load_acc_unchecked::<T>(&account_info.borrow_data_unchecked())? };

    Ok(account_type)
}

/// Asserts the given account is not empty, owned by the given program and of
/// the expected type Note: The function assumes the account type T is stored as
/// the first element in the account data
pub fn assert_is_valid_account_of_type<T: Copy + DataLen + PartialEq>(
    owner_program_id: &Pubkey,
    account_info: &AccountInfo,
    account_type: T,
) -> Result<(), ProgramError> {
    assert_is_valid_account_of_types(owner_program_id, account_info, |at: &T| *at == account_type)
}

/// Asserts the given account is not empty, owned by the given program and one
/// of the types asserted via the provided predicate function Note: The function
/// assumes the account type T is stored as the first element in the account
/// data
pub fn assert_is_valid_account_of_types<T: Copy + DataLen + PartialEq, F: Fn(&T) -> bool>(
    owner_program_id: &Pubkey,
    account_info: &AccountInfo,
    is_account_type: F,
) -> Result<(), ProgramError> {
    if account_info.data_is_empty() {
        return Err(GovernanceToolsError::AccountDoesNotExist.into());
    }
    // Get raw account_info owner
    let account_info_owner: &Pubkey = unsafe { account_info.owner() };

    if account_info_owner != owner_program_id {
        return Err(GovernanceToolsError::InvalidAccountOwner.into());
    }

    let account_type = unsafe { load_acc_unchecked::<T>(&account_info.borrow_data_unchecked())? };

    if !is_account_type(&account_type) {
        return Err(GovernanceToolsError::InvalidAccountType.into());
    };

    Ok(())
}

/// Disposes account by transferring its lamports to the beneficiary account,
/// resizing data to 0 and changing program owner to SystemProgram
// After transaction completes the runtime would remove the account with no
// lamports
pub fn dispose_account(
    account_info: &AccountInfo,
    beneficiary_info: &AccountInfo,
) -> Result<(), ProgramError> {
    // SAFETY: There are no active borrows to accounts' lamports.
    unsafe {
        let account_lamports = account_info.borrow_mut_lamports_unchecked();
        let destination_lamports = beneficiary_info.borrow_mut_lamports_unchecked();

        *destination_lamports = destination_lamports
            .checked_add(*account_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        *account_lamports = 0;
    }

    account_info.close()
}

/// Extends account size to the new account size
pub fn extend_account_size(
    account_info: &AccountInfo,
    payer_info: &AccountInfo,
    new_account_size: usize,
    rent: &Rent,
    _system_info: &AccountInfo,
) -> Result<(), ProgramError> {
    if new_account_size <= account_info.data_len() {
        return Err(GovernanceToolsError::InvalidNewAccountSize.into());
    }

    let rent_exempt_lamports = rent.minimum_balance(new_account_size);
    let top_up_lamports = rent_exempt_lamports.saturating_sub(account_info.lamports());

    if top_up_lamports > 0 {
        Transfer {
            from: payer_info,
            to: account_info,
            lamports: top_up_lamports,
        }
        .invoke()?;
    }

    account_info.realloc(new_account_size, false)
}

pub unsafe fn to_bytes<T: DataLen>(data: &T) -> &[u8] {
    core::slice::from_raw_parts(data as *const T as *const u8, T::LEN)
}

pub unsafe fn to_bytes_with_len<T>(data: &T, data_len: usize) -> &[u8] {
    core::slice::from_raw_parts(data as *const T as *const u8, data_len)
}

pub unsafe fn to_mut_bytes<T: DataLen>(data: &mut T) -> &mut [u8] {
    core::slice::from_raw_parts_mut(data as *mut T as *mut u8, T::LEN)
}

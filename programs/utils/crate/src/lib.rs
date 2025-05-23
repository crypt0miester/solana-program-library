use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
extern crate pinocchio;
#[cfg(feature = "macro")]
pub use pinocchio_utils_macro::*;

pub mod macros;

#[cfg(feature = "sha256_hash")]
pub mod sha256_hash;

#[cfg(feature = "sha256_hash")]
pub use sha256_hash::*;

use core::mem::MaybeUninit;

/// A single uninitialized byte value.
///
/// Useful for initializing buffers of `MaybeUninit<u8>`.
pub const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();

/// Deserialize a type from a byte array.
///
/// # Safety
///
/// This function is unsafe because it transmutes the input data to the output type.
pub unsafe fn from_bytes_unchecked<T: Copy>(data: &[u8]) -> T {
    *(data.as_ptr() as *const T)
}

/// Deserialize a type from a byte array into a reference.
///
/// # Safety
///
/// This function is unsafe because it transmutes the input data to the output type.
pub unsafe fn from_bytes_ref_unchecked<T>(data: &[u8]) -> &T {
    &*(data.as_ptr() as *const T)
}

/// Writes each byte from `source` into the `destination` buffer.
///
/// Initializes each element of `destination` via `MaybeUninit::write`.
#[inline(always)]
pub fn write_bytes(destination: &mut [MaybeUninit<u8>], source: &[u8]) {
    for (d, s) in destination.iter_mut().zip(source.iter()) {
        d.write(*s);
    }
}

/// Returns the next account info from the iterator.
///
/// # Errors
///
/// Returns `ProgramError::NotEnoughAccountKeys` if the iterator is empty.
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a AccountInfo>>(
    iter: &mut I,
) -> Result<I::Item, ProgramError> {
    iter.next().ok_or(ProgramError::NotEnoughAccountKeys)
}

/// Reads a little-endian boolean from the first byte.
pub fn read_bool(x: &[u8]) -> bool {
    assert!(x.len() >= 1);
    x[0] != 0
}

/// Reads a little-endian u16.
pub fn read_u16(x: &[u8]) -> u16 {
    assert!(x.len() >= 2);
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&x[..2]);
    u16::from_le_bytes(buf)
}

/// Reads a little-endian u32.
pub fn read_u32(x: &[u8]) -> u32 {
    assert!(x.len() >= 4);
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&x[..4]);
    u32::from_le_bytes(buf)
}

/// Reads a little-endian u64.
pub fn read_u64(x: &[u8]) -> u64 {
    assert!(x.len() >= 8);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&x[..8]);
    u64::from_le_bytes(buf)
}

/// Reads a &str from a byte slice (full slice) as UTF-8.
pub fn read_str(x: &[u8]) -> &str {
    core::str::from_utf8(x).expect("Invalid UTF-8")
}

/// Reads a String from a byte slice (full slice) as UTF-8.
pub fn read_string(x: &[u8]) -> String {
    read_str(x).to_string()
}

/// Disposes account by transferring its lamports to the beneficiary account,
/// resizing data to 0 and changing program owner to SystemProgram
pub fn dispose_account(
    account_info: &AccountInfo,
    beneficiary_info: &AccountInfo,
) -> Result<(), ProgramError> {
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

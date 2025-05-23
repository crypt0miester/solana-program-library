//! An upgradeable BPF loader native program.

use core::slice::from_raw_parts;
use pinocchio::{program_error::ProgramError, pubkey::Pubkey};
use pinocchio_pubkey::pubkey;

use pinocchio::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction, Signer},
    program::invoke_signed,
    ProgramResult,
};

use crate::{write_bytes, UNINIT_BYTE};

pub const BPF_LOADER_UPGRADEABLE_PUBKEY: Pubkey =
    pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");

/// Upgradeable loader account states
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UpgradeableLoaderState {
    /// Account is not initialized.
    Uninitialized,
    /// A Buffer account.
    Buffer {
        /// Authority address
        authority_address: Option<Pubkey>,
        // The raw program data follows this serialized structure in the
        // account's data.
    },
    /// An Program account.
    Program {
        /// Address of the ProgramData account.
        programdata_address: Pubkey,
    },
    // A ProgramData account.
    ProgramData {
        /// Slot that the program was last modified.
        slot: u64,
        /// Address of the Program's upgrade authority.
        upgrade_authority_address: Option<Pubkey>,
        // The raw program data follows this serialized structure in the
        // account's data.
    },
}

impl UpgradeableLoaderState {
    /// Size of a serialized program account.
    pub const fn size_of_uninitialized() -> usize {
        4 // see test_state_size_of_uninitialized
    }

    /// Size of a buffer account's serialized metadata.
    pub const fn size_of_buffer_metadata() -> usize {
        37 // see test_state_size_of_buffer_metadata
    }

    /// Size of a programdata account's serialized metadata.
    pub const fn size_of_programdata_metadata() -> usize {
        45 // see test_state_size_of_programdata_metadata
    }

    /// Size of a serialized program account.
    pub const fn size_of_program() -> usize {
        36 // see test_state_size_of_program
    }

    /// Size of a serialized buffer account.
    pub const fn size_of_buffer(program_len: usize) -> usize {
        Self::size_of_buffer_metadata().saturating_add(program_len)
    }

    /// Size of a serialized programdata account.
    pub const fn size_of_programdata(program_len: usize) -> usize {
        Self::size_of_programdata_metadata().saturating_add(program_len)
    }

    /// Deserialize from raw bytes (no Borsh, no bincode)
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let discriminator = u8::from_le_bytes([data[0]]);
        match discriminator {
            0 => Some(UpgradeableLoaderState::Uninitialized),
            1 => {
                // Buffer { authority_address: Option<Pubkey> }
                if data.len() < 1 + 1 + 32 {
                    return None;
                }
                let has_auth = data[1];
                let authority_address = if has_auth == 0 {
                    None
                } else {
                    let mut pubkey_bytes = [0u8; 32];
                    pubkey_bytes.copy_from_slice(&data[2..34]);
                    Some(pubkey_bytes)
                };
                Some(UpgradeableLoaderState::Buffer { authority_address })
            }
            2 => {
                // Program { programdata_address: Pubkey }
                if data.len() < 1 + 32 {
                    return None;
                }
                let mut pubkey_bytes = [0u8; 32];
                pubkey_bytes.copy_from_slice(&data[1..33]);
                Some(UpgradeableLoaderState::Program {
                    programdata_address: pubkey_bytes,
                })
            }
            3 => {
                // ProgramData { slot: u64, upgrade_authority_address: Option<Pubkey> }
                if data.len() < 1 + 8 + 1 + 32 {
                    return None;
                }
                let slot = u64::from_le_bytes(
                    data[2..10].try_into().expect("slice with incorrect length"),
                );
                let has_auth = data[11];
                let upgrade_authority_address = if has_auth == 0 {
                    None
                } else {
                    let mut pubkey_bytes = [0u8; 32];
                    pubkey_bytes.copy_from_slice(&data[12..44]);
                    Some(pubkey_bytes.into())
                };
                Some(UpgradeableLoaderState::ProgramData {
                    slot,
                    upgrade_authority_address,
                })
            }
            _ => None,
        }
    }
}

/// SetUpgradeAuthority
///
/// ### Accounts:
///   0. `[writable]` The Buffer or ProgramData account to change the
///      authority of.
///   1. `[signer]` The current authority.
///   2. `[]` The new authority, optional, if omitted then the program will
///      not be upgradeable.
///
pub struct SetUpgradeAuthority<'a> {
    /// program_data Account.
    pub program_data: &'a AccountInfo,
    /// current authority account
    pub current_authority: &'a AccountInfo,
    /// The new authority
    pub new_upgrade_authority: &'a AccountInfo,
}

impl SetUpgradeAuthority<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // account metadata
        let account_metas = [
            AccountMeta::writable(self.program_data.key()),
            AccountMeta::readonly_signer(self.current_authority.key()),
            AccountMeta::readonly(self.new_upgrade_authority.key()),
        ];

        // Instruction data layout:
        // -  [0]: instruction discriminator (4 byte, u8)
        let mut instruction_data = [UNINIT_BYTE; 4];

        // Set discriminator as u8 at offset [0]
        write_bytes(&mut instruction_data, &[4]);

        let instruction = Instruction {
            program_id: &BPF_LOADER_UPGRADEABLE_PUBKEY,
            accounts: &account_metas,
            data: unsafe { from_raw_parts(instruction_data.as_ptr() as _, 4) },
        };

        invoke_signed(
            &instruction,
            &[
                self.program_data,
                self.current_authority,
                self.new_upgrade_authority,
            ],
            signers,
        )
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UpgradeableLoaderInstruction {
    /// Initialize a Buffer account.
    ///
    /// A Buffer account is an intermediary that once fully populated is used
    /// with the `DeployWithMaxDataLen` instruction to populate the program's
    /// ProgramData account.
    ///
    /// The `InitializeBuffer` instruction requires no signers and MUST be
    /// included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party may initialize the account.
    ///
    /// # Account references
    ///   0. `[writable]` source account to initialize.
    ///   1. `[]` Buffer authority, optional, if omitted then the buffer will be
    ///      immutable.
    InitializeBuffer,

    /// Write program data into a Buffer account.
    ///
    /// # Account references
    ///   0. `[writable]` Buffer account to write program data to.
    ///   1. `[signer]` Buffer authority
    Write {
        /// Offset at which to write the given bytes.
        offset: u32,
        /// Serialized program data
        bytes: Vec<u8>,
    },

    /// Deploy an executable program.
    ///
    /// A program consists of a Program and ProgramData account pair.
    ///   - The Program account's address will serve as the program id for any
    ///     instructions that execute this program.
    ///   - The ProgramData account will remain mutable by the loader only and
    ///     holds the program data and authority information.  The ProgramData
    ///     account's address is derived from the Program account's address and
    ///     created by the DeployWithMaxDataLen instruction.
    ///
    /// The ProgramData address is derived from the Program account's address as
    /// follows:
    ///
    /// ```
    /// # use solana_program::pubkey::Pubkey;
    /// # use solana_program::bpf_loader_upgradeable;
    /// # let program_address = &[];
    /// let (program_data_address, _) = Pubkey::find_program_address(
    ///      &[program_address],
    ///      &bpf_loader_upgradeable::id()
    ///  );
    /// ```
    ///
    /// The `DeployWithMaxDataLen` instruction does not require the ProgramData
    /// account be a signer and therefore MUST be included within the same
    /// Transaction as the system program's `CreateAccount` instruction that
    /// creates the Program account. Otherwise another party may initialize the
    /// account.
    ///
    /// # Account references
    ///   0. `[signer]` The payer account that will pay to create the ProgramData
    ///      account.
    ///   1. `[writable]` The uninitialized ProgramData account.
    ///   2. `[writable]` The uninitialized Program account.
    ///   3. `[writable]` The Buffer account where the program data has been
    ///      written.  The buffer account's authority must match the program's
    ///      authority
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[]` System program (`solana_sdk::system_program::id()`).
    ///   7. `[signer]` The program's authority
    DeployWithMaxDataLen {
        /// Maximum length that the program can be upgraded to.
        max_data_len: usize,
    },

    /// Upgrade a program.
    ///
    /// A program can be updated as long as the program's authority has not been
    /// set to `None`.
    ///
    /// The Buffer account must contain sufficient lamports to fund the
    /// ProgramData account to be rent-exempt, any additional lamports left over
    /// will be transferred to the spill account, leaving the Buffer account
    /// balance at zero.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The Program account.
    ///   2. `[writable]` The Buffer account where the program data has been
    ///      written.  The buffer account's authority must match the program's
    ///      authority
    ///   3. `[writable]` The spill account.
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[signer]` The program's authority.
    Upgrade,

    /// Set a new authority that is allowed to write the buffer or upgrade the
    /// program.  To permanently make the buffer immutable or disable program
    /// updates omit the new authority.
    ///
    /// # Account references
    ///   0. `[writable]` The Buffer or ProgramData account to change the
    ///      authority of.
    ///   1. `[signer]` The current authority.
    ///   2. `[]` The new authority, optional, if omitted then the program will
    ///      not be upgradeable.
    SetAuthority,

    /// Closes an account owned by the upgradeable loader of all lamports and
    /// withdraws all the lamports
    ///
    /// # Account references
    ///   0. `[writable]` The account to close, if closing a program must be the
    ///      ProgramData account.
    ///   1. `[writable]` The account to deposit the closed account's lamports.
    ///   2. `[signer]` The account's authority, Optional, required for
    ///      initialized accounts.
    ///   3. `[writable]` The associated Program account if the account to close
    ///      is a ProgramData account.
    Close,

    /// Extend a program's ProgramData account by the specified number of bytes.
    /// Only upgradeable program's can be extended.
    ///
    /// The payer account must contain sufficient lamports to fund the
    /// ProgramData account to be rent-exempt. If the ProgramData account
    /// balance is already sufficient to cover the rent exemption cost
    /// for the extended bytes, the payer account is not required.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The ProgramData account's associated Program account.
    ///   2. `[]` System program (`solana_sdk::system_program::id()`), optional, used to transfer
    ///      lamports from the payer to the ProgramData account.
    ///   3. `[signer]` The payer account, optional, that will pay necessary rent exemption costs
    ///      for the increased storage size.
    ExtendProgram {
        /// Number of bytes to extend the program data.
        additional_bytes: u32,
    },

    /// Set a new authority that is allowed to write the buffer or upgrade the
    /// program.
    ///
    /// This instruction differs from SetAuthority in that the new authority is a
    /// required signer.
    ///
    /// # Account references
    ///   0. `[writable]` The Buffer or ProgramData account to change the
    ///      authority of.
    ///   1. `[signer]` The current authority.
    ///   2. `[signer]` The new authority.
    SetAuthorityChecked,
}

impl TryFrom<u8> for UpgradeableLoaderInstruction {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UpgradeableLoaderInstruction::InitializeBuffer),
            3 => Ok(UpgradeableLoaderInstruction::Upgrade),
            4 => Ok(UpgradeableLoaderInstruction::SetAuthority),
            6 => Ok(UpgradeableLoaderInstruction::Close),
            8 => Ok(UpgradeableLoaderInstruction::SetAuthorityChecked),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

//! ProposalTransaction Account

use {
    crate::{
        error::GovernanceError,
        state::{
            enums::{GovernanceAccountType, TransactionExecutionStatus},
            legacy::ProposalInstructionV1,
        },
        PROGRAM_AUTHORITY_SEED,
    },
    core::panic,
    p_spl_governance_tools::account::{
        get_account_data_borrowed, get_account_type, to_bytes, AccountMaxSize, DataLen,
        IsInitialized,
    },
    pinocchio::{
        account_info::AccountInfo,
        instruction::Instruction,
        memory::sol_memcpy,
        program_error::ProgramError,
        pubkey::{find_program_address, Pubkey},
        sysvars::clock::UnixTimestamp,
    }, pinocchio_utils_macro::PStruct,
};

/// InstructionData wrapper. It can be removed once Borsh serialization for
/// Instruction is supported in the SDK
#[derive(Clone, Debug, PartialEq, Eq, PStruct)]
pub struct InstructionData {
    /// Pubkey of the instruction processor that executes this instruction
    pub program_id: Pubkey,
    /// Metadata for what accounts should be passed to the instruction processor
    pub accounts: Vec<AccountMetaData>,
    /// Opaque data passed to the instruction processor
    pub data: Vec<u8>,
}

impl InstructionData {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let program_id: Pubkey = bytes[0..32]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let accounts_len = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) as usize;
        let mut offset = 36;
        let mut accounts = Vec::with_capacity(accounts_len);

        for _ in 0..accounts_len {
            let pubkey: Pubkey = bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let is_signer = bytes[offset + 32] != 0;
            let is_writable = bytes[offset + 33] != 0;
            accounts.push(AccountMetaData {
                pubkey,
                is_signer,
                is_writable,
            });
            offset += 34;
        }

        let instruction_data = bytes[offset..].to_vec();

        Ok(InstructionData {
            program_id,
            accounts,
            data: instruction_data,
        })
    }
    pub fn from_bytes_partial(bytes: &[u8]) -> Result<(Self, &[u8]), ProgramError> {
        let program_id: Pubkey = bytes[0..32].try_into().map_err(|_| ProgramError::InvalidInstructionData)?;

        let accounts_len = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) as usize;
        let mut offset = 36;

        // Parse accounts
        let mut accounts = Vec::with_capacity(accounts_len);
        for _ in 0..accounts_len {
            if bytes.len() < offset + 34 {
                return Err(ProgramError::InvalidInstructionData.into());
            }
            let pubkey: Pubkey = bytes[offset..offset + 32].try_into().map_err(|_| ProgramError::InvalidInstructionData)?;
            let is_signer = bytes[offset + 32] != 0;
            let is_writable = bytes[offset + 33] != 0;
            accounts.push(AccountMetaData {
                pubkey,
                is_signer,
                is_writable,
            });
            offset += 34;
        }

        // The rest is instruction data
        let data = bytes[offset..].to_vec();
        let data_len = data.len();
        // Return the parsed struct and the remaining bytes (if any)
        Ok((
            InstructionData {
                program_id,
                accounts,
                data,
            },
            &bytes[offset + data_len..],
        ))
    }
    pub fn vec_from_bytes(mut bytes: &[u8]) -> Result<Vec<Self>, ProgramError> {
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        bytes = &bytes[4..];
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            // You must implement from_bytes for InstructionData
            let (item, rest) = Self::from_bytes_partial(bytes)?;
            result.push(item);
            bytes = rest;
        }
        Ok(result)
    }
}

/// Account metadata used to define Instructions
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct AccountMetaData {
    /// An account's public key
    pub pubkey: Pubkey,
    /// True if an Instruction requires a Transaction signature matching
    /// `pubkey`.
    pub is_signer: bool,
    /// True if the `pubkey` can be loaded as a read-write account.
    pub is_writable: bool,
}

impl DataLen for AccountMetaData {
    const LEN: usize = core::mem::size_of::<AccountMetaData>();
}
impl From<Instruction<'_, '_, '_, '_>> for InstructionData {
    fn from(instruction: Instruction) -> Self {
        InstructionData {
            program_id: *instruction.program_id,
            accounts: instruction
                .accounts
                .iter()
                .map(|a| AccountMetaData {
                    pubkey: *a.pubkey,
                    is_signer: a.is_signer,
                    is_writable: a.is_writable,
                })
                .collect::<Vec<_>>(),
            data: instruction.data.to_vec(),
        }
    }
}

/// Account for an instruction to be executed for Proposal
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalTransactionV2 {
    /// Governance Account type
    pub account_type: GovernanceAccountType,

    /// The Proposal the instruction belongs to
    pub proposal: Pubkey,

    /// The option index the instruction belongs to
    pub option_index: u8,

    /// Unique transaction index within it's parent Proposal
    pub transaction_index: u16,

    /// Minimum waiting time in seconds for the  instruction to be executed once
    /// proposal is voted on
    pub hold_up_time: u32,

    /// Instructions to execute
    /// The instructions will be signed by Governance PDA the Proposal belongs
    /// to
    // For example for ProgramGovernance the instruction to upgrade program will be signed by
    // ProgramGovernance PDA All instructions will be executed within a single transaction
    pub instructions: Vec<InstructionData>,

    /// Executed at flag
    pub executed_at: Option<UnixTimestamp>,

    /// Instruction execution status
    pub execution_status: TransactionExecutionStatus,

    /// Reserved space for versions v2 and onwards
    /// Note: V1 accounts must be resized before using this space
    pub reserved_v2: [u8; 8],
}

impl AccountMaxSize for ProposalTransactionV2 {
    fn get_max_size(&self) -> Option<usize> {
        let instructions_size = self
            .instructions
            .iter()
            .map(|i| i.accounts.len() * 34 + i.data.len() + 40)
            .sum::<usize>();

        Some(instructions_size + 62)
    }
}

impl IsInitialized for ProposalTransactionV2 {
    fn is_initialized(&self) -> bool {
        self.account_type == GovernanceAccountType::ProposalTransactionV2
    }
}

impl DataLen for ProposalTransactionV2 {
    const LEN: usize = core::mem::size_of::<ProposalTransactionV2>();
}

impl ProposalTransactionV2 {
    /// Serializes account into the target buffer
    pub fn serialize(self, data: &mut [u8]) -> Result<(), ProgramError> {
        if self.account_type == GovernanceAccountType::ProposalTransactionV2 {
            unsafe {
                sol_memcpy(data, to_bytes::<Self>(&self), self.get_max_size().unwrap());
            }
        } else if self.account_type == GovernanceAccountType::ProposalInstructionV1 {
            if self.instructions.len() != 1 {
                panic!("Multiple instructions are not supported by ProposalInstructionV1")
            };

            // V1 account can't be resized and we have to translate it back to the original
            // format

            // If reserved_v2 is used it must be individually asses for v1 backward
            // compatibility impact
            if self.reserved_v2 != [0; 8] {
                panic!("Extended data not supported by ProposalInstructionV1")
            }

            let proposal_transaction_data_v1 = ProposalInstructionV1 {
                account_type: self.account_type,
                proposal: self.proposal,
                instruction_index: self.transaction_index,
                hold_up_time: self.hold_up_time,
                instruction: self.instructions[0].clone(),
                executed_at: self.executed_at,
                execution_status: self.execution_status,
            };

            unsafe {
                sol_memcpy(
                    data,
                    to_bytes::<ProposalInstructionV1>(&proposal_transaction_data_v1),
                    self.get_max_size().unwrap(),
                );
            }
        }

        Ok(())
    }
}

/// Returns ProposalTransaction PDA seeds
pub fn get_proposal_transaction_address_seeds<'a>(
    proposal: &'a Pubkey,
    option_index: &'a [u8; 1],               // u8 le bytes
    instruction_index_le_bytes: &'a [u8; 2], // u16 le bytes
) -> [&'a [u8]; 4] {
    [
        PROGRAM_AUTHORITY_SEED,
        proposal.as_ref(),
        option_index,
        instruction_index_le_bytes,
    ]
}

/// Returns ProposalTransaction PDA address
pub fn get_proposal_transaction_address<'a>(
    program_id: &Pubkey,
    proposal: &'a Pubkey,
    option_index_le_bytes: &'a [u8; 1],      // u8 le bytes
    instruction_index_le_bytes: &'a [u8; 2], // u16 le bytes
) -> Pubkey {
    find_program_address(
        &get_proposal_transaction_address_seeds(
            proposal,
            option_index_le_bytes,
            instruction_index_le_bytes,
        ),
        program_id,
    )
    .0
}

/// Deserializes ProposalTransaction account and checks owner program
pub fn get_proposal_transaction_data(
    program_id: &Pubkey,
    proposal_transaction_info: &AccountInfo,
) -> Result<ProposalTransactionV2, ProgramError> {
    let account_type: GovernanceAccountType =
        get_account_type(program_id, proposal_transaction_info)?;

    // If the account is V1 version then translate to V2
    if account_type == GovernanceAccountType::ProposalInstructionV1 {
        let proposal_transaction_data_v1 = get_account_data_borrowed::<ProposalInstructionV1>(
            program_id,
            proposal_transaction_info,
        )?;

        return Ok(ProposalTransactionV2 {
            account_type,
            proposal: proposal_transaction_data_v1.proposal,
            option_index: 0, // V1 has a single implied option at index 0
            transaction_index: proposal_transaction_data_v1.instruction_index,
            hold_up_time: proposal_transaction_data_v1.hold_up_time,
            instructions: vec![proposal_transaction_data_v1.instruction.clone()],
            executed_at: proposal_transaction_data_v1.executed_at,
            execution_status: proposal_transaction_data_v1.execution_status,
            reserved_v2: [0; 8],
        });
    }

    get_account_data_borrowed::<ProposalTransactionV2>(program_id, proposal_transaction_info)
        .cloned()
}

///  Deserializes and returns ProposalTransaction account and checks it belongs
/// to the given Proposal
pub fn get_proposal_transaction_data_for_proposal(
    program_id: &Pubkey,
    proposal_transaction_info: &AccountInfo,
    proposal: &Pubkey,
) -> Result<ProposalTransactionV2, ProgramError> {
    let proposal_transaction_data =
        get_proposal_transaction_data(program_id, proposal_transaction_info)?;

    if proposal_transaction_data.proposal != *proposal {
        return Err(GovernanceError::InvalidProposalForProposalTransaction.into());
    }

    Ok(proposal_transaction_data)
}

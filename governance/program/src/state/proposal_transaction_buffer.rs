//! ProposalTransactionBuffer Account

use {
    crate::error::GovernanceError,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{hash::hashv, program_error::ProgramError, pubkey::Pubkey},
};

/// Maximum PDA allocation size in an inner ix is 10240 bytes.
/// 10240 - account contents = 10128 bytes
pub const MAX_BUFFER_SIZE: usize = 10128;

/// One of onchain buffer that consumes buffers and transforms them into Versioned Transactions
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct ProposalTransactionBuffer {
    /// The Proposal the transaction buffer belongs to
    pub proposal: Pubkey,
    /// Member of the Multisig who created the TransactionBuffer.
    pub creator: Pubkey,
    /// Index to seed address derivation
    pub buffer_index: u8,
    /// Hash of the final assembled transaction message.
    pub final_buffer_hash: [u8; 32],
    /// The size of the final assembled transaction message.
    pub final_buffer_size: u16,
    /// The buffer of the transaction message.
    pub buffer: Vec<u8>,
}

impl ProposalTransactionBuffer {
    /// Size of onchain transaction buffer
    pub fn size(final_message_buffer_size: u16) -> Result<usize, ProgramError> {
        // Make sure final size is not greater than MAX_BUFFER_SIZE bytes.
        if (final_message_buffer_size as usize) > MAX_BUFFER_SIZE {
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }
        Ok(
            1 +   // anchor account discriminator
            32 +  // proposal
            32 +  // creator
            1 +   // buffer_index
            32 +  // transaction_message_hash
            2 +  // final_buffer_size
            4 + // vec length bytes
            final_message_buffer_size as usize, // buffer
        )
    }

    /// validate the final buffer has of the transaction buffer
    pub fn validate_hash(&self) -> Result<(), ProgramError> {
        let message_buffer_hash = hashv(&[self.buffer.as_slice()]);
        if message_buffer_hash.to_bytes() == self.final_buffer_hash {
            return Err(GovernanceError::FinalBufferHashMismatch.into());
        }
        Ok(())
    }

    /// validate the size of buffer of the transaction buffer
    pub fn validate_size(&self) -> Result<(), ProgramError> {
        if self.buffer.len() == self.final_buffer_size as usize {
            return Err(GovernanceError::FinalBufferSizeMismatch.into());
        }
        Ok(())
    }

    /// Check to make validate the size of buffer of the transaction buffer
    pub fn invariant(&self) -> Result<(), ProgramError> {
        if self.final_buffer_size as usize <= MAX_BUFFER_SIZE {
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }
        if self.buffer.len() <= MAX_BUFFER_SIZE {
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }
        if self.buffer.len() <= self.final_buffer_size as usize {
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }

        Ok(())
    }
}

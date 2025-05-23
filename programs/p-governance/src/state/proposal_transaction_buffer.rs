//! ProposalTransactionBuffer Account

use {
    super::enums::GovernanceAccountType,
    crate::error::GovernanceError,
    p_spl_governance_tools::account::{
        to_bytes_with_len, AccountMaxSize, IsInitialized
    },
    pinocchio::{
        account_info::{AccountInfo, Ref},
        memory::sol_memcpy,
        program_error::ProgramError,
        pubkey::{find_program_address, Pubkey},
    },
    pinocchio_log::log,
    solana_sha256_hasher::hashv,
};

/// Maximum PDA allocation size in an inner ix is 10240 bytes.
/// 10240 - account contents = 10032 bytes
pub const MAX_BUFFER_SIZE: usize = 10032;

/// One of onchain buffer that consumes buffers and transforms them into
/// Versioned Transactions This account will be closed once it gets transformed
/// into ProposalVersionedTransaction
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalTransactionBuffer {
    /// Governance Account type
    pub account_type: GovernanceAccountType,
    /// The Proposal the transaction buffer belongs to
    pub proposal: Pubkey,
    /// Member of the Goverenance who created the TransactionBuffer.
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

impl AccountMaxSize for ProposalTransactionBuffer {
    fn get_max_size(&self) -> Option<usize> {
        Some(
            1 +   // account discriminator
            1 +   // account type
            32 +  // proposal
            32 +  // creator
            1 +   // buffer_index
            32 +  // transaction_message_hash
            2 +  // final_buffer_size
            4 + // vec length bytes
            self.final_buffer_size as usize, // buffer
        )
    }
}

impl IsInitialized for ProposalTransactionBuffer {
    fn is_initialized(&self) -> bool {
        self.account_type == GovernanceAccountType::ProposalTransactionBuffer
    }
}

impl ProposalTransactionBuffer {
    /// Size of onchain transaction buffer
    pub fn size(final_message_buffer_size: u16) -> Result<usize, ProgramError> {
        // Make sure final size is not greater than MAX_BUFFER_SIZE bytes.
        if (final_message_buffer_size as usize) > MAX_BUFFER_SIZE {
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }
        Ok(
            1 +   // account discriminator
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
        if message_buffer_hash.to_bytes() != self.final_buffer_hash {
            return Err(GovernanceError::FinalBufferHashMismatch.into());
        }
        Ok(())
    }

    /// validate the size of buffer of the transaction buffer
    pub fn validate_size(&self) -> Result<(), ProgramError> {
        if self.buffer.len() != self.final_buffer_size as usize {
            return Err(GovernanceError::FinalBufferSizeMismatch.into());
        }
        Ok(())
    }

    /// Check to make validate the size of buffer of the transaction buffer
    pub fn invariant(&self) -> Result<(), ProgramError> {
        if self.final_buffer_size as usize > MAX_BUFFER_SIZE {
            log!("Current final buffer size: {}", self.final_buffer_size);
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }
        if self.buffer.len() > MAX_BUFFER_SIZE {
            log!("Current buffer size: {}", self.buffer.len());
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }
        if self.buffer.len() > self.final_buffer_size as usize {
            log!(
                "Current buffer size: {}, is larger than final buffer size: {}",
                self.buffer.len(),
                self.final_buffer_size
            );
            return Err(GovernanceError::FinalBufferSizeExceeded.into());
        }

        Ok(())
    }

    pub fn serialize_to_account(self, target_account: AccountInfo) -> Result<(), ProgramError> {
        let data = unsafe { target_account.borrow_mut_data_unchecked() };

        unsafe {
            sol_memcpy(data, to_bytes_with_len::<Self>(&self, self.get_max_size().unwrap()), self.get_max_size().unwrap());
        }
        Ok(())
    }

    /// Returns a `ProposalTransactionBuffer` from account info.
    ///
    /// This method will perform the following validations on the account info:
    ///  1. Owner check: it must match the program.
    ///  2. Account discriminator: it must match [`GovernanceAccountType::ProposalTransactionBuffer`].
    ///  3. Borrow data: it must be allowed to borrow the account data.
    #[inline]
    pub fn from_account_info<'a>(account_info: &'a AccountInfo, program_id: &'a Pubkey) -> Result<Ref<'a, Self>, ProgramError> {
        if !account_info.is_owned_by(program_id) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let data = account_info.try_borrow_data()?;
        if data[0] != GovernanceAccountType::ProposalTransactionBuffer as u8 {
            return Err(ProgramError::InvalidAccountData);
        }
        // SAFETY: `data` was validated to have the correct owner and discriminator.
        Ok(Ref::map(data, |data| unsafe {
            Self::from_bytes_unchecked(data)
        }))
    }

    /// Returns a `ProposalTransactionBuffer` from account info.
    ///
    /// This method will perform the following validations on the account info:
    ///  1. Owner check: it must match the program.
    ///  2. Account discriminator: it must match [`GovernanceAccountType::ProposalTransactionBuffer`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that it is safe to borrow the account data, e.g., there are
    /// no mutable borrows of the account data.
    #[inline]
    pub unsafe fn from_account_info_unchecked<'a>(
        account_info: &'a AccountInfo,
        program_id: &'a Pubkey,
    ) -> Result<&'a Self, ProgramError> {
        if account_info.owner() != program_id {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let data = account_info.borrow_data_unchecked();
        if data[0] != GovernanceAccountType::ProposalTransactionBuffer as u8 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self::from_bytes_unchecked(data))
    }

    /// Return a `ProposalTransactionBuffer` from the given bytes.
    ///
    /// This method validates that `bytes` has at least the minimum required
    /// length.
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, ProgramError> {
        // SAFETY: `bytes` was validated to have the expected length
        // to hold a `ProposalTransactionBuffer` reference.
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Return a `ProposalTransactionBuffer` from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `ProposalTransactionBuffer`.
    #[inline(always)]
    pub unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        &*(bytes.as_ptr() as *const Self)
    }

    /// Return a mutable `ProposalTransactionBuffer` from the given bytes.
    ///
    /// This method validates that `bytes` has at least the minimum required
    /// length.
    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        // SAFETY: `bytes` was validated to have the expected length
        // to hold a `ProposalTransactionBuffer` reference.
        Ok(unsafe { Self::from_bytes_mut_unchecked(bytes) })
    }

    /// Return a mutable `ProposalTransactionBuffer` from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `ProposalTransactionBuffer`.
    #[inline(always)]
    pub(crate) unsafe fn from_bytes_mut_unchecked(bytes: &mut [u8]) -> &mut Self {
        &mut *(bytes.as_mut_ptr() as *mut Self)
    }
}

/// Seed prefix for ProposalTransactionBuffer PDAs
pub const TRANSACTION_BUFFER_SEED: &[u8] = b"transaction_buffer";

/// Returns ProposalTransactionBuffer PDA seeds
pub fn get_proposal_transaction_buffer_address_seeds<'a>(
    proposal: &'a Pubkey,
    creator: &'a Pubkey,
    buffer_index: &'a [u8; 1], // u8 le bytes
) -> [&'a [u8]; 4] {
    [
        TRANSACTION_BUFFER_SEED,
        proposal.as_ref(),
        creator.as_ref(),
        buffer_index,
    ]
}

/// Returns ProposalTransactionBuffer PDA address
pub fn get_proposal_transaction_buffer_address<'a>(
    program_id: &Pubkey,
    proposal: &'a Pubkey,
    creator: &'a Pubkey,
    buffer_index: &'a [u8; 1], // u8 le bytes
) -> Pubkey {
    find_program_address(
        &get_proposal_transaction_buffer_address_seeds(proposal, creator, buffer_index),
        program_id,
    )
    .0
}

/// Deserializes ProposalTransactionBuffer account and checks owner program
pub fn get_proposal_transaction_buffer_data(
    program_id: &Pubkey,
    proposal_transaction_buffer_info: &AccountInfo,
) -> Result<ProposalTransactionBuffer, ProgramError> {
    let proposal_transaction_buffer_data = ProposalTransactionBuffer::from_account_info(
        proposal_transaction_buffer_info,
        program_id,
    )?;

    if proposal_transaction_buffer_data.account_type
        != GovernanceAccountType::ProposalTransactionBuffer
    {
        log!("Invalid proposal transaction buffer account type");
        return Err(GovernanceError::InvalidGovernanceForProposal.into());
    }
    Ok(proposal_transaction_buffer_data.clone())
}

/// Deserializes ProposalTransactionBuffer and validates it belongs to the given
/// Governance
pub fn get_proposal_transaction_buffer_data_for_proposal(
    program_id: &Pubkey,
    proposal_transaction_buffer_info: &AccountInfo,
    proposal: &Pubkey,
) -> Result<ProposalTransactionBuffer, ProgramError> {
    let proposal_transaction_buffer_data =
        get_proposal_transaction_buffer_data(program_id, proposal_transaction_buffer_info)?;

    if proposal_transaction_buffer_data.proposal != *proposal {
        log!("Mismatch of proposal for proposal transaction buffer");
        return Err(GovernanceError::InvalidGovernanceForProposal.into());
    }

    Ok(proposal_transaction_buffer_data)
}

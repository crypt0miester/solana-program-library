//! Proposal Vote Record Account

use {
    crate::{
        error::GovernanceError,
        state::{
            enums::GovernanceAccountType,
            legacy::{VoteRecordV1, VoteWeightV1},
            proposal::ProposalV2,
            realm::RealmV2,
            token_owner_record::TokenOwnerRecordV2,
            IsEnum
        },
        PROGRAM_AUTHORITY_SEED,
    },
    p_spl_governance_tools::account::{
        get_account_data, get_account_type, to_bytes, AccountMaxSize, DataLen, IsInitialized,
    },
    pinocchio::{
        account_info::{AccountInfo, Ref},
        memory::sol_memcpy,
        program_error::ProgramError,
        pubkey::{find_program_address, Pubkey},
    },
    pinocchio_utils_macro::{IsEnum, PStruct},
};

/// Voter choice for a proposal option
/// In the current version only 1) Single choice, 2) Multiple choices proposals
/// and 3) Weighted voting are supported.
/// In the future versions we can add support for 1) Quadratic voting and
/// 2) Ranked choice voting
#[derive(Clone, Debug, PartialEq, Eq, PStruct)]
pub struct VoteChoice {
    /// The rank given to the choice by voter
    /// Note: The field is not used in the current version
    pub rank: u8,

    /// The voter's weight percentage given by the voter to the choice
    pub weight_percentage: u8,
}

impl VoteChoice {
    /// Returns the choice weight given the voter's weight
    pub fn get_choice_weight(&self, voter_weight: u64) -> Result<u64, ProgramError> {
        Ok(match self.weight_percentage {
            // Avoid any rounding errors for full weight
            100 => voter_weight,
            // Note: The total weight for all choices might not equal voter_weight due to rounding
            // errors
            0..=99 => (voter_weight as u128)
                .checked_mul(self.weight_percentage as u128)
                .unwrap()
                .checked_div(100)
                .unwrap() as u64,
            _ => return Err(GovernanceError::InvalidVoteChoiceWeightPercentage.into()),
        })
    }
}

/// User's vote
#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(IsEnum)]
pub enum Vote {
    /// Vote approving choices
    Approve(Vec<VoteChoice>),

    /// Vote rejecting proposal
    Deny,

    /// Declare indifference to proposal
    /// Note: Not supported in the current version
    Abstain,

    /// Veto proposal
    Veto,
}

impl TryFrom<&[u8]> for Vote {
    type Error = ProgramError;
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let discriminator = input[0];
        let bytes = &input[1..];
        match discriminator {
            0 => {
                // Approve(Vec<VoteChoice>)
                if bytes.len() < 4 {
                    return Err(ProgramError::InvalidInstructionData.into());
                }
                let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                let mut bytes_data = &bytes[4..];
                let mut choices = Vec::with_capacity(len);
                for _ in 0..len {
                    let rank = bytes_data[0];
                    let weight_percentage = bytes_data[1];
                    choices.push(VoteChoice {
                        rank,
                        weight_percentage,
                    });
                    bytes_data = &bytes_data[2..];
                }
                Ok(Vote::Approve(choices))
            }
            1 => Ok(Vote::Deny),
            2 => Ok(Vote::Abstain),
            3 => Ok(Vote::Veto),
            _ => Err(ProgramError::InvalidInstructionData.into()),
        }
    }
}

// impl Vote {
//     pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, ProgramError> {
//         if bytes.is_empty() {
//             return Err(ProgramError::InvalidInstructionData.into());
//         }
//         let discriminator = bytes[0];
//         bytes = &bytes[1..];
//         match discriminator {
//             0 => { // Approve(Vec<VoteChoice>)
//                 if bytes.len() < 4 {
//                     return Err(ProgramError::InvalidInstructionData.into());
//                 }
//                 let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
//                 bytes = &bytes[4..];
//                 let mut choices = Vec::with_capacity(len);
//                 for _ in 0..len {
//                     let rank = bytes[0];
//                     let weight_percentage = bytes[1];
//                     choices.push(VoteChoice { rank, weight_percentage });
//                     bytes = &bytes[2..];
//                 }
//                 Ok(Vote::Approve(choices))
//             }
//             1 => Ok(Vote::Deny),
//             2 => Ok(Vote::Abstain),
//             3 => Ok(Vote::Veto),
//             _ => Err(ProgramError::InvalidInstructionData.into())
//         }
//     }
// }

/// VoteKind defines the type of the vote being cast
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoteKind {
    /// Electorate vote is cast by the voting population identified by
    /// governing_token_mint Approve, Deny and Abstain votes are Electorate
    /// votes
    Electorate,

    /// Vote cast by the opposite voting population to the Electorate identified
    /// by governing_token_mint
    Veto,
}

/// Returns the VoteKind for the given Vote
pub fn get_vote_kind(vote: &Vote) -> VoteKind {
    match vote {
        Vote::Approve(_) | Vote::Deny | Vote::Abstain => VoteKind::Electorate,
        Vote::Veto => VoteKind::Veto,
    }
}

/// Proposal VoteRecord
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteRecordV2 {
    /// Governance account type
    pub account_type: GovernanceAccountType,

    /// Proposal account
    pub proposal: Pubkey,

    /// The user who casted this vote
    /// This is the Governing Token Owner who deposited governing tokens into
    /// the Realm
    pub governing_token_owner: Pubkey,

    /// Indicates whether the vote was relinquished by voter
    pub is_relinquished: bool,

    /// The weight of the user casting the vote
    pub voter_weight: u64,

    /// Voter's vote
    pub vote: Vote,

    /// Reserved space for versions v2 and onwards
    /// Note: V1 accounts must be resized before using this space
    pub reserved_v2: [u8; 8],
}

impl AccountMaxSize for VoteRecordV2 {}

impl IsInitialized for VoteRecordV2 {
    fn is_initialized(&self) -> bool {
        self.account_type == GovernanceAccountType::VoteRecordV2
    }
}

impl DataLen for VoteRecordV2 {
    const LEN: usize = core::mem::size_of::<VoteRecordV2>();
}

impl VoteRecordV2 {
    pub fn len(&self) -> usize {
        let mut size = 1 + // account_type
                      32 + // proposal
                      32 + // governing_token_owner
                      1 +  // is_relinquished
                      8 +  // voter_weight
                      1 +  // vote enum discriminator
                      8; // reserved_v2

        // Add size for the Vote variant data
        size += match &self.vote {
            Vote::Approve(choices) => {
                4 + // Vec length
                choices.len() * VoteChoice::LEN // Each VoteChoice
            }
            Vote::Deny | Vote::Abstain | Vote::Veto => 1,
        };

        size
    }

    /// Checks the vote can be relinquished
    pub fn assert_can_relinquish_vote(&self) -> Result<(), ProgramError> {
        if self.is_relinquished {
            return Err(GovernanceError::VoteAlreadyRelinquished.into());
        }

        Ok(())
    }

    /// Serializes account into the target buffer
    pub fn serialize(self, data: &mut [u8]) -> Result<(), ProgramError> {
        if self.account_type == GovernanceAccountType::VoteRecordV2 {
            unsafe {
                sol_memcpy(data, to_bytes::<Self>(&self), self.len());
            }
        } else if self.account_type == GovernanceAccountType::VoteRecordV1 {
            // V1 account can't be resized and we have to translate it back to the original
            // format

            // If reserved_v2 is used it must be individually asses for v1 backward
            // compatibility impact
            if self.reserved_v2 != [0; 8] {
                panic!("Extended data not supported by VoteRecordV1")
            }

            let vote_weight = match &self.vote {
                Vote::Approve(_options) => VoteWeightV1::Yes(self.voter_weight),
                Vote::Deny => VoteWeightV1::No(self.voter_weight),
                Vote::Abstain | Vote::Veto => {
                    panic!("Vote type: {:?} not supported by VoteRecordV1", &self.vote)
                }
            };

            let vote_record_data_v1 = VoteRecordV1 {
                account_type: self.account_type,
                proposal: self.proposal,
                governing_token_owner: self.governing_token_owner,
                is_relinquished: self.is_relinquished,
                vote_weight,
            };

            unsafe {
                sol_memcpy(
                    data,
                    to_bytes::<VoteRecordV1>(&vote_record_data_v1),
                    self.len(),
                );
            }
        }

        Ok(())
    }

    /// Returns a `VoteRecordV2` from account info.
    ///
    /// This method will perform the following validations on the account info:
    ///  1. Owner check: it must match the program.
    ///  2. Account discriminator: it must match [`GovernanceAccountType::VoteRecordV2`].
    ///  3. Borrow data: it must be allowed to borrow the account data.
    #[inline]
    pub fn from_account_info<'a>(
        account_info: &'a AccountInfo,
        program_id: &'a Pubkey,
    ) -> Result<Ref<'a, Self>, ProgramError> {
        if !account_info.is_owned_by(program_id) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let data = account_info.try_borrow_data()?;
        if data[0] != GovernanceAccountType::VoteRecordV2 as u8 {
            return Err(ProgramError::InvalidAccountData);
        }
        // SAFETY: `data` was validated to have the correct owner and discriminator.
        Ok(Ref::map(data, |data| unsafe {
            Self::from_bytes_unchecked(data)
        }))
    }

    /// Returns a `VoteRecordV2` from account info.
    ///
    /// This method will perform the following validations on the account info:
    ///  1. Owner check: it must match the program.
    ///  2. Account discriminator: it must match [`GovernanceAccountType::VoteRecordV2`].
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
        if data[0] != GovernanceAccountType::VoteRecordV2 as u8 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self::from_bytes_unchecked(data))
    }

    /// Return a `VoteRecordV2` from the given bytes.
    ///
    /// This method validates that `bytes` has at least the minimum required
    /// length.
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, ProgramError> {
        // SAFETY: `bytes` was validated to have the expected length
        // to hold a `VoteRecordV2` reference.
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Return a `VoteRecordV2` from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `VoteRecordV2`.
    #[inline(always)]
    pub unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        &*(bytes.as_ptr() as *const Self)
    }

    /// Return a mutable `VoteRecordV2` from the given bytes.
    ///
    /// This method validates that `bytes` has at least the minimum required
    /// length.
    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        // SAFETY: `bytes` was validated to have the expected length
        // to hold a `VoteRecordV2` reference.
        Ok(unsafe { Self::from_bytes_mut_unchecked(bytes) })
    }

    /// Return a mutable `VoteRecordV2` from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `VoteRecordV2`.
    #[inline(always)]
    pub(crate) unsafe fn from_bytes_mut_unchecked(bytes: &mut [u8]) -> &mut Self {
        &mut *(bytes.as_mut_ptr() as *mut Self)
    }
}

/// Deserializes VoteRecord account and checks owner program
pub fn get_vote_record_data(
    program_id: &Pubkey,
    vote_record_info: &AccountInfo,
) -> Result<VoteRecordV2, ProgramError> {
    let account_type: GovernanceAccountType = get_account_type(program_id, vote_record_info)?;

    // If the account is V1 version then translate to V2
    if account_type == GovernanceAccountType::VoteRecordV1 {
        let vote_record_data_v1 = get_account_data::<VoteRecordV1>(program_id, vote_record_info)?;

        let (vote, voter_weight) = match vote_record_data_v1.vote_weight {
            VoteWeightV1::Yes(weight) => (
                Vote::Approve(vec![VoteChoice {
                    rank: 0,
                    weight_percentage: 100,
                }]),
                weight,
            ),
            VoteWeightV1::No(weight) => (Vote::Deny, weight),
        };

        return Ok(VoteRecordV2 {
            account_type,
            proposal: vote_record_data_v1.proposal,
            governing_token_owner: vote_record_data_v1.governing_token_owner,
            is_relinquished: vote_record_data_v1.is_relinquished,
            voter_weight,
            vote,
            reserved_v2: [0; 8],
        });
    }

    let vote_record = VoteRecordV2::from_account_info(vote_record_info, program_id)?;
    Ok(vote_record.clone())
}

/// Deserializes VoteRecord and checks it belongs to the provided Proposal and
/// TokenOwnerRecord
pub fn get_vote_record_data_for_proposal_and_token_owner_record(
    program_id: &Pubkey,
    vote_record_info: &AccountInfo,
    realm_data: &RealmV2,
    proposal: &Pubkey,
    proposal_data: &ProposalV2,
    token_owner_record_data: &TokenOwnerRecordV2,
) -> Result<VoteRecordV2, ProgramError> {
    let vote_record_data = get_vote_record_data(program_id, vote_record_info)?;

    if vote_record_data.proposal != *proposal {
        return Err(GovernanceError::InvalidProposalForVoterRecord.into());
    }

    if vote_record_data.governing_token_owner != token_owner_record_data.governing_token_owner {
        return Err(GovernanceError::InvalidGoverningTokenOwnerForVoteRecord.into());
    }

    // Assert governing_token_mint between Proposal and TokenOwnerRecord match for
    // the deserialized VoteRecord For Approve, Deny and Abstain votes
    // Proposal.governing_token_mint must equal
    // TokenOwnerRecord.governing_token_mint For Veto vote it must be the
    // governing_token_mint of the opposite voting population
    let proposal_governing_token_mint = realm_data.get_proposal_governing_token_mint_for_vote(
        &token_owner_record_data.governing_token_mint,
        &get_vote_kind(&vote_record_data.vote),
    )?;

    if proposal_data.governing_token_mint != proposal_governing_token_mint {
        return Err(GovernanceError::InvalidGoverningMintForProposal.into());
    }

    Ok(vote_record_data)
}

/// Returns VoteRecord PDA seeds
pub fn get_vote_record_address_seeds<'a>(
    proposal: &'a Pubkey,
    token_owner_record: &'a Pubkey,
) -> [&'a [u8]; 3] {
    [
        PROGRAM_AUTHORITY_SEED,
        proposal.as_ref(),
        token_owner_record.as_ref(),
    ]
}

/// Returns VoteRecord PDA address
pub fn get_vote_record_address<'a>(
    program_id: &Pubkey,
    proposal: &'a Pubkey,
    token_owner_record: &'a Pubkey,
) -> Pubkey {
    find_program_address(
        &get_vote_record_address_seeds(proposal, token_owner_record),
        program_id,
    )
    .0
}

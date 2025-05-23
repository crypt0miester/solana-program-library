//! Proposal  Account

use {
    crate::{
        addins::max_voter_weight::{
            assert_is_valid_max_voter_weight,
            get_max_voter_weight_record_data_for_realm_and_governing_token_mint,
        },
        error::GovernanceError,
        state::{
            enums::{
                GovernanceAccountType, InstructionExecutionFlags, MintMaxVoterWeightSource,
                ProposalState, TransactionExecutionStatus, VoteThreshold, VoteTipping,
            },
            IsEnum,
            governance::GovernanceConfig,
            legacy::ProposalV1,
            proposal_transaction::ProposalTransactionV2,
            proposal_versioned_transaction::ProposalVersionedTransaction,
            realm::RealmV2,
            realm_config::RealmConfigAccount,
            vote_record::{Vote, VoteKind},
        },
        tools::{next_account_info, spl_token::get_spl_token_mint_supply},
        PROGRAM_AUTHORITY_SEED,
    }, p_spl_governance_tools::account::{
        get_account_type, to_bytes, to_bytes_with_len, AccountMaxSize, DataLen, IsInitialized
    }, pinocchio::{
        account_info::{AccountInfo, Ref},
        memory::sol_memcpy,
        program_error::ProgramError,
        pubkey::{find_program_address, Pubkey},
        sysvars::clock::{Slot, UnixTimestamp},
    }, 
    pinocchio_utils_macro::{FromEnum, FromU8, IsEnum, PInstruction}, std::{cmp::Ordering, slice::Iter}
};

/// Proposal option vote result
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub enum OptionVoteResult {
    /// Vote on the option is not resolved yet
    None,

    /// Vote on the option is completed and the option passed
    Succeeded,

    /// Vote on the option is completed and the option was defeated
    Defeated,
}

impl TryFrom<&[u8]> for OptionVoteResult {
    type Error = ProgramError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        match input[0] {
            0 => Ok(OptionVoteResult::None),
            1 => Ok(OptionVoteResult::Succeeded),
            2 => Ok(OptionVoteResult::Defeated),
            _ => Err(ProgramError::InvalidArgument),
        }
    }
}
/// Proposal Option
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalOption {
    /// Option label
    pub label: String,

    /// Vote weight for the option
    pub vote_weight: u64,

    /// Vote result for the option
    pub vote_result: OptionVoteResult,

    /// The number of the transactions already executed
    pub transactions_executed_count: u16,

    /// The number of transactions included in the option
    pub transactions_count: u16,

    /// The index of the the next transaction to be added
    pub transactions_next_index: u16,
}

impl DataLen for ProposalOption {
    const LEN: usize = core::mem::size_of::<ProposalOption>();
}

/// Proposal vote type
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[repr(u8)]
#[derive(IsEnum)]
pub enum VoteType {
    /// Single choice vote with mutually exclusive choices
    /// In the SingeChoice mode there can ever be a single winner
    /// If multiple options score the same highest vote then the Proposal is
    /// not resolved and considered as Failed.
    /// Note: Yes/No vote is a single choice (Yes) vote with the deny
    /// option (No)
    SingleChoice,

    /// Multiple options can be selected with up to max_voter_options per voter
    /// and with up to max_winning_options of successful options
    /// Ex. voters are given 5 options, can choose up to 3 (max_voter_options)
    /// and only 1 (max_winning_options) option can win and be executed
    MultiChoice {
        /// Type of MultiChoice
        #[allow(dead_code)]
        choice_type: MultiChoiceType,

        /// The min number of options a voter must choose
        ///
        /// Note: In the current version the limit is not supported and not
        /// enforced and must always be set to 1
        #[allow(dead_code)]
        min_voter_options: u8,

        /// The max number of options a voter can choose
        ///
        /// Note: In the current version the limit is not supported and not
        /// enforced and must always be set to the number of available
        /// options
        #[allow(dead_code)]
        max_voter_options: u8,

        /// The max number of wining options
        /// For executable proposals it limits how many options can be executed
        /// for a Proposal
        ///
        /// Note: In the current version the limit is not supported and not
        /// enforced and must always be set to the number of available
        /// options
        #[allow(dead_code)]
        max_winning_options: u8,
    },
}

impl TryFrom<&[u8]> for VoteType {
    type Error = ProgramError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        match input[0] {
            0 => Ok(VoteType::SingleChoice),
            1 => {
                // MultiChoice variant needs at least 5 bytes:
                // - 1 byte for variant tag
                // - 1 byte for choice_type
                // - 1 byte for min_voter_options
                // - 1 byte for max_voter_options
                // - 1 byte for max_winning_options
                if input.len() < 5 {
                    return Err(ProgramError::InvalidInstructionData);
                }

                let choice_type = match input[1] {
                    0 => MultiChoiceType::FullWeight,
                    1 => MultiChoiceType::Weighted,
                    _ => return Err(ProgramError::InvalidInstructionData),
                };

                Ok(VoteType::MultiChoice {
                    choice_type,
                    min_voter_options: input[2],
                    max_voter_options: input[3],
                    max_winning_options: input[4],
                })
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Type of MultiChoice.
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[repr(u8)]
#[derive(FromEnum, FromU8)]
#[derive(IsEnum)]
pub enum MultiChoiceType {
    /// Multiple options can be approved with full weight allocated to each
    /// approved option
    FullWeight,

    /// Multiple options can be approved with weight allocated proportionally
    /// to the percentage of the total weight.
    /// The full weight has to be voted among the approved options, i.e.,
    /// 100% of the weight has to be allocated
    Weighted,
}

impl MultiChoiceType {
    const LEN: usize = core::mem::size_of::<MultiChoiceType>();
}

impl TryFrom<&[u8]> for MultiChoiceType {
    type Error = ProgramError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        match input[0] {
            0 => Ok(MultiChoiceType::FullWeight),
            1 => Ok(MultiChoiceType::Weighted),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Governance Proposal
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalV2 {
    /// Governance account type
    pub account_type: GovernanceAccountType,

    /// Governance account the Proposal belongs to
    pub governance: Pubkey,

    /// Indicates which Governing Token is used to vote on the Proposal
    /// Whether the general Community token owners or the Council tokens owners
    /// vote on this Proposal
    pub governing_token_mint: Pubkey,

    /// Current proposal state
    pub state: ProposalState,

    // TODO: add state_at timestamp to have single field to filter recent proposals in the UI
    /// The TokenOwnerRecord representing the user who created and owns this
    /// Proposal
    pub token_owner_record: Pubkey,

    /// The number of signatories assigned to the Proposal
    pub signatories_count: u8,

    /// The number of signatories who already signed
    pub signatories_signed_off_count: u8,

    /// Vote type
    pub vote_type: VoteType,

    /// Proposal options
    pub options: Vec<ProposalOption>,

    /// The total weight of the Proposal rejection votes
    /// If the proposal has no deny option then the weight is None
    ///
    /// Only proposals with the deny option can have executable instructions
    /// attached to them Without the deny option a proposal is only non
    /// executable survey
    ///
    /// The deny options is also used for off-chain and/or manually executable
    /// proposal to make them binding as opposed to survey only proposals
    pub deny_vote_weight: Option<u64>,

    /// Reserved space for future versions
    /// This field is a leftover from unused veto_vote_weight: Option<u64>
    pub reserved1: u8,

    /// The total weight of  votes
    /// Note: Abstain is not supported in the current version
    pub abstain_vote_weight: Option<u64>,

    /// Optional start time if the Proposal should not enter voting state
    /// immediately after being signed off Note: start_at is not supported
    /// in the current version
    pub start_voting_at: Option<UnixTimestamp>,

    /// When the Proposal was created and entered Draft state
    pub draft_at: UnixTimestamp,

    /// When Signatories started signing off the Proposal
    pub signing_off_at: Option<UnixTimestamp>,

    /// When the Proposal began voting as UnixTimestamp
    pub voting_at: Option<UnixTimestamp>,

    /// When the Proposal began voting as Slot
    /// Note: The slot is not currently used but the exact slot is going to be
    /// required to support snapshot based vote weights
    pub voting_at_slot: Option<Slot>,

    /// When the Proposal ended voting and entered either Succeeded or Defeated
    pub voting_completed_at: Option<UnixTimestamp>,

    /// When the Proposal entered Executing state
    pub executing_at: Option<UnixTimestamp>,

    /// When the Proposal entered final state Completed or Cancelled and was
    /// closed
    pub closed_at: Option<UnixTimestamp>,

    /// Instruction execution flag for ordered and transactional instructions
    /// Note: This field is not used in the current version
    pub execution_flags: InstructionExecutionFlags,

    /// The max vote weight for the Governing Token mint at the time Proposal
    /// was decided.
    /// It's used to show correct vote results for historical proposals in
    /// cases when the mint supply or max weight source changed after vote was
    /// completed.
    pub max_vote_weight: Option<u64>,

    /// Max voting time for the proposal if different from parent Governance
    /// (only higher value possible).
    /// Note: This field is not used in the current version
    pub max_voting_time: Option<u32>,

    /// The vote threshold at the time Proposal was decided
    /// It's used to show correct vote results for historical proposals in cases
    /// when the threshold was changed for governance config after vote was
    /// completed.
    /// TODO: Use this field to override the threshold from parent Governance
    /// (only higher value possible)
    pub vote_threshold: Option<VoteThreshold>,

    /// Reserved space for future versions
    pub reserved: [u8; 64],

    /// Proposal name
    pub name: String,

    /// Link to proposal's description
    pub description_link: String,

    /// The total weight of Veto votes
    pub veto_vote_weight: u64,
}

impl AccountMaxSize for ProposalV2 {
    fn get_max_size(&self) -> Option<usize> {
        let options_size: usize = self.options.iter().map(|o| o.label.len() + 19).sum();
        Some(self.name.len() + self.description_link.len() + options_size + 297)
    }
}

impl IsInitialized for ProposalV2 {
    fn is_initialized(&self) -> bool {
        self.account_type == GovernanceAccountType::ProposalV2
    }
}

impl ProposalV2 {
    /// Checks if Signatories can be edited (added or removed) for the Proposal
    /// in the given state
    pub fn assert_can_edit_signatories(&self) -> Result<(), ProgramError> {
        self.assert_is_draft_state()
            .map_err(|_| GovernanceError::InvalidStateCannotEditSignatories.into())
    }

    /// Checks if Proposal can be singed off
    pub fn assert_can_sign_off(&self) -> Result<(), ProgramError> {
        match self.state {
            ProposalState::Draft | ProposalState::SigningOff => Ok(()),
            ProposalState::Executing
            | ProposalState::ExecutingWithErrors
            | ProposalState::Completed
            | ProposalState::Cancelled
            | ProposalState::Voting
            | ProposalState::Succeeded
            | ProposalState::Defeated
            | ProposalState::Vetoed => Err(GovernanceError::InvalidStateCannotSignOff.into()),
        }
    }

    /// Checks the Proposal is in Voting state
    fn assert_is_voting_state(&self) -> Result<(), ProgramError> {
        if self.state != ProposalState::Voting {
            return Err(GovernanceError::InvalidProposalState.into());
        }

        Ok(())
    }

    /// Checks the Proposal is in Draft state
    fn assert_is_draft_state(&self) -> Result<(), ProgramError> {
        if self.state != ProposalState::Draft {
            return Err(GovernanceError::InvalidProposalState.into());
        }

        Ok(())
    }

    /// Checks the Proposal was finalized (no more state transition will happen)
    pub fn assert_is_final_state(&self) -> Result<(), ProgramError> {
        match self.state {
            ProposalState::Completed
            | ProposalState::Cancelled
            | ProposalState::Defeated
            | ProposalState::Vetoed => Ok(()),
            ProposalState::Executing
            | ProposalState::ExecutingWithErrors
            | ProposalState::SigningOff
            | ProposalState::Voting
            | ProposalState::Draft
            | ProposalState::Succeeded => Err(GovernanceError::InvalidStateNotFinal.into()),
        }
    }

    /// Checks if Proposal can be voted on
    pub fn assert_can_cast_vote(
        &self,
        config: &GovernanceConfig,
        vote: &Vote,
        current_unix_timestamp: UnixTimestamp,
    ) -> Result<(), ProgramError> {
        self.assert_is_voting_state()
            .map_err(|_| GovernanceError::InvalidStateCannotVote)?;

        // Check if we are still within the configured max voting time period
        if self.has_voting_max_time_ended(config, current_unix_timestamp) {
            return Err(GovernanceError::ProposalVotingTimeExpired.into());
        }

        match vote {
            Vote::Approve(_) | Vote::Abstain => {
                // Once the base voting time passes and we are in the voting cool off time
                // approving votes are no longer accepted Abstain is considered
                // as positive vote because when attendance quorum is used it can tip the scales
                if self.has_voting_base_time_ended(config, current_unix_timestamp) {
                    Err(GovernanceError::VoteNotAllowedInCoolOffTime.into())
                } else {
                    Ok(())
                }
            }
            // Within voting cool off time only counter votes are allowed
            Vote::Deny | Vote::Veto => Ok(()),
        }
    }

    /// Checks if proposal has concluded so that security deposit is no longer
    /// needed
    pub fn assert_can_refund_proposal_deposit(&self) -> Result<(), ProgramError> {
        match self.state {
            ProposalState::Succeeded
            | ProposalState::Executing
            | ProposalState::Completed
            | ProposalState::Cancelled
            | ProposalState::Defeated
            | ProposalState::ExecutingWithErrors
            | ProposalState::Vetoed => Ok(()),
            ProposalState::Draft | ProposalState::SigningOff | ProposalState::Voting => {
                Err(GovernanceError::CannotRefundProposalDeposit.into())
            }
        }
    }

    /// Expected base vote end time determined by the configured
    /// base_voting_time and actual voting start time
    pub fn voting_base_time_end(&self, config: &GovernanceConfig) -> UnixTimestamp {
        self.voting_at
            .unwrap()
            .checked_add(config.voting_base_time as i64)
            .unwrap()
    }

    /// Checks whether the base voting time has ended for the proposal
    pub fn has_voting_base_time_ended(
        &self,
        config: &GovernanceConfig,
        current_unix_timestamp: UnixTimestamp,
    ) -> bool {
        // Check if we passed the configured base vote end time
        self.voting_base_time_end(config) < current_unix_timestamp
    }

    /// Expected max vote end time determined by the configured
    /// base_voting_time, optional voting_cool_off_time and actual voting start
    /// time
    pub fn voting_max_time_end(&self, config: &GovernanceConfig) -> UnixTimestamp {
        self.voting_base_time_end(config)
            .checked_add(config.voting_cool_off_time as i64)
            .unwrap()
    }

    /// Checks whether the max voting time has ended for the proposal
    pub fn has_voting_max_time_ended(
        &self,
        config: &GovernanceConfig,
        current_unix_timestamp: UnixTimestamp,
    ) -> bool {
        // Check if we passed the max vote end time
        self.voting_max_time_end(config) < current_unix_timestamp
    }

    /// Checks if Proposal can be finalized
    pub fn assert_can_finalize_vote(
        &self,
        config: &GovernanceConfig,
        current_unix_timestamp: UnixTimestamp,
    ) -> Result<(), ProgramError> {
        self.assert_is_voting_state()
            .map_err(|_| GovernanceError::InvalidStateCannotFinalize)?;

        // We can only finalize the vote after the configured max_voting_time has
        // expired and vote time ended
        if !self.has_voting_max_time_ended(config, current_unix_timestamp) {
            return Err(GovernanceError::CannotFinalizeVotingInProgress.into());
        }

        Ok(())
    }

    /// Finalizes vote by moving it to final state Succeeded or Defeated if
    /// max_voting_time has passed If Proposal is still within
    /// max_voting_time period then error is returned
    pub fn finalize_vote(
        &mut self,
        max_voter_weight: u64,
        config: &GovernanceConfig,
        current_unix_timestamp: UnixTimestamp,
        vote_threshold: &VoteThreshold,
    ) -> Result<(), ProgramError> {
        self.assert_can_finalize_vote(config, current_unix_timestamp)?;

        self.state = self.resolve_final_vote_state(max_voter_weight, vote_threshold)?;
        self.voting_completed_at = Some(self.voting_max_time_end(config));

        // Capture vote params to correctly display historical results
        self.max_vote_weight = Some(max_voter_weight);
        self.vote_threshold = Some(vote_threshold.clone());

        Ok(())
    }

    /// Resolves final proposal state after vote ends
    /// It inspects all proposals options and resolves their final vote results
    fn resolve_final_vote_state(
        &mut self,
        max_vote_weight: u64,
        vote_threshold: &VoteThreshold,
    ) -> Result<ProposalState, ProgramError> {
        // Get the min vote weight required for options to pass
        let min_vote_threshold_weight =
            get_min_vote_threshold_weight(vote_threshold, max_vote_weight).unwrap();

        // If the proposal has a reject option then any other option must beat it
        // regardless of the configured min_vote_threshold_weight
        let deny_vote_weight = self.deny_vote_weight.unwrap_or(0);

        let mut best_succeeded_option_weight = 0;
        let mut best_succeeded_option_count = 0u16;

        for option in self.options.iter_mut() {
            // Any positive vote (Yes) must be equal or above the required
            // min_vote_threshold_weight and higher than the reject option vote (No)
            // The same number of positive (Yes) and rejecting (No) votes is a tie and
            // resolved as Defeated In other words  +1 vote as a tie breaker is
            // required to succeed for the positive option vote
            if option.vote_weight >= min_vote_threshold_weight
                && option.vote_weight > deny_vote_weight
            {
                option.vote_result = OptionVoteResult::Succeeded;

                match option.vote_weight.cmp(&best_succeeded_option_weight) {
                    Ordering::Greater => {
                        best_succeeded_option_weight = option.vote_weight;
                        best_succeeded_option_count = 1;
                    }
                    Ordering::Equal => {
                        best_succeeded_option_count =
                            best_succeeded_option_count.checked_add(1).unwrap()
                    }
                    Ordering::Less => {}
                }
            } else {
                option.vote_result = OptionVoteResult::Defeated;
            }
        }

        let mut final_state = if best_succeeded_option_count == 0 {
            // If none of the individual options succeeded then the proposal as a whole is
            // defeated
            ProposalState::Defeated
        } else {
            match &self.vote_type {
                VoteType::SingleChoice => {
                    let proposal_state = if best_succeeded_option_count > 1 {
                        // If there is more than one winning option then the single choice proposal
                        // is considered as defeated
                        best_succeeded_option_weight = u64::MAX; // no winning option
                        ProposalState::Defeated
                    } else {
                        ProposalState::Succeeded
                    };

                    // Coerce options vote results based on the winning score
                    // (best_succeeded_vote_weight)
                    for option in self.options.iter_mut() {
                        option.vote_result = if option.vote_weight == best_succeeded_option_weight {
                            OptionVoteResult::Succeeded
                        } else {
                            OptionVoteResult::Defeated
                        };
                    }

                    proposal_state
                }
                VoteType::MultiChoice {
                    choice_type: _,
                    max_voter_options: _,
                    max_winning_options: _,
                    min_voter_options: _,
                } => {
                    // If any option succeeded for multi choice then the proposal as a whole
                    // succeeded as well
                    ProposalState::Succeeded
                }
            }
        };

        // None executable proposal is just a survey and is considered Completed once
        // the vote ends and no more actions are available There is no overall
        // Success or Failure status for the Proposal however individual options still
        // have their own status
        //
        // Note: An off-chain/manually executable Proposal has no instructions but it
        // still must have the deny vote enabled to be binding In such a case,
        // if successful, the Proposal vote ends in Succeeded state and it must be
        // manually transitioned to Completed state by the Proposal owner once
        // the external actions are executed
        if self.deny_vote_weight.is_none() {
            final_state = ProposalState::Completed;
        }

        Ok(final_state)
    }

    /// Calculates max voter weight for given mint supply and realm config
    fn get_max_voter_weight_from_mint_supply(
        &mut self,
        realm_data: &RealmV2,
        governing_token_mint: &Pubkey,
        governing_token_mint_supply: u64,
        vote_kind: &VoteKind,
    ) -> Result<u64, ProgramError> {
        // max vote weight fraction is only used for community mint
        if Some(*governing_token_mint) == realm_data.config.council_mint {
            return Ok(governing_token_mint_supply);
        }

        let max_voter_weight = match realm_data.config.community_mint_max_voter_weight_source {
            MintMaxVoterWeightSource::SupplyFraction(fraction) => {
                if fraction == MintMaxVoterWeightSource::SUPPLY_FRACTION_BASE {
                    return Ok(governing_token_mint_supply);
                }

                (governing_token_mint_supply as u128)
                    .checked_mul(fraction as u128)
                    .unwrap()
                    .checked_div(MintMaxVoterWeightSource::SUPPLY_FRACTION_BASE as u128)
                    .unwrap() as u64
            }
            MintMaxVoterWeightSource::Absolute(value) => value,
        };

        // When the fraction or absolute value is used it's possible we can go over the
        // calculated max_vote_weight and we have to adjust it in case more
        // votes have been cast
        Ok(self.coerce_max_voter_weight(max_voter_weight, vote_kind))
    }

    /// Adjusts max voter weight to ensure it's not lower than total cast votes
    fn coerce_max_voter_weight(&self, max_voter_weight: u64, vote_kind: &VoteKind) -> u64 {
        let total_vote_weight = match vote_kind {
            VoteKind::Electorate => {
                let deny_vote_weight = self.deny_vote_weight.unwrap_or(0);

                let max_option_vote_weight =
                    self.options.iter().map(|o| o.vote_weight).max().unwrap();

                max_option_vote_weight
                    .checked_add(deny_vote_weight)
                    .unwrap()
            }
            VoteKind::Veto => self.veto_vote_weight,
        };

        max_voter_weight.max(total_vote_weight)
    }

    /// Resolves max voter weight using either 1) voting governing_token_mint
    /// supply or 2) max voter weight if configured for the token mint
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_max_voter_weight(
        &mut self,
        account_info_iter: &mut Iter<AccountInfo>,
        realm: &Pubkey,
        realm_data: &RealmV2,
        realm_config_data: &RealmConfigAccount,
        vote_governing_token_mint_info: &AccountInfo,
        vote_kind: &VoteKind,
    ) -> Result<u64, ProgramError> {
        // if the Realm is configured to use max voter weight for the given voting
        // governing_token_mint then use the externally provided max_voter_weight
        // instead of the supply based max
        if let Some(max_voter_weight_addin) = realm_config_data
            .get_token_config(realm_data, vote_governing_token_mint_info.key())?
            .max_voter_weight_addin
        {
            let max_voter_weight_record_info = next_account_info(account_info_iter)?;

            let max_voter_weight_record_data =
                get_max_voter_weight_record_data_for_realm_and_governing_token_mint(
                    &max_voter_weight_addin,
                    max_voter_weight_record_info,
                    realm,
                    vote_governing_token_mint_info.key(),
                )?;

            assert_is_valid_max_voter_weight(&max_voter_weight_record_data)?;

            // When the max voter weight addin is used it's possible it can be inaccurate
            // and we can have more votes then the max provided by the addin and
            // we have to adjust it to whatever result is higher
            return Ok(self.coerce_max_voter_weight(
                max_voter_weight_record_data.max_voter_weight,
                vote_kind,
            ));
        }

        let vote_governing_token_mint_supply =
            get_spl_token_mint_supply(vote_governing_token_mint_info)?;

        let max_voter_weight = self.get_max_voter_weight_from_mint_supply(
            realm_data,
            vote_governing_token_mint_info.key(),
            vote_governing_token_mint_supply,
            vote_kind,
        )?;

        Ok(max_voter_weight)
    }

    /// Checks if vote can be tipped and automatically transitioned to Succeeded
    /// or Defeated state If the conditions are met the state is updated
    /// accordingly
    pub fn try_tip_vote(
        &mut self,
        max_voter_weight: u64,
        vote_tipping: &VoteTipping,
        current_unix_timestamp: UnixTimestamp,
        vote_threshold: &VoteThreshold,
        vote_kind: &VoteKind,
    ) -> Result<bool, ProgramError> {
        if let Some(tipped_state) = self.try_get_tipped_vote_state(
            max_voter_weight,
            vote_tipping,
            vote_threshold,
            vote_kind,
        ) {
            self.state = tipped_state;
            self.voting_completed_at = Some(current_unix_timestamp);

            // Capture vote params to correctly display historical results
            // Note: For Veto vote the captured params are from the Veto config
            self.max_vote_weight = Some(max_voter_weight);
            self.vote_threshold = Some(vote_threshold.clone());

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Checks if vote can be tipped and automatically transitioned to
    /// Succeeded, Defeated or Vetoed state.
    /// If yes then Some(ProposalState) is returned and None otherwise
    pub fn try_get_tipped_vote_state(
        &mut self,
        max_voter_weight: u64,
        vote_tipping: &VoteTipping,
        vote_threshold: &VoteThreshold,
        vote_kind: &VoteKind,
    ) -> Option<ProposalState> {
        let min_vote_threshold_weight =
            get_min_vote_threshold_weight(vote_threshold, max_voter_weight).unwrap();

        match vote_kind {
            VoteKind::Electorate => self.try_get_tipped_electorate_vote_state(
                max_voter_weight,
                vote_tipping,
                min_vote_threshold_weight,
            ),
            VoteKind::Veto => self.try_get_tipped_veto_vote_state(min_vote_threshold_weight),
        }
    }

    /// Checks if Electorate vote can be tipped and automatically transitioned
    /// to Succeeded or Defeated state.
    /// If yes then Some(ProposalState) is returned and None otherwise
    fn try_get_tipped_electorate_vote_state(
        &mut self,
        max_voter_weight: u64,
        vote_tipping: &VoteTipping,
        min_vote_threshold_weight: u64,
    ) -> Option<ProposalState> {
        // Vote tipping is currently supported for SingleChoice votes with
        // single Yes and No (rejection) options only.
        // Note: Tipping for multiple options (single choice and multiple
        // choices) should be possible but it requires a great deal of
        // considerations and I decided to fight it another day
        if self.vote_type != VoteType::SingleChoice
            // Tipping should not be allowed for opinion only proposals (surveys
            // without rejection) to allow everybody's voice to be heard
            || self.deny_vote_weight.is_none()
            || self.options.len() != 1
        {
            return None;
        };

        let yes_option = &mut self.options[0];

        let yes_vote_weight = yes_option.vote_weight;
        let deny_vote_weight = self.deny_vote_weight.unwrap();

        match vote_tipping {
            VoteTipping::Disabled => {}
            VoteTipping::Strict => {
                if yes_vote_weight >= min_vote_threshold_weight
                    && yes_vote_weight > (max_voter_weight.saturating_sub(yes_vote_weight))
                {
                    yes_option.vote_result = OptionVoteResult::Succeeded;
                    return Some(ProposalState::Succeeded);
                }
            }
            VoteTipping::Early => {
                if yes_vote_weight >= min_vote_threshold_weight
                    && yes_vote_weight > deny_vote_weight
                {
                    yes_option.vote_result = OptionVoteResult::Succeeded;
                    return Some(ProposalState::Succeeded);
                }
            }
        }

        // If vote tipping isn't disabled entirely, allow a vote to complete as
        // "defeated" if there is no possible way of reaching majority or the
        // min_vote_threshold_weight for another option. This tipping is always
        // strict, there's no equivalent to "early" tipping for deny votes.
        if *vote_tipping != VoteTipping::Disabled
            && (deny_vote_weight > (max_voter_weight.saturating_sub(min_vote_threshold_weight))
                || deny_vote_weight >= (max_voter_weight.saturating_sub(deny_vote_weight)))
        {
            yes_option.vote_result = OptionVoteResult::Defeated;
            return Some(ProposalState::Defeated);
        }

        None
    }

    /// Checks if vote can be tipped and transitioned to Vetoed state
    /// If yes then Some(ProposalState::Vetoed) is returned and None otherwise
    fn try_get_tipped_veto_vote_state(
        &mut self,
        min_vote_threshold_weight: u64,
    ) -> Option<ProposalState> {
        // Veto vote tips as soon as the required threshold is reached
        // It's irrespectively of vote_tipping config because the outcome of the
        // Proposal can't change any longer after being vetoed
        if self.veto_vote_weight >= min_vote_threshold_weight {
            // Note: Since we don't tip multi option votes all options vote_result would
            // remain as None
            Some(ProposalState::Vetoed)
        } else {
            None
        }
    }

    /// Checks if Proposal can be canceled in the given state
    pub fn assert_can_cancel(
        &self,
        config: &GovernanceConfig,
        current_unix_timestamp: UnixTimestamp,
    ) -> Result<(), ProgramError> {
        match self.state {
            ProposalState::Draft | ProposalState::SigningOff => Ok(()),
            ProposalState::Voting => {
                // Note: If there is no tipping point the proposal can be still in Voting state
                // but already past the configured max_voting_time In that case
                // we treat the proposal as finalized and it's no longer allowed to be canceled
                if self.has_voting_max_time_ended(config, current_unix_timestamp) {
                    return Err(GovernanceError::ProposalVotingTimeExpired.into());
                }
                Ok(())
            }
            ProposalState::Executing
            | ProposalState::ExecutingWithErrors
            | ProposalState::Completed
            | ProposalState::Cancelled
            | ProposalState::Succeeded
            | ProposalState::Defeated
            | ProposalState::Vetoed => {
                Err(GovernanceError::InvalidStateCannotCancelProposal.into())
            }
        }
    }

    /// Checks if Instructions can be edited (inserted or removed) for the
    /// Proposal in the given state It also asserts whether the Proposal is
    /// executable (has the reject option)
    pub fn assert_can_edit_instructions(&self) -> Result<(), ProgramError> {
        if self.assert_is_draft_state().is_err() {
            return Err(GovernanceError::InvalidStateCannotEditTransactions.into());
        }

        // For security purposes only proposals with the reject option can have
        // executable instructions
        if self.deny_vote_weight.is_none() {
            return Err(GovernanceError::ProposalIsNotExecutable.into());
        }

        Ok(())
    }

    /// Checks if Instructions can be executed for the Proposal in the given
    /// state
    pub fn assert_can_execute_transaction(
        &self,
        proposal_transaction_data: &ProposalTransactionV2,
        current_unix_timestamp: UnixTimestamp,
    ) -> Result<(), ProgramError> {
        match self.state {
            ProposalState::Succeeded
            | ProposalState::Executing
            | ProposalState::ExecutingWithErrors => {}
            ProposalState::Draft
            | ProposalState::SigningOff
            | ProposalState::Completed
            | ProposalState::Voting
            | ProposalState::Cancelled
            | ProposalState::Defeated
            | ProposalState::Vetoed => {
                return Err(GovernanceError::InvalidStateCannotExecuteTransaction.into())
            }
        }

        if self.options[proposal_transaction_data.option_index as usize].vote_result
            != OptionVoteResult::Succeeded
        {
            return Err(GovernanceError::CannotExecuteDefeatedOption.into());
        }

        if self
            .voting_completed_at
            .unwrap()
            .checked_add(proposal_transaction_data.hold_up_time as i64)
            .unwrap()
            >= current_unix_timestamp
        {
            return Err(GovernanceError::CannotExecuteTransactionWithinHoldUpTime.into());
        }

        if proposal_transaction_data.executed_at.is_some() {
            return Err(GovernanceError::TransactionAlreadyExecuted.into());
        }

        Ok(())
    }

    /// Checks if Instructions can be executed for the Proposal in the given
    /// state
    pub fn assert_can_execute_versioned_transaction(
        &self,
        proposal_versioned_transaction_data: &ProposalVersionedTransaction,
        governance_config: &GovernanceConfig,
        current_unix_timestamp: UnixTimestamp,
    ) -> Result<(), ProgramError> {
        match self.state {
            ProposalState::Succeeded
            | ProposalState::Executing
            | ProposalState::ExecutingWithErrors => {}
            ProposalState::Draft
            | ProposalState::SigningOff
            | ProposalState::Completed
            | ProposalState::Voting
            | ProposalState::Cancelled
            | ProposalState::Defeated
            | ProposalState::Vetoed => {
                return Err(GovernanceError::InvalidStateCannotExecuteTransaction.into())
            }
        }

        if self.options[proposal_versioned_transaction_data.option_index as usize].vote_result
            != OptionVoteResult::Succeeded
        {
            return Err(GovernanceError::CannotExecuteDefeatedOption.into());
        }

        if self
            .voting_completed_at
            .unwrap()
            .checked_add(governance_config.min_transaction_hold_up_time as i64)
            .unwrap()
            >= current_unix_timestamp
        {
            return Err(GovernanceError::CannotExecuteTransactionWithinHoldUpTime.into());
        }

        if proposal_versioned_transaction_data.executed_at.is_some() {
            return Err(GovernanceError::TransactionAlreadyExecuted.into());
        }

        Ok(())
    }

    /// Checks if the instruction can be flagged with error for the Proposal in
    /// the given state
    pub fn assert_can_flag_transaction_error(
        &self,
        proposal_transaction_data: &ProposalTransactionV2,
        current_unix_timestamp: UnixTimestamp,
    ) -> Result<(), ProgramError> {
        // Instruction can be flagged for error only when it's eligible for execution
        self.assert_can_execute_transaction(proposal_transaction_data, current_unix_timestamp)?;

        if proposal_transaction_data.execution_status == TransactionExecutionStatus::Error {
            return Err(GovernanceError::TransactionAlreadyFlaggedWithError.into());
        }

        Ok(())
    }

    /// Checks if Proposal with off-chain/manual actions can be transitioned to
    /// Completed
    pub fn assert_can_complete(&self) -> Result<(), ProgramError> {
        // Proposal vote must be successful
        if self.state != ProposalState::Succeeded {
            return Err(GovernanceError::InvalidStateToCompleteProposal.into());
        }

        // There must be no on-chain executable actions
        if self.options.iter().any(|o| o.transactions_count != 0) {
            return Err(GovernanceError::InvalidStateToCompleteProposal.into());
        }

        Ok(())
    }

    /// Asserts the given vote is valid for the proposal
    pub fn assert_valid_vote(&self, vote: &Vote) -> Result<(), ProgramError> {
        match vote {
            Vote::Approve(choices) => {
                if self.options.len() != choices.len() {
                    return Err(GovernanceError::InvalidNumberOfVoteChoices.into());
                }

                let mut choice_count = 0u16;
                let mut total_choice_weight_percentage = 0u8;

                for choice in choices {
                    if choice.rank > 0 {
                        return Err(GovernanceError::RankedVoteIsNotSupported.into());
                    }

                    if choice.weight_percentage > 0 {
                        choice_count = choice_count.checked_add(1).unwrap();

                        match self.vote_type {
                            VoteType::MultiChoice {
                                choice_type: MultiChoiceType::Weighted,
                                min_voter_options: _,
                                max_voter_options: _,
                                max_winning_options: _,
                            } => {
                                // Calculate the total percentage for all choices for weighted
                                // choice vote. The total must add up
                                // to exactly 100%
                                total_choice_weight_percentage = total_choice_weight_percentage
                                    .checked_add(choice.weight_percentage)
                                    .ok_or(GovernanceError::TotalVoteWeightMustBe100Percent)?;
                            }
                            _ => {
                                if choice.weight_percentage != 100 {
                                    return Err(
                                        GovernanceError::ChoiceWeightMustBe100Percent.into()
                                    );
                                }
                            }
                        }
                    }
                }

                match self.vote_type {
                    VoteType::SingleChoice => {
                        if choice_count != 1 {
                            return Err(GovernanceError::SingleChoiceOnlyIsAllowed.into());
                        }
                    }
                    VoteType::MultiChoice {
                        choice_type: MultiChoiceType::FullWeight,
                        min_voter_options: _,
                        max_voter_options: _,
                        max_winning_options: _,
                    } => {
                        if choice_count == 0 {
                            return Err(GovernanceError::AtLeastSingleChoiceIsRequired.into());
                        }
                    }
                    VoteType::MultiChoice {
                        choice_type: MultiChoiceType::Weighted,
                        min_voter_options: _,
                        max_voter_options: _,
                        max_winning_options: _,
                    } => {
                        if choice_count == 0 {
                            return Err(GovernanceError::AtLeastSingleChoiceIsRequired.into());
                        }
                        if total_choice_weight_percentage != 100 {
                            return Err(GovernanceError::TotalVoteWeightMustBe100Percent.into());
                        }
                    }
                }
            }
            Vote::Deny => {
                if self.deny_vote_weight.is_none() {
                    return Err(GovernanceError::DenyVoteIsNotAllowed.into());
                }
            }
            Vote::Abstain => {
                return Err(GovernanceError::NotSupportedVoteType.into());
            }
            Vote::Veto => {}
        }

        Ok(())
    }

    /// Serializes account into the target buffer
    pub fn serialize(self, data: &mut [u8]) -> Result<(), ProgramError> {
        let data_len = self.get_max_size().unwrap();
        if self.account_type == GovernanceAccountType::ProposalV2 {
            unsafe {
                sol_memcpy(data, to_bytes_with_len::<Self>(&self, data_len), data_len);
            }
        } else if self.account_type == GovernanceAccountType::ProposalV1 {
            // V1 account can't be resized and we have to translate it back to the original
            // format

            if self.abstain_vote_weight.is_some() {
                panic!("ProposalV1 doesn't support Abstain vote")
            }

            if self.veto_vote_weight > 0 {
                panic!("ProposalV1 doesn't support Veto vote")
            }

            if self.start_voting_at.is_some() {
                panic!("ProposalV1 doesn't support start time")
            }

            if self.max_voting_time.is_some() {
                panic!("ProposalV1 doesn't support max voting time")
            }

            if self.options.len() != 1 {
                panic!("ProposalV1 doesn't support multiple options")
            }

            let proposal_data_v1 = ProposalV1 {
                account_type: self.account_type,
                governance: self.governance,
                governing_token_mint: self.governing_token_mint,
                state: self.state,
                token_owner_record: self.token_owner_record,
                signatories_count: self.signatories_count,
                signatories_signed_off_count: self.signatories_signed_off_count,
                yes_votes_count: self.options[0].vote_weight,
                no_votes_count: self.deny_vote_weight.unwrap(),
                instructions_executed_count: self.options[0].transactions_executed_count,
                instructions_count: self.options[0].transactions_count,
                instructions_next_index: self.options[0].transactions_next_index,
                draft_at: self.draft_at,
                signing_off_at: self.signing_off_at,
                voting_at: self.voting_at,
                voting_at_slot: self.voting_at_slot,
                voting_completed_at: self.voting_completed_at,
                executing_at: self.executing_at,
                closed_at: self.closed_at,
                execution_flags: self.execution_flags,
                max_vote_weight: self.max_vote_weight,
                vote_threshold: self.vote_threshold,
                name: self.name,
                description_link: self.description_link,
            };

            unsafe {
                sol_memcpy(data, to_bytes::<ProposalV1>(&proposal_data_v1), ProposalV1::LEN);
            }
        }

        Ok(())
    }

    /// Returns a `ProposalV2` from account info.
    ///
    /// This method will perform the following validations on the account info:
    ///  1. Owner check: it must match the program.
    ///  2. Account discriminator: it must match [`GovernanceAccountType::ProposalV2`].
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
        if data[0] != GovernanceAccountType::ProposalV2 as u8 {
            return Err(ProgramError::InvalidAccountData);
        }
        // SAFETY: `data` was validated to have the correct owner and discriminator.
        Ok(Ref::map(data, |data| unsafe {
            Self::from_bytes_unchecked(data)
        }))
    }

    /// Returns a `ProposalV2` from account info.
    ///
    /// This method will perform the following validations on the account info:
    ///  1. Owner check: it must match the program.
    ///  2. Account discriminator: it must match [`GovernanceAccountType::ProposalV2`].
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
        if data[0] != GovernanceAccountType::ProposalV2 as u8 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self::from_bytes_unchecked(data))
    }

    /// Return a `ProposalV2` from the given bytes.
    ///
    /// This method validates that `bytes` has at least the minimum required
    /// length.
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, ProgramError> {
        // SAFETY: `bytes` was validated to have the expected length
        // to hold a `ProposalV2` reference.
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Return a `ProposalV2` from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `ProposalV2`.
    #[inline(always)]
    pub unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        &*(bytes.as_ptr() as *const Self)
    }

    /// Return a mutable `ProposalV2` from the given bytes.
    ///
    /// This method validates that `bytes` has at least the minimum required
    /// length.
    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        // SAFETY: `bytes` was validated to have the expected length
        // to hold a `ProposalV2` reference.
        Ok(unsafe { Self::from_bytes_mut_unchecked(bytes) })
    }

    /// Return a mutable `ProposalV2` from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `ProposalV2`.
    #[inline(always)]
    pub(crate) unsafe fn from_bytes_mut_unchecked(bytes: &mut [u8]) -> &mut Self {
        &mut *(bytes.as_mut_ptr() as *mut Self)
    }
}

/// Converts given vote threshold (ex. in percentages) to absolute vote weight
/// and returns the min weight required for a proposal option to pass
fn get_min_vote_threshold_weight(
    vote_threshold: &VoteThreshold,
    max_voter_weight: u64,
) -> Result<u64, ProgramError> {
    let yes_vote_threshold_percentage = match vote_threshold {
        VoteThreshold::YesVotePercentage(yes_vote_threshold_percentage) => {
            *yes_vote_threshold_percentage
        }
        _ => {
            return Err(GovernanceError::VoteThresholdTypeNotSupported.into());
        }
    };

    let numerator = (yes_vote_threshold_percentage as u128)
        .checked_mul(max_voter_weight as u128)
        .unwrap();

    let mut yes_vote_threshold = numerator.checked_div(100).unwrap();

    if yes_vote_threshold.checked_mul(100).unwrap() < numerator {
        yes_vote_threshold = yes_vote_threshold.checked_add(1).unwrap();
    }

    Ok(yes_vote_threshold as u64)
}

/// Deserializes Proposal account and checks owner program
pub fn get_proposal_data(
    program_id: &Pubkey,
    proposal_info: &AccountInfo,
) -> Result<ProposalV2, ProgramError> {
    let account_type: GovernanceAccountType = get_account_type(program_id, proposal_info)?;

    // If the account is V1 version then translate to V2
    if account_type == GovernanceAccountType::ProposalV1 {
        let proposal_data_v1 = ProposalV1::from_account_info(proposal_info, program_id)?;

        let vote_result = match proposal_data_v1.state {
            ProposalState::Draft
            | ProposalState::SigningOff
            | ProposalState::Voting
            | ProposalState::Cancelled => OptionVoteResult::None,
            ProposalState::Succeeded
            | ProposalState::Executing
            | ProposalState::ExecutingWithErrors
            | ProposalState::Completed => OptionVoteResult::Succeeded,
            ProposalState::Vetoed | ProposalState::Defeated => OptionVoteResult::None,
        };

        return Ok(ProposalV2 {
            account_type,
            governance: proposal_data_v1.governance,
            governing_token_mint: proposal_data_v1.governing_token_mint,
            state: proposal_data_v1.state,
            token_owner_record: proposal_data_v1.token_owner_record,
            signatories_count: proposal_data_v1.signatories_count,
            signatories_signed_off_count: proposal_data_v1.signatories_signed_off_count,
            vote_type: VoteType::SingleChoice,
            options: vec![ProposalOption {
                label: "Yes".to_string(),
                vote_weight: proposal_data_v1.yes_votes_count,
                vote_result,
                transactions_executed_count: proposal_data_v1.instructions_executed_count,
                transactions_count: proposal_data_v1.instructions_count,
                transactions_next_index: proposal_data_v1.instructions_next_index,
            }],
            deny_vote_weight: Some(proposal_data_v1.no_votes_count),
            veto_vote_weight: 0,
            abstain_vote_weight: None,
            start_voting_at: None,
            draft_at: proposal_data_v1.draft_at,
            signing_off_at: proposal_data_v1.signing_off_at,
            voting_at: proposal_data_v1.voting_at,
            voting_at_slot: proposal_data_v1.voting_at_slot,
            voting_completed_at: proposal_data_v1.voting_completed_at,
            executing_at: proposal_data_v1.executing_at,
            closed_at: proposal_data_v1.closed_at,
            execution_flags: proposal_data_v1.execution_flags.clone(),
            max_vote_weight: proposal_data_v1.max_vote_weight,
            max_voting_time: None,
            vote_threshold: proposal_data_v1.vote_threshold,
            name: proposal_data_v1.name.clone(),
            description_link: proposal_data_v1.description_link.clone(),
            reserved: [0; 64],
            reserved1: 0,
        });
    }

    let proposal_v2 = ProposalV2::from_account_info(proposal_info, program_id)?;
    Ok(proposal_v2.clone())
}

/// Deserializes Proposal and validates it belongs to the given Governance and
/// governing_token_mint
pub fn get_proposal_data_for_governance_and_governing_mint(
    program_id: &Pubkey,
    proposal_info: &AccountInfo,
    governance: &Pubkey,
    governing_token_mint: &Pubkey,
) -> Result<ProposalV2, ProgramError> {
    let proposal_data = get_proposal_data_for_governance(program_id, proposal_info, governance)?;

    if proposal_data.governing_token_mint != *governing_token_mint {
        return Err(GovernanceError::InvalidGoverningMintForProposal.into());
    }

    Ok(proposal_data)
}

/// Deserializes Proposal and validates it belongs to the given Governance
pub fn get_proposal_data_for_governance(
    program_id: &Pubkey,
    proposal_info: &AccountInfo,
    governance: &Pubkey,
) -> Result<ProposalV2, ProgramError> {
    let proposal_data = get_proposal_data(program_id, proposal_info)?;

    if proposal_data.governance != *governance {
        return Err(GovernanceError::InvalidGovernanceForProposal.into());
    }

    Ok(proposal_data)
}

/// Returns Proposal PDA seeds
pub fn get_proposal_address_seeds<'a>(
    governance: &'a Pubkey,
    governing_token_mint: &'a Pubkey,
    proposal_seed: &'a Pubkey,
) -> [&'a [u8]; 4] {
    [
        PROGRAM_AUTHORITY_SEED,
        governance.as_ref(),
        governing_token_mint.as_ref(),
        proposal_seed.as_ref(),
    ]
}

/// Returns Proposal PDA address
pub fn get_proposal_address<'a>(
    program_id: &Pubkey,
    governance: &'a Pubkey,
    governing_token_mint: &'a Pubkey,
    proposal_seed: &'a Pubkey,
) -> Pubkey {
    find_program_address(
        &get_proposal_address_seeds(governance, governing_token_mint, proposal_seed),
        program_id,
    )
    .0
}

/// Assert options to create proposal are valid for the Proposal vote_type
pub fn assert_valid_proposal_options(
    options: &[String],
    vote_type: &VoteType,
) -> Result<(), ProgramError> {
    if options.is_empty() || options.len() > 10 {
        return Err(GovernanceError::InvalidProposalOptions.into());
    }

    if let VoteType::MultiChoice {
        choice_type: _,
        min_voter_options,
        max_voter_options,
        max_winning_options,
    } = vote_type
    {
        if options.len() == 1
            || *max_voter_options as usize != options.len()
            || *max_winning_options as usize != options.len()
            || *min_voter_options != 1
        {
            return Err(GovernanceError::InvalidMultiChoiceProposalParameters.into());
        }
    }

    // TODO: Check for duplicated option labels
    // The options are identified by index so it's ok for now

    if options.iter().any(|o| o.is_empty()) {
        return Err(GovernanceError::InvalidProposalOptions.into());
    }

    Ok(())
}

//! Program instructions

// Needed to avoid deprecation warning when building/testing the program
#![allow(deprecated)]

use {
    crate::state::{
        governance::GovernanceConfig,
        proposal::VoteType,
        proposal_transaction::InstructionData,
        realm::{RealmConfigArgs, SetRealmAuthorityAction},
        vote_record::Vote,
    },
    p_spl_governance_tools::account::{load_acc_unchecked, load_data_unchecked, DataLen},
    pinocchio::{program_error::ProgramError, pubkey::Pubkey}, pinocchio_utils_macro::PInstruction,
};

/// Instructions supported by the Governance program
#[derive(Clone, Debug, PartialEq, Eq, PInstruction)]
#[allow(clippy::large_enum_variant)]
pub enum GovernanceInstruction {
    /// Creates Governance Realm account which aggregates governances for given
    /// Community Mint and optional Council Mint
    ///
    /// 0. `[writable]` Governance Realm account.
    ///     * PDA seeds:['governance',name]
    /// 1. `[]` Realm authority
    /// 2. `[]` Community Token Mint
    /// 3. `[writable]` Community Token Holding account.
    ///     * PDA seeds: ['governance',realm,community_mint]
    ///     The account will be created with the Realm PDA as its owner
    /// 4. `[signer]` Payer
    /// 5. `[]` System
    /// 6. `[]` SPL Token or SPL Token 2022 program
    /// 7. `[]` Sysvar Rent
    /// 8. `[]` Council Token Mint - optional
    /// 9. `[writable]` Council Token Holding account - optional unless council
    ///    is used.
    ///     * PDA seeds: ['governance',realm,council_mint]
    ///     The account will be created with the Realm PDA as its owner
    /// 10. `[writable]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    /// 11. `[]` Optional Community Voter Weight Addin Program Id
    /// 12. `[]` Optional Max Community Voter Weight Addin Program Id
    /// 13. `[]` Optional Council Voter Weight Addin Program Id
    /// 14. `[]` Optional Max Council Voter Weight Addin Program Id
    CreateRealm {
        #[allow(dead_code)]
        /// UTF-8 encoded Governance Realm name
        name: String,

        #[allow(dead_code)]
        /// Realm config args
        config_args: RealmConfigArgs,
    },

    /// Deposits governing tokens (Community or Council) to Governance Realm and
    /// establishes your voter weight to be used for voting within the Realm
    /// Note: If subsequent (top up) deposit is made and there are active votes
    /// for the Voter then the vote weights won't be updated automatically
    /// It can be done by relinquishing votes on active Proposals and voting
    /// again with the new weight
    ///
    ///  0. `[]` Realm account
    ///  1. `[writable]` Governing Token Holding account.
    ///     * PDA seeds: ['governance',realm, governing_token_mint]
    ///  2. `[writable]` Governing Token Source account. It can be either
    ///     spl-token TokenAccount or MintAccount Tokens will be transferred or
    ///     minted to the Holding account
    ///  3. `[signer]` Governing Token Owner account
    ///  4. `[signer]` Governing Token Source account authority It should be
    ///     owner for TokenAccount and mint_authority for MintAccount
    ///  5. `[writable]` TokenOwnerRecord account.
    ///     * PDA seeds: ['governance',realm, governing_token_mint,
    ///       governing_token_owner]
    ///  6. `[signer]` Payer
    ///  7. `[]` System
    ///  8. `[]` SPL Token or SPL Token 2022 program
    ///  9. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    DepositGoverningTokens {
        /// The amount to deposit into the realm
        #[allow(dead_code)]
        amount: u64,
    },

    /// Withdraws governing tokens (Community or Council) from Governance Realm
    /// and downgrades your voter weight within the Realm.
    /// Note: It's only possible to withdraw tokens if the Voter doesn't have
    /// any outstanding active votes.
    /// If there are any outstanding votes then they must be relinquished
    /// before tokens could be withdrawn
    ///
    ///  0. `[]` Realm account
    ///  1. `[writable]` Governing Token Holding account.
    ///     * PDA seeds: ['governance',realm, governing_token_mint]
    ///  2. `[writable]` Governing Token Destination account. All tokens will be
    ///     transferred to this account
    ///  3. `[signer]` Governing Token Owner account
    ///  4. `[writable]` TokenOwnerRecord account.
    ///     * PDA seeds: ['governance',realm, governing_token_mint,
    ///       governing_token_owner]
    ///  5. `[]` SPL Token or SPL Token 2022 program
    ///  6. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    WithdrawGoverningTokens {},

    /// Sets Governance Delegate for the given Realm and Governing Token Mint
    /// (Community or Council). The Delegate would have voting rights and
    /// could vote on behalf of the Governing Token Owner. The Delegate would
    /// also be able to create Proposals on behalf of the Governing Token
    /// Owner.
    /// Note: This doesn't take voting rights from the Token Owner who still can
    /// vote and change governance_delegate
    ///
    /// 0. `[signer]` Current Governance Delegate or Governing Token owner
    /// 1. `[writable]` Token Owner  Record
    SetGovernanceDelegate {
        #[allow(dead_code)]
        /// New Governance Delegate
        new_governance_delegate: Option<Pubkey>,
    },

    /// Creates Governance account which can be used to govern any arbitrary
    /// Solana account or asset
    ///
    ///   0. `[]` Realm account the created Governance belongs to
    ///   1. `[writable]` Account Governance account.
    ///     * PDA seeds: ['account-governance', realm, governed_account]
    ///   2. `[]` Account governed by this Governance Note: The account doesn't
    ///      have to exist and can be only used as a unique identifier for the
    ///      Governance account
    ///   3. `[]` Governing TokenOwnerRecord account (Used only if not signed by
    ///      RealmAuthority)
    ///   4. `[signer]` Payer
    ///   5. `[]` System program
    ///   6. `[signer]` Governance authority
    ///   7. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   8. `[]` Optional Voter Weight Record
    CreateGovernance {
        /// Governance config
        #[allow(dead_code)]
        config: GovernanceConfig,
    },

    /// Creates Program Governance account which governs an upgradable program
    ///
    ///   0. `[]` Realm account the created Governance belongs to
    ///   1. `[writable]` Program Governance account.
    ///     * PDA seeds: ['program-governance', realm, governed_program]
    ///   2. `[]` Program governed by this Governance account
    ///   3. `[writable]` Program Data account of the Program governed by this
    ///      Governance account
    ///   4. `[signer]` Current Upgrade Authority account of the Program
    ///      governed by this Governance account
    ///   5. `[]` Governing TokenOwnerRecord account (Used only if not signed by
    ///      RealmAuthority)
    ///   6. `[signer]` Payer
    ///   7. `[]` bpf_upgradeable_loader program
    ///   8. `[]` System program
    ///   9. `[signer]` Governance authority
    ///   10. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   11. `[]` Optional Voter Weight Record
    CreateProgramGovernance {
        /// Governance config
        #[allow(dead_code)]
        config: GovernanceConfig,

        #[allow(dead_code)]
        /// Indicates whether Program's upgrade_authority should be transferred
        /// to the Governance PDA If it's set to false then it can be
        /// done at a later time However the instruction would validate
        /// the current upgrade_authority signed the transaction nonetheless
        transfer_upgrade_authority: bool,
    },

    /// Creates Proposal account for Transactions which will be executed at some
    /// point in the future
    ///
    ///   0. `[]` Realm account the created Proposal belongs to
    ///   1. `[writable]` Proposal account.
    ///     * PDA seeds ['governance',governance, governing_token_mint,
    ///       proposal_seed]
    ///   2. `[writable]` Governance account
    ///   3. `[writable]` TokenOwnerRecord account of the Proposal owner
    ///   4. `[]` Governing Token Mint the Proposal is created for
    ///   5. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   6. `[signer]` Payer
    ///   7. `[]` System program
    ///   8. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   9. `[]` Optional Voter Weight Record
    ///   10.`[writable]` Optional ProposalDeposit account.
    ///     * PDA seeds: ['proposal-deposit', proposal, deposit payer]
    ///     Proposal deposit is required when there are more active proposals
    ///     than the configured deposit exempt amount.
    ///     The deposit is paid by the Payer of the transaction and can be
    ///     reclaimed using RefundProposalDeposit once the Proposal is no
    ///     longer active.
    CreateProposal {
        #[allow(dead_code)]
        /// UTF-8 encoded name of the proposal
        name: String,

        #[allow(dead_code)]
        /// Link to a gist explaining the proposal
        description_link: String,

        #[allow(dead_code)]
        /// Proposal vote type
        vote_type: VoteType,

        #[allow(dead_code)]
        /// Proposal options
        options: Vec<String>,

        #[allow(dead_code)]
        /// Indicates whether the proposal has the deny option
        /// A proposal without the rejecting option is a non binding survey
        /// Only proposals with the rejecting option can have executable
        /// transactions
        use_deny_option: bool,

        #[allow(dead_code)]
        /// Unique seed for the Proposal PDA
        proposal_seed: Pubkey,
    },

    /// Adds a signatory to the Proposal which means this Proposal can't leave
    /// Draft state until yet another Signatory signs
    ///
    ///   0. `[]` Governance account
    ///   1. `[writable]` Proposal account associated with the governance
    ///   2. `[writable]` Signatory Record Account
    ///   3. `[signer]` Payer
    ///   4. `[]` System program
    ///   Either:
    ///      - 5. `[]` TokenOwnerRecord account of the Proposal owner
    ///        6. `[signer]` Governance Authority (Token Owner or Governance
    ///           Delegate)
    ///
    ///      - 5. `[]` RequiredSignatory account associated with the governance.
    AddSignatory {
        #[allow(dead_code)]
        /// Signatory to add to the Proposal
        signatory: Pubkey,
    },

    /// Formerly RemoveSignatory. Exists for backwards-compatibility.
    Legacy1,

    /// Inserts Transaction with a set of instructions for the Proposal at the
    /// given index position New Transaction must be inserted at the end of
    /// the range indicated by Proposal transactions_next_index
    /// If a Transaction replaces an existing Transaction at a given index then
    /// the old one must be removed using RemoveTransaction first

    ///   0. `[]` Governance account
    ///   1. `[writable]` Proposal account
    ///   2. `[]` TokenOwnerRecord account of the Proposal owner
    ///   3. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   4. `[writable]` ProposalTransaction, account.
    ///     * PDA seeds: ['governance', proposal, option_index, index]
    ///   5. `[signer]` Payer
    ///   6. `[]` System program
    ///   7. `[]` Rent sysvar
    InsertTransaction {
        #[allow(dead_code)]
        /// The index of the option the transaction is for
        option_index: u8,
        #[allow(dead_code)]
        /// Transaction index to be inserted at.
        index: u16,
        #[allow(dead_code)]
        /// Waiting time (in seconds) between vote period ending and this being
        /// eligible for execution
        hold_up_time: u32,

        #[allow(dead_code)]
        /// Instructions Data
        instructions: Vec<InstructionData>,
    },

    /// Removes Transaction from the Proposal
    ///
    ///   0. `[writable]` Proposal account
    ///   1. `[]` TokenOwnerRecord account of the Proposal owner
    ///   2. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   3. `[writable]` ProposalTransaction, account
    ///   4. `[writable]` Beneficiary Account which would receive lamports from
    ///      the disposed ProposalTransaction account
    RemoveTransaction,

    /// Cancels Proposal by changing its state to Canceled
    ///
    ///   0. `[]` Realm account
    ///   1. `[writable]` Governance account
    ///   2. `[writable]` Proposal account
    ///   3. `[writable]`  TokenOwnerRecord account of the  Proposal owner
    ///   4. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    CancelProposal,

    /// Signs off Proposal indicating the Signatory approves the Proposal
    /// When the last Signatory signs off the Proposal it enters Voting state
    /// Note: Adding signatories to a Proposal is a quality and not a security
    /// gate and it's entirely at the discretion of the Proposal owner
    /// If Proposal owner doesn't designate any signatories then can sign off
    /// the Proposal themself
    ///
    ///   0. `[]` Realm account
    ///   1. `[]` Governance account
    ///   2. `[writable]` Proposal account
    ///   3. `[signer]` Signatory account signing off the Proposal Or Proposal
    ///      owner if the owner hasn't appointed any signatories
    ///   4. `[]` TokenOwnerRecord for the Proposal owner, required when the
    ///      owner signs off the Proposal Or `[writable]` SignatoryRecord
    ///      account, required when non owner sings off the Proposal
    SignOffProposal,

    ///  Uses your voter weight (deposited Community or Council tokens) to cast
    /// a vote on a Proposal  By doing so you indicate you approve or
    /// disapprove of running the Proposal set of transactions  If you tip
    /// the consensus then the transactions can begin to be run after their hold
    /// up time
    ///
    ///   0. `[]` Realm account
    ///   1. `[writable]` Governance account
    ///   2. `[writable]` Proposal account
    ///   3. `[writable]` TokenOwnerRecord of the Proposal owner
    ///   4. `[writable]` TokenOwnerRecord of the voter.
    ///     * PDA seeds: ['governance',realm, vote_governing_token_mint,
    ///       governing_token_owner]
    ///   5. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   6. `[writable]` Proposal VoteRecord account.
    ///     * PDA seeds: ['governance',proposal,token_owner_record]
    ///   7. `[]` The Governing Token Mint which is used to cast the vote
    ///      (vote_governing_token_mint).
    ///     The voting token mint is the governing_token_mint of the Proposal
    ///     for Approve, Deny and Abstain votes.
    ///     For Veto vote the voting token mint is the mint of the opposite
    ///     voting population Council mint to veto Community proposals and
    ///     Community mint to veto Council proposals.
    ///     Note: In the current version only Council veto is supported
    ///   8. `[signer]` Payer
    ///   9. `[]` System program
    ///   10. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   11. `[]` Optional Voter Weight Record
    ///   12. `[]` Optional Max Voter Weight Record
    CastVote {
        // #[allow(dead_code)]
        // User's vote
        vote: Vote,
    },

    /// Finalizes vote in case the Vote was not automatically tipped within
    /// max_voting_time period
    ///
    ///   0. `[]` Realm account
    ///   1. `[writable]` Governance account
    ///   2. `[writable]` Proposal account
    ///   3. `[writable]` TokenOwnerRecord of the Proposal owner
    ///   4. `[]` Governing Token Mint
    ///   5. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   6. `[]` Optional Max Voter Weight Record
    FinalizeVote {},

    ///  Relinquish Vote removes voter weight from a Proposal and removes it
    /// from voter's active votes. If the Proposal is still being voted on
    /// then the voter's weight won't count towards the vote outcome. If the
    /// Proposal is already in decided state then the instruction has no impact
    /// on the Proposal and only allows voters to prune their outstanding
    /// votes in case they wanted to withdraw Governing tokens from the Realm
    ///
    ///   0. `[]` Realm account
    ///   1. `[]` Governance account
    ///   2. `[writable]` Proposal account
    ///   3. `[writable]` TokenOwnerRecord account.
    ///     * PDA seeds: ['governance',realm, vote_governing_token_mint,
    ///       governing_token_owner]
    ///   4. `[writable]` Proposal VoteRecord account.
    ///     * PDA seeds: ['governance',proposal, token_owner_record]
    ///   5. `[]` The Governing Token Mint which was used to cast the vote
    ///      (vote_governing_token_mint)
    ///   6. `[signer]` Optional Governance Authority (Token Owner or Governance
    ///      Delegate) It's required only when Proposal is still being voted on
    ///   7. `[writable]` Optional Beneficiary account which would receive
    ///      lamports when VoteRecord Account is disposed It's required only
    ///      when Proposal is still being voted on
    RelinquishVote,

    /// Executes a Transaction in the Proposal
    /// Anybody can execute transaction once Proposal has been voted Yes and
    /// transaction_hold_up time has passed The actual transaction being
    /// executed will be signed by Governance PDA the Proposal belongs to
    /// For example to execute Program upgrade the ProgramGovernance PDA would
    /// be used as the signer
    ///
    ///   0. `[]` Governance account
    ///   1. `[writable]` Proposal account
    ///   2. `[writable]` ProposalTransaction account you wish to execute
    ///   3+ Any extra accounts that are part of the transaction, in order
    ExecuteTransaction,

    /// Creates Mint Governance account which governs a mint
    ///
    ///   0. `[]` Realm account the created Governance belongs to
    ///   1. `[writable]` Mint Governance account.
    ///     * PDA seeds: ['mint-governance', realm, governed_mint]
    ///   2. `[writable]` Mint governed by this Governance account
    ///   3. `[signer]` Current Mint authority (MintTokens and optionally
    ///      FreezeAccount)
    ///   4. `[]` Governing TokenOwnerRecord account (Used only if not signed by
    ///      RealmAuthority)
    ///   5. `[signer]` Payer
    ///   6. `[]` SPL Token or SPL Token 2022 program
    ///   7. `[]` System program
    ///   8. `[signer]` Governance authority
    ///   9. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   10. `[]` Optional Voter Weight Record
    #[deprecated(since = "3.1.1", note = "please use `CreateGovernance` instead")]
    CreateMintGovernance {
        #[allow(dead_code)]
        /// Governance config
        config: GovernanceConfig,

        #[allow(dead_code)]
        /// Indicates whether Mint's authorities (MintTokens, FreezeAccount)
        /// should be transferred to the Governance PDA. If it's set to
        /// false then it can be done at a later time. However the
        /// instruction would validate the current mint authority signed the
        /// transaction nonetheless
        transfer_mint_authorities: bool,
    },

    /// Creates Token Governance account which governs a token account
    ///
    ///   0. `[]` Realm account the created Governance belongs to
    ///   1. `[writable]` Token Governance account.
    ///     * PDA seeds: ['token-governance', realm, governed_token]
    ///   2. `[writable]` Token account governed by this Governance account
    ///   3. `[signer]` Current token account authority (AccountOwner and
    ///      optionally CloseAccount)
    ///   4. `[]` Governing TokenOwnerRecord account (Used only if not signed by
    ///      RealmAuthority)
    ///   5. `[signer]` Payer
    ///   6. `[]` SPL Token or SPL Token 2022 program
    ///   7. `[]` System program
    ///   8. `[signer]` Governance authority
    ///   9. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   10. `[]` Optional Voter Weight Record
    #[deprecated(since = "3.1.1", note = "please use `CreateGovernance` instead")]
    CreateTokenGovernance {
        #[allow(dead_code)]
        /// Governance config
        config: GovernanceConfig,

        #[allow(dead_code)]
        /// Indicates whether the token account authorities (AccountOwner and
        /// optionally CloseAccount) should be transferred to the Governance PDA
        /// If it's set to false then it can be done at a later time
        /// However the instruction would validate the current token owner
        /// signed the transaction nonetheless
        transfer_account_authorities: bool,
    },

    /// Sets GovernanceConfig for a Governance
    ///
    ///   0. `[]` Realm account the Governance account belongs to
    ///   1. `[writable, signer]` The Governance account the config is for
    SetGovernanceConfig {
        #[allow(dead_code)]
        /// New governance config
        config: GovernanceConfig,
    },

    /// Flags a transaction and its parent Proposal with error status
    /// It can be used by Proposal owner in case the transaction is permanently
    /// broken and can't be executed.
    /// Note: This instruction is a workaround because currently it's not
    /// possible to catch errors from CPI calls and the Governance program has
    /// no way to know when instruction failed and flag it automatically.
    ///
    ///   0. `[writable]` Proposal account
    ///   1. `[]` TokenOwnerRecord account of the Proposal owner
    ///   2. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   3. `[writable]` ProposalTransaction account to flag
    FlagTransactionError,

    /// Sets new Realm authority
    ///
    ///   0. `[writable]` Realm account
    ///   1. `[signer]` Current Realm authority
    ///   2. `[]` New realm authority. Must be one of the realm governances when
    ///      set
    SetRealmAuthority {
        #[allow(dead_code)]
        /// Set action ( SetUnchecked, SetChecked, Remove)
        action: SetRealmAuthorityAction,
    },

    /// Sets realm config
    ///   0. `[writable]` Realm account
    ///   1. `[signer]`  Realm authority
    ///   2. `[]` Council Token Mint - optional
    ///     Note: In the current version it's only possible to remove council
    ///     mint (set it to None).
    ///     After setting council to None it won't be possible to withdraw the
    ///     tokens from the Realm any longer.
    ///     If that's required then it must be done before executing this
    ///     instruction.
    ///   3. `[writable]` Council Token Holding account - optional unless
    ///     council is used.
    ///     * PDA seeds: ['governance',realm,council_mint] The account will be
    ///     created with the Realm PDA as its owner
    ///   4. `[]` System
    ///   5. `[writable]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///   6. `[]` Optional Community Voter Weight Addin Program Id
    ///   7. `[]` Optional Max Community Voter Weight Addin Program Id
    ///   8. `[]` Optional Council Voter Weight Addin Program Id
    ///   9. `[]` Optional Max Council Voter Weight Addin Program Id
    ///   10. `[signer]` Optional Payer. Required if RealmConfig doesn't exist
    ///       and needs to be created
    SetRealmConfig {
        #[allow(dead_code)]
        /// Realm config args
        config_args: RealmConfigArgs,
    },

    /// Creates TokenOwnerRecord with 0 deposit amount
    /// It's used to register TokenOwner when voter weight addin is used and the
    /// Governance program doesn't take deposits
    ///
    ///   0. `[]` Realm account
    ///   1. `[]` Governing Token Owner account
    ///   2. `[writable]` TokenOwnerRecord account.
    ///     * PDA seeds: ['governance',realm, governing_token_mint,
    ///       governing_token_owner]
    ///   3. `[]` Governing Token Mint
    ///   4. `[signer]` Payer
    ///   5. `[]` System
    CreateTokenOwnerRecord {},

    /// Updates ProgramMetadata account
    /// The instruction dumps information implied by the program's code into a
    /// persistent account
    ///
    ///  0. `[writable]` ProgramMetadata account.
    ///     * PDA seeds: ['metadata']
    ///  1. `[signer]` Payer
    ///  2. `[]` System
    UpdateProgramMetadata {},

    /// Creates native SOL treasury account for a Governance account
    /// The account has no data and can be used as a payer for instructions
    /// signed by Governance PDAs or as a native SOL treasury
    ///
    ///  0. `[]` Governance account the treasury account is for
    ///  1. `[writable]` NativeTreasury account.
    ///     * PDA seeds: ['native-treasury', governance]
    ///  2. `[signer]` Payer
    ///  3. `[]` System
    CreateNativeTreasury,

    /// Revokes (burns) membership governing tokens for the given
    /// TokenOwnerRecord and hence takes away governance power from the
    /// TokenOwner. Note: If there are active votes for the TokenOwner then
    /// the vote weights won't be updated automatically
    ///
    ///  0. `[]` Realm account
    ///  1. `[writable]` Governing Token Holding account.
    ///     * PDA seeds: ['governance',realm, governing_token_mint]
    ///  2. `[writable]` TokenOwnerRecord account.
    ///     * PDA seeds: ['governance',realm, governing_token_mint,
    ///       governing_token_owner]
    ///  3. `[writable]` GoverningTokenMint
    ///  4. `[signer]` Revoke authority which can be either of:
    ///                1) GoverningTokenMint mint_authority to forcefully revoke
    ///                   the membership tokens
    ///                2) GoverningTokenOwner who voluntarily revokes their own
    ///                   membership
    ///  5. `[]` RealmConfig account.
    ///     * PDA seeds: ['realm-config', realm]
    ///  6. `[]` SPL Token or SPL Token 2022 program
    RevokeGoverningTokens {
        /// The amount to revoke
        #[allow(dead_code)]
        amount: u64,
    },

    /// Refunds ProposalDeposit once the given proposal is no longer active
    /// (Draft, SigningOff, Voting) Once the condition is met the
    /// instruction is permissionless and returns the deposit amount to the
    /// deposit payer
    ///
    ///   0. `[]` Proposal account
    ///   1. `[writable]` ProposalDeposit account.
    ///     * PDA seeds: ['proposal-deposit', proposal, deposit payer]
    ///   2. `[writable]` Proposal deposit payer (beneficiary) account
    RefundProposalDeposit {},

    /// Transitions an off-chain or manually executable Proposal from Succeeded
    /// into Completed state
    ///
    /// Upon a successful vote on an off-chain or manually executable proposal
    /// it remains in Succeeded state Once the external actions are executed
    /// the Proposal owner can use the instruction to manually transition it to
    /// Completed state
    ///
    ///
    ///   0. `[writable]` Proposal account
    ///   1. `[]` TokenOwnerRecord account of the Proposal owner
    ///   2. `[signer]` CompleteProposal authority (Token Owner or Delegate)
    CompleteProposal {},

    /// Adds a required signatory to the Governance, which will be applied to
    /// all proposals created with it
    ///
    ///   0. `[writable, signer]` The Governance account the config is for
    ///   1. `[writable]` RequiredSignatory Account
    ///   2. `[signer]` Payer
    ///   3. `[]` System program
    AddRequiredSignatory {
        #[allow(dead_code)]
        /// Required signatory to add to the Governance
        signatory: Pubkey,
    },

    /// Removes a required signatory from the Governance
    ///
    ///  0. `[writable, signer]` The Governance account the config is for
    ///  1. `[writable]` RequiredSignatory Account
    ///  2. `[writable]` Beneficiary Account which would receive lamports from
    ///     the disposed RequiredSignatory Account
    RemoveRequiredSignatory,

    /// Creates a Transaction Buffer with a set of instructions for the Proposal
    /// at the given index position New Transaction must be inserted at the
    /// end of the range indicated by Proposal transactions_next_index
    ///   0. `[]` Governance account
    ///   1. `[writable]` Proposal account
    ///   2. `[]` TokenOwnerRecord account of the Proposal owner
    ///   3. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   4. `[writable]` ProposalTransactionBuffer, account.
    ///     * PDA seeds: ['transaction_buffer', proposal, creator, buffer_index]
    ///   5. `[signer]` Payer
    ///   6. `[]` System program
    ///   7. `[]` Rent sysvar
    CreateTransactionBuffer {
        /// Index of the buffer account to seed the account derivation
        buffer_index: u8,
        /// Hash of the final assembled transaction message.
        // final_buffer_hash: [u8; 32],
        /// Final size of the buffer.
        final_buffer_size: u16,
        /// Initial slice of the buffer.
        buffer: Vec<u8>,
    },

    /// Extend a Transaction Buffer with a set of instructions for the Proposal
    /// at the given index position New Transaction must be inserted at the
    /// end of the range indicated by Proposal transactions_next_index
    ///   0. `[]` Governance account
    ///   1. `[]` Proposal account
    ///   2. `[writable]` ProposalTransactionBuffer, account.
    ///     * PDA seeds: ['transaction_buffer', proposal, creator, buffer_index]
    ///   3. `[signer]` Creator
    ExtendTransactionBuffer {
        /// Index of the buffer account to seed the account derivation
        buffer_index: u8,
        /// Initial slice of the buffer.
        buffer: Vec<u8>,
    },

    /// Closes a Transaction Buffer
    ///   1. `[writable]` Proposal account
    ///   2. `[]` TokenOwnerRecord account of the Proposal owner
    ///   3. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   4. `[writable]` ProposalTransactionBuffer, account.
    ///     * PDA seeds: ['transaction_buffer', proposal, creator, buffer_index]
    ///   5. `[signer]` Benificiary
    CloseTransactionBuffer {
        /// Index of the buffer account to seed the account derivation
        buffer_index: u8,
    },

    /// Creates a Versioned Transaction from Buffer Transaction for the Proposal
    /// at the given index position New Transaction must be inserted at the
    /// end of the range indicated by Proposal transactions_next_index
    ///   0. `[]` Governance account
    ///   1. `[writable]` Proposal account
    ///   2. `[]` TokenOwnerRecord account of the Proposal owner
    ///   3. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   4. `[writable]` ProposalVersionedTransaction, account.
    ///     * PDA seeds: ['version_transaction', proposal, option_index,
    ///       instruction_index]
    ///   5. `[writable]` ProposalTransactionBuffer, account.
    ///     * PDA seeds: ['transaction_buffer', proposal, creator, buffer_index]
    ///   6. `[signer]` Payer
    ///   7. `[]` System program
    ///   8. `[]` Rent sysvar
    InsertVersionedTransactionFromBuffer {
        /// The index of the option the transaction is for
        option_index: u8,
        /// Number of ephemeral signing PDAs required by the transaction.
        ephemeral_signers: u8,
        /// The index of the transaction in the proposal
        transaction_index: u16,
    },

    /// Creates a Versioned Transaction for the Proposal at the
    /// given index position New Transaction must be inserted at the end of
    /// the range indicated by Proposal transactions_next_index
    ///   0. `[]` Governance account
    ///   1. `[writable]` Proposal account
    ///   2. `[]` TokenOwnerRecord account of the Proposal owner
    ///   3. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   4. `[writable]` ProposalVersionedTransaction, account.
    ///     * PDA seeds: ['version_transaction', proposal, option_index,
    ///       instruction_index]
    ///   5. `[signer]` Payer
    ///   6. `[]` System program
    ///   7. `[]` Rent sysvar
    InsertVersionedTransaction {
        /// The index of the option the transaction is for
        option_index: u8,
        /// Number of ephemeral signing PDAs required by the transaction.
        ephemeral_signers: u8,
        /// The index of the transaction in the proposal
        transaction_index: u16,
        /// The transaction message in bytes
        transaction_message: Vec<u8>,
    },

    /// Executes a Versioned Transaction in the Proposal
    /// Anybody can execute transaction once Proposal has been voted Yes and
    /// transaction_hold_up time has passed The actual transaction being
    /// executed will be signed by Governance PDA the Proposal belongs to
    /// For example to execute Program upgrade the ProgramGovernance PDA would
    /// be used as the signer
    ///
    ///   0. `[]` Governance account
    ///   1. `[writable]` Proposal account
    ///   2. `[writable]` ProposalVersionedTransaction account you wish to
    ///      execute
    ///   `remaining_accounts` must include the following accounts in the exact
    /// order:
    ///    1. AddressLookupTable accounts in the order they appear in
    ///       `message.address_table_lookups`.
    ///    2. Accounts in the order they appear in `message.account_keys`.
    ///    3. Accounts in the order they appear in
    ///       `message.address_table_lookups`.
    ExecuteVersionedTransaction,

    /// Removes Versioned Transaction from the Proposal
    ///
    ///   0. `[writable]` Proposal account
    ///   1. `[]` TokenOwnerRecord account of the Proposal owner
    ///   2. `[signer]` Governance Authority (Token Owner or Governance
    ///      Delegate)
    ///   3. `[writable]` ProposalVersionedTransaction account
    ///   4. `[writable]` Beneficiary Account which would receive lamports from
    ///      the disposed ProposalVersionedTransaction account
    RemoveVersionedTransaction,
}

// impl TryFrom<&[u8]> for GovernanceInstruction {
//     type Error = ProgramError;

//     fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
//         if input.is_empty() {
//             return Err(ProgramError::InvalidInstructionData);
//         }

//         let (&discriminator, remaining) = input
//             .split_first()
//             .ok_or(ProgramError::InvalidInstructionData)?;

//         match discriminator {
//             // CreateRealm
//             0 => {
//                 let real_config_args_len = RealmConfigArgs::LEN;
//                 // Deserialize RealmConfigArgs using bincode from the data
//                 let config_args: &RealmConfigArgs =
//                     unsafe { load_data_unchecked(&remaining[..real_config_args_len])? };

//                 // Get the name from the remainder of the data
//                 let name_data = &remaining[real_config_args_len..];

//                 let name = String::from_utf8(name_data.to_vec())
//                     .map_err(|_| ProgramError::InvalidInstructionData)?;

//                 Ok(GovernanceInstruction::CreateRealm { name, config_args: config_args.clone() })
//             }

//             // DepositGoverningTokens
//             1 => {
//                 if remaining.len() < 8 {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let amount = u64::from_le_bytes(
//                     remaining.try_into()
//                         .map_err(|_| ProgramError::InvalidInstructionData)?,
//                 );

//                 Ok(GovernanceInstruction::DepositGoverningTokens { amount })
//             }

//             // WithdrawGoverningTokens
//             2 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::WithdrawGoverningTokens {})
//             }

//             // SetGovernanceDelegate
//             3 => {
//                 if remaining.len() == 33 {
//                     let new_governance_delegate_pubkey: Pubkey = remaining[1..33]
//                         .try_into()
//                         .map_err(|_| ProgramError::InvalidInstructionData)?;
//                     let new_governance_delegate = Some(new_governance_delegate_pubkey);

//                     Ok(GovernanceInstruction::SetGovernanceDelegate {
//                         new_governance_delegate,
//                     })
//                 } else if remaining.is_empty() {
//                     Ok(GovernanceInstruction::SetGovernanceDelegate {
//                         new_governance_delegate: None,
//                     })
//                 } else {
//                     Err(ProgramError::InvalidInstructionData)
//                 }
//             }

//             // CreateGovernance
//             4 => {
//                 let config: &GovernanceConfig = unsafe { load_data_unchecked(&remaining)? };
//                 Ok(GovernanceInstruction::CreateGovernance { config: *config })
//             }

//             // CreateProgramGovernance
//             5 => {
//                 if remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 let config_data_len = GovernanceConfig::LEN;
//                 let config: GovernanceConfig = unsafe { *load_data_unchecked(&remaining)? };

//                 let transfer_upgrade_authority = remaining[config_data_len] != 0;

//                 Ok(GovernanceInstruction::CreateProgramGovernance {
//                     config,
//                     transfer_upgrade_authority,
//                 })
//             }

//             // CreateProposal
//             6 => {
//                 // Deserialize proposal data from the binary format
//                 let proposal_data_size = remaining.len();
//                 if proposal_data_size < 4 {
//                     // At least need some data for minimal struct
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 // First we need to parse out the lengths of name and description
//                 let name_len = u32::from_le_bytes(
//                     remaining[0..4]
//                         .try_into()
//                         .map_err(|_| ProgramError::InvalidInstructionData)?,
//                 ) as usize;

//                 if proposal_data_size < 4 + name_len + 4 {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let name_end = 4 + name_len;
//                 let name = String::from_utf8(remaining[4..name_end].to_vec())
//                     .map_err(|_| ProgramError::InvalidInstructionData)?;

//                 let desc_len = u32::from_le_bytes(
//                     remaining[name_end..name_end + 4]
//                         .try_into()
//                         .map_err(|_| ProgramError::InvalidInstructionData)?,
//                 ) as usize;

//                 if proposal_data_size < name_end + 4 + desc_len + 1 {
//                     // +1 for vote_type
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let desc_end = name_end + 4 + desc_len;
//                 let description_link = String::from_utf8(remaining[name_end + 4..desc_end].to_vec())
//                     .map_err(|_| ProgramError::InvalidInstructionData)?;

//                 let vote_type_end = desc_end + 1;
//                 let vote_type = VoteType::try_from(&remaining[desc_end..vote_type_end])?;

//                 // Read the options count
//                 let options_count_end = vote_type_end + 4;
//                 if proposal_data_size < options_count_end {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let options_count = u32::from_le_bytes(
//                     remaining[vote_type_end..options_count_end]
//                         .try_into()
//                         .map_err(|_| ProgramError::InvalidInstructionData)?,
//                 ) as usize;

//                 // Parse the options
//                 let mut options = Vec::with_capacity(options_count);
//                 let mut current_pos = options_count_end;

//                 for _ in 0..options_count {
//                     if current_pos + 4 > proposal_data_size {
//                         return Err(ProgramError::InvalidInstructionData);
//                     }

//                     let option_len = u32::from_le_bytes(
//                         remaining[current_pos..current_pos + 4]
//                             .try_into()
//                             .map_err(|_| ProgramError::InvalidInstructionData)?,
//                     ) as usize;

//                     current_pos += 4;

//                     if current_pos + option_len > proposal_data_size {
//                         return Err(ProgramError::InvalidInstructionData);
//                     }

//                     let option =
//                         String::from_utf8(remaining[current_pos..current_pos + option_len].to_vec())
//                             .map_err(|_| ProgramError::InvalidInstructionData)?;

//                     options.push(option);
//                     current_pos += option_len;
//                 }

//                 // Parse use_deny_option
//                 if current_pos >= proposal_data_size {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let use_deny_option = remaining[current_pos] != 0;
//                 current_pos += 1;

//                 // Parse proposal_seed
//                 if current_pos + 32 > proposal_data_size {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let proposal_seed: Pubkey = remaining[current_pos..]
//                     .try_into()
//                     .map_err(|_| ProgramError::InvalidInstructionData)?;

//                 Ok(GovernanceInstruction::CreateProposal {
//                     name,
//                     description_link,
//                     vote_type,
//                     options,
//                     use_deny_option,
//                     proposal_seed,
//                 })
//             }

//             // AddSignatory
//             7 => {
//                 if remaining.len() != 32 {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let signatory: Pubkey = remaining
//                     .try_into()
//                     .map_err(|_| ProgramError::InvalidInstructionData)?;

//                 Ok(GovernanceInstruction::AddSignatory { signatory })
//             }

//             // InsertTransaction
//             8 => {
//                 if remaining.len() < 7 {
//                     // Need at least option_index(1) + index(2) + hold_up_time(4)
//                     return Err(ProgramError::InvalidInstructionData);
//                 }

//                 let option_index = remaining[0];

//                 let index = u16::from_le_bytes(
//                     remaining[1..3]
//                         .try_into()
//                         .map_err(|_| ProgramError::InvalidInstructionData)?,
//                 );

//                 let hold_up_time = u32::from_le_bytes(
//                     remaining[3..7]
//                         .try_into()
//                         .map_err(|_| ProgramError::InvalidInstructionData)?,
//                 );

//                 let instructions = InstructionData::vec_from_bytes(&remaining[7..])
//                     .map_err(|_| ProgramError::InvalidInstructionData)?;

//                 Ok(GovernanceInstruction::InsertTransaction {
//                     option_index,
//                     index,
//                     hold_up_time,
//                     instructions,
//                 })
//             }

//             // RemoveTransaction
//             9 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::RemoveTransaction)
//             }

//             // CancelProposal
//             10 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::CancelProposal)
//             }

//             // SignOffProposal
//             11 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::SignOffProposal)
//             }

//             // CastVote
//             12 => {
//                 let vote =
//                     Vote::from_bytes(remaining).map_err(|_| ProgramError::InvalidInstructionData)?;

//                 Ok(GovernanceInstruction::CastVote { vote })
//             }

//             // FinalizeVote
//             13 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::FinalizeVote {})
//             }

//             // RelinquishVote
//             14 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::RelinquishVote)
//             }

//             // ExecuteTransaction
//             15 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::ExecuteTransaction)
//             }

//             // CreateMintGovernance - deprecated but still supported
//             16 => {
//                 let config_data_len = remaining.len() - 1;
//                 let config =
//                     unsafe { load_acc_unchecked::<GovernanceConfig>(&remaining[..config_data_len])? };

//                 let transfer_mint_authorities = remaining[config_data_len] != 0;

//                 #[allow(deprecated)]
//                 Ok(GovernanceInstruction::CreateMintGovernance {
//                     config,
//                     transfer_mint_authorities,
//                 })
//             }

//             // RemoveVersionedTransaction
//             17 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::RemoveVersionedTransaction)
//             }

//             // ExecuteVersionedTransaction
//             18 => {
//                 if !remaining.is_empty() {
//                     return Err(ProgramError::InvalidInstructionData);
//                 }
//                 Ok(GovernanceInstruction::ExecuteVersionedTransaction)
//             }

//             _ => Err(ProgramError::InvalidInstructionData),
//         }
//     }
// }

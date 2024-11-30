// #![cfg(feature = "test-sbf")]

mod program_test;

use {
    program_test::*,
    solana_program_test::tokio,
    spl_governance::{error::GovernanceError, state::{enums::{ProposalState, TransactionExecutionStatus}, proposal::MAX_LIVE_PROPOSAL_DURATION}},
};


#[tokio::test]
async fn test_execute_transfer_transaction() {
    // Arrange
    let mut governance_test = GovernanceProgramTest::start_new().await;

    let realm_cookie = governance_test.with_realm().await;

    let token_owner_record_cookie = governance_test
        .with_community_token_deposit(&realm_cookie)
        .await
        .unwrap();

    let mut governance_cookie = governance_test
        .with_governance(&realm_cookie, &token_owner_record_cookie)
        .await
        .unwrap();

    let governed_token_account_cookie = governance_test
        .with_governed_token_account(&governance_cookie)
        .await;

    let mut proposal_cookie = governance_test
        .with_proposal(&token_owner_record_cookie, &mut governance_cookie)
        .await
        .unwrap();

    let signatory_record_cookie = governance_test
        .with_signatory(
            &proposal_cookie,
            &governance_cookie,
            &token_owner_record_cookie,
        )
        .await
        .unwrap();

    let (proposal_transaction_cookie_1, proposal_transaction_cookie_2) = governance_test
        .with_multiple_transfer_tokens_transaction(
            &governed_token_account_cookie,
            &mut proposal_cookie,
            &token_owner_record_cookie,
            None,
        )
        .await
        .unwrap();

    governance_test
        .sign_off_proposal(&proposal_cookie, &signatory_record_cookie)
        .await
        .unwrap();

    governance_test
        .with_cast_yes_no_vote(&proposal_cookie, &token_owner_record_cookie, YesNoVote::Yes)
        .await
        .unwrap();

    // Advance timestamp past hold_up_time
    governance_test
        .advance_clock_by_min_timespan(
            governance_cookie.account.config.transactions_hold_up_time as u64,
        )
        .await;

    let clock = governance_test.bench.get_clock().await;

    // Act
    governance_test
        .execute_proposal_transaction(&proposal_cookie, &proposal_transaction_cookie_1)
        .await
        .unwrap();

    // Assert

    let proposal_account = governance_test
        .get_proposal_account(&proposal_cookie.address)
        .await;

    let yes_option = proposal_account.options.first().unwrap();

    assert_eq!(1, yes_option.transactions_executed_count);
    assert_eq!(ProposalState::Executing, proposal_account.state);
    assert_eq!(None, proposal_account.closed_at);
    assert_eq!(Some(clock.unix_timestamp), proposal_account.executing_at);

    let proposal_transaction_account = governance_test
        .get_proposal_transaction_account(&proposal_transaction_cookie_1.address)
        .await;

    assert_eq!(
        Some(clock.unix_timestamp),
        proposal_transaction_account.executed_at
    );

    assert_eq!(
        TransactionExecutionStatus::Success,
        proposal_transaction_account.execution_status
    );

    let instruction_token_account = governance_test
        .get_token_account(&proposal_transaction_cookie_1.account.instructions[0].accounts[1].pubkey)
        .await;

    assert_eq!(15, instruction_token_account.amount);


    // Advance clock past hold_up_time
    governance_test
        .advance_clock_by_min_timespan(
            (MAX_LIVE_PROPOSAL_DURATION + 1) as u64
        )
        .await;

    // Act
    let err = governance_test
        .execute_proposal_transaction(&proposal_cookie, &proposal_transaction_cookie_2)
        .await
        .err()
        .unwrap();

    // Assert

    assert_eq!(err, GovernanceError::CannotExecuteAnExpiredProposal.into());

    governance_test
        .expire_proposal(&proposal_cookie, &token_owner_record_cookie)
        .await
        .unwrap();

    // Assert
    let proposal_account = governance_test
        .get_proposal_account(&proposal_cookie.address)
        .await;

    let clock = governance_test.bench.get_clock().await;
    assert_eq!(ProposalState::Expired, proposal_account.state);
    assert_eq!(Some(clock.unix_timestamp), proposal_account.closed_at);

    let token_owner_record_account = governance_test
        .get_token_owner_record_account(&token_owner_record_cookie.address)
        .await;

    assert_eq!(0, token_owner_record_account.outstanding_proposal_count);

    let governance_account = governance_test
        .get_governance_account(&governance_cookie.address)
        .await;

    assert_eq!(0, governance_account.active_proposal_count);
    
}


#[tokio::test]
async fn test_expire_proposal() {
    // Arrange
    let mut governance_test = GovernanceProgramTest::start_new().await;

    let realm_cookie = governance_test.with_realm().await;

    let token_owner_record_cookie = governance_test
        .with_community_token_deposit(&realm_cookie)
        .await
        .unwrap();

    let mut governance_cookie = governance_test
        .with_governance(&realm_cookie, &token_owner_record_cookie)
        .await
        .unwrap();

    let proposal_cookie = governance_test
        .with_proposal(&token_owner_record_cookie, &mut governance_cookie)
        .await
        .unwrap();

    let signatory_record_cookie = governance_test
        .with_signatory(
            &proposal_cookie,
            &governance_cookie,
            &token_owner_record_cookie,
        )
        .await
        .unwrap();

    governance_test
        .sign_off_proposal(&proposal_cookie, &signatory_record_cookie)
        .await
        .unwrap();

    governance_test
        .with_cast_yes_no_vote(&proposal_cookie, &token_owner_record_cookie, YesNoVote::Yes)
        .await
        .unwrap();


    governance_test
        .advance_clock_by_min_timespan(
            (MAX_LIVE_PROPOSAL_DURATION + 1) as u64
        )
        .await;
    // Act
    governance_test
        .expire_proposal(&proposal_cookie, &token_owner_record_cookie)
        .await
        .unwrap();

    // Assert
    let proposal_account = governance_test
        .get_proposal_account(&proposal_cookie.address)
        .await;

    let clock = governance_test.bench.get_clock().await;
    assert_eq!(ProposalState::Expired, proposal_account.state);
    assert_eq!(Some(clock.unix_timestamp), proposal_account.closed_at);

    let token_owner_record_account = governance_test
        .get_token_owner_record_account(&token_owner_record_cookie.address)
        .await;

    assert_eq!(0, token_owner_record_account.outstanding_proposal_count);

    let governance_account = governance_test
        .get_governance_account(&governance_cookie.address)
        .await;

    assert_eq!(0, governance_account.active_proposal_count);
}

#[tokio::test]
async fn test_expire_proposal_with_proposal_has_not_expired() {
    // Arrange
    let mut governance_test = GovernanceProgramTest::start_new().await;

    let realm_cookie = governance_test.with_realm().await;

    let token_owner_record_cookie = governance_test
        .with_community_token_deposit(&realm_cookie)
        .await
        .unwrap();

    let mut governance_cookie = governance_test
        .with_governance(&realm_cookie, &token_owner_record_cookie)
        .await
        .unwrap();

    let proposal_cookie = governance_test
        .with_proposal(&token_owner_record_cookie, &mut governance_cookie)
        .await
        .unwrap();

    // Act
    let err = governance_test
        .expire_proposal(&proposal_cookie, &token_owner_record_cookie)
        .await
        .err()
        .unwrap();

    // Assert

    assert_eq!(
        err,
        GovernanceError::ProposalHasNotExpired.into()
    );
}


#[tokio::test]
async fn test_expire_proposal_after_voting_cool_off_with_vote_time_expired_error() {
    // Arrange
    let mut governance_test = GovernanceProgramTest::start_new().await;

    let realm_cookie = governance_test.with_realm().await;

    let token_owner_record_cookie = governance_test
        .with_community_token_deposit(&realm_cookie)
        .await
        .unwrap();

    // Set none default voting cool off time
    let mut governance_config = governance_test.get_default_governance_config();
    governance_config.voting_cool_off_time = 10;

    let mut governance_cookie = governance_test
        .with_governance_using_config(
            &realm_cookie,
            &token_owner_record_cookie,
            &governance_config,
        )
        .await
        .unwrap();

    let clock = governance_test.bench.get_clock().await;

    let proposal_cookie = governance_test
        .with_signed_off_proposal(&token_owner_record_cookie, &mut governance_cookie)
        .await
        .unwrap();

    // Advance timestamp past max_voting_time
    governance_test
        .advance_clock_past_timestamp(
            (MAX_LIVE_PROPOSAL_DURATION) as i64
                + clock.unix_timestamp,
        )
        .await;

    // Act

    let err = governance_test
        .expire_proposal(&proposal_cookie, &token_owner_record_cookie)
        .await
        .err()
        .unwrap();

    // Assert

    assert_eq!(err, GovernanceError::ProposalHasNotExpired.into());
}
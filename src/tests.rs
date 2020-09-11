use super::{
    storage::{
        default_portfolio_btreeset, make_account_without_cdd, register_keyring_account,
        user_portfolio_btreeset, TestStorage,
    },
    ExtBuilder,
};

use pallet_asset::{self as asset, AssetType};
use pallet_balances as balances;
use pallet_compliance_manager as compliance_manager;
use pallet_identity as identity;
use pallet_portfolio::MovePortfolioItem;
use pallet_settlement::{
    self as settlement, weight_for, AuthorizationStatus, Call as SettlementCall, Instruction,
    InstructionStatus, Leg, LegStatus, Receipt, ReceiptDetails, SettlementType, VenueDetails,
    VenueType,
};
use polymesh_primitives::{
    Claim, Condition, ConditionType, IdentityId, PortfolioId, PortfolioName, Ticker,
};

use codec::Encode;
use frame_support::dispatch::GetDispatchInfo;
use frame_support::{assert_noop, assert_ok};
use rand::{prelude::*, thread_rng};
use sp_core::sr25519::Public;
use sp_runtime::AnySignature;
use sp_std::collections::btree_set::BTreeSet;
use std::collections::HashMap;
use std::convert::TryFrom;
use test_client::AccountKeyring;

type Identity = identity::Module<TestStorage>;
type Balances = balances::Module<TestStorage>;
type Asset = asset::Module<TestStorage>;
type Portfolio = pallet_portfolio::Module<TestStorage>;
type Timestamp = pallet_timestamp::Module<TestStorage>;
type ComplianceManager = compliance_manager::Module<TestStorage>;
type AssetError = asset::Error<TestStorage>;
type OffChainSignature = AnySignature;
type Origin = <TestStorage as frame_system::Trait>::Origin;
type DidRecords = identity::DidRecords<TestStorage>;
type Settlement = settlement::Module<TestStorage>;
type System = frame_system::Module<TestStorage>;
type Error = settlement::Error<TestStorage>;

macro_rules! assert_add_claim {
    ($signer:expr, $target:expr, $claim:expr) => {
        assert_ok!(Identity::add_claim($signer, $target, $claim, None,));
    };
}

fn init(token_name: &[u8], ticker: Ticker, keyring: Public) -> u64 {
    create_token(token_name, ticker, keyring);
    let venue_counter = Settlement::venue_counter();
    assert_ok!(Settlement::create_venue(
        Origin::signed(keyring),
        VenueDetails::default(),
        vec![keyring],
        VenueType::Other
    ));
    venue_counter
}

fn create_token(token_name: &[u8], ticker: Ticker, keyring: Public) {
    assert_ok!(Asset::create_asset(
        Origin::signed(keyring),
        token_name.into(),
        ticker,
        100_000,
        true,
        AssetType::default(),
        vec![],
        None,
    ));
    assert_ok!(ComplianceManager::add_compliance_requirement(
        Origin::signed(keyring),
        ticker,
        vec![],
        vec![]
    ));
}

fn next_block() {
    let block_number = System::block_number() + 1;
    System::set_block_number(block_number);
    Settlement::on_initialize(block_number);
}

#[test]
fn venue_registration() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let venue_counter = Settlement::venue_counter();
            assert_ok!(Settlement::create_venue(
                alice_signed.clone(),
                VenueDetails::default(),
                vec![AccountKeyring::Alice.public(), AccountKeyring::Bob.public()],
                VenueType::Exchange
            ));
            let venue_info = Settlement::venue_info(venue_counter);
            assert_eq!(Settlement::venue_counter(), venue_counter + 1);
            assert_eq!(Settlement::user_venues(alice_did), [venue_counter]);
            assert_eq!(venue_info.creator, alice_did);
            assert_eq!(venue_info.instructions.len(), 0);
            assert_eq!(venue_info.details, VenueDetails::default());
            assert_eq!(venue_info.venue_type, VenueType::Exchange);
            assert_eq!(
                Settlement::venue_signers(venue_counter, AccountKeyring::Alice.public()),
                true
            );
            assert_eq!(
                Settlement::venue_signers(venue_counter, AccountKeyring::Bob.public()),
                true
            );
            assert_eq!(
                Settlement::venue_signers(venue_counter, AccountKeyring::Charlie.public()),
                false
            );

            // Creating a second venue
            assert_ok!(Settlement::create_venue(
                alice_signed.clone(),
                VenueDetails::default(),
                vec![AccountKeyring::Alice.public(), AccountKeyring::Bob.public()],
                VenueType::Exchange
            ));
            assert_eq!(
                Settlement::user_venues(alice_did),
                [venue_counter, venue_counter + 1]
            );

            // Editing venue details
            assert_ok!(Settlement::edit_venue(
                alice_signed,
                venue_counter,
                Some([0x01].into()),
                None
            ));
            let venue_info = Settlement::venue_info(venue_counter);
            assert_eq!(venue_info.creator, alice_did);
            assert_eq!(venue_info.instructions.len(), 0);
            assert_eq!(venue_info.details, [0x01].into());
            assert_eq!(venue_info.venue_type, VenueType::Exchange);
        });
}

#[test]
fn basic_settlement() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let amount = 100u128;
            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                vec![Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount
                }]
            ));
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));

            // Instruction should've settled
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - amount
            );
            assert_eq!(
                Asset::balance_of(&ticker, bob_did),
                bob_init_balance + amount
            );
        });
}

#[test]
fn create_and_authorize_instruction() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let amount = 100u128;
            assert_ok!(Settlement::add_and_authorize_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                vec![Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount
                }],
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);

            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );

            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));

            // Instruction should've settled
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - amount
            );
            assert_eq!(
                Asset::balance_of(&ticker, bob_did),
                bob_init_balance + amount
            );
        });
}

#[test]
fn overdraft_failure() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let _bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let amount = 100_000_000u128;
            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                vec![Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount
                }]
            ));
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_noop!(
                Settlement::authorize_instruction(
                    alice_signed.clone(),
                    instruction_counter,
                    default_portfolio_btreeset(alice_did)
                ),
                Error::FailedToLockTokens
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        });
}

#[test]
fn token_swap() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let token_name2 = b"ACME2";
            let ticker2 = Ticker::try_from(&token_name2[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            init(token_name2, ticker2, AccountKeyring::Bob.public());

            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let alice_init_balance2 = Asset::balance_of(&ticker2, alice_did);
            let bob_init_balance2 = Asset::balance_of(&ticker2, bob_did);

            let amount = 100u128;
            let legs = vec![
                Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount,
                },
                Leg {
                    from: PortfolioId::default_portfolio(bob_did),
                    to: PortfolioId::default_portfolio(alice_did),
                    asset: ticker2,
                    amount: amount,
                },
            ];

            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                legs.clone()
            ));

            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );

            for i in 0..legs.len() {
                assert_eq!(
                    Settlement::instruction_legs(
                        instruction_counter,
                        u64::try_from(i).unwrap_or_default()
                    ),
                    legs[i]
                );
            }

            let instruction_details = Instruction {
                instruction_id: instruction_counter,
                venue_id: venue_counter,
                status: InstructionStatus::Pending,
                settlement_type: SettlementType::SettleOnAuthorization,
                created_at: Some(Timestamp::get()),
                valid_from: None,
            };
            assert_eq!(
                Settlement::instruction_details(instruction_counter),
                instruction_details
            );
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                2
            );
            assert_eq!(
                Settlement::venue_info(venue_counter).instructions,
                vec![instruction_counter]
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::unauthorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                2
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );

            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));

            // Instruction should've settled
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - amount
            );
            assert_eq!(
                Asset::balance_of(&ticker, bob_did),
                bob_init_balance + amount
            );
            assert_eq!(
                Asset::balance_of(&ticker2, alice_did),
                alice_init_balance2 + amount
            );
            assert_eq!(
                Asset::balance_of(&ticker2, bob_did),
                bob_init_balance2 - amount
            );
        });
}

#[test]
fn claiming_receipt() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let token_name2 = b"ACME2";
            let ticker2 = Ticker::try_from(&token_name2[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            init(token_name2, ticker2, AccountKeyring::Bob.public());

            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let alice_init_balance2 = Asset::balance_of(&ticker2, alice_did);
            let bob_init_balance2 = Asset::balance_of(&ticker2, bob_did);

            let amount = 100u128;
            let legs = vec![
                Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount,
                },
                Leg {
                    from: PortfolioId::default_portfolio(bob_did),
                    to: PortfolioId::default_portfolio(alice_did),
                    asset: ticker2,
                    amount: amount,
                },
            ];

            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                legs.clone()
            ));

            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );

            for i in 0..legs.len() {
                assert_eq!(
                    Settlement::instruction_legs(
                        instruction_counter,
                        u64::try_from(i).unwrap_or_default()
                    ),
                    legs[i]
                );
            }

            let instruction_details = Instruction {
                instruction_id: instruction_counter,
                venue_id: venue_counter,
                status: InstructionStatus::Pending,
                settlement_type: SettlementType::SettleOnAuthorization,
                created_at: Some(Timestamp::get()),
                valid_from: None,
            };
            assert_eq!(
                Settlement::instruction_details(instruction_counter),
                instruction_details
            );
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                2
            );
            assert_eq!(
                Settlement::venue_info(venue_counter).instructions,
                vec![instruction_counter]
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            let msg = Receipt {
                receipt_uid: 0,
                from: PortfolioId::default_portfolio(alice_did),
                to: PortfolioId::default_portfolio(bob_did),
                asset: ticker,
                amount: amount,
            };

            assert_noop!(
                Settlement::claim_receipt(
                    alice_signed.clone(),
                    instruction_counter,
                    ReceiptDetails {
                        receipt_uid: 0,
                        leg_id: 0,
                        signer: AccountKeyring::Alice.public(),
                        signature: OffChainSignature::from(
                            AccountKeyring::Alice.sign(&msg.encode())
                        )
                    }
                ),
                Error::LegNotPending
            );

            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            let msg2 = Receipt {
                receipt_uid: 0,
                from: PortfolioId::default_portfolio(alice_did),
                to: PortfolioId::default_portfolio(alice_did),
                asset: ticker,
                amount: amount,
            };

            assert_noop!(
                Settlement::claim_receipt(
                    alice_signed.clone(),
                    instruction_counter,
                    ReceiptDetails {
                        receipt_uid: 0,
                        leg_id: 0,
                        signer: AccountKeyring::Alice.public(),
                        signature: OffChainSignature::from(
                            AccountKeyring::Alice.sign(&msg2.encode())
                        )
                    }
                ),
                Error::InvalidSignature
            );

            // Claiming, unclaiming and claiming receipt
            assert_ok!(Settlement::claim_receipt(
                alice_signed.clone(),
                instruction_counter,
                ReceiptDetails {
                    receipt_uid: 0,
                    leg_id: 0,
                    signer: AccountKeyring::Alice.public(),
                    signature: OffChainSignature::from(AccountKeyring::Alice.sign(&msg.encode()))
                }
            ));

            assert_eq!(
                Settlement::receipts_used(AccountKeyring::Alice.public(), 0),
                true
            );
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionToBeSkipped(AccountKeyring::Alice.public(), 0)
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::unclaim_receipt(
                alice_signed.clone(),
                instruction_counter,
                0
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::claim_receipt(
                alice_signed.clone(),
                instruction_counter,
                ReceiptDetails {
                    receipt_uid: 0,
                    leg_id: 0,
                    signer: AccountKeyring::Alice.public(),
                    signature: OffChainSignature::from(AccountKeyring::Alice.sign(&msg.encode()))
                }
            ));

            assert_eq!(
                Settlement::receipts_used(AccountKeyring::Alice.public(), 0),
                true
            );
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionToBeSkipped(AccountKeyring::Alice.public(), 0)
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));

            // Instruction should've settled
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(
                Asset::balance_of(&ticker2, alice_did),
                alice_init_balance2 + amount
            );
            assert_eq!(
                Asset::balance_of(&ticker2, bob_did),
                bob_init_balance2 - amount
            );
        });
}

#[test]
fn settle_on_block() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let token_name2 = b"ACME2";
            let ticker2 = Ticker::try_from(&token_name2[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            init(token_name2, ticker2, AccountKeyring::Bob.public());
            let block_number = System::block_number() + 1;

            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let alice_init_balance2 = Asset::balance_of(&ticker2, alice_did);
            let bob_init_balance2 = Asset::balance_of(&ticker2, bob_did);

            let amount = 100u128;
            let legs = vec![
                Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount,
                },
                Leg {
                    from: PortfolioId::default_portfolio(bob_did),
                    to: PortfolioId::default_portfolio(alice_did),
                    asset: ticker2,
                    amount: amount,
                },
            ];

            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnBlock(block_number),
                None,
                legs.clone()
            ));

            assert_eq!(
                Settlement::scheduled_instructions(block_number),
                vec![instruction_counter]
            );

            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );

            for i in 0..legs.len() {
                assert_eq!(
                    Settlement::instruction_legs(
                        instruction_counter,
                        u64::try_from(i).unwrap_or_default()
                    ),
                    legs[i]
                );
            }

            let instruction_details = Instruction {
                instruction_id: instruction_counter,
                venue_id: venue_counter,
                status: InstructionStatus::Pending,
                settlement_type: SettlementType::SettleOnBlock(block_number),
                created_at: Some(Timestamp::get()),
                valid_from: None,
            };
            assert_eq!(
                Settlement::instruction_details(instruction_counter),
                instruction_details
            );
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                2
            );
            assert_eq!(
                Settlement::venue_info(venue_counter).instructions,
                vec![instruction_counter]
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                0
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(bob_did), &ticker2),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            next_block();

            // Instruction should've settled
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - amount
            );
            assert_eq!(
                Asset::balance_of(&ticker, bob_did),
                bob_init_balance + amount
            );
            assert_eq!(
                Asset::balance_of(&ticker2, alice_did),
                alice_init_balance2 + amount
            );
            assert_eq!(
                Asset::balance_of(&ticker2, bob_did),
                bob_init_balance2 - amount
            );
        });
}

#[test]
fn failed_execution() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let token_name2 = b"ACME2";
            let ticker2 = Ticker::try_from(&token_name2[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            init(token_name2, ticker2, AccountKeyring::Bob.public());
            assert_ok!(ComplianceManager::reset_asset_compliance(
                Origin::signed(AccountKeyring::Bob.public()),
                ticker2,
            ));
            let block_number = System::block_number() + 1;

            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let alice_init_balance2 = Asset::balance_of(&ticker2, alice_did);
            let bob_init_balance2 = Asset::balance_of(&ticker2, bob_did);

            let amount = 100u128;
            let legs = vec![
                Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount,
                },
                Leg {
                    from: PortfolioId::default_portfolio(bob_did),
                    to: PortfolioId::default_portfolio(alice_did),
                    asset: ticker2,
                    amount: amount,
                },
            ];

            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnBlock(block_number),
                None,
                legs.clone()
            ));

            assert_eq!(
                Settlement::scheduled_instructions(block_number),
                vec![instruction_counter]
            );

            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );

            for i in 0..legs.len() {
                assert_eq!(
                    Settlement::instruction_legs(
                        instruction_counter,
                        u64::try_from(i).unwrap_or_default()
                    ),
                    legs[i]
                );
            }

            let instruction_details = Instruction {
                instruction_id: instruction_counter,
                venue_id: venue_counter,
                status: InstructionStatus::Pending,
                settlement_type: SettlementType::SettleOnBlock(block_number),
                created_at: Some(Timestamp::get()),
                valid_from: None,
            };
            assert_eq!(
                Settlement::instruction_details(instruction_counter),
                instruction_details
            );
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                2
            );
            assert_eq!(
                Settlement::venue_info(venue_counter).instructions,
                vec![instruction_counter]
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::PendingTokenLock
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));
            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                0
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::ExecutionPending
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(bob_did), &ticker2),
                amount
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            next_block();

            // Instruction should've settled
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(bob_did), &ticker2),
                0
            );
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);
        });
}

#[test]
fn venue_filtering() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            let block_number = System::block_number() + 1;
            let instruction_counter = Settlement::instruction_counter();

            let legs = vec![Leg {
                from: PortfolioId::default_portfolio(alice_did),
                to: PortfolioId::default_portfolio(bob_did),
                asset: ticker,
                amount: 10,
            }];
            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnBlock(block_number),
                None,
                legs.clone()
            ));
            assert_ok!(Settlement::set_venue_filtering(
                alice_signed.clone(),
                ticker,
                true
            ));
            assert_noop!(
                Settlement::add_instruction(
                    alice_signed.clone(),
                    venue_counter,
                    SettlementType::SettleOnBlock(block_number),
                    None,
                    legs.clone()
                ),
                Error::UnauthorizedVenue
            );
            assert_ok!(Settlement::allow_venues(
                alice_signed.clone(),
                ticker,
                vec![venue_counter]
            ));
            assert_ok!(Settlement::add_and_authorize_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnBlock(block_number + 1),
                None,
                legs.clone(),
                default_portfolio_btreeset(alice_did)
            ));
            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));
            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));
            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter + 1,
                default_portfolio_btreeset(bob_did)
            ));
            next_block();
            assert_eq!(Asset::balance_of(&ticker, bob_did), 10);
            assert_ok!(Settlement::disallow_venues(
                alice_signed.clone(),
                ticker,
                vec![venue_counter]
            ));
            next_block();
            // Second instruction fails to settle due to venue being not whitelisted
            assert_eq!(Asset::balance_of(&ticker, bob_did), 10);
        });
}

#[test]
fn basic_fuzzing() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let charlie_signed = Origin::signed(AccountKeyring::Charlie.public());
            let charlie_did = register_keyring_account(AccountKeyring::Charlie).unwrap();
            let dave_signed = Origin::signed(AccountKeyring::Dave.public());
            let dave_did = register_keyring_account(AccountKeyring::Dave).unwrap();
            let venue_counter = Settlement::venue_counter();
            assert_ok!(Settlement::create_venue(
                Origin::signed(AccountKeyring::Alice.public()),
                VenueDetails::default(),
                vec![AccountKeyring::Alice.public()],
                VenueType::Other
            ));
            let mut tickers = Vec::with_capacity(40);
            let mut balances = HashMap::with_capacity(320);
            let dids = vec![alice_did, bob_did, charlie_did, dave_did];
            let signers = vec![
                alice_signed.clone(),
                bob_signed.clone(),
                charlie_signed.clone(),
                dave_signed.clone(),
            ];

            for i in 0..10 {
                let mut token_name = [123u8 + u8::try_from(i * 4 + 0).unwrap()];
                tickers.push(Ticker::try_from(&token_name[..]).unwrap());
                create_token(
                    &token_name[..],
                    tickers[i * 4 + 0],
                    AccountKeyring::Alice.public(),
                );

                token_name = [123u8 + u8::try_from(i * 4 + 1).unwrap()];
                tickers.push(Ticker::try_from(&token_name[..]).unwrap());
                create_token(
                    &token_name[..],
                    tickers[i * 4 + 1],
                    AccountKeyring::Bob.public(),
                );

                token_name = [123u8 + u8::try_from(i * 4 + 2).unwrap()];
                tickers.push(Ticker::try_from(&token_name[..]).unwrap());
                create_token(
                    &token_name[..],
                    tickers[i * 4 + 2],
                    AccountKeyring::Charlie.public(),
                );

                token_name = [123u8 + u8::try_from(i * 4 + 3).unwrap()];
                tickers.push(Ticker::try_from(&token_name[..]).unwrap());
                create_token(
                    &token_name[..],
                    tickers[i * 4 + 3],
                    AccountKeyring::Dave.public(),
                );
            }

            let block_number = System::block_number() + 1;
            let instruction_counter = Settlement::instruction_counter();

            // initialize balances
            for i in 0..10 {
                for j in 0..4 {
                    balances.insert((tickers[i * 4 + j], dids[j], "init").encode(), 100_000);
                    balances.insert((tickers[i * 4 + j], dids[j], "final").encode(), 100_000);
                    for k in 0..4 {
                        if j == k {
                            continue;
                        }
                        balances.insert((tickers[i * 4 + j], dids[k], "init").encode(), 0);
                        balances.insert((tickers[i * 4 + j], dids[k], "final").encode(), 0);
                    }
                }
            }

            let mut legs = Vec::with_capacity(100);
            let mut receipts = Vec::with_capacity(100);
            let mut receipt_legs = HashMap::with_capacity(100);
            for i in 0..10 {
                for j in 0..4 {
                    let mut final_i = 100_000;
                    balances.insert((tickers[i * 4 + j], dids[j], "init").encode(), 100_000);
                    for k in 0..4 {
                        if j == k {
                            continue;
                        }
                        balances.insert((tickers[i * 4 + j], dids[k], "init").encode(), 0);
                        if random() {
                            // This leg should happen
                            if random() {
                                // Receipt to be claimed
                                balances.insert((tickers[i * 4 + j], dids[k], "final").encode(), 0);
                                receipts.push(Receipt {
                                    receipt_uid: u64::try_from(k * 1000 + i * 4 + j).unwrap(),
                                    from: PortfolioId::default_portfolio(dids[j]),
                                    to: PortfolioId::default_portfolio(dids[k]),
                                    asset: tickers[i * 4 + j],
                                    amount: 1u128,
                                });
                                receipt_legs.insert(receipts.last().unwrap().encode(), legs.len());
                            } else {
                                balances.insert((tickers[i * 4 + j], dids[k], "final").encode(), 1);
                                final_i -= 1;
                            }
                            legs.push(Leg {
                                from: PortfolioId::default_portfolio(dids[j]),
                                to: PortfolioId::default_portfolio(dids[k]),
                                asset: tickers[i * 4 + j],
                                amount: 1,
                            });
                            if legs.len() >= 100 {
                                break;
                            }
                        }
                    }
                    balances.insert((tickers[i * 4 + j], dids[j], "final").encode(), final_i);
                    if legs.len() >= 100 {
                        break;
                    }
                }
                if legs.len() >= 100 {
                    break;
                }
            }

            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnBlock(block_number),
                None,
                legs
            ));

            // Authorize instructions and do a few authorize/unauthorize in between
            for (i, signer) in signers.clone().iter().enumerate() {
                for _ in 0..2 {
                    if random() {
                        assert_ok!(Settlement::authorize_instruction(
                            signer.clone(),
                            instruction_counter,
                            default_portfolio_btreeset(dids[i])
                        ));
                        assert_ok!(Settlement::unauthorize_instruction(
                            signer.clone(),
                            instruction_counter,
                            default_portfolio_btreeset(dids[i])
                        ));
                    }
                }
                assert_ok!(Settlement::authorize_instruction(
                    signer.clone(),
                    instruction_counter,
                    default_portfolio_btreeset(dids[i])
                ));
            }

            // Claim receipts and do a few claim/unclaims in between
            for receipt in receipts {
                let leg_num =
                    u64::try_from(*receipt_legs.get(&(receipt.encode())).unwrap()).unwrap();
                let signer = &signers[dids
                    .iter()
                    .position(|&from| PortfolioId::default_portfolio(from) == receipt.from)
                    .unwrap()];
                for _ in 0..2 {
                    if random() {
                        assert_ok!(Settlement::claim_receipt(
                            signer.clone(),
                            instruction_counter,
                            ReceiptDetails {
                                receipt_uid: receipt.receipt_uid,
                                leg_id: leg_num,
                                signer: AccountKeyring::Alice.public(),
                                signature: OffChainSignature::from(
                                    AccountKeyring::Alice.sign(&receipt.encode())
                                )
                            }
                        ));
                        assert_ok!(Settlement::unclaim_receipt(
                            signer.clone(),
                            instruction_counter,
                            leg_num
                        ));
                    }
                }
                assert_ok!(Settlement::claim_receipt(
                    signer.clone(),
                    instruction_counter,
                    ReceiptDetails {
                        receipt_uid: receipt.receipt_uid,
                        leg_id: leg_num,
                        signer: AccountKeyring::Alice.public(),
                        signature: OffChainSignature::from(
                            AccountKeyring::Alice.sign(&receipt.encode())
                        )
                    }
                ));
            }

            let fail: bool = random();
            if fail {
                let mut rng = thread_rng();
                let i = rng.gen_range(0, 4);
                assert_ok!(Settlement::unauthorize_instruction(
                    signers[i].clone(),
                    instruction_counter,
                    default_portfolio_btreeset(dids[i])
                ));
            }

            next_block();

            for i in 0..40 {
                for j in 0..4 {
                    assert_eq!(
                        Portfolio::locked_assets(
                            PortfolioId::default_portfolio(dids[j]),
                            &tickers[i]
                        ),
                        0
                    );
                    if fail {
                        assert_eq!(
                            Asset::balance_of(&tickers[i], dids[j]),
                            u128::try_from(
                                *balances
                                    .get(&(tickers[i], dids[j], "init").encode())
                                    .unwrap()
                            )
                            .unwrap()
                        );
                    } else {
                        assert_eq!(
                            Asset::balance_of(&tickers[i], dids[j]),
                            u128::try_from(
                                *balances
                                    .get(&(tickers[i], dids[j], "final").encode())
                                    .unwrap()
                            )
                            .unwrap()
                        );
                    }
                }
            }
        });
}

#[test]
fn claim_multiple_receipts_during_authorization() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let token_name2 = b"ACME2";
            let ticker2 = Ticker::try_from(&token_name2[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            init(token_name2, ticker2, AccountKeyring::Bob.public());

            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let alice_init_balance2 = Asset::balance_of(&ticker2, alice_did);
            let bob_init_balance2 = Asset::balance_of(&ticker2, bob_did);

            let amount = 100u128;
            let legs = vec![
                Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: amount,
                },
                Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker2,
                    amount: amount,
                },
            ];

            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                legs.clone()
            ));

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            let msg1 = Receipt {
                receipt_uid: 0,
                from: PortfolioId::default_portfolio(alice_did),
                to: PortfolioId::default_portfolio(bob_did),
                asset: ticker,
                amount: amount,
            };
            let msg2 = Receipt {
                receipt_uid: 0,
                from: PortfolioId::default_portfolio(alice_did),
                to: PortfolioId::default_portfolio(bob_did),
                asset: ticker2,
                amount: amount,
            };
            let msg3 = Receipt {
                receipt_uid: 1,
                from: PortfolioId::default_portfolio(alice_did),
                to: PortfolioId::default_portfolio(bob_did),
                asset: ticker2,
                amount: amount,
            };

            assert_noop!(
                Settlement::authorize_with_receipts(
                    alice_signed.clone(),
                    instruction_counter,
                    vec![
                        ReceiptDetails {
                            receipt_uid: 0,
                            leg_id: 0,
                            signer: AccountKeyring::Alice.public(),
                            signature: OffChainSignature::from(
                                AccountKeyring::Alice.sign(&msg1.encode())
                            )
                        },
                        ReceiptDetails {
                            receipt_uid: 0,
                            leg_id: 0,
                            signer: AccountKeyring::Alice.public(),
                            signature: OffChainSignature::from(
                                AccountKeyring::Alice.sign(&msg2.encode())
                            )
                        },
                    ],
                    default_portfolio_btreeset(alice_did)
                ),
                Error::ReceiptAlreadyClaimed
            );

            assert_ok!(Settlement::authorize_with_receipts(
                alice_signed.clone(),
                instruction_counter,
                vec![
                    ReceiptDetails {
                        receipt_uid: 0,
                        leg_id: 0,
                        signer: AccountKeyring::Alice.public(),
                        signature: OffChainSignature::from(
                            AccountKeyring::Alice.sign(&msg1.encode())
                        )
                    },
                    ReceiptDetails {
                        receipt_uid: 1,
                        leg_id: 1,
                        signer: AccountKeyring::Alice.public(),
                        signature: OffChainSignature::from(
                            AccountKeyring::Alice.sign(&msg3.encode())
                        )
                    },
                ],
                default_portfolio_btreeset(alice_did)
            ));

            assert_eq!(
                Settlement::instruction_auths_pending(instruction_counter),
                1
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Pending
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(alice_did)
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::auths_received(
                    instruction_counter,
                    PortfolioId::default_portfolio(bob_did)
                ),
                AuthorizationStatus::Unknown
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 0),
                LegStatus::ExecutionToBeSkipped(AccountKeyring::Alice.public(), 0)
            );
            assert_eq!(
                Settlement::instruction_leg_status(instruction_counter, 1),
                LegStatus::ExecutionToBeSkipped(AccountKeyring::Alice.public(), 1)
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did)
            ));

            // Instruction should've settled
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(alice_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Settlement::user_auths(
                    PortfolioId::default_portfolio(bob_did),
                    instruction_counter
                ),
                AuthorizationStatus::Authorized
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
            assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);
        });
}

#[test]
fn overload_settle_on_block() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);

            let block_number = System::block_number() + 1;

            let legs = vec![
                Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::default_portfolio(bob_did),
                    asset: ticker,
                    amount: 1u128,
                };
                500
            ];

            for _ in 0..2 {
                assert_ok!(Settlement::add_instruction(
                    alice_signed.clone(),
                    venue_counter,
                    SettlementType::SettleOnBlock(block_number),
                    None,
                    legs.clone()
                ));
                assert_ok!(Settlement::add_instruction(
                    alice_signed.clone(),
                    venue_counter,
                    SettlementType::SettleOnBlock(block_number + 1),
                    None,
                    legs.clone()
                ));
            }

            for i in &[0u64, 1, 3] {
                assert_ok!(Settlement::authorize_instruction(
                    alice_signed.clone(),
                    instruction_counter + i,
                    default_portfolio_btreeset(alice_did)
                ));
                assert_ok!(Settlement::authorize_instruction(
                    bob_signed.clone(),
                    instruction_counter + i,
                    default_portfolio_btreeset(bob_did)
                ));
            }

            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);

            assert_eq!(
                Settlement::scheduled_instructions(block_number),
                vec![instruction_counter, instruction_counter + 2]
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 1),
                vec![instruction_counter + 1, instruction_counter + 3]
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 2).len(),
                0
            );

            next_block();
            // First Instruction should've settled
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - 500
            );
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance + 500);
            assert_eq!(Settlement::scheduled_instructions(block_number).len(), 0);
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 1),
                vec![
                    instruction_counter + 1,
                    instruction_counter + 3,
                    instruction_counter + 2
                ]
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 2).len(),
                0
            );

            next_block();
            // Second instruction should've settled
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - 1000
            );
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance + 1000);
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 1).len(),
                0
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 2),
                vec![instruction_counter + 3, instruction_counter + 2]
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 3).len(),
                0
            );

            next_block();
            // Fourth instruction should've settled
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - 1500
            );
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance + 1500);
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 2).len(),
                0
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 3),
                vec![instruction_counter + 2]
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 4).len(),
                0
            );

            assert_noop!(
                Settlement::authorize_instruction(
                    alice_signed.clone(),
                    instruction_counter + 2,
                    default_portfolio_btreeset(alice_did)
                ),
                Error::InstructionSettleBlockPassed
            );
            next_block();
            // Third instruction should've settled (Failed due to missing auth)
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - 1500
            );
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance + 1500);
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 3).len(),
                0
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 4).len(),
                0
            );
            assert_eq!(
                Settlement::scheduled_instructions(block_number + 5).len(),
                0
            );
        });
}

#[test]
fn encode_receipt() {
    ExtBuilder::default().build().execute_with(|| {
        let token_name = [0x01u8];
        let ticker = Ticker::try_from(&token_name[..]).unwrap();
        let msg1 = Receipt {
            receipt_uid: 0,
            from: PortfolioId::default_portfolio(
                IdentityId::try_from(
                    "did:poly:0600000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            ),
            to: PortfolioId::default_portfolio(
                IdentityId::try_from(
                    "did:poly:0600000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap()
                .into(),
            ),
            asset: ticker,
            amount: 100u128,
        };
        println!("{:?}", AccountKeyring::Alice.sign(&msg1.encode()));
    });
}

#[test]
fn test_weights_for_settlement_transaction() {
    ExtBuilder::default()
        .set_max_legs_allowed(5) // set maximum no. of legs allowed for an instruction.
        .set_max_tms_allowed(4) // set maximum no. of tms an asset can have.
        .build()
        .execute_with(|| {
            let alice = AccountKeyring::Alice.public();
            let (alice_signed, alice_did) = make_account_without_cdd(alice).unwrap();

            let bob = AccountKeyring::Bob.public();
            let (bob_signed, bob_did) = make_account_without_cdd(bob).unwrap();

            let eve = AccountKeyring::Eve.public();
            let (eve_signed, eve_did) = make_account_without_cdd(eve).unwrap();

            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();

            let venue_counter = init(token_name, ticker, alice);
            let instruction_counter = Settlement::instruction_counter();

            // Remove existing rules
            assert_ok!(ComplianceManager::remove_compliance_requirement(
                alice_signed.clone(),
                ticker,
                1
            ));
            // Add claim rules for settlement
            assert_ok!(ComplianceManager::add_compliance_requirement(
                alice_signed.clone(),
                ticker,
                vec![
                    Condition {
                        condition_type: ConditionType::IsPresent(Claim::Accredited(ticker.into())),
                        issuers: vec![eve_did]
                    },
                    Condition {
                        condition_type: ConditionType::IsAbsent(Claim::BuyLockup(ticker.into())),
                        issuers: vec![eve_did]
                    }
                ],
                vec![
                    Condition {
                        condition_type: ConditionType::IsPresent(Claim::Accredited(ticker.into())),
                        issuers: vec![eve_did]
                    },
                    Condition {
                        condition_type: ConditionType::IsAnyOf(vec![
                            Claim::BuyLockup(ticker.into()),
                            Claim::KnowYourCustomer(ticker.into())
                        ]),
                        issuers: vec![eve_did]
                    }
                ]
            ));

            // Providing claim to sender and receiver
            // For Alice
            assert_add_claim!(
                eve_signed.clone(),
                alice_did,
                Claim::Accredited(ticker.into())
            );
            // For Bob
            assert_add_claim!(
                eve_signed.clone(),
                bob_did,
                Claim::Accredited(ticker.into())
            );
            assert_add_claim!(
                eve_signed.clone(),
                bob_did,
                Claim::KnowYourCustomer(ticker.into())
            );

            // Create instruction
            let legs = vec![Leg {
                from: PortfolioId::default_portfolio(alice_did),
                to: PortfolioId::default_portfolio(bob_did),
                asset: ticker,
                amount: 100u128,
            }];

            let weight_to_add_instruction = SettlementCall::<TestStorage>::add_instruction(
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                legs.clone(),
            )
            .get_dispatch_info()
            .weight;

            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                legs.clone()
            ));

            assert_eq!(
                weight_to_add_instruction,
                weight_for::weight_for_instruction_creation::<TestStorage>(legs.len())
            );

            // Authorize instruction by Alice first and check for weight.
            let weight_for_authorize_instruction_1 =
                SettlementCall::<TestStorage>::authorize_instruction(
                    instruction_counter,
                    default_portfolio_btreeset(alice_did),
                )
                .get_dispatch_info()
                .weight;
            let result_authorize_instruction_1 = Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did),
            );
            assert_ok!(result_authorize_instruction_1);
            assert_eq!(
                weight_for::weight_for_authorize_instruction::<TestStorage>(),
                weight_for_authorize_instruction_1
                    - weight_for::weight_for_transfer::<TestStorage>()
            );

            let weight_for_authorize_instruction_2 =
                SettlementCall::<TestStorage>::authorize_instruction(
                    instruction_counter,
                    default_portfolio_btreeset(bob_did),
                )
                .get_dispatch_info()
                .weight;
            let result_authorize_instruction_2 = Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(bob_did),
            );
            assert_ok!(result_authorize_instruction_2);
            assert_eq!(Asset::balance_of(ticker, bob_did), 100);
            let acutal_weight = result_authorize_instruction_2
                .unwrap()
                .actual_weight
                .unwrap();
            let (transfer_result, _weight_for_is_valid_transfer) = Asset::_is_valid_transfer(
                &ticker,
                alice,
                PortfolioId::default_portfolio(alice_did),
                PortfolioId::default_portfolio(bob_did),
                100,
            )
            .unwrap();
            assert_eq!(transfer_result, 81);
            assert!(weight_for_authorize_instruction_2 > acutal_weight);
        });
}

#[test]
fn cross_portfolio_settlement() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let name = PortfolioName::from([42u8].to_vec());
            let num = Portfolio::next_portfolio_number(&bob_did);
            assert_ok!(Portfolio::create_portfolio(
                bob_signed.clone(),
                name.clone()
            ));
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let amount = 100u128;

            // Instruction referencing a user defined portfolio is created
            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                vec![Leg {
                    from: PortfolioId::default_portfolio(alice_did),
                    to: PortfolioId::user_portfolio(bob_did, num),
                    asset: ticker,
                    amount: amount
                }]
            ));
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(
                Portfolio::default_portfolio_balance(alice_did, &ticker),
                alice_init_balance,
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(bob_did, &ticker),
                bob_init_balance,
            );
            assert_eq!(Portfolio::user_portfolio_balance(bob_did, num, &ticker), 0,);
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );

            // Approved by Alice
            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(
                Portfolio::default_portfolio_balance(alice_did, &ticker),
                alice_init_balance,
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(bob_did, &ticker),
                bob_init_balance,
            );
            assert_eq!(Portfolio::user_portfolio_balance(bob_did, num, &ticker), 0,);
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            // Bob fails to approve the instruction with a
            // different portfolio than the one specified in the instruction
            assert_noop!(
                Settlement::authorize_instruction(
                    bob_signed.clone(),
                    instruction_counter,
                    default_portfolio_btreeset(bob_did),
                ),
                Error::NoPendingAuth
            );

            // Bob approves the instruction with the correct portfolio
            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                user_portfolio_btreeset(bob_did, num)
            ));

            // Instruction should've settled
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - amount
            );
            assert_eq!(
                Asset::balance_of(&ticker, bob_did),
                bob_init_balance + amount
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(alice_did, &ticker),
                alice_init_balance - amount,
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(bob_did, &ticker),
                bob_init_balance,
            );
            assert_eq!(
                Portfolio::user_portfolio_balance(bob_did, num, &ticker),
                amount,
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );
        });
}

#[test]
fn multiple_portfolio_settlement() {
    ExtBuilder::default()
        .set_max_legs_allowed(500)
        .build()
        .execute_with(|| {
            let alice_signed = Origin::signed(AccountKeyring::Alice.public());
            let alice_did = register_keyring_account(AccountKeyring::Alice).unwrap();
            let bob_signed = Origin::signed(AccountKeyring::Bob.public());
            let bob_did = register_keyring_account(AccountKeyring::Bob).unwrap();
            let name = PortfolioName::from([42u8].to_vec());
            let alice_num = Portfolio::next_portfolio_number(&alice_did);
            let bob_num = Portfolio::next_portfolio_number(&bob_did);
            assert_ok!(Portfolio::create_portfolio(
                bob_signed.clone(),
                name.clone()
            ));
            assert_ok!(Portfolio::create_portfolio(
                alice_signed.clone(),
                name.clone()
            ));
            let token_name = b"ACME";
            let ticker = Ticker::try_from(&token_name[..]).unwrap();
            let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
            let instruction_counter = Settlement::instruction_counter();
            let alice_init_balance = Asset::balance_of(&ticker, alice_did);
            let bob_init_balance = Asset::balance_of(&ticker, bob_did);
            let amount = 100u128;

            // An instruction is created with multiple legs referencing multiple portfolios
            assert_ok!(Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnAuthorization,
                None,
                vec![
                    Leg {
                        from: PortfolioId::user_portfolio(alice_did, alice_num),
                        to: PortfolioId::default_portfolio(bob_did),
                        asset: ticker,
                        amount: amount
                    },
                    Leg {
                        from: PortfolioId::default_portfolio(alice_did),
                        to: PortfolioId::user_portfolio(bob_did, bob_num),
                        asset: ticker,
                        amount: amount
                    }
                ]
            ));
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(
                Portfolio::default_portfolio_balance(alice_did, &ticker),
                alice_init_balance,
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(bob_did, &ticker),
                bob_init_balance,
            );
            assert_eq!(
                Portfolio::user_portfolio_balance(bob_did, bob_num, &ticker),
                0,
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );

            // Alice approves the instruction from her default portfolio
            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                default_portfolio_btreeset(alice_did)
            ));
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(
                Portfolio::default_portfolio_balance(alice_did, &ticker),
                alice_init_balance,
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(bob_did, &ticker),
                bob_init_balance,
            );
            assert_eq!(
                Portfolio::user_portfolio_balance(bob_did, bob_num, &ticker),
                0
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );

            // Alice fails to approve the instruction from her user specified portfolio due to lack of funds
            assert_noop!(
                Settlement::authorize_instruction(
                    alice_signed.clone(),
                    instruction_counter,
                    user_portfolio_btreeset(alice_did, alice_num)
                ),
                Error::FailedToLockTokens
            );

            // Alice moves her funds to the correct portfolio
            assert_ok!(Portfolio::move_portfolio_funds(
                alice_signed.clone(),
                PortfolioId::default_portfolio(alice_did),
                PortfolioId::user_portfolio(alice_did, alice_num),
                vec![MovePortfolioItem { ticker, amount }]
            ));

            // Alice is now able to approve the instruction with the user portfolio
            assert_ok!(Settlement::authorize_instruction(
                alice_signed.clone(),
                instruction_counter,
                user_portfolio_btreeset(alice_did, alice_num)
            ));
            assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
            assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
            assert_eq!(
                Portfolio::default_portfolio_balance(alice_did, &ticker),
                alice_init_balance - amount,
            );
            assert_eq!(
                Portfolio::user_portfolio_balance(alice_did, alice_num, &ticker),
                amount,
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(bob_did, &ticker),
                bob_init_balance,
            );
            assert_eq!(
                Portfolio::user_portfolio_balance(bob_did, bob_num, &ticker),
                0
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                amount
            );
            assert_eq!(
                Portfolio::locked_assets(
                    PortfolioId::user_portfolio(alice_did, alice_num),
                    &ticker
                ),
                amount
            );

            // Bob approves the instruction with both of his portfolios in a single transaction
            let mut set = BTreeSet::new();
            set.insert(PortfolioId::default_portfolio(bob_did));
            set.insert(PortfolioId::user_portfolio(bob_did, bob_num));
            assert_ok!(Settlement::authorize_instruction(
                bob_signed.clone(),
                instruction_counter,
                set
            ));

            // Instruction should've settled
            assert_eq!(
                Asset::balance_of(&ticker, alice_did),
                alice_init_balance - amount * 2
            );
            assert_eq!(
                Asset::balance_of(&ticker, bob_did),
                bob_init_balance + amount * 2
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(alice_did, &ticker),
                alice_init_balance - amount * 2,
            );
            assert_eq!(
                Portfolio::default_portfolio_balance(bob_did, &ticker),
                bob_init_balance + amount,
            );
            assert_eq!(
                Portfolio::user_portfolio_balance(bob_did, bob_num, &ticker),
                amount,
            );
            assert_eq!(
                Portfolio::locked_assets(PortfolioId::default_portfolio(alice_did), &ticker),
                0
            );
        });
}

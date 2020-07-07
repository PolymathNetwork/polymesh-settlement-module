use super::{
    storage::{make_account, TestStorage},
    ExtBuilder,
};

use pallet_asset::{self as asset, AssetType};
use pallet_balances as balances;
use pallet_compliance_manager as compliance_manager;
use pallet_identity as identity;
use pallet_settlement::{
    self as settlement, AuthorizationStatus, Instruction, InstructionStatus, Leg, LegDetails,
    LegStatus, Receipt, SettlementType,
};
use polymesh_common_utilities::SystematicIssuers::Settlement as SettlementDID;
use polymesh_primitives::Ticker;

use codec::Encode;
use frame_support::{assert_err, assert_ok};
use rand::prelude::*;
use sp_core::sr25519::Public;
use sp_runtime::AnySignature;
use std::collections::HashMap;
use std::convert::TryFrom;
use test_client::AccountKeyring;

type Identity = identity::Module<TestStorage>;
type Balances = balances::Module<TestStorage>;
type Asset = asset::Module<TestStorage>;
type Timestamp = pallet_timestamp::Module<TestStorage>;
type ComplianceManager = compliance_manager::Module<TestStorage>;
type AssetError = asset::Error<TestStorage>;
type OffChainSignature = AnySignature;
type Origin = <TestStorage as frame_system::Trait>::Origin;
type DidRecords = identity::DidRecords<TestStorage>;
type Settlement = settlement::Module<TestStorage>;
type System = frame_system::Module<TestStorage>;
type Error = settlement::Error<TestStorage>;

fn init(token_name: &[u8], ticker: Ticker, keyring: Public) -> u64 {
    create_token(token_name, ticker, keyring);
    let venue_counter = Settlement::venue_counter();
    assert_ok!(Settlement::create_venue(
        Origin::signed(keyring),
        vec![13],
        vec![keyring]
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
        None
    ));
    assert_ok!(ComplianceManager::add_active_rule(
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
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let venue_counter = Settlement::venue_counter();
        assert_ok!(Settlement::create_venue(
            alice_signed,
            vec![13],
            vec![AccountKeyring::Alice.public(), AccountKeyring::Bob.public()]
        ));
        let venue_info = Settlement::venue_info(venue_counter);
        assert_eq!(Settlement::venue_counter(), venue_counter + 1);
        assert_eq!(venue_info.creator, alice_did);
        assert_eq!(venue_info.instructions.len(), 0);
        assert_eq!(venue_info.details, vec![13]);
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
    });
}

#[test]
fn basic_settlement() {
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let (bob_signed, bob_did) = make_account(AccountKeyring::Bob.public()).unwrap();
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
            vec![LegDetails {
                from: alice_did,
                to: bob_did,
                asset: ticker,
                amount: amount
            }]
        ));
        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_ok!(Settlement::authorize_instruction(
            alice_signed.clone(),
            instruction_counter,
        ));
        println!(
            "{:?}",
            Settlement::instruction_leg_status(instruction_counter, 0)
        );

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_ok!(Settlement::authorize_instruction(
            bob_signed.clone(),
            instruction_counter,
        ));

        let system_events = System::events();
        println!("{:?}", system_events);

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
fn token_swap() {
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let (bob_signed, bob_did) = make_account(AccountKeyring::Bob.public()).unwrap();
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
        let leg_details = vec![
            LegDetails {
                from: alice_did,
                to: bob_did,
                asset: ticker,
                amount: amount,
            },
            LegDetails {
                from: bob_did,
                to: alice_did,
                asset: ticker2,
                amount: amount,
            },
        ];
        let mut legs = Vec::with_capacity(leg_details.len());
        for i in 0..leg_details.len() {
            legs.push(Leg::new(
                u64::try_from(i).unwrap_or_default(),
                leg_details[i].clone(),
            ));
        }

        assert_ok!(Settlement::add_instruction(
            alice_signed.clone(),
            venue_counter,
            SettlementType::SettleOnAuthorization,
            None,
            leg_details.clone()
        ));

        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
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
        ));
        println!(
            "{:?}",
            Settlement::instruction_leg_status(instruction_counter, 0)
        );

        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            1
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        assert_ok!(Settlement::unauthorize_instruction(
            alice_signed.clone(),
            instruction_counter,
        ));

        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            2
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Unknown
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), 0);

        assert_ok!(Settlement::authorize_instruction(
            alice_signed.clone(),
            instruction_counter,
        ));
        println!(
            "{:?}",
            Settlement::instruction_leg_status(instruction_counter, 0)
        );

        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            1
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        assert_ok!(Settlement::authorize_instruction(
            bob_signed.clone(),
            instruction_counter,
        ));

        let system_events = System::events();
        println!("{:?}", system_events);

        // Instruction should've settled
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), 0);
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
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let (bob_signed, bob_did) = make_account(AccountKeyring::Bob.public()).unwrap();
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
        let leg_details = vec![
            LegDetails {
                from: alice_did,
                to: bob_did,
                asset: ticker,
                amount: amount,
            },
            LegDetails {
                from: bob_did,
                to: alice_did,
                asset: ticker2,
                amount: amount,
            },
        ];
        let mut legs = Vec::with_capacity(leg_details.len());
        for i in 0..leg_details.len() {
            legs.push(Leg::new(
                u64::try_from(i).unwrap_or_default(),
                leg_details[i].clone(),
            ));
        }

        assert_ok!(Settlement::add_instruction(
            alice_signed.clone(),
            venue_counter,
            SettlementType::SettleOnAuthorization,
            None,
            leg_details.clone()
        ));

        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
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
            from: alice_did,
            to: bob_did,
            asset: ticker,
            amount: amount,
        };

        assert_err!(
            Settlement::claim_receipt(
                alice_signed.clone(),
                instruction_counter,
                0,
                0,
                AccountKeyring::Alice.public(),
                OffChainSignature::from(AccountKeyring::Alice.sign(&msg.encode()))
            ),
            Error::LegNotPending
        );

        assert_ok!(Settlement::authorize_instruction(
            alice_signed.clone(),
            instruction_counter,
        ));
        println!(
            "{:?}",
            Settlement::instruction_leg_status(instruction_counter, 0)
        );

        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            1
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        let msg2 = Receipt {
            receipt_uid: 0,
            from: alice_did,
            to: alice_did,
            asset: ticker,
            amount: amount,
        };

        assert_err!(
            Settlement::claim_receipt(
                alice_signed.clone(),
                instruction_counter,
                0,
                0,
                AccountKeyring::Alice.public(),
                OffChainSignature::from(AccountKeyring::Alice.sign(&msg2.encode()))
            ),
            Error::InvalidSignature
        );

        // Claiming, unclaiming and claiming receipt
        assert_ok!(Settlement::claim_receipt(
            alice_signed.clone(),
            instruction_counter,
            0,
            0,
            AccountKeyring::Alice.public(),
            OffChainSignature::from(AccountKeyring::Alice.sign(&msg.encode()))
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
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), 0);

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
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        assert_ok!(Settlement::claim_receipt(
            alice_signed.clone(),
            instruction_counter,
            0,
            0,
            AccountKeyring::Alice.public(),
            OffChainSignature::from(AccountKeyring::Alice.sign(&msg.encode()))
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
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), 0);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        assert_ok!(Settlement::authorize_instruction(
            bob_signed.clone(),
            instruction_counter,
        ));

        let system_events = System::events();
        println!("{:?}", system_events);

        // Instruction should've settled
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), 0);
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
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let (bob_signed, bob_did) = make_account(AccountKeyring::Bob.public()).unwrap();
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
        let leg_details = vec![
            LegDetails {
                from: alice_did,
                to: bob_did,
                asset: ticker,
                amount: amount,
            },
            LegDetails {
                from: bob_did,
                to: alice_did,
                asset: ticker2,
                amount: amount,
            },
        ];
        let mut legs = Vec::with_capacity(leg_details.len());
        for i in 0..leg_details.len() {
            legs.push(Leg::new(
                u64::try_from(i).unwrap_or_default(),
                leg_details[i].clone(),
            ));
        }

        assert_ok!(Settlement::add_instruction(
            alice_signed.clone(),
            venue_counter,
            SettlementType::SettleOnBlock(block_number),
            None,
            leg_details.clone()
        ));

        assert_eq!(
            Settlement::scheduled_instructions(block_number),
            vec![instruction_counter]
        );

        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
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

        // assert_err!(
        //     Settlement::authorize_instruction(
        //         alice_signed.clone(),
        //         instruction_counter,
        //     ),
        //     Error::InstructionSettleBlockPassed
        // );
        assert_ok!(Settlement::authorize_instruction(
            alice_signed.clone(),
            instruction_counter,
        ));

        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            1
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        assert_ok!(Settlement::authorize_instruction(
            bob_signed.clone(),
            instruction_counter,
        ));
        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            0
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);
        assert_eq!(
            Asset::custodian_allowance((&ticker2, bob_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker2, bob_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        next_block();

        // Instruction should've settled
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), 0);
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
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let (bob_signed, bob_did) = make_account(AccountKeyring::Bob.public()).unwrap();
        let token_name = b"ACME";
        let ticker = Ticker::try_from(&token_name[..]).unwrap();
        let token_name2 = b"ACME2";
        let ticker2 = Ticker::try_from(&token_name2[..]).unwrap();
        let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
        init(token_name2, ticker2, AccountKeyring::Bob.public());
        assert_ok!(ComplianceManager::reset_active_rules(
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
        let leg_details = vec![
            LegDetails {
                from: alice_did,
                to: bob_did,
                asset: ticker,
                amount: amount,
            },
            LegDetails {
                from: bob_did,
                to: alice_did,
                asset: ticker2,
                amount: amount,
            },
        ];
        let mut legs = Vec::with_capacity(leg_details.len());
        for i in 0..leg_details.len() {
            legs.push(Leg::new(
                u64::try_from(i).unwrap_or_default(),
                leg_details[i].clone(),
            ));
        }

        assert_ok!(Settlement::add_instruction(
            alice_signed.clone(),
            venue_counter,
            SettlementType::SettleOnBlock(block_number),
            None,
            leg_details.clone()
        ));

        assert_eq!(
            Settlement::scheduled_instructions(block_number),
            vec![instruction_counter]
        );

        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
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
        ));

        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            1
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        assert_ok!(Settlement::authorize_instruction(
            bob_signed.clone(),
            instruction_counter,
        ));
        assert_eq!(
            Settlement::instruction_auths_pending(instruction_counter),
            0
        );
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, alice_did),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::auths_received(instruction_counter, bob_did),
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
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), amount);
        assert_eq!(
            Asset::custodian_allowance((&ticker2, bob_did, SettlementDID.as_id())),
            amount
        );
        assert_eq!(Asset::total_custody_allowance((&ticker2, bob_did)), amount);

        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);

        next_block();

        // Instruction should've settled
        assert_eq!(
            Settlement::user_auths(alice_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Settlement::user_auths(bob_did, instruction_counter),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            Asset::custodian_allowance((&ticker, alice_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker, alice_did)), 0);
        assert_eq!(
            Asset::custodian_allowance((&ticker2, bob_did, SettlementDID.as_id())),
            0
        );
        assert_eq!(Asset::total_custody_allowance((&ticker2, bob_did)), 0);
        assert_eq!(Asset::balance_of(&ticker, alice_did), alice_init_balance);
        assert_eq!(Asset::balance_of(&ticker, bob_did), bob_init_balance);
        assert_eq!(Asset::balance_of(&ticker2, alice_did), alice_init_balance2);
        assert_eq!(Asset::balance_of(&ticker2, bob_did), bob_init_balance2);
    });
}

#[test]
fn venue_filtering() {
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let (bob_signed, bob_did) = make_account(AccountKeyring::Bob.public()).unwrap();
        let token_name = b"ACME";
        let ticker = Ticker::try_from(&token_name[..]).unwrap();
        let venue_counter = init(token_name, ticker, AccountKeyring::Alice.public());
        let block_number = System::block_number() + 1;
        let instruction_counter = Settlement::instruction_counter();

        let leg_details = vec![LegDetails {
            from: alice_did,
            to: bob_did,
            asset: ticker,
            amount: 10,
        }];
        assert_ok!(Settlement::add_instruction(
            alice_signed.clone(),
            venue_counter,
            SettlementType::SettleOnBlock(block_number),
            None,
            leg_details.clone()
        ));
        assert_ok!(Settlement::set_venue_filtering(
            alice_signed.clone(),
            ticker,
            true
        ));
        assert_err!(
            Settlement::add_instruction(
                alice_signed.clone(),
                venue_counter,
                SettlementType::SettleOnBlock(block_number),
                None,
                leg_details.clone()
            ),
            Error::UnauthorizedVenue
        );
        assert_ok!(Settlement::allow_venues(
            alice_signed.clone(),
            ticker,
            vec![venue_counter]
        ));
        assert_ok!(Settlement::add_instruction(
            alice_signed.clone(),
            venue_counter,
            SettlementType::SettleOnBlock(block_number + 1),
            None,
            leg_details.clone()
        ));
        assert_ok!(Settlement::authorize_instruction(
            alice_signed.clone(),
            instruction_counter,
        ));
        assert_ok!(Settlement::authorize_instruction(
            alice_signed.clone(),
            instruction_counter + 1,
        ));
        assert_ok!(Settlement::authorize_instruction(
            bob_signed.clone(),
            instruction_counter,
        ));
        assert_ok!(Settlement::authorize_instruction(
            bob_signed.clone(),
            instruction_counter + 1,
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
    ExtBuilder::default().build().execute_with(|| {
        let (alice_signed, alice_did) = make_account(AccountKeyring::Alice.public()).unwrap();
        let (bob_signed, bob_did) = make_account(AccountKeyring::Bob.public()).unwrap();
        let (charlie_signed, charlie_did) = make_account(AccountKeyring::Charlie.public()).unwrap();
        let (dave_signed, dave_did) = make_account(AccountKeyring::Dave.public()).unwrap();
        let venue_counter = Settlement::venue_counter();
        assert_ok!(Settlement::create_venue(
            Origin::signed(AccountKeyring::Alice.public()),
            vec![13],
            vec![AccountKeyring::Alice.public()]
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

        let mut leg_details = Vec::with_capacity(100);
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
                                from: dids[j],
                                to: dids[k],
                                asset: tickers[i * 4 + j],
                                amount: 1u128,
                            });
                            receipt_legs
                                .insert(receipts.last().unwrap().encode(), leg_details.len());
                        } else {
                            balances.insert((tickers[i * 4 + j], dids[k], "final").encode(), 1);
                            final_i -= 1;
                        }
                        leg_details.push(LegDetails {
                            from: dids[j],
                            to: dids[k],
                            asset: tickers[i * 4 + j],
                            amount: 1,
                        });
                        if leg_details.len() >= 100 {
                            break;
                        }
                    }
                }
                balances.insert((tickers[i * 4 + j], dids[j], "final").encode(), final_i);
                if leg_details.len() >= 100 {
                    break;
                }
            }
            if leg_details.len() >= 100 {
                break;
            }
        }

        assert_ok!(Settlement::add_instruction(
            alice_signed.clone(),
            venue_counter,
            SettlementType::SettleOnBlock(block_number),
            None,
            leg_details
        ));

        // Authorize instructions and do a few authorize/unauthorize in between
        for signer in signers.clone() {
            for _ in 0..3 {
                if random() {
                    assert_ok!(Settlement::authorize_instruction(
                        signer.clone(),
                        instruction_counter,
                    ));
                    assert_ok!(Settlement::unauthorize_instruction(
                        signer.clone(),
                        instruction_counter,
                    ));
                }
            }
            assert_ok!(Settlement::authorize_instruction(
                signer.clone(),
                instruction_counter,
            ));
        }

        // Claim receipts and do a few claim/unclaims in between
        for receipt in receipts {
            let leg_num = u64::try_from(*receipt_legs.get(&(receipt.encode())).unwrap()).unwrap();
            let signer = &signers[dids.iter().position(|&from| from == receipt.from).unwrap()];
            for _ in 0..3 {
                if random() {
                    assert_ok!(Settlement::claim_receipt(
                        signer.clone(),
                        instruction_counter,
                        leg_num,
                        receipt.receipt_uid,
                        AccountKeyring::Alice.public(),
                        OffChainSignature::from(AccountKeyring::Alice.sign(&receipt.encode()))
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
                leg_num,
                receipt.receipt_uid,
                AccountKeyring::Alice.public(),
                OffChainSignature::from(AccountKeyring::Alice.sign(&receipt.encode()))
            ));
        }

        next_block();

        for i in 0..40 {
            for j in 0..4 {
                assert_eq!(
                    Asset::custodian_allowance((&tickers[i], dids[j], SettlementDID.as_id())),
                    0
                );
                assert_eq!(Asset::total_custody_allowance((&tickers[i], dids[j])), 0);
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
    });
}

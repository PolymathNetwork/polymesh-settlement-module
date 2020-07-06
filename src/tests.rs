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
use sp_core::sr25519::Public;
use sp_runtime::AnySignature;
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
    let venue_counter = Settlement::venue_counter();
    assert_ok!(Settlement::create_venue(
        Origin::signed(keyring),
        vec![13],
        vec![keyring]
    ));
    venue_counter
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

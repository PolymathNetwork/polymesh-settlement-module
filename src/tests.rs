use super::{
    storage::{add_signing_item, make_account, register_keyring_account, TestStorage},
    ExtBuilder,
};

use pallet_asset::{
    self as asset, AssetType, FundingRoundName, IdentifierType, SecurityToken, SignData,
};
use pallet_balances as balances;
use pallet_compliance_manager as compliance_manager;
use pallet_identity as identity;
use pallet_settlement::{self as settlement, LegDetails, SettlementType};
use polymesh_common_utilities::{
    constants::*, traits::asset::IssueAssetItem, traits::balances::Memo,
};
use polymesh_primitives::{
    AuthorizationData, Document, IdentityId, LinkData, Signatory, SmartExtension,
    SmartExtensionType, Ticker,
};

use chrono::prelude::Utc;
use codec::Encode;
use frame_support::{
    assert_err, assert_noop, assert_ok, traits::Currency, StorageDoubleMap, StorageMap,
};
use rand::Rng;
use sp_runtime::AnySignature;
use std::{
    convert::{TryFrom, TryInto},
    mem,
};
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
        let venue_counter = init(token_name, ticker);
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

fn init(token_name: &[u8], ticker: Ticker) -> u64 {
    assert_ok!(Asset::create_asset(
        Origin::signed(AccountKeyring::Alice.public()),
        token_name.into(),
        ticker,
        100_000,
        true,
        AssetType::default(),
        vec![],
        None
    ));
    assert_ok!(ComplianceManager::add_active_rule(
        Origin::signed(AccountKeyring::Alice.public()),
        ticker,
        vec![],
        vec![]
    ));
    let venue_counter = Settlement::venue_counter();
    assert_ok!(Settlement::create_venue(
        Origin::signed(AccountKeyring::Alice.public()),
        vec![13],
        vec![AccountKeyring::Alice.public()]
    ));
    venue_counter
}

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

#[test]
fn issuers_can_create_and_rename_tokens() {
    ExtBuilder::default().build().execute_with(|| {
        let (owner_signed, owner_did) = make_account(AccountKeyring::Dave.public()).unwrap();
        let funding_round_name: FundingRoundName = b"round1".into();
        // Expected token entry
        let mut token = SecurityToken {
            name: vec![0x01].into(),
            owner_did,
            total_supply: 1_000_000,
            divisible: true,
            asset_type: AssetType::default(),
            ..Default::default()
        };
        let ticker = Ticker::try_from(token.name.as_slice()).unwrap();
        assert!(!<DidRecords>::contains_key(
            Identity::get_token_did(&ticker).unwrap()
        ));
        let identifiers = vec![(IdentifierType::default(), b"undefined".into())];
        let ticker = Ticker::try_from(token.name.as_slice()).unwrap();
        assert_err!(
            Asset::create_asset(
                owner_signed.clone(),
                token.name.clone(),
                ticker,
                1_000_000_000_000_000_000_000_000, // Total supply over the limit
                true,
                token.asset_type.clone(),
                identifiers.clone(),
                Some(funding_round_name.clone()),
            ),
            AssetError::TotalSupplyAboveLimit
        );

        // Issuance is successful
        assert_ok!(Asset::create_asset(
            owner_signed.clone(),
            token.name.clone(),
            ticker,
            token.total_supply,
            true,
            token.asset_type.clone(),
            identifiers.clone(),
            Some(funding_round_name.clone())
        ));

        let token_link = Identity::get_link(
            Signatory::from(owner_did),
            Asset::token_details(ticker).link_id,
        );
        assert_eq!(token_link.link_data, LinkData::AssetOwned(ticker));
        assert_eq!(token_link.expiry, None);

        let ticker_link = Identity::get_link(
            Signatory::from(owner_did),
            Asset::ticker_registration(ticker).link_id,
        );

        assert_eq!(ticker_link.link_data, LinkData::TickerOwned(ticker));
        assert_eq!(ticker_link.expiry, None);

        token.link_id = Asset::token_details(ticker).link_id;
        // A correct entry is added
        assert_eq!(Asset::token_details(ticker), token);
        assert!(<DidRecords>::contains_key(
            Identity::get_token_did(&ticker).unwrap()
        ));
        assert_eq!(Asset::funding_round(ticker), funding_round_name.clone());

        // Unauthorized identities cannot rename the token.
        let (eve_signed, _eve_did) = make_account(AccountKeyring::Eve.public()).unwrap();
        assert_err!(
            Asset::rename_asset(eve_signed, ticker, vec![0xde, 0xad, 0xbe, 0xef].into()),
            AssetError::Unauthorized
        );
        // The token should remain unchanged in storage.
        assert_eq!(Asset::token_details(ticker), token);
        // Rename the token and check storage has been updated.
        let renamed_token = SecurityToken {
            name: vec![0x42].into(),
            owner_did: token.owner_did,
            total_supply: token.total_supply,
            divisible: token.divisible,
            asset_type: token.asset_type.clone(),
            link_id: Asset::token_details(ticker).link_id,
        };
        assert_ok!(Asset::rename_asset(
            owner_signed.clone(),
            ticker,
            renamed_token.name.clone()
        ));
        assert_eq!(Asset::token_details(ticker), renamed_token);
        for (typ, val) in identifiers {
            assert_eq!(Asset::identifiers((ticker, typ)), val);
        }
    });
}

// Copyright (c) 2020 Polymath

//! # Settlement Module
//!
//! Settlement module manages all kinds of transfers and settlements of assets
//!
//! ## Overview
//!
//! The settlement module provides functionality to settle onchain as well as offchain trades between multiple parties.
//! All trades are settled under venues. A token issuer can allow/block certain venues from settling trades that involve their tokens.
//! An atomic settlement is called an Instruction. An instruction can contain multiple legs. Legs are essentially simple one to one transfers.
//! When an instruction is settled, either all legs are executed successfully or none are. In other words, if one of the leg fails due to
//! compliance failure, all other legs will also fail.
//!
//! An instruction must be authorized by all the counter parties involved for it to be executed.
//! An instruction can be set to automatically execute when all authorizations are received or at a particular block number.
//!
//! Offchain settlements are represented via receipts. If a leg has a receipt attached to it, it will not be executed onchain.
//! All other legs will be executed onchain during settlement.
//!
//! ## Dispatchable Functions
//!
//! - `create_venue` - Registers a new venue.
//! - `add_instruction` - Adds a new instruction.
//! - `authorize_instruction` - Authorizes an existing instruction.
//! - `unauthorize_instruction` - Unauthorizes an existing instruction.
//! - `reject_instruction` - Rejects an existing instruction.
//! - `claim_receipt` - Claims a signed receipt.
//! - `unclaim_receipt` - Unclaims a previously claimed receipt.
//! - `set_venue_filtering` - Enables or disabled venue filtering for a token.
//! - `allow_venues` - Allows additional venues to create instructions involving an asset.
//! - `disallow_venues` - Revokes permission given to venues for creating instructions involving a particular asset.
//!
#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

use pallet_identity as identity;
use polymesh_common_utilities::{
    constants::SETTLEMENT_MODULE_ID,
    traits::{asset::Trait as AssetTrait, identity::Trait as IdentityTrait, CommonTrait},
    Context,
    SystematicIssuers::Settlement as SettlementDID,
};
use polymesh_primitives::{IdentityId, Ticker};

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
    traits::Get, weights::Weight, IterableStorageDoubleMap,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{AccountIdConversion, Verify};
use sp_std::{convert::TryFrom, prelude::*};

type Identity<T> = identity::Module<T>;

pub trait Trait:
    frame_system::Trait + CommonTrait + IdentityTrait + pallet_timestamp::Trait
{
    // The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
    /// Asset module
    type Asset: AssetTrait<Self::Balance, Self::AccountId>;
    /// The maximum number of total legs in scheduled instructions that can be executed in a single block.
    /// Any excess instructions are scheduled in later blocks.
    type MaxScheduledInstructionLegsPerBlock: Get<u32>;
}

/// Status of an instruction
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstructionStatus {
    /// Invalid instruction or details pruned
    Unknown,
    /// Instruction is pending execution
    Pending,
}

impl Default for InstructionStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Status of a leg
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LegStatus<AccountId> {
    /// It is waiting for authorization
    PendingTokenLock,
    /// It is waiting execution (tokens currently locked)
    ExecutionPending,
    /// receipt used, (receipt signer, receipt uid)
    ExecutionToBeSkipped(AccountId, u64),
}

impl<AccountId> Default for LegStatus<AccountId> {
    fn default() -> Self {
        Self::PendingTokenLock
    }
}

/// Status of a authorization
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorizationStatus {
    /// Invalid authorization
    Unknown,
    /// Pending user's consent
    Pending,
    /// Authorized by the user
    Authorized,
    /// Rejected by the user
    Rejected,
}

impl Default for AuthorizationStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Type of settlement
#[derive(Encode, Decode, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettlementType<BlockNumber> {
    /// Instruction should be settled as soon as all authorizations are received
    SettleOnAuthorization,
    /// Instruction should be settled on a particular block
    SettleOnBlock(BlockNumber),
}

impl<BlockNumber> Default for SettlementType<BlockNumber> {
    fn default() -> Self {
        Self::SettleOnAuthorization
    }
}

/// Details about an instruction
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct Instruction<Moment, BlockNumber> {
    /// Unique instruction id. It is an auto incrementing number
    pub instruction_id: u64,
    /// Id of the venue this instruction belongs to
    pub venue_id: u64,
    /// Status of the instruction
    pub status: InstructionStatus,
    /// Type of settlement used for this instruction
    pub settlement_type: SettlementType<BlockNumber>,
    /// Date at which this instruction was created
    pub created_at: Option<Moment>,
    /// Date from which this instruction is valid
    pub valid_from: Option<Moment>,
}

/// Details of a leg including the leg number in the instruction
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct Leg<Balance> {
    /// Identity of the sender
    pub from: IdentityId,
    /// Identity of the receiver
    pub to: IdentityId,
    /// Ticker of the asset being transferred
    pub asset: Ticker,
    /// Amount being transferred
    pub amount: Balance,
}

/// Details about a venue
#[derive(Encode, Decode, Clone, Default, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct Venue {
    /// Identity of the venue's creator
    pub creator: IdentityId,
    /// instructions under this venue (Only needed for the UI)
    pub instructions: Vec<u64>,
    /// Additional details about this venue
    pub details: Vec<u8>,
}

impl Venue {
    pub fn new(creator: IdentityId, details: Vec<u8>) -> Self {
        Self {
            creator,
            instructions: Vec::new(),
            details,
        }
    }
}

/// Details about an offchain transaction receipt
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct Receipt<Balance> {
    /// Unique receipt number set by the signer for their receipts
    pub receipt_uid: u64,
    /// Identity of the sender
    pub from: IdentityId,
    /// Identity of the receiver
    pub to: IdentityId,
    /// Ticker of the asset being transferred
    pub asset: Ticker,
    /// Amount being transferred
    pub amount: Balance,
}

/// Details about an offchain transaction receipt that a user must input
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct ReceiptDetails<AccountId, OffChainSignature> {
    /// Unique receipt number set by the signer for their receipts
    pub receipt_uid: u64,
    /// Target leg number
    pub leg_number: u64,
    /// Signer for this receipt
    pub signer: AccountId,
    /// signature confirming the receipt details
    pub signature: OffChainSignature,
}

decl_event!(
    pub enum Event<T>
    where
        Balance = <T as CommonTrait>::Balance,
        Moment = <T as pallet_timestamp::Trait>::Moment,
        BlockNumber = <T as frame_system::Trait>::BlockNumber,
        AccountId = <T as frame_system::Trait>::AccountId,
    {
        /// A new venue has been created (did, venue_id)
        VenueCreated(IdentityId, u64),
        /// A new instruction has been created
        /// (did, venue_id, instruction_id, settlement_type, valid_from, legs)
        InstructionCreated(
            IdentityId,
            u64,
            u64,
            SettlementType<BlockNumber>,
            Option<Moment>,
            Vec<Leg<Balance>>,
        ),
        /// An instruction has been authorized (did, instruction_id)
        InstructionAuthorized(IdentityId, u64),
        /// An instruction has been unauthorized (did, instruction_id)
        InstructionUnauthorized(IdentityId, u64),
        /// An instruction has been rejected (did, instruction_id)
        InstructionRejected(IdentityId, u64),
        /// A receipt has been claimed (did, instruction_id, leg_number, receipt_uid, signer)
        ReceiptClaimed(IdentityId, u64, u64, u64, AccountId),
        /// A receipt has been unclaimed (did, instruction_id, leg_number, receipt_uid, signer)
        ReceiptUnclaimed(IdentityId, u64, u64, u64, AccountId),
        /// Venue filtering has been enabled or disabled for a ticker (did, ticker, filtering_enabled)
        VenueFiltering(IdentityId, Ticker, bool),
        /// Venues added to allow list (did, ticker, vec<venue_id>)
        VenuesAllowed(IdentityId, Ticker, Vec<u64>),
        /// Venues added to block list (did, ticker, vec<venue_id>)
        VenuesBlocked(IdentityId, Ticker, Vec<u64>),
        /// Execution of a leg failed (did, instruction_id, leg_id)
        LegFailedExecution(IdentityId, u64, u64),
        /// Instruction failed execution (did, instruction_id)
        InstructionFailed(IdentityId, u64),
        /// Instruction executed successfully(did, instruction_id)
        InstructionExecuted(IdentityId, u64),
        /// Venue unauthorized by ticker owner (did, Ticker, venue_id)
        VenueUnauthorized(IdentityId, Ticker, u64),
    }
);

decl_error! {
    /// Errors for the Settlement module.
    pub enum Error for Module<T: Trait> {
        /// Venue does not exist
        InvalidVenue,
        /// Sender does not have required permissions
        Unauthorized,
        /// No pending authorization for the provided instruction
        NoPendingAuth,
        /// Instruction has not been authorized
        InstructionNotAuthorized,
        /// Provided instruction is not pending execution
        InstructionNotPending,
        /// Provided leg is not pending execution
        LegNotPending,
        /// Signer is not authorized by the venue
        UnauthorizedSigner,
        /// Receipt already used
        ReceiptAlreadyClaimed,
        /// Receipt not used yet
        ReceiptNotClaimed,
        /// Venue does not have required permissions
        UnauthorizedVenue,
        /// While authorizing the transfer, system failed to take custodial ownership of the assets involved
        FailedToTakeCustodialOwnership,
        /// Instruction validity has not started yet
        InstructionWaitingValidity,
        /// Instruction's target settle block reached
        InstructionSettleBlockPassed,
        /// Instruction waiting for settle block
        InstructionWaitingSettleBlock,
        /// Offchain signature is invalid
        InvalidSignature,
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as StoCapped {
        /// Info about a venue. venue_id -> venue_details
        VenueInfo get(fn venue_info): map hasher(twox_64_concat) u64 => Venue;
        /// Signers authorized by the venue. (venue_id, signer) -> authorized_bool
        VenueSigners get(fn venue_signers): double_map hasher(twox_64_concat) u64, hasher(twox_64_concat) T::AccountId => bool;
        /// Details about an instruction. instruction_id -> instruction_details
        InstructionDetails get(fn instruction_details): map hasher(twox_64_concat) u64 => Instruction<T::Moment, T::BlockNumber>;
        /// Legs under an instruction. (instruction_id, leg_number) -> Leg
        InstructionLegs get(fn instruction_legs): double_map hasher(twox_64_concat) u64, hasher(twox_64_concat) u64 => Leg<T::Balance>;
        /// Status of a leg under an instruction. (instruction_id, leg_number) -> LegStatus
        InstructionLegStatus get(fn instruction_leg_status): double_map hasher(twox_64_concat) u64, hasher(twox_64_concat) u64 => LegStatus<T::AccountId>;
        /// Number of authorizations pending before instruction is executed. instruction_id -> auths_pending
        InstructionAuthsPending get(fn instruction_auths_pending): map hasher(twox_64_concat) u64 => u64;
        /// Tracks authorizations received for an instruction. (instruction_id, counter_party) -> AuthorizationStatus
        AuthsReceived get(fn auths_received): double_map hasher(twox_64_concat) u64, hasher(twox_64_concat) IdentityId => AuthorizationStatus;
        /// Helps a user track their pending instructions and authorizations (only needed for UI).
        /// (counter_party, instruction_id) -> AuthorizationStatus
        UserAuths get(fn user_auths): double_map hasher(twox_64_concat) IdentityId, hasher(twox_64_concat) u64 => AuthorizationStatus;
        /// Tracks redemption of receipts. (signer, receipt_uid) -> receipt_used
        ReceiptsUsed get(fn receipts_used): double_map hasher(twox_64_concat) T::AccountId, hasher(blake2_128_concat) u64 => bool;
        /// Tracks if a token has enabled filtering venues that can create instructions involving their token. Ticker -> filtering_enabled
        VenueFiltering get(fn venue_filtering): map hasher(blake2_128_concat) Ticker => bool;
        /// Venues that are allowed to create instructions involving a particular ticker. Oly used if filtering is enabled.
        /// (ticker, venue_id) -> allowed
        VenueAllowList get(fn venue_allow_list): double_map hasher(blake2_128_concat) Ticker, hasher(twox_64_concat) u64 => bool;
        /// Number of venues in the system
        VenueCounter get(fn venue_counter) build(|_| 1u64): u64;
        /// Number of instructions in the system
        InstructionCounter get(fn instruction_counter) build(|_| 1u64): u64;
        /// The list of scheduled instructions with the block numbers in which those instructions
        /// become eligible to be executed. BlockNumber -> Vec<instruction_id>
        ScheduledInstructions get(fn scheduled_instructions): map hasher(twox_64_concat) T::BlockNumber => Vec<u64>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        const MaxScheduledInstructionLegsPerBlock: u32 = T::MaxScheduledInstructionLegsPerBlock::get();

        /// Registers a new venue.
        ///
        /// * `details` - Extra details about a venue
        /// * `signers` - Array of signers that are allowed to sign receipts for this venue
        ///
        /// # Weight
        /// `200_000 + 50_000 * signers.len()`
        #[weight = 200_000 + 50_000 * u64::try_from(signers.len()).unwrap_or_default()]
        pub fn create_venue(origin, details: Vec<u8>, signers: Vec<T::AccountId>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;
            let venue = Venue::new(did, details);
            let venue_counter = Self::venue_counter();
            <VenueInfo>::insert(venue_counter, venue);
            for signer in signers {
                <VenueSigners<T>>::insert(venue_counter, signer, true);
            }
            <VenueCounter>::put(venue_counter + 1);
            Self::deposit_event(RawEvent::VenueCreated(did, venue_counter));
            Ok(())
        }

        /// Adds a new instruction.
        ///
        /// # Arguments
        /// * `venue_id` - ID of the venue this instruction belongs to.
        /// * `settlement_type` - Defines if the instruction should be settled
        ///    immediately after receiving all auths or waiting till a specific block.
        /// * `valid_from` - Optional date from which people can interact with this instruction.
        /// * `legs` - Legs included in this instruction.
        ///
        /// # Weight
        /// `200_000 + 100_000 * legs.len()`
        #[weight = 200_000 + 100_000 * u64::try_from(legs.len()).unwrap_or_default()]
        pub fn add_instruction(
            origin,
            venue_id: u64,
            settlement_type: SettlementType<T::BlockNumber>,
            valid_from: Option<T::Moment>,
            legs: Vec<Leg<T::Balance>>
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;

            // check if venue exists and sender has permissions
            ensure!(<VenueInfo>::contains_key(venue_id), Error::<T>::InvalidVenue);
            let mut venue = Self::venue_info(venue_id);
            ensure!(venue.creator == did, Error::<T>::Unauthorized);

            // Prepare data to store in storage
            let instruction_counter = Self::instruction_counter();
            let mut counter_parties = Vec::with_capacity(legs.len() * 2);
            let mut tickers = Vec::with_capacity(legs.len());
            for i in 0..legs.len() {
                counter_parties.push(legs[i].from);
                counter_parties.push(legs[i].to);
                tickers.push(legs[i].asset);
            }

            // Check if venue has required permissions from token owners
            tickers.sort();
            tickers.dedup();
            for ticker in &tickers {
                if Self::venue_filtering(ticker) {
                    ensure!(Self::venue_allow_list(ticker, venue_id), Error::<T>::UnauthorizedVenue);
                }
            }

            counter_parties.sort();
            counter_parties.dedup();
            venue.instructions.push(instruction_counter);
            let instruction = Instruction {
                instruction_id: instruction_counter,
                venue_id: venue_id,
                status: InstructionStatus::Pending,
                settlement_type: settlement_type,
                created_at: Some(<pallet_timestamp::Module<T>>::get()),
                valid_from: valid_from
            };

            // write data to storage
            for counter_party in &counter_parties {
                <UserAuths>::insert(counter_party, instruction_counter, AuthorizationStatus::Pending);
            }

            for i in 0..legs.len() {
                <InstructionLegs<T>>::insert(instruction_counter, u64::try_from(i).unwrap_or_default(), legs[i].clone());
            }

            if let SettlementType::SettleOnBlock(block_number) = settlement_type {
                <ScheduledInstructions<T>>::mutate(block_number, |instruction_ids| instruction_ids.push(instruction_counter));
            }

            <InstructionDetails<T>>::insert(instruction_counter, instruction);
            <InstructionAuthsPending>::insert(instruction_counter, u64::try_from(counter_parties.len()).unwrap_or_default());
            <VenueInfo>::insert(venue_id, venue);
            <InstructionCounter>::put(instruction_counter + 1);
            Self::deposit_event(RawEvent::InstructionCreated(did, venue_id, instruction_counter, settlement_type, valid_from, legs));
            Ok(())
        }

        /// Authorizes an existing instruction.
        ///
        /// # Arguments
        /// * `instruction_id` - Instruction id to authorize.
        #[weight = 1_000_000]
        pub fn authorize_instruction(origin, instruction_id: u64) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;

            Self::unsafe_authorize_instruction(did, instruction_id)?;

            let auths_pending = Self::instruction_auths_pending(instruction_id);

            if auths_pending == 0 && Self::instruction_details(instruction_id).settlement_type == SettlementType::SettleOnAuthorization {
                Self::execute_instruction(instruction_id);
            }

            Ok(())
        }

        /// Unauthorizes an existing instruction.
        ///
        /// # Arguments
        /// * `instruction_id` - Instruction id to unauthorize.
        #[weight = 1_000_000]
        pub fn unauthorize_instruction(origin, instruction_id: u64) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;

            Self::ensure_instruction_validity(instruction_id)?;

            // checks if instruction exists and sender is a counter party with an active authorization
            ensure!(Self::user_auths(did, instruction_id) == AuthorizationStatus::Authorized, Error::<T>::InstructionNotAuthorized);

            Self::unsafe_unauthorize_instruction(did, instruction_id)
        }

        /// Rejects an existing instruction.
        ///
        /// # Arguments
        /// * `instruction_id` - Instruction id to reject.
        #[weight = 1_000_000]
        pub fn reject_instruction(origin, instruction_id: u64) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;

            Self::ensure_instruction_validity(instruction_id)?;

            let user_auth_status = Self::user_auths(did, instruction_id);
            match user_auth_status {
                AuthorizationStatus::Authorized => Self::unsafe_unauthorize_instruction(did, instruction_id)?,
                AuthorizationStatus::Pending => { },
                _ => return Err(Error::<T>::NoPendingAuth.into())
            };

            // Updates storage
            <UserAuths>::insert(did, instruction_id, AuthorizationStatus::Rejected);
            <AuthsReceived>::insert(instruction_id, did, AuthorizationStatus::Rejected);

            if Self::instruction_details(instruction_id).settlement_type == SettlementType::SettleOnAuthorization {
                Self::execute_instruction(instruction_id);
            }

            Self::deposit_event(RawEvent::InstructionRejected(did, instruction_id));
            Ok(())
        }

        // TODO: Add add_offchain_auth

        /// Accepts an instruction and claims a signed receipt.
        ///
        /// # Arguments
        /// * `instruction_id` - Target instruction id.
        /// * `leg_number` - Target leg id for the receipt
        /// * `receipt_uid` - Receipt ID generated by the signer.
        /// * `signer` - Signer of the receipt.
        /// * `signed_data` - Signed receipt.
        #[weight = 1_000_000]
        pub fn authorize_with_receipts(origin, instruction_id: u64, receipt_details: Vec<ReceiptDetails<T::AccountId, T::OffChainSignature>>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;
            Self::ensure_instruction_validity(instruction_id)?;

            // checks if the sender is a counter party with a pending or rejected authorization
            let user_auth = Self::user_auths(did, instruction_id);
            ensure!(
                user_auth == AuthorizationStatus::Pending || user_auth == AuthorizationStatus::Rejected,
                Error::<T>::NoPendingAuth
            );

            let instruction_details = Self::instruction_details(instruction_id);

            let mut receipt_ids = receipt_details.iter().map(|receipt| (receipt.signer.clone(), receipt.receipt_uid)).collect::<Vec<_>>();
            receipt_ids.sort();
            receipt_ids.dedup();

            ensure!(
                receipt_ids.len() == receipt_details.len(),
                Error::<T>::ReceiptAlreadyClaimed
            );

            for receipt in &receipt_details {
                ensure!(
                    Self::venue_signers(&instruction_details.venue_id, &receipt.signer), Error::<T>::UnauthorizedSigner
                );
                ensure!(
                    !Self::receipts_used(&receipt.signer, &receipt.receipt_uid), Error::<T>::ReceiptAlreadyClaimed
                );

                let leg = Self::instruction_legs(&instruction_id, &receipt.leg_number);
                ensure!(leg.from == did, Error::<T>::Unauthorized);

                let msg = Receipt {
                    receipt_uid: receipt.receipt_uid,
                    from: leg.from,
                    to: leg.to,
                    asset: leg.asset,
                    amount: leg.amount
                };

                ensure!(
                    receipt.signature.verify(&msg.encode()[..], &receipt.signer),
                    Error::<T>::InvalidSignature
                );
            }

            // lock tokens
            let legs = <InstructionLegs<T>>::iter_prefix(instruction_id).collect::<Vec<_>>();
            for i in 0..legs.len() {
                if legs[i].1.from == did {
                    if let Some(receipt) = receipt_details.iter().find(|receipt| receipt.leg_number == legs[i].0) {
                        <InstructionLegStatus<T>>::insert(
                            instruction_id,
                            legs[i].0,
                            LegStatus::ExecutionToBeSkipped(receipt.signer.clone(), receipt.receipt_uid)
                        );
                    } else if T::Asset::unsafe_increase_custody_allowance(
                        did,
                        legs[i].1.asset,
                        did,
                        SettlementDID.as_id(),
                        legs[i].1.amount
                    ).is_err() {
                        // Undo previous locks
                        for j in 0..i {
                            if !receipt_details.iter().any(|receipt| receipt.leg_number == legs[i].0) {
                                T::Asset::unsafe_decrease_custody_allowance(did,
                                    legs[j].1.asset,
                                    did,
                                    SettlementDID.as_id(),
                                    legs[j].1.amount
                                );
                            }
                            <InstructionLegStatus<T>>::insert(
                                instruction_id,
                                legs[i].0,
                                LegStatus::PendingTokenLock,
                            );
                        }
                        return Err(Error::<T>::FailedToTakeCustodialOwnership.into());
                    } else {
                        <InstructionLegStatus<T>>::insert(
                            instruction_id,
                            legs[i].0,
                            LegStatus::ExecutionPending,
                        );
                    }
                }
            }

            // Updates storage
            let auths_pending = Self::instruction_auths_pending(instruction_id).saturating_sub(1);
            <UserAuths>::insert(did, instruction_id, AuthorizationStatus::Authorized);
            <AuthsReceived>::insert(instruction_id, did, AuthorizationStatus::Authorized);
            <InstructionAuthsPending>::insert(instruction_id, auths_pending);
            for receipt in &receipt_details {
                <ReceiptsUsed<T>>::insert(&receipt.signer, receipt.receipt_uid, true);
                Self::deposit_event(RawEvent::ReceiptClaimed(did, instruction_id, receipt.leg_number, receipt.receipt_uid, receipt.signer.clone()));
            }

            Self::deposit_event(RawEvent::InstructionAuthorized(did, instruction_id));


            if auths_pending == 0 && instruction_details.settlement_type == SettlementType::SettleOnAuthorization {
                Self::execute_instruction(instruction_id);
            }

            Ok(())
        }

        /// Claims a signed receipt.
        ///
        /// # Arguments
        /// * `instruction_id` - Target instruction id for the receipt.
        /// * `leg_number` - Target leg id for the receipt
        /// * `receipt_uid` - Receipt ID generated by the signer.
        /// * `signer` - Signer of the receipt.
        /// * `signed_data` - Signed receipt.
        #[weight = 1_000_000]
        pub fn claim_receipt(origin, instruction_id: u64, receipt_details: ReceiptDetails<T::AccountId, T::OffChainSignature>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;

            Self::unsafe_claim_receipt(
                did,
                instruction_id,
                receipt_details.leg_number,
                receipt_details.receipt_uid,
                receipt_details.signer,
                receipt_details.signature
            )
        }

        /// Unclaims a previously claimed receipt.
        ///
        /// # Arguments
        /// * `instruction_id` - Target instruction id for the receipt.
        /// * `leg_number` - Target leg id for the receipt
        #[weight = 2_000_000]
        pub fn unclaim_receipt(origin, instruction_id: u64, leg_number: u64) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;

            Self::ensure_instruction_validity(instruction_id)?;
            if let LegStatus::ExecutionToBeSkipped(signer, receipt_uid) = Self::instruction_leg_status(instruction_id, leg_number) {
                let leg = Self::instruction_legs(instruction_id, leg_number);
                ensure!(leg.from == did, Error::<T>::Unauthorized);
                T::Asset::unsafe_increase_custody_allowance(
                    did,
                    leg.asset,
                    did,
                    SettlementDID.as_id(),
                    leg.amount
                )?;
                <ReceiptsUsed<T>>::insert(&signer, receipt_uid, false);
                <InstructionLegStatus<T>>::insert(instruction_id, leg_number, LegStatus::ExecutionPending);
                Self::deposit_event(RawEvent::ReceiptUnclaimed(did, instruction_id, leg_number, receipt_uid, signer));
                Ok(())
            } else {
                Err(Error::<T>::ReceiptNotClaimed.into())
            }
        }

        /// Enables or disabled venue filtering for a token.
        ///
        /// # Arguments
        /// * `ticker` - Ticker of the token in question.
        /// * `enabled` - Boolean that decides if the filtering should be enabled.
        #[weight = 200_000]
        pub fn set_venue_filtering(origin, ticker: Ticker, enabled: bool) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;
            ensure!(Self::is_owner(&ticker, did), Error::<T>::Unauthorized);
            <VenueFiltering>::insert(ticker, enabled);
            Self::deposit_event(RawEvent::VenueFiltering(did, ticker, enabled));
            Ok(())
        }

        /// Allows additional venues to create instructions involving an asset.
        ///
        /// * `ticker` - Ticker of the token in question.
        /// * `venues` - Array of venues that are allowed to create instructions for the token in question.
        ///
        /// # Weight
        /// `200_000 + 50_000 * venues.len()`
        #[weight = 200_000 + 50_000 * u64::try_from(venues.len()).unwrap_or_default()]
        pub fn allow_venues(origin, ticker: Ticker, venues: Vec<u64>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;
            ensure!(Self::is_owner(&ticker, did), Error::<T>::Unauthorized);
            for venue in &venues {
                <VenueAllowList>::insert(&ticker, venue, true);
            }
            Self::deposit_event(RawEvent::VenuesAllowed(did, ticker, venues));
            Ok(())
        }

        /// Revokes permission given to venues for creating instructions involving a particular asset.
        ///
        /// * `ticker` - Ticker of the token in question.
        /// * `venues` - Array of venues that are no longer allowed to create instructions for the token in question.
        ///
        /// # Weight
        /// `200_000 + 50_000 * venues.len()`
        #[weight = 200_000 + 50_000 * u64::try_from(venues.len()).unwrap_or_default()]
        pub fn disallow_venues(origin, ticker: Ticker, venues: Vec<u64>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let did = Context::current_identity_or::<Identity<T>>(&sender)?;
            ensure!(Self::is_owner(&ticker, did), Error::<T>::Unauthorized);
            for venue in &venues {
                <VenueAllowList>::insert(&ticker, venue, false);
            }
            Self::deposit_event(RawEvent::VenuesBlocked(did, ticker, venues));
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    /// The account ID of the settlement module.
    ///
    /// This actually does computation. If you need to keep using it, then make sure you cache the
    /// value and only call this once.
    pub fn account_id() -> T::AccountId {
        SETTLEMENT_MODULE_ID.into_account()
    }

    /// Returns true if `sender_did` is the owner of `ticker` asset.
    fn is_owner(ticker: &Ticker, sender_did: IdentityId) -> bool {
        T::Asset::is_owner(ticker, sender_did)
    }

    /// Settles scheduled instructions
    pub fn on_initialize(block_number: T::BlockNumber) -> Weight {
        let scheduled_instructions = <ScheduledInstructions<T>>::take(block_number);
        let mut legs_executed: u32 = 0;
        let max_legs = T::MaxScheduledInstructionLegsPerBlock::get();
        for i in 0..scheduled_instructions.len() {
            legs_executed += Self::execute_instruction(scheduled_instructions[i]);
            if legs_executed >= max_legs {
                let mut next_block_instructions =
                    Self::scheduled_instructions(block_number + 1.into());
                next_block_instructions.extend_from_slice(&scheduled_instructions[i..]);
                break;
            }
        }
        (10_000 * legs_executed).into()
    }

    fn unsafe_unauthorize_instruction(did: IdentityId, instruction_id: u64) -> DispatchResult {
        // unlock tokens
        let legs = <InstructionLegs<T>>::iter_prefix(instruction_id).collect::<Vec<_>>();
        for i in 0..legs.len() {
            if legs[i].1.from == did {
                match Self::instruction_leg_status(instruction_id, legs[i].0) {
                    LegStatus::ExecutionToBeSkipped(signer, receipt_uid) => {
                        <ReceiptsUsed<T>>::insert(&signer, receipt_uid, false);
                        <InstructionLegStatus<T>>::insert(
                            instruction_id,
                            legs[i].0,
                            LegStatus::PendingTokenLock,
                        );
                        Self::deposit_event(RawEvent::ReceiptUnclaimed(
                            did,
                            instruction_id,
                            legs[i].0,
                            receipt_uid,
                            signer,
                        ));
                    }
                    LegStatus::ExecutionPending => {
                        T::Asset::unsafe_decrease_custody_allowance(
                            did,
                            legs[i].1.asset,
                            did,
                            SettlementDID.as_id(),
                            legs[i].1.amount,
                        );
                        <InstructionLegStatus<T>>::insert(
                            instruction_id,
                            legs[i].0,
                            LegStatus::PendingTokenLock,
                        );
                    }
                    LegStatus::PendingTokenLock => {
                        return Err(Error::<T>::InstructionNotAuthorized.into())
                    }
                };
            }
        }

        // Updates storage
        <UserAuths>::insert(did, instruction_id, AuthorizationStatus::Pending);
        <AuthsReceived>::remove(instruction_id, did);
        <InstructionAuthsPending>::mutate(instruction_id, |auths_pending| *auths_pending += 1);

        Self::deposit_event(RawEvent::InstructionUnauthorized(did, instruction_id));
        Ok(())
    }

    fn ensure_instruction_validity(instruction_id: u64) -> DispatchResult {
        let instruction_details = Self::instruction_details(instruction_id);
        ensure!(
            instruction_details.status == InstructionStatus::Pending,
            Error::<T>::InstructionNotPending
        );
        if let Some(valid_from) = instruction_details.valid_from {
            ensure!(
                <pallet_timestamp::Module<T>>::get() >= valid_from,
                Error::<T>::InstructionWaitingValidity
            );
        }
        if let SettlementType::SettleOnBlock(block_number) = instruction_details.settlement_type {
            ensure!(
                block_number > system::Module::<T>::block_number(),
                Error::<T>::InstructionSettleBlockPassed
            );
        }
        Ok(())
    }

    fn execute_instruction(instruction_id: u64) -> u32 {
        let legs = <InstructionLegs<T>>::iter_prefix(instruction_id).collect::<Vec<_>>();
        let mut instructions_processed: u32 = 0;
        // Instruction rejected.
        if Self::instruction_auths_pending(instruction_id) > 0 {
            // unlock any locked tokens and mark receipts as unused

            instructions_processed += u32::try_from(legs.len()).unwrap_or_default();

            for leg in legs {
                match Self::instruction_leg_status(instruction_id, leg.0) {
                    LegStatus::ExecutionToBeSkipped(signer, receipt_uid) => {
                        <ReceiptsUsed<T>>::insert(&signer, receipt_uid, false);
                        Self::deposit_event(RawEvent::ReceiptUnclaimed(
                            SettlementDID.as_id(),
                            instruction_id,
                            leg.0,
                            receipt_uid,
                            signer,
                        ));
                    }
                    LegStatus::ExecutionPending => T::Asset::unsafe_decrease_custody_allowance(
                        SettlementDID.as_id(),
                        leg.1.asset,
                        leg.1.from,
                        SettlementDID.as_id(),
                        leg.1.amount,
                    ),
                    _ => {}
                }
            }
            Self::deposit_event(RawEvent::InstructionRejected(
                SettlementDID.as_id(),
                instruction_id,
            ));
        } else {
            let mut failed = false;
            let mut tickers = Vec::with_capacity(legs.len());
            for i in 0..legs.len() {
                tickers.push(legs[i].1.asset);
            }
            tickers.sort();
            tickers.dedup();
            let venue_id = Self::instruction_details(instruction_id).venue_id;
            for ticker in &tickers {
                if Self::venue_filtering(ticker) {
                    if !Self::venue_allow_list(ticker, venue_id) {
                        failed = true;
                        Self::deposit_event(RawEvent::VenueUnauthorized(
                            SettlementDID.as_id(),
                            *ticker,
                            venue_id,
                        ));
                    }
                }
            }
            // TODO Implement a way to do the checks before committing changes to storage.
            if !failed {
                for i in 0..legs.len() {
                    let status = Self::instruction_leg_status(instruction_id, legs[i].0);
                    if status == LegStatus::ExecutionPending {
                        if T::Asset::unsafe_transfer_by_custodian(
                            SettlementDID.as_id(),
                            legs[i].1.asset,
                            legs[i].1.from,
                            legs[i].1.to,
                            legs[i].1.amount,
                        )
                        .is_err()
                        {
                            failed = true;
                            Self::deposit_event(RawEvent::LegFailedExecution(
                                SettlementDID.as_id(),
                                instruction_id,
                                legs[i].0,
                            ));
                            Self::deposit_event(RawEvent::InstructionFailed(
                                SettlementDID.as_id(),
                                instruction_id,
                            ));

                            for j in 0..legs.len() {
                                match Self::instruction_leg_status(instruction_id, legs[j].0) {
                                    LegStatus::ExecutionToBeSkipped(signer, receipt_uid) => {
                                        <ReceiptsUsed<T>>::insert(&signer, receipt_uid, false);
                                        Self::deposit_event(RawEvent::ReceiptUnclaimed(
                                            SettlementDID.as_id(),
                                            instruction_id,
                                            legs[j].0,
                                            receipt_uid,
                                            signer,
                                        ));
                                    }
                                    LegStatus::ExecutionPending => {
                                        if j < i {
                                            // Undo previous legs
                                            T::Asset::unsafe_system_transfer(
                                                SettlementDID.as_id(),
                                                &legs[j].1.asset,
                                                legs[j].1.to,
                                                legs[j].1.from,
                                                legs[j].1.amount,
                                            );
                                        } else {
                                            // Remove custodian allowance
                                            T::Asset::unsafe_decrease_custody_allowance(
                                                SettlementDID.as_id(),
                                                legs[j].1.asset,
                                                legs[j].1.from,
                                                SettlementDID.as_id(),
                                                legs[j].1.amount,
                                            );
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            break;
                        }
                    }
                }
                if !failed {
                    Self::deposit_event(RawEvent::InstructionExecuted(
                        SettlementDID.as_id(),
                        instruction_id,
                    ));
                }
            }
        }

        <InstructionLegs<T>>::remove_prefix(instruction_id);
        <InstructionDetails<T>>::remove(instruction_id);
        <InstructionLegStatus<T>>::remove_prefix(instruction_id);
        <InstructionAuthsPending>::remove(instruction_id);
        <AuthsReceived>::remove_prefix(instruction_id);
        // NB UserAuths mapping is not cleared
        instructions_processed
    }

    fn unsafe_authorize_instruction(did: IdentityId, instruction_id: u64) -> DispatchResult {
        Self::ensure_instruction_validity(instruction_id)?;

        // checks if the sender is a counter party with a pending or rejected authorization
        let user_auth = Self::user_auths(did, instruction_id);
        ensure!(
            user_auth == AuthorizationStatus::Pending || user_auth == AuthorizationStatus::Rejected,
            Error::<T>::NoPendingAuth
        );

        // lock tokens
        let legs = <InstructionLegs<T>>::iter_prefix(instruction_id).collect::<Vec<_>>();
        for i in 0..legs.len() {
            if legs[i].1.from == did {
                // TODO Implement a way to do the checks before committing changes to storage.
                if T::Asset::unsafe_increase_custody_allowance(
                    did,
                    legs[i].1.asset,
                    did,
                    SettlementDID.as_id(),
                    legs[i].1.amount,
                )
                .is_err()
                {
                    // Undo custody locks
                    for j in 0..i {
                        T::Asset::unsafe_decrease_custody_allowance(
                            did,
                            legs[j].1.asset,
                            did,
                            SettlementDID.as_id(),
                            legs[j].1.amount,
                        );
                        <InstructionLegStatus<T>>::insert(
                            instruction_id,
                            legs[i].0,
                            LegStatus::PendingTokenLock,
                        );
                    }
                    return Err(Error::<T>::FailedToTakeCustodialOwnership.into());
                } else {
                    <InstructionLegStatus<T>>::insert(
                        instruction_id,
                        legs[i].0,
                        LegStatus::ExecutionPending,
                    );
                }
            }
        }

        let auths_pending = Self::instruction_auths_pending(instruction_id);

        // Updates storage
        <UserAuths>::insert(did, instruction_id, AuthorizationStatus::Authorized);
        <AuthsReceived>::insert(instruction_id, did, AuthorizationStatus::Authorized);
        <InstructionAuthsPending>::insert(instruction_id, auths_pending.saturating_sub(1));
        Self::deposit_event(RawEvent::InstructionAuthorized(did, instruction_id));

        Ok(())
    }

    fn unsafe_claim_receipt(
        did: IdentityId,
        instruction_id: u64,
        leg_number: u64,
        receipt_uid: u64,
        signer: T::AccountId,
        signature: T::OffChainSignature,
    ) -> DispatchResult {
        Self::ensure_instruction_validity(instruction_id)?;

        ensure!(
            Self::instruction_leg_status(instruction_id, leg_number) == LegStatus::ExecutionPending,
            Error::<T>::LegNotPending
        );
        let venue_id = Self::instruction_details(instruction_id).venue_id;
        ensure!(
            Self::venue_signers(venue_id, &signer),
            Error::<T>::UnauthorizedSigner
        );
        ensure!(
            !Self::receipts_used(&signer, receipt_uid),
            Error::<T>::ReceiptAlreadyClaimed
        );

        let leg = Self::instruction_legs(instruction_id, leg_number);
        ensure!(leg.from == did, Error::<T>::Unauthorized);

        let msg = Receipt {
            receipt_uid: receipt_uid,
            from: leg.from,
            to: leg.to,
            asset: leg.asset,
            amount: leg.amount,
        };

        ensure!(
            signature.verify(&msg.encode()[..], &signer),
            Error::<T>::InvalidSignature
        );

        T::Asset::unsafe_decrease_custody_allowance(
            did,
            leg.asset,
            did,
            SettlementDID.as_id(),
            leg.amount,
        );

        <ReceiptsUsed<T>>::insert(&signer, receipt_uid, true);

        <InstructionLegStatus<T>>::insert(
            instruction_id,
            leg_number,
            LegStatus::ExecutionToBeSkipped(signer.clone(), receipt_uid),
        );
        Self::deposit_event(RawEvent::ReceiptClaimed(
            did,
            instruction_id,
            leg_number,
            receipt_uid,
            signer,
        ));
        Ok(())
    }
}

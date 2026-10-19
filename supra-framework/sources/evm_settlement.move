/// Escrow and settlement records for value that crosses between the Move side of the chain and
/// the Supra EVM (SEVM).
///
/// SUPRA has a fixed supply cap and the SEVM cannot mint. Native SUPRA on the SEVM is therefore a
/// mirror of value escrowed here: a Move -> SEVM crossing moves coins into this module's escrow
/// store and records the intent, and a SEVM -> Move crossing is settled by releasing escrowed
/// coins (or, when mirrored value is retired, burning them).
///
/// ### Who can move escrowed value
///
/// The escrow is the primary fungible store of an *escrow authority* object: a named object
/// created at genesis, immediately transferred to its own address and with ungated transfer
/// disabled, so that no account owns it. `initialize` keeps exactly one capability over it, an
/// `ExtendRef`, inside the `Escrow` resource. An `ExtendRef` is confined to that one object: it
/// mints a signer for the authority address and for nothing else.
///
/// Move's own visibility rules are what make that capability safe. `Escrow` is a resource of this
/// module, so only this module can borrow it, and therefore only this module can turn the
/// `ExtendRef` into a signer. There is no entry function, no governance script and no other
/// framework module that can produce the escrow authority's signer, and because the authority owns
/// itself, the ownership chain above the escrow store reaches no account at all, so no external
/// signer passes the store's owner check - `test_supra_framework_signer_cannot_withdraw_from_escrow`
/// asserts exactly that, for the most privileged signer on the chain.
///
/// So the only routes by which escrowed value moves are this module's own primitives: `deposit`
/// (permissionless, in), `release` and `burn` (settlement-only, out).
///
/// One consequence of the authority owning itself is worth knowing before touching this module or
/// anything that authorizes against its objects. `object::owns` walks the ownership chain until it
/// reaches the address it is asking about or an address with no `ObjectCore`; above the escrow
/// store the chain runs authority -> authority forever, so for any address other than the
/// authority itself the walk ends by aborting on the nesting bound, `0x20006`
/// (`out_of_range(EMAXIMUM_NESTING)`), rather than returning `false`. Any `owns`-based
/// authorization naming the escrow authority, the escrow store or a settlement record object
/// therefore fails with an out-of-range error instead of a clean permission denial, including for
/// a caller that has done nothing wrong. The walk is bounded by `MAXIMUM_OBJECT_NESTING`, so this
/// costs a fixed handful of reads and is not a gas concern, and a check by the actual owner
/// short-circuits on the first hop, which is why this module's own withdrawals are unaffected.
///
/// ### Why nothing here is contended
///
/// A Move -> SEVM crossing is a normal user transaction and many of them land in the same block,
/// so the deposit path must not touch any location that other deposits also write:
/// * the escrow balance is a `ConcurrentFungibleBalance`, so a deposit is a commutative aggregator
///   add rather than a read-modify-write of a `u64`. Feature `DEFAULT_TO_CONCURRENT_FUNGIBLE_BALANCE`
///   is off in production, so `initialize` upgrades the store explicitly;
/// * settlement ids come from `transaction_context::generate_auid_address` by way of
///   `object::create_object`, which is per-transaction state, not a chain-wide counter;
/// * each recorded intent is a `SettlementRecord` resource in its own object, addressed by its
///   settlement id, rather than pushed onto a shared queue resource;
/// * all events are module events (`#[event]` + `event::emit`). A legacy `EventHandle` carries a
///   counter inside the resource that owns it, so an escrow-owned handle would make every deposit
///   write the same location. No `EventHandle` is used here, and none may be added.
///
/// The `Escrow` resource itself is written once, by `initialize`, and only read afterwards.
///
/// The settlement-applying path writes one location on every block it settles: the
/// `SettlementWatermark`. That is not contention. `apply_settlements` runs in exactly one
/// executor-synthesised transaction per block, so the watermark has a single writer and a single
/// write per block - the same reason the block prologue can hold mutable state without serialising
/// anything - and no user transaction touches it at all.
///
/// ### Retiring escrowed value
///
/// The SEVM burns transaction fees rather than paying them out, and retires the balance of a
/// self-destructed account the same way, so the value it mirrors shrinks without any crossing. The
/// escrow follows by retiring the same amount: `apply_settlements` takes one whole-quant figure per
/// block and passes it to `burn`. That is the only reason this path exists, and its only caller.
///
/// `burn` withdraws escrowed fungible SUPRA and retires it in that form with the
/// `BurnCapability<SupraCoin>` in `Escrow`, through `coin::burn_paired_fungible_asset`. Neither step
/// reads a feature flag, so whether a burn succeeds does not depend on governance feature state
/// (#4135). It deliberately does not use the `BurnRef` paired with `SupraCoin`, because that ref is
/// a single chain-wide object that governance can remove from the pairing permanently, and a burn
/// has no refund path: if burning stopped working, escrow could never be reduced and the supply peg
/// this module exists to hold would drift. A `BurnCapability` is a copyable capability, so holding
/// one here takes nothing away from any other holder.
///
/// The capability is a field of `Escrow` rather than a resource of its own, so the escrow cannot
/// exist without the means to retire value. `initialize` copies `transaction_fee`'s, genesis passes
/// its own to `initialize_with_burn_cap`, and there is no second call that installs it afterwards.
///
/// That copy is self-sufficient once taken. `coin::burn_paired_fungible_asset` reads nothing from
/// the capability it is passed - it is an empty struct, and proof of authority rather than a handle
/// - so this module keeps retiring value after `transaction_fee::convert_to_aptos_fa_burn_ref` has
/// consumed the chain's other copy. The ordering that follows is one-way: that conversion leaves no
/// `BurnCapability<SupraCoin>` for `initialize` to copy, and none can be minted, so an escrow
/// created before it goes on working and an escrow not yet created can never be.
///
/// ### The escrow balance is a lower bound
///
/// The escrow is a primary fungible store at a publicly derivable address, so SUPRA can arrive
/// there by an ordinary transfer that never calls `deposit` and so creates no settlement record.
/// On a chain where the escrow is created by an upgrade rather than at genesis, value may also
/// already sit at that address before `initialize` runs, so the escrow is not necessarily empty
/// once it exists.
///
/// Such value is unowned: paying anything out requires a settlement record, and only a crossing or
/// a refund creates one, so a surplus is inert and stays in the store. Consumers must therefore
/// read `escrow_balance` as a lower bound on what the settlement path can pay - the value the
/// settlement path has escrowed is at most the balance, never more - rather than as an exact
/// account of crossed value. Anything reconciling crossings against the balance has to allow for
/// the difference.
///
/// ### Settlement application
///
/// The code that applies settlements - `apply_settlements`, driven by a system transaction the node
/// injects - belongs in this module. It is not a separate module because the state it works on is
/// module-private: it reads the `SETTLEMENT_*` codes and the fields of `SettlementRecord`, and Move
/// scopes constants and struct fields to the declaring module without extending either to a
/// `friend`. A separate module would therefore need one public accessor per constant and per field
/// - public API whose only consumer is inside the framework - so the primitives it needs
/// (`record_settlement`, `take_record`, `release`, `release_to_recipient`, `burn`) are plain
/// private functions here instead.
///
/// Because that code applies many settlements in one transaction, where an abort would halt the
/// block, `release` and `burn` report per-settlement failures as a `u64` status code (see the
/// `SETTLEMENT_*` constants) and never abort on a per-item precondition. Aborts here are reserved
/// for genuine programming errors, such as initializing twice.
///
/// A batch reaches this module as parallel columns of primitives - one column per field of an
/// inbound settlement - alongside scalars that describe the whole block. That shape is positional,
/// so a column built in a different order from its neighbours would pay one settlement's amount to
/// another settlement's recipient, and nothing in the types would catch it. Two things hold it
/// together: the columns are filled in a single pass over one list on the Rust side, so a row's
/// fields are pushed together or not at all, and `test_apply_pairs_each_row_across_all_columns`
/// uses values no two columns share, so any mis-pairing shows up as a wrong payment. Whole-block
/// scalars add no columns and so do not add to that pressure. If a later phase needs a new
/// *per-settlement* field, revisit the encoding before adding a seventh column - a single
/// BCS-encoded batch, as a validator transaction carrying `data_bytes` does - because each column
/// makes a mis-pairing cheaper to introduce and no cheaper to detect.
///
/// The two directions get their exactly-once property from different state. A Move -> SEVM crossing
/// leaves a `SettlementRecord` behind, and `take_record` is already a no-op once that record is
/// gone, so applying the same crossing twice removes nothing twice. A SEVM -> Move credit leaves no
/// record here to consume, so each carries its position in the total settlement order - the block
/// that recorded it, the transaction within that block, and the settlement within that transaction -
/// and `SettlementWatermark` holds the highest position the applier has processed. Anything at or
/// below the watermark is skipped, and every entry that is processed advances it, whether the credit
/// was paid, returned or skipped. A replayed batch therefore sits entirely at or below the watermark
/// and applies nothing, and a batch that follows a partially applied one applies exactly the entries
/// above it. Exactly-once for a credit is an invariant of this module, not an obligation on its
/// caller. A block's burn is neither an outbound record nor an ordered credit, so it gets a cursor
/// of its own in the same resource; `apply_burn` has the one respect in which its rule differs.
module supra_framework::evm_settlement {
    use std::bcs;
    use std::error;
    use std::features;
    use std::option::{Self, Option};
    use std::signer;
    use std::vector;

    use aptos_std::from_bcs;

    use supra_framework::account;
    use supra_framework::aggregator_v2::{Self, Aggregator};
    use supra_framework::coin::{Self, BurnCapability};
    use supra_framework::event;
    use supra_framework::fungible_asset::{Self, FungibleAsset, FungibleStore, Metadata};
    use supra_framework::object::{Self, DeleteRef, ExtendRef, Object};
    use supra_framework::primary_fungible_store;
    use supra_framework::reconfiguration;
    use supra_framework::supra_account;
    use supra_framework::supra_coin::SupraCoin;
    use supra_framework::system_addresses;
    use supra_framework::transaction_fee;

    friend supra_framework::genesis;

    /// Most settlement records that may be outstanding before a new crossing is refused.
    ///
    /// A record is outstanding from the moment a crossing is recorded until the settlement
    /// transaction clears it, so this bounds the work waiting to be settled rather than the rate it
    /// arrives at. It is a **latency budget**, not a capacity: the node applies a fixed number of
    /// settlements per block, so this figure divided by that rate is how many blocks a full backlog
    /// takes to drain, and a crossing started against a full backlog is refused rather than queued
    /// behind it.
    ///
    /// The two figures are therefore a pair, and they are changed by different means - this one by
    /// a framework upgrade, the per-block rate by a node release. Raising this without raising that
    /// lengthens the worst-case wait in proportion. See #3703.
    const MAX_OUTSTANDING_CROSSINGS: u64 = 12_800;

    /// Seed of the named object that is the escrow authority. Frozen: changing it would move the
    /// escrow to a different address.
    const ESCROW_SEED: vector<u8> = b"supra_framework::evm_settlement::escrow";

    /// The 16 bytes that open the settlement id of every SEVM -> Move crossing. Frozen: the node
    /// derives the same id with the same tag (`inbound_settlement_id` in smr-moonshot's
    /// `chain_storage::pending_settlements`), and the two derivations must agree byte for byte.
    const INBOUND_SETTLEMENT_ID_TAG: vector<u8> = b"supra:sevm->move";
    /// The largest transaction or settlement index an inbound settlement id can carry. The id gives
    /// each index four bytes, because the node's indices are `u32`.
    const MAX_INBOUND_ID_INDEX: u64 = 0xffffffff;

    /// Length in bytes of an EVM address.
    const EVM_ADDRESS_LENGTH: u64 = 20;
    /// The EVM zero address. A balance mirrored to it is claimable by nobody.
    const EVM_ZERO_ADDRESS: vector<u8> = x"0000000000000000000000000000000000000000";

    /// The Move side of the chain.
    const DOMAIN_MOVE: u8 = 1;
    /// The Supra EVM.
    const DOMAIN_SEVM: u8 = 2;

    /// The settlement was applied.
    const SETTLEMENT_OK: u64 = 0;
    /// The escrow holds less than the requested amount.
    const SETTLEMENT_INSUFFICIENT_ESCROW: u64 = 1;
    /// The recipient's primary store for SUPRA is frozen.
    const SETTLEMENT_RECIPIENT_FROZEN: u64 = 2;
    /// The settlement moves no value.
    const SETTLEMENT_ZERO_AMOUNT: u64 = 3;
    /// The escrow has not been initialized on this chain.
    const SETTLEMENT_NOT_INITIALIZED: u64 = 4;
    /// The recipient is not on the domain the settlement pays out on.
    const SETTLEMENT_WRONG_DOMAIN: u64 = 5;
    /// The recipient is an address a settlement may not pay out to.
    const SETTLEMENT_INVALID_RECIPIENT: u64 = 6;
    /// The settlement's sender is not a usable EVM address, so it can be neither paid nor returned.
    const SETTLEMENT_INVALID_SENDER: u64 = 7;

    /// The escrow has already been initialized.
    const EALREADY_INITIALIZED: u64 = 1;
    /// The escrow has not been initialized.
    const ENOT_INITIALIZED: u64 = 2;
    /// An EVM address must be exactly 20 bytes.
    const EINVALID_EVM_ADDRESS: u64 = 3;
    /// The recipient does not belong to the domain it claims.
    const EINVALID_RECIPIENT: u64 = 4;
    /// The deposit moves no value.
    const EZERO_AMOUNT: u64 = 5;
    /// The EVM zero address cannot receive a crossing.
    const EZERO_EVM_ADDRESS: u64 = 6;
    /// The parallel vectors describing a batch of inbound settlements have different lengths.
    const EMISMATCHED_BATCH_LENGTHS: u64 = 7;
    /// A crossing may not start while the EVM settlement feature is disabled.
    const ESETTLEMENT_DISABLED: u64 = 8;
    /// A batch of inbound settlements is not in strictly increasing settlement order.
    const EBATCH_NOT_ORDERED: u64 = 9;

    /// No new crossing may start while this many settlement records are outstanding.
    const EBACKLOG_FULL: u64 = 10;
    /// An inbound settlement's transaction or settlement index is above `MAX_INBOUND_ID_INDEX`, so
    /// it does not fit the four bytes the crossing's settlement id gives it.
    const EINBOUND_ID_INDEX_TOO_LARGE: u64 = 11;

    /// A 20-byte address on the Supra EVM.
    struct EvmAddress has copy, drop, store {
        bytes: vector<u8>,
    }

    /// The identifier of a single crossing, unique across both directions. For a crossing recorded
    /// here - a deposit or a refund - it is the 32 bytes of the address of the object its
    /// `SettlementRecord` lives in; see `settlement_record_address` for the uniqueness argument and
    /// for how the Rust side maps an id back to an address. A SEVM -> Move crossing has no record
    /// here, and its id is derived from its position in the settlement order by
    /// `inbound_settlement_id`.
    struct SettlementId has copy, drop, store {
        bytes: vector<u8>,
    }

    /// Where a settlement pays out. Exactly one of the two addresses is set, and which one is set
    /// is determined by `domain`. The two address spaces are modelled separately rather than as a
    /// raw byte vector so that a Move address can never be reinterpreted as an EVM address.
    struct Recipient has copy, drop, store {
        /// `DOMAIN_MOVE` or `DOMAIN_SEVM`.
        domain: u8,
        move_address: Option<address>,
        evm_address: Option<EvmAddress>,
    }

    /// Where a settlement falls in the total order settlements are applied in: the block that
    /// recorded it, the transaction within that block, and the settlement within that transaction.
    /// Compared lexicographically in that order, so it is a total order over every settlement the
    /// chain has ever recorded.
    struct SettlementOrder has copy, drop, store {
        block_height: u64,
        transaction_index: u64,
        settlement_index: u64,
    }

    /// The highest settlement order the applier has processed, and the highest block whose burn it
    /// has retired. This is what makes applying a credit or a burn that arrived from the SEVM
    /// exactly-once: neither leaves a record on this side to consume, so the watermark is the only
    /// state that can tell a new one from a replayed one. Written once per block, by the one
    /// transaction that applies settlements.
    struct SettlementWatermark has key {
        /// None before the first settlement has been processed.
        highest_applied: Option<SettlementOrder>,
        /// The height of the highest block whose burn has been retired. None before the first one.
        /// It advances exactly when value was retired, which is not the same rule the credits
        /// follow; `apply_burn` says why.
        highest_burned_block: Option<u64>,
    }

    /// The record of one crossing. Written at `settlement_record_address(&id)` - one resource per
    /// settlement, never a shared queue - so that the node executor can extract it from the
    /// transaction write set, and so that the settlement-applying module can delete it
    /// independently of every other settlement.
    struct SettlementRecord has key, copy, drop, store {
        /// The domain the value came from.
        source_domain: u8,
        /// The domain the value is owed on.
        destination_domain: u8,
        /// The epoch in which the crossing was recorded.
        epoch: u64,
        /// The identifier of this crossing.
        id: SettlementId,
        /// Who originated the crossing, on `source_domain`. For a deposit this is the account that
        /// signed it. For a record written by the settlement-applying module it is the party the
        /// settlement came from where one is known, and `@supra_framework` where the settlement
        /// originates with the chain itself rather than with a party. It is not consulted when a
        /// settlement is applied; it is here so that a settlement can be attributed to its
        /// originator afterwards, from the record itself rather than from an event.
        sender: address,
        /// Who the value is owed to. Its domain matches `destination_domain`.
        recipient: Recipient,
        /// The amount owed, in the base unit of SUPRA.
        amount: u64,
        /// Set when this record returns value to its sender instead of delivering it, and then
        /// carries one of the `SETTLEMENT_*` status codes describing why.
        refund_reason: Option<u64>,
    }

    /// The capability that removes a settlement record's object once the record is applied. It
    /// lives at the record's own address, so applying a settlement leaves nothing behind.
    struct SettlementRecordDeleteRef has key {
        delete_ref: DeleteRef,
    }

    /// The escrow. Written once by `initialize` and read-only thereafter.
    struct Escrow has key {
        /// The store holding all SUPRA escrowed against SEVM balances. It is the primary fungible
        /// store of the escrow authority object.
        store: Object<FungibleStore>,
        /// The fungible asset metadata paired with `SupraCoin`.
        metadata: Object<Metadata>,
        /// The only capability over the escrow authority object, and hence over the escrow store.
        /// Confined to that one object, and reachable only from inside this module.
        extend_ref: ExtendRef,
        /// The capability `burn` retires escrowed SUPRA with. Held here, rather than in a resource
        /// of its own, so that an escrow without the means to retire value cannot be created.
        burn_cap: BurnCapability<SupraCoin>,
    }

    /// How many settlement records are outstanding, against which a new crossing is admitted.
    ///
    /// An aggregator rather than a plain counter, because every crossing moves it and a plain
    /// counter would make each one conflict with the rest. It is written by deltas and asked
    /// `is_at_least`, and neither operation reads the value, so admitting a crossing costs the
    /// block executor nothing until the backlog approaches the bound - which is where the back
    /// pressure belongs.
    ///
    /// Kept out of `Escrow` so that the deltas land on a resource nothing else reads.
    struct SettlementBacklog has key {
        outstanding: Aggregator<u64>,
    }

    #[event]
    /// Emitted once, when the escrow is created.
    struct EscrowInitialized has drop, store {
        escrow_authority: address,
        escrow_store: address,
        metadata: address,
    }

    #[event]
    /// Emitted when a crossing is recorded and its value escrowed.
    struct SettlementRecorded has drop, store {
        id: SettlementId,
        record_address: address,
        source_domain: u8,
        destination_domain: u8,
        epoch: u64,
        sender: address,
        recipient: Recipient,
        amount: u64,
    }

    #[event]
    /// Emitted on every attempt to release escrowed value, successful or not.
    struct EscrowReleased has drop, store {
        recipient: address,
        amount: u64,
        status: u64,
    }

    #[event]
    /// Emitted on every attempt to retire escrowed value, successful or not.
    struct EscrowBurned has drop, store {
        amount: u64,
        status: u64,
    }

    #[event]
    /// Emitted for every inbound settlement `apply_settlements` processes, whether the credit was
    /// paid or returned, so that the outcome of each entry in a batch is recorded individually.
    struct InboundSettlementApplied has drop, store {
        /// The crossing's settlement id, derived from `order` by `inbound_settlement_id`.
        id: SettlementId,
        /// The credit's position in the total settlement order, which the watermark now sits at.
        order: SettlementOrder,
        /// The SEVM address the credit came from, and the address a refund returns it to.
        sender: EvmAddress,
        recipient: address,
        amount: u64,
        /// `SETTLEMENT_OK`, or why the credit could not be paid.
        status: u64,
        /// The refund recorded because the credit could not be paid, or none.
        refund: Option<SettlementId>,
    }

    #[event]
    /// Emitted once for every batch the applier processes, carrying what that block's burn request
    /// retired. A consumer reconciling the escrow against the mirrored supply reads `status` rather
    /// than assuming the request was met, because a burn that does not happen has no refund and no
    /// record: nothing else would say it did not happen. A request of zero is reported too, so a
    /// block with no fees to retire is not indistinguishable from a missing event.
    struct SettlementBurnApplied has drop, store {
        block_height: u64,
        amount: u64,
        status: u64,
    }

    #[event]
    /// Emitted when the burn for a block at or below the burn watermark is requested again. Nothing
    /// is retired a second time. This is what a re-requested burn looks like.
    struct SettlementBurnAlreadyApplied has drop, store {
        block_height: u64,
        amount: u64,
    }

    #[event]
    /// Emitted for an inbound settlement whose sender is not a usable EVM address. Such a credit can
    /// be neither paid nor returned, since a refund would have no address to name, so it is skipped.
    /// The bytes are reported as given, so the entry can be traced back to whatever produced it.
    struct InboundSettlementSenderRejected has drop, store {
        /// The crossing's settlement id, derived from `order` by `inbound_settlement_id`.
        id: SettlementId,
        order: SettlementOrder,
        sender_bytes: vector<u8>,
        recipient: address,
        amount: u64,
        /// Always `SETTLEMENT_INVALID_SENDER`, carried so the event describes its own outcome.
        status: u64,
    }

    #[event]
    /// Emitted for an inbound settlement the applier declined, because its order is at or below the
    /// watermark and it has therefore already been processed. This is what a replayed batch looks
    /// like: every entry in it is reported here and none of them moves any value.
    struct InboundSettlementAlreadyProcessed has drop, store {
        order: SettlementOrder,
        recipient: address,
        amount: u64,
    }

    #[event]
    /// Emitted for every record `apply_settlements` is asked to clear once the SEVM side has
    /// credited it.
    struct OutboundSettlementCleared has drop, store {
        record_address: address,
        /// False when no record was found there, which is what re-applying a batch looks like.
        removed: bool,
    }

    /// Create the escrow on a chain that predates this module. Called by governance with the
    /// `@supra_framework` signer; genesis uses `initialize_with_burn_cap` instead.
    ///
    /// The escrow's `BurnCapability<SupraCoin>` is a copy of `transaction_fee`'s, taken here so
    /// that it passes from one framework module to the other without being handed to the caller.
    /// Aborts with `transaction_fee`'s `ENO_SUPRA_COIN_BURN_CAPABILITY` once the conversion to the
    /// paired `BurnRef` has taken that module's capability.
    ///
    /// Every other requirement is `initialize_with_burn_cap`'s.
    public fun initialize(supra_framework: &signer) {
        system_addresses::assert_supra_framework(supra_framework);
        let burn_cap = transaction_fee::copy_supra_coin_burn_cap(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
    }

    /// Create the escrow holding `burn_cap`, with the `@supra_framework` signer. Called by genesis,
    /// which holds the capability already, and by `initialize`.
    ///
    /// It needs: `coin::create_coin_conversion_map` to have run and the `SupraCoin` pairing to
    /// exist (this function creates the pairing if it does not), and the
    /// `COIN_TO_FUNGIBLE_ASSET_MIGRATION` and `CONCURRENT_FUNGIBLE_BALANCE` feature flags to be
    /// enabled before it runs.
    ///
    /// The capability is taken here rather than installed afterwards because an escrow that cannot
    /// retire value has no use: the value the SEVM destroys would stay escrowed with nothing
    /// mirroring it, and nothing in state would record that it was owed.
    public(friend) fun initialize_with_burn_cap(
        supra_framework: &signer,
        burn_cap: BurnCapability<SupraCoin>,
    ) {
        system_addresses::assert_supra_framework(supra_framework);
        assert!(!exists<Escrow>(@supra_framework), error::already_exists(EALREADY_INITIALIZED));

        if (option::is_none(&coin::paired_metadata<SupraCoin>())) {
            coin::create_pairing<SupraCoin>(supra_framework);
        };
        let metadata = option::destroy_some(coin::paired_metadata<SupraCoin>());

        // The escrow authority object is created by `@supra_framework` and then handed to itself,
        // so that after this function returns no account owns it and no account's signer passes
        // the escrow store's owner check. The `ExtendRef` taken here is the only capability over
        // it that survives; the `ConstructorRef` and `TransferRef` are locals and are dropped.
        let constructor_ref = object::create_named_object(supra_framework, ESCROW_SEED);
        let authority = object::address_from_constructor_ref(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        object::transfer_with_ref(object::generate_linear_transfer_ref(&transfer_ref), authority);
        object::disable_ungated_transfer_at_creation(&constructor_ref);

        // `upgrade_store_to_concurrent` requires the store's owner to sign, and the escrow store
        // is owned by the authority object, whose signer comes from the `ExtendRef`.
        let authority_signer = object::generate_signer_for_extending(&extend_ref);
        let store = primary_fungible_store::ensure_primary_store_exists(authority, metadata);
        fungible_asset::upgrade_store_to_concurrent(&authority_signer, store);

        move_to(supra_framework, Escrow { store, metadata, extend_ref, burn_cap });
        ensure_watermark_exists(supra_framework);
        ensure_backlog_exists(supra_framework);

        event::emit(EscrowInitialized {
            escrow_authority: authority,
            escrow_store: object::object_address(&store),
            metadata: object::object_address(&metadata),
        });
    }

    #[view]
    /// Whether the escrow exists on this chain.
    public fun is_initialized(): bool {
        exists<Escrow>(@supra_framework)
    }

    #[view]
    /// The address of the escrow authority object, which owns the escrow store. Deterministic,
    /// and defined whether or not `initialize` has run.
    public fun escrow_authority_address(): address {
        object::create_object_address(&@supra_framework, ESCROW_SEED)
    }

    #[view]
    /// The address of the escrow store itself. Aborts when the escrow has not been initialized,
    /// so a caller probing a chain that predates it gets a not-found abort rather than an address.
    public fun escrow_store_address(): address acquires Escrow {
        assert!(is_initialized(), error::not_found(ENOT_INITIALIZED));
        object::object_address(&borrow_global<Escrow>(@supra_framework).store)
    }

    #[view]
    /// The amount of SUPRA currently escrowed. Aborts when the escrow has not been initialized,
    /// rather than reporting zero, so that an uninitialized chain is distinguishable from an empty
    /// escrow. Pair it with `is_initialized` when probing over RPC.
    public fun escrow_balance(): u64 acquires Escrow {
        assert!(is_initialized(), error::not_found(ENOT_INITIALIZED));
        fungible_asset::balance(borrow_global<Escrow>(@supra_framework).store)
    }

    #[view]
    /// Whether the escrow balance is held in an aggregator rather than in the store's plain `u64`
    /// field. This must be true on any chain that has run `initialize`, and it aborts rather than
    /// returning false on a chain that has not.
    public fun escrow_is_concurrent(): bool acquires Escrow {
        fungible_asset::concurrent_balance_exists(escrow_store_address())
    }

    /// Wrap 20 bytes as an EVM address. The EVM zero address is rejected: a balance mirrored to
    /// it is claimable by nobody.
    public fun new_evm_address(bytes: vector<u8>): EvmAddress {
        assert!(vector::length(&bytes) == EVM_ADDRESS_LENGTH, error::invalid_argument(EINVALID_EVM_ADDRESS));
        assert!(bytes != EVM_ZERO_ADDRESS, error::invalid_argument(EZERO_EVM_ADDRESS));
        EvmAddress { bytes }
    }

    /// Whether `bytes` is a usable EVM address, which is exactly what `new_evm_address` accepts.
    /// It is the same rule expressed as a predicate rather than as an abort, so that a caller which
    /// must not abort - the settlement applier - can ask the question first and turn the answer into
    /// a status. Keeping one rule here is what stops the two from diverging;
    /// `test_evm_address_validity_matches_the_constructor` pins that they agree.
    fun is_valid_evm_address(bytes: &vector<u8>): bool {
        vector::length(bytes) == EVM_ADDRESS_LENGTH && *bytes != EVM_ZERO_ADDRESS
    }

    /// The 20 bytes of an EVM address.
    fun evm_address_bytes(evm_address: &EvmAddress): vector<u8> {
        evm_address.bytes
    }

    /// A recipient on the Move side of the chain.
    fun recipient_move(addr: address): Recipient {
        Recipient {
            domain: DOMAIN_MOVE,
            move_address: option::some(addr),
            evm_address: option::none(),
        }
    }

    /// A recipient on the Supra EVM.
    fun recipient_evm(evm_address: EvmAddress): Recipient {
        Recipient {
            domain: DOMAIN_SEVM,
            move_address: option::none(),
            evm_address: option::some(evm_address),
        }
    }

    /// The bytes of a settlement id.
    public fun settlement_id_bytes(id: &SettlementId): vector<u8> {
        id.bytes
    }

    /// The address the `SettlementRecord` for `id` lives at.
    ///
    /// For a crossing recorded here - a deposit or a refund - the settlement id *is* that address:
    /// `record_settlement` allocates the record's object with
    /// `object::create_object`, whose address is a fresh AUID - `sha3_256(transaction hash ||
    /// per-transaction counter || 0xFB)`. So an id is unique for every crossing in a transaction,
    /// for every transaction on the chain, and across both directions, without any location that
    /// two crossings both write; a chain-wide counter would be exactly such a location, and would
    /// serialise the deposits that the concurrent escrow balance exists to keep parallel.
    /// Uniqueness is enforced, not merely argued: object creation aborts if anything already
    /// exists at the address.
    ///
    /// The mapping is the identity on bytes, so the Rust side reads the 32 id bytes as an account
    /// address and finds the record there. A SEVM -> Move crossing has no record here: its id comes
    /// from `inbound_settlement_id`, and no record exists at the address its bytes name.
    public fun settlement_record_address(id: &SettlementId): address {
        settlement_record_address_from_id_bytes(id.bytes)
    }

    #[view]
    /// `settlement_record_address` over the raw id bytes, callable as a view function.
    public fun settlement_record_address_from_id_bytes(id_bytes: vector<u8>): address {
        from_bcs::to_address(id_bytes)
    }

    /// The id of the settlement whose record lives at `record_address`.
    public fun settlement_id_at(record_address: address): SettlementId {
        SettlementId { bytes: bcs::to_bytes(&record_address) }
    }

    #[view]
    /// Whether a settlement record is currently written at `record_address`.
    public fun record_exists(record_address: address): bool {
        exists<SettlementRecord>(record_address)
    }

    #[view]
    /// A copy of the settlement record at `record_address`, or none.
    public fun record_at(record_address: address): Option<SettlementRecord> acquires SettlementRecord {
        if (exists<SettlementRecord>(record_address)) {
            option::some(*borrow_global<SettlementRecord>(record_address))
        } else {
            option::none()
        }
    }

    /// Escrow `amount` of the sender's SUPRA against a balance on the SEVM and record the
    /// crossing. Callable from an ordinary user transaction; the entry wrapper is
    /// `deposit_to_evm`. Returns the identifier of the crossing, which is also the address of the
    /// record resource this writes.
    public fun deposit(
        sender: &signer,
        amount: u64,
        recipient: EvmAddress,
    ): SettlementId acquires Escrow, SettlementBacklog {
        assert!(is_initialized(), error::not_found(ENOT_INITIALIZED));
        // No new crossing may start while settlement is disabled. Refusing here is what keeps the
        // sender's SUPRA with the sender: a crossing that escrowed its value first and then found
        // no settlement to carry it would leave that value held with no way to release it.
        assert!(
            features::supra_evm_settlement_enabled(),
            error::invalid_state(ESETTLEMENT_DISABLED),
        );
        assert!(amount > 0, error::invalid_argument(EZERO_AMOUNT));
        // A crossing started against a full backlog is refused rather than queued behind it, so
        // that the wait a crossing can be committed to is bounded by the backlog and not by however
        // many arrived with it. Aborting is what returns the sender's SUPRA - the transaction
        // reverts entire - and this sits with the other refusals so that a refused crossing does no
        // work first. `is_at_least` answers without reading the aggregator, so an admitted crossing
        // conflicts with nothing and only one arriving at the bound resolves the value.
        assert!(
            !aggregator_v2::is_at_least(
                &borrow_global<SettlementBacklog>(@supra_framework).outstanding,
                MAX_OUTSTANDING_CROSSINGS,
            ),
            error::resource_exhausted(EBACKLOG_FULL),
        );

        let sender_address = signer::address_of(sender);
        let coins = coin::withdraw<SupraCoin>(sender, amount);
        let fa = coin::coin_to_fungible_asset(coins);
        fungible_asset::deposit(borrow_global<Escrow>(@supra_framework).store, fa);

        let epoch = reconfiguration::current_epoch();
        let recipient = recipient_evm(recipient);
        let id = record_settlement(
            DOMAIN_MOVE,
            DOMAIN_SEVM,
            epoch,
            sender_address,
            recipient,
            amount,
            option::none(),
        );

        event::emit(SettlementRecorded {
            id,
            record_address: settlement_record_address(&id),
            source_domain: DOMAIN_MOVE,
            destination_domain: DOMAIN_SEVM,
            epoch,
            sender: sender_address,
            recipient,
            amount,
        });
        id
    }

    /// Entry wrapper over `deposit`. `recipient` is the 20 bytes of the SEVM address that the
    /// mirrored balance is credited to.
    public entry fun deposit_to_evm(
        sender: &signer,
        amount: u64,
        recipient: vector<u8>,
    ) acquires Escrow, SettlementBacklog {
        deposit(sender, amount, new_evm_address(recipient));
    }

    /// Write a settlement record into a freshly allocated object and return its id.
    ///
    /// The object is deletable and carries its own `DeleteRef`, so `take_record` removes the
    /// record and the object together. Only this module can write a record, so a record found in
    /// a write set is always one this module wrote.
    fun record_settlement(
        source_domain: u8,
        destination_domain: u8,
        epoch: u64,
        sender: address,
        recipient: Recipient,
        amount: u64,
        refund_reason: Option<u64>,
    ): SettlementId acquires SettlementBacklog {
        assert!(recipient.domain == destination_domain, error::invalid_argument(EINVALID_RECIPIENT));

        let constructor_ref = object::create_object(escrow_authority_address());
        let record_address = object::address_from_constructor_ref(&constructor_ref);
        let id = settlement_id_at(record_address);
        let record_signer = object::generate_signer(&constructor_ref);

        move_to(&record_signer, SettlementRecord {
            source_domain,
            destination_domain,
            epoch,
            id,
            sender,
            recipient,
            amount,
            refund_reason,
        });
        move_to(&record_signer, SettlementRecordDeleteRef {
            delete_ref: object::generate_delete_ref(&constructor_ref),
        });
        count_records_written(1);
        id
    }

    /// Delete the settlement record at `record_address`, along with the object that held it, and
    /// return the record - or return none if there is no record there. Never aborts: applying
    /// settlements walks many records in one transaction and an abort there would halt the
    /// block.
    fun take_record(
        record_address: address
    ): Option<SettlementRecord> acquires SettlementRecord, SettlementRecordDeleteRef {
        if (exists<SettlementRecord>(record_address) && exists<SettlementRecordDeleteRef>(record_address)) {
            let record = move_from<SettlementRecord>(record_address);
            let SettlementRecordDeleteRef { delete_ref } = move_from<SettlementRecordDeleteRef>(record_address);
            object::delete(delete_ref);
            option::some(record)
        } else {
            option::none()
        }
    }

    /// Pay `amount` of escrowed SUPRA to `recipient` on the Move side. Settlement-only.
    ///
    /// Returns `SETTLEMENT_OK`, or the status describing why nothing was paid. It does not abort
    /// on a per-settlement precondition, so that the caller can route the failure to a refund
    /// rather than halting the block.
    fun release(recipient: address, amount: u64): u64 acquires Escrow {
        let status = release_status(recipient, amount);
        if (status == SETTLEMENT_OK) {
            let fa = withdraw_from_escrow(amount);
            primary_fungible_store::deposit(recipient, fa);
        };
        event::emit(EscrowReleased { recipient, amount, status });
        status
    }

    /// Pay `amount` to `recipient` out of `held`, the funds a batch drew from the escrow up front.
    ///
    /// Same outcome as `release` for every entry of a batch, and the same events. The batch holds
    /// the lesser of what it needs and what the escrow has, so what it still holds is what the
    /// escrow would still have, and an entry runs out of funds at exactly the point it would have.
    ///
    /// `held` is empty on a chain with no escrow, where the status is decided before the funds are
    /// consulted.
    fun release_from(held: &mut Option<FungibleAsset>, recipient: address, amount: u64): u64 acquires Escrow {
        let status = release_status_against(held_amount(held), recipient, amount);
        if (status == SETTLEMENT_OK) {
            primary_fungible_store::deposit(
                recipient,
                fungible_asset::extract(option::borrow_mut(held), amount),
            );
        };
        event::emit(EscrowReleased { recipient, amount, status });
        status
    }

    /// What `held` is worth, and zero when a batch drew nothing.
    fun held_amount(held: &Option<FungibleAsset>): u64 {
        if (option::is_some(held)) {
            fungible_asset::amount(option::borrow(held))
        } else {
            0
        }
    }

    /// Draw the funds one batch of credits needs, in one withdrawal.
    ///
    /// `wanted` is what the batch's payable entries come to, already capped at the escrow balance
    /// by the caller. Whatever is left when the batch has been applied is returned by
    /// `return_unspent`, so the escrow ends the transaction holding everything the batch did not
    /// pay out.
    fun draw_for_batch(wanted: u64): Option<FungibleAsset> acquires Escrow {
        if (!is_initialized()) {
            option::none()
        } else if (wanted == 0) {
            option::some(fungible_asset::zero(borrow_global<Escrow>(@supra_framework).metadata))
        } else {
            option::some(withdraw_from_escrow(wanted))
        }
    }

    /// Return to the escrow whatever a batch drew and did not pay out.
    fun return_unspent(held: Option<FungibleAsset>) acquires Escrow {
        if (option::is_none(&held)) {
            option::destroy_none(held);
            return
        };
        let remaining = option::destroy_some(held);
        if (fungible_asset::amount(&remaining) == 0) {
            fungible_asset::destroy_zero(remaining);
        } else {
            fungible_asset::deposit(borrow_global<Escrow>(@supra_framework).store, remaining);
        }
    }

    /// `release`, keyed on a settlement record's recipient. Returns `SETTLEMENT_WRONG_DOMAIN`,
    /// rather than aborting, when the recipient is not on the Move side of the chain.
    fun release_to_recipient(recipient: &Recipient, amount: u64): u64 acquires Escrow {
        if (recipient.domain != DOMAIN_MOVE || option::is_none(&recipient.move_address)) {
            let status = SETTLEMENT_WRONG_DOMAIN;
            event::emit(EscrowReleased { recipient: @0x0, amount, status });
            status
        } else {
            release(*option::borrow(&recipient.move_address), amount)
        }
    }

    /// Retire `amount` of escrowed SUPRA, reducing the total supply of SUPRA by that much.
    /// Settlement-only, and reports failures the same way `release` does.
    fun burn(amount: u64): u64 acquires Escrow {
        let status = burn_status(amount);
        if (status == SETTLEMENT_OK) {
            // Withdrawn from the escrow store and retired in fungible form, so that no step reads a
            // feature flag. Retiring needs only the `BurnCapability` held here, and no chain-wide
            // `BurnRef`.
            let fa = withdraw_from_escrow(amount);
            coin::burn_paired_fungible_asset(fa, &borrow_global<Escrow>(@supra_framework).burn_cap);
        };
        event::emit(EscrowBurned { amount, status });
        status
    }

    /// Apply a batch of settlements. Called only by the system transaction the node injects into
    /// the block after the one whose crossings it settles, with the `@supra_framework` signer.
    ///
    /// Both directions are applied in one call, because one block can record crossings both ways,
    /// and the block's burn is applied alongside them:
    ///
    /// * the *burn* is `burn_amount`, the value the SEVM retired in the block at
    ///   `burn_block_height`, in whole quants. It is one figure for the whole block rather than a
    ///   per-settlement one, and it is independent of the settlement list: the common case is a
    ///   block that burns and crosses nothing. `apply_burn` has what a failed burn means;
    /// * an *inbound* entry is a credit that originated on the SEVM, so there is no record on this
    ///   side to read. Six parallel columns carry it, one element each per credit:
    ///   `inbound_block_heights`, `inbound_transaction_indices` and `inbound_settlement_indices`
    ///   give its position in the total settlement order, and `inbound_senders`,
    ///   `inbound_recipients` and `inbound_amounts` give the settlement itself. Escrowed value is
    ///   released to the recipient; a credit that cannot be paid is neither dropped nor aborted on,
    ///   but returned by writing a refund record that names the SEVM sender as its recipient, which
    ///   the SEVM side applies as a re-credit;
    /// * a *cleared* entry is the address of a `SettlementRecord` written by a Move -> SEVM
    ///   crossing that the SEVM side has now credited. The record is deleted, so that an applied
    ///   crossing leaves nothing behind and Move state does not grow by one resource per crossing.
    ///
    /// A credit is applied at most once, enforced here rather than assumed of the caller: its order
    /// is compared against `SettlementWatermark`, anything at or below the watermark is reported as
    /// already processed and moves nothing, and every entry that is processed advances the watermark
    /// past itself - including one that was returned or skipped, since those have been processed
    /// too. Refunds this function records are new crossings in the other direction, ordered by their
    /// own transaction, so they are never compared against this watermark. Clearing needs no
    /// watermark: `take_record` is already a no-op on a record that is gone. A burn is applied at
    /// most once by the same means, against its own cursor in that resource.
    ///
    /// The burn runs before the credits. Both come out of the same escrow, so when the escrow cannot
    /// cover everything the order decides which one fails, and a failed credit is the better of the
    /// two: it is returned to its sender and the SEVM re-credits it, while a failed burn leaves a
    /// divergence that only an operator can close. In the healthy case both fit and the order does
    /// not matter.
    ///
    /// The entries are independent: no entry's outcome can stop another entry from applying, and no
    /// per-settlement condition aborts - including a sender that is not a usable EVM address, which
    /// is a property of one entry and is reported as a status like any other. Only a malformed batch
    /// aborts - columns of different lengths, or inbound entries that are not in strictly increasing
    /// order - and both are checked before anything is applied, so an aborted call has settled
    /// nothing. An inbound index above `MAX_INBOUND_ID_INDEX` also aborts the call, in
    /// `inbound_settlement_id`; the node's indices are `u32`, so it never sends one.
    fun apply_settlements(
        supra_framework: &signer,
        burn_block_height: u64,
        burn_amount: u64,
        inbound_block_heights: vector<u64>,
        inbound_transaction_indices: vector<u64>,
        inbound_settlement_indices: vector<u64>,
        inbound_senders: vector<vector<u8>>,
        inbound_recipients: vector<address>,
        inbound_amounts: vector<u64>,
        cleared_records: vector<address>,
    ) acquires
        Escrow,
        SettlementBacklog,
        SettlementRecord,
        SettlementRecordDeleteRef,
        SettlementWatermark
    {
        system_addresses::assert_supra_framework(supra_framework);
        // Deliberately not gated on the feature, which governs only whether a new crossing may
        // start. This function is the sole means of finishing one, and the value it settles has
        // already left its sender; refusing here while the feature is off would strand it. With
        // initiation gated and settlement open, disabling the feature stops the flow and lets the
        // outstanding crossings drain. See #3700.

        let inbound_count = vector::length(&inbound_recipients);
        assert!(
            vector::length(&inbound_block_heights) == inbound_count
                && vector::length(&inbound_transaction_indices) == inbound_count
                && vector::length(&inbound_settlement_indices) == inbound_count
                && vector::length(&inbound_senders) == inbound_count
                && vector::length(&inbound_amounts) == inbound_count,
            error::invalid_argument(EMISMATCHED_BATCH_LENGTHS),
        );

        // The orders are built and checked up front, so that a batch in the wrong order aborts
        // before any settlement has been applied rather than partway through one.
        let orders = vector::empty<SettlementOrder>();
        let i = 0;
        while (i < inbound_count) {
            let order = SettlementOrder {
                block_height: *vector::borrow(&inbound_block_heights, i),
                transaction_index: *vector::borrow(&inbound_transaction_indices, i),
                settlement_index: *vector::borrow(&inbound_settlement_indices, i),
            };
            // Strictly increasing, so that the watermark cannot reject an entry that a preceding
            // entry in the same batch has already carried it past, and so that one batch cannot
            // name the same settlement twice.
            assert!(
                i == 0 || order_is_after(&order, vector::borrow(&orders, i - 1)),
                error::invalid_argument(EBATCH_NOT_ORDERED),
            );
            vector::push_back(&mut orders, order);
            i = i + 1;
        };

        ensure_watermark_exists(supra_framework);
        apply_burn(burn_block_height, burn_amount);

        // The watermark this batch is measured against, read once. Every entry is compared with
        // it, which is the same test as comparing each entry with a watermark advanced entry by
        // entry: the batch is strictly increasing, asserted above, so an entry that clears the
        // batch's opening watermark clears every value the watermark takes while the batch runs.
        // The advanced value is written once at the end for the same reason - the entries are
        // increasing, so the last one processed is the highest, and the writes in between are
        // values no later entry is measured against.
        let watermark = borrow_global<SettlementWatermark>(@supra_framework).highest_applied;

        // What the payable entries come to, capped at the escrow balance as it is accumulated so
        // that the total is bounded by a figure the escrow can hold. Read once: the balance is a
        // `ConcurrentFungibleBalance`, so asking for it resolves an aggregator, and the credits
        // are paid from one withdrawal rather than one apiece.
        let available = if (is_initialized()) { escrow_balance() } else { 0 };
        let wanted = 0;
        let i = 0;
        while (i < inbound_count) {
            if (order_is_unprocessed(vector::borrow(&orders, i), &watermark) && wanted < available) {
                let room = available - wanted;
                let amount = *vector::borrow(&inbound_amounts, i);
                wanted = wanted + if (amount < room) { amount } else { room };
            };
            i = i + 1;
        };
        let held = draw_for_batch(wanted);

        let highest = watermark;
        let processed_any = false;
        let i = 0;
        while (i < inbound_count) {
            let order = *vector::borrow(&orders, i);
            let recipient = *vector::borrow(&inbound_recipients, i);
            let amount = *vector::borrow(&inbound_amounts, i);
            if (order_is_unprocessed(&order, &watermark)) {
                apply_inbound_settlement(
                    &mut held,
                    order,
                    *vector::borrow(&inbound_senders, i),
                    recipient,
                    amount,
                );
                // Advanced whatever the outcome was: a credit that was returned or skipped has
                // still been processed, and must not be looked at again.
                highest = option::some(order);
                processed_any = true;
            } else {
                event::emit(InboundSettlementAlreadyProcessed { order, recipient, amount });
            };
            i = i + 1;
        };
        return_unspent(held);
        if (processed_any) {
            borrow_global_mut<SettlementWatermark>(@supra_framework).highest_applied = highest;
        };

        let cleared_count = 0;
        vector::for_each_ref(&cleared_records, |address_ref| {
            let record_address = *address_ref;
            let removed = option::is_some(&take_record(record_address));
            if (removed) {
                cleared_count = cleared_count + 1;
            };
            event::emit(OutboundSettlementCleared { record_address, removed });
        });
        // Only the records that were really there, so that clearing one twice discounts it once.
        count_records_cleared(cleared_count);
    }

    /// Retire the value the SEVM destroyed in the block at `block_height`, and report the outcome.
    ///
    /// Never aborts. What a failure means here has no counterpart on the credit side, so it is worth
    /// being exact about. A credit that cannot be paid is returned to its sender, and the SEVM
    /// re-credits it, so the two sides stay level either way. A burn has nobody to return anything
    /// to: the SEVM has already destroyed its mirror of the value, so a burn that does not happen
    /// leaves the escrow holding value the SEVM no longer mirrors, and `escrow_balance` exceeds the
    /// mirrored supply by `amount` until something retires it. Nothing else in state records that,
    /// which is why `SettlementBurnApplied` carries the status: a caller must read it rather than
    /// assume its request was met, and must not treat a non-`SETTLEMENT_OK` status as retired.
    ///
    /// The statuses are distinguishable because they call for different things:
    ///
    /// * `SETTLEMENT_INSUFFICIENT_ESCROW` - the escrow holds less than the SEVM says it mirrors.
    ///   That is a divergence in the peg itself rather than anything about this request, and this
    ///   module cannot close it: refusing the burn is the conservative outcome, since it leaves the
    ///   escrow untouched rather than draining what is left;
    /// * `SETTLEMENT_NOT_INITIALIZED` - there is no escrow on this chain to retire from.
    ///
    /// The burn cursor advances exactly when value was retired. So a burn that succeeded is never
    /// applied twice, and a burn that did not is not finished: requesting it again for the same
    /// block attempts it again, which is the only way a burn that failed can still happen. This is
    /// the one place the module's rule differs from a credit's, and it differs because a credit that
    /// cannot be paid is returned and so is settled either way, whereas a burn that did not happen
    /// has not been settled by anything.
    fun apply_burn(
        block_height: u64,
        amount: u64,
    ) acquires Escrow, SettlementWatermark {
        let highest = borrow_global<SettlementWatermark>(@supra_framework).highest_burned_block;
        if (option::is_some(&highest) && block_height <= *option::borrow(&highest)) {
            event::emit(SettlementBurnAlreadyApplied { block_height, amount });
            return
        };

        // A block with no fees to retire is not a failed burn, and `burn` would report one, so the
        // request is answered without it.
        let status = if (amount == 0) { SETTLEMENT_OK } else { burn(amount) };
        if (amount > 0 && status == SETTLEMENT_OK) {
            borrow_global_mut<SettlementWatermark>(@supra_framework).highest_burned_block =
                option::some(block_height);
        };
        event::emit(SettlementBurnApplied { block_height, amount, status });
    }

    /// Pay one credit that originated on the SEVM out of escrow, or record the refund that returns
    /// it. Every outcome of the credit is a status, so one unappliable credit cannot stop the rest
    /// of the batch or the block. The one abort is `inbound_settlement_id`'s, for an index above
    /// `MAX_INBOUND_ID_INDEX`, which the node never sends.
    fun apply_inbound_settlement(
        held: &mut Option<FungibleAsset>,
        order: SettlementOrder,
        sender_bytes: vector<u8>,
        recipient: address,
        amount: u64,
    ) acquires Escrow, SettlementBacklog {
        let id = inbound_settlement_id(&order);
        // A refund is the only way this module returns value it cannot deliver, and a refund has to
        // name an address on the SEVM. A credit whose sender is not one can therefore be neither
        // paid nor returned, so it is skipped and reported, which is what every other entry that
        // cannot be applied does.
        if (!is_valid_evm_address(&sender_bytes)) {
            event::emit(InboundSettlementSenderRejected {
                id,
                order,
                sender_bytes,
                recipient,
                amount,
                status: SETTLEMENT_INVALID_SENDER,
            });
            return
        };
        // Checked immediately above, which is exactly what this asserts.
        let sender = new_evm_address(sender_bytes);

        // A credit from the SEVM is often the first value an address sees on this side, so a
        // recipient without an account gets one, as `supra_account::transfer` does, leaving a
        // credited address as usable as one paid by an ordinary transfer. The account is created
        // only when the credit is about to be paid, so a refunded credit leaves no account behind,
        // and only for an address `account::is_reserved_address` allows one at, which is the same
        // set `account::create_account` refuses; the release below does not need an account to
        // land, so a recipient at a reserved address is paid without one.
        if (release_status_against(held_amount(held), recipient, amount) == SETTLEMENT_OK
            && !account::exists_at(recipient)
            && !account::is_reserved_address(recipient)) {
            supra_account::create_account(recipient);
        };

        // `release_from` decides the outcome and emits `EscrowReleased` either way, so the status
        // here is the one the escrow actually acted on rather than a prediction of it.
        let status = release_from(held, recipient, amount);
        let refund = if (status == SETTLEMENT_OK || amount == 0) {
            // A credit that moves nothing has nothing to return.
            option::none()
        } else {
            // The credit's value never left the escrow, so returning it moves no value either: the
            // record alone is what tells the SEVM side to restore the sender's balance.
            let epoch = reconfiguration::current_epoch();
            let refund_recipient = recipient_evm(sender);
            let refund_id = record_settlement(
                DOMAIN_MOVE,
                DOMAIN_SEVM,
                epoch,
                // The refund originates with the chain rather than with a party on this side.
                @supra_framework,
                refund_recipient,
                amount,
                option::some(status),
            );
            event::emit(SettlementRecorded {
                id: refund_id,
                record_address: settlement_record_address(&refund_id),
                source_domain: DOMAIN_MOVE,
                destination_domain: DOMAIN_SEVM,
                epoch,
                sender: @supra_framework,
                recipient: refund_recipient,
                amount,
            });
            option::some(refund_id)
        };

        event::emit(InboundSettlementApplied { id, order, sender, recipient, amount, status, refund });
    }

    /// The settlement id of the SEVM -> Move crossing at `order`: the 16 bytes of
    /// `INBOUND_SETTLEMENT_ID_TAG`, then `block_height` as 8 bytes, then `transaction_index` as 4
    /// bytes, then `settlement_index` as 4 bytes, each integer big-endian. This is the id the node
    /// gives the crossing in its settlement queue (`inbound_settlement_id` in smr-moonshot's
    /// `chain_storage::pending_settlements`), and
    /// `test_inbound_settlement_id_matches_the_node_derivation` pins a vector that the node's test of
    /// that function pins too.
    ///
    /// Aborts with `EINBOUND_ID_INDEX_TOO_LARGE` when either index is above `MAX_INBOUND_ID_INDEX`.
    /// Keeping only the low four bytes of such an index would give two orders the same id.
    fun inbound_settlement_id(order: &SettlementOrder): SettlementId {
        assert!(
            order_fits_inbound_settlement_id(order),
            error::invalid_argument(EINBOUND_ID_INDEX_TOO_LARGE),
        );
        let bytes = INBOUND_SETTLEMENT_ID_TAG;
        vector::append(&mut bytes, big_endian(bcs::to_bytes(&order.block_height)));
        // Both indices are at most `MAX_INBOUND_ID_INDEX`, asserted above, so neither cast truncates.
        vector::append(&mut bytes, big_endian(bcs::to_bytes(&(order.transaction_index as u32))));
        vector::append(&mut bytes, big_endian(bcs::to_bytes(&(order.settlement_index as u32))));
        SettlementId { bytes }
    }

    /// Whether both indices of `order` are at most `MAX_INBOUND_ID_INDEX`, and so fit the four bytes
    /// `inbound_settlement_id` gives each of them.
    fun order_fits_inbound_settlement_id(order: &SettlementOrder): bool {
        order.transaction_index <= MAX_INBOUND_ID_INDEX
            && order.settlement_index <= MAX_INBOUND_ID_INDEX
    }

    /// `bcs_bytes`, an integer as `bcs::to_bytes` writes it - least significant byte first -
    /// reversed into most-significant-byte-first order.
    fun big_endian(bcs_bytes: vector<u8>): vector<u8> {
        vector::reverse(&mut bcs_bytes);
        bcs_bytes
    }

    /// Whether `a` comes after `b` in the settlement order.
    fun order_is_after(a: &SettlementOrder, b: &SettlementOrder): bool {
        if (a.block_height != b.block_height) {
            a.block_height > b.block_height
        } else if (a.transaction_index != b.transaction_index) {
            a.transaction_index > b.transaction_index
        } else {
            a.settlement_index > b.settlement_index
        }
    }

    /// Whether `order` is above `watermark`, and so names a settlement that has not been processed.
    fun order_is_unprocessed(order: &SettlementOrder, watermark: &Option<SettlementOrder>): bool {
        option::is_none(watermark) || order_is_after(order, option::borrow(watermark))
    }

    /// The watermark is created with the escrow. It is created here as well, so that applying
    /// settlements on a chain whose escrow predates the watermark records a watermark rather than
    /// halting the block on a missing resource.
    fun ensure_watermark_exists(supra_framework: &signer) {
        if (!exists<SettlementWatermark>(@supra_framework)) {
            move_to(supra_framework, SettlementWatermark {
                highest_applied: option::none(),
                highest_burned_block: option::none(),
            });
        }
    }

    /// The backlog counter is created with the escrow. It is created here as well, for the same
    /// reason the watermark is: so that a chain whose escrow predates it records a backlog rather
    /// than halting the block on a missing resource. A backlog created this way starts at zero and
    /// so under-counts the records already outstanding, which only ever admits more crossings than
    /// the bound allows - never fewer - and corrects itself as those records are cleared.
    fun ensure_backlog_exists(supra_framework: &signer) {
        if (!exists<SettlementBacklog>(@supra_framework)) {
            move_to(supra_framework, SettlementBacklog {
                outstanding: aggregator_v2::create_unbounded_aggregator<u64>(),
            });
        }
    }

    /// Count `count` newly outstanding settlement records.
    ///
    /// Unconditional, so that a refund is never refused: a refund names value that has already left
    /// the SEVM, and the only way to return it is a record. The bound is applied where a crossing
    /// *starts* instead, which is the one place refusing costs nobody anything.
    fun count_records_written(count: u64) acquires SettlementBacklog {
        if (exists<SettlementBacklog>(@supra_framework) && count > 0) {
            aggregator_v2::add(
                &mut borrow_global_mut<SettlementBacklog>(@supra_framework).outstanding,
                count,
            );
        }
    }

    /// Discount `count` settlement records that have been cleared.
    ///
    /// `try_sub` rather than `sub`, so that clearing a record written before the counter existed
    /// leaves the count alone instead of aborting and taking the block with it. That leaves the
    /// count high by the number of such records, which tightens the bound rather than loosening it.
    fun count_records_cleared(count: u64) acquires SettlementBacklog {
        if (exists<SettlementBacklog>(@supra_framework) && count > 0) {
            let _ = aggregator_v2::try_sub(
                &mut borrow_global_mut<SettlementBacklog>(@supra_framework).outstanding,
                count,
            );
        }
    }

    #[view]
    /// How many settlement records are outstanding. A crossing started while this is at
    /// `MAX_OUTSTANDING_CROSSINGS` or above is refused.
    ///
    /// This reads the aggregator, which the admission check deliberately does not, so it belongs in
    /// a view call and not on the path of a transaction that also moves the count.
    public fun outstanding_crossings(): u64 acquires SettlementBacklog {
        if (!exists<SettlementBacklog>(@supra_framework)) {
            0
        } else {
            aggregator_v2::read(&borrow_global<SettlementBacklog>(@supra_framework).outstanding)
        }
    }

    #[view]
    /// The bound `outstanding_crossings` is admitted against.
    public fun max_outstanding_crossings(): u64 {
        MAX_OUTSTANDING_CROSSINGS
    }

    /// Whether `release` would pay out, and if not, why not.
    fun release_status(recipient: address, amount: u64): u64 acquires Escrow {
        release_status_against(escrow_balance(), recipient, amount)
    }

    /// `release_status`, asked of `available` rather than of the escrow store.
    ///
    /// The escrow balance is a `ConcurrentFungibleBalance`, so reading it resolves an aggregator.
    /// A batch draws its funds once and asks this of what it still holds, which is the same
    /// question: the funds held are the escrow balance less what this batch has already paid out.
    fun release_status_against(available: u64, recipient: address, amount: u64): u64 acquires Escrow {
        if (!is_initialized()) {
            SETTLEMENT_NOT_INITIALIZED
        } else if (amount == 0) {
            SETTLEMENT_ZERO_AMOUNT
        } else if (available < amount) {
            SETTLEMENT_INSUFFICIENT_ESCROW
        } else if (recipient == escrow_authority_address()) {
            // The escrow is the authority's own primary store, so a payment to the authority
            // would leave the value where it is while reporting the settlement as paid. A
            // settlement is only paid when the value leaves the escrow.
            SETTLEMENT_INVALID_RECIPIENT
        } else {
            let metadata = borrow_global<Escrow>(@supra_framework).metadata;
            if (primary_fungible_store::primary_store_exists(recipient, metadata)
                && primary_fungible_store::is_frozen(recipient, metadata)) {
                SETTLEMENT_RECIPIENT_FROZEN
            } else {
                SETTLEMENT_OK
            }
        }
    }

    /// Whether `burn` would retire value, and if not, why not.
    fun burn_status(amount: u64): u64 acquires Escrow {
        if (!is_initialized()) {
            SETTLEMENT_NOT_INITIALIZED
        } else if (amount == 0) {
            SETTLEMENT_ZERO_AMOUNT
        } else if (escrow_balance() < amount) {
            SETTLEMENT_INSUFFICIENT_ESCROW
        } else {
            SETTLEMENT_OK
        }
    }

    /// The only path by which fungible value leaves the escrow.
    fun withdraw_from_escrow(amount: u64): FungibleAsset acquires Escrow {
        let store = borrow_global<Escrow>(@supra_framework).store;
        fungible_asset::withdraw(&authority_signer(), store, amount)
    }

    /// The signer of the escrow authority object. Only this module can call this, because only
    /// this module can borrow the `Escrow` resource that holds the `ExtendRef`.
    fun authority_signer(): signer acquires Escrow {
        object::generate_signer_for_extending(&borrow_global<Escrow>(@supra_framework).extend_ref)
    }

    #[test_only]
    use supra_framework::aggregator_factory;
    #[test_only]
    use supra_framework::coin::{FreezeCapability, MintCapability};
    #[test_only]
    use supra_framework::supra_coin;

    #[test_only]
    /// A twenty-byte EVM address for tests.
    fun test_evm_address(tag: u8): EvmAddress {
        let bytes = vector::empty<u8>();
        let i = 0;
        while (i < EVM_ADDRESS_LENGTH) {
            vector::push_back(&mut bytes, tag);
            i = i + 1;
        };
        EvmAddress { bytes }
    }

    #[test_only]
    /// Everything the escrow needs on a test chain, short of the coin itself.
    fun setup_chain(supra_framework: &signer) {
        account::create_account_for_test(signer::address_of(supra_framework));
        features::change_feature_flags_for_testing(
            supra_framework,
            vector[
                features::get_coin_to_fungible_asset_migration_feature(),
                features::get_concurrent_fungible_balance_feature(),
            ],
            vector[],
        );
        aggregator_factory::initialize_aggregator_factory_for_test(supra_framework);
        reconfiguration::initialize_for_test(supra_framework);
    }

    #[test_only]
    fun setup(supra_framework: &signer): (BurnCapability<SupraCoin>, MintCapability<SupraCoin>) {
        setup_chain(supra_framework);
        supra_coin::initialize_for_test_without_aggregator_factory(supra_framework)
    }

    #[test_only]
    /// `setup`, keeping the freeze capability, for the tests that need a frozen recipient.
    fun setup_with_freeze_cap(
        supra_framework: &signer,
    ): (BurnCapability<SupraCoin>, FreezeCapability<SupraCoin>, MintCapability<SupraCoin>) {
        setup_chain(supra_framework);
        supra_coin::initialize_for_test_with_freeze_cap(supra_framework)
    }

    #[test_only]
    fun enable_settlements(supra_framework: &signer) {
        features::change_feature_flags_for_testing(
            supra_framework,
            vector[features::get_supra_evm_settlement_feature()],
            vector[],
        );
    }

    #[test_only]
    /// Freeze `recipient`'s primary SUPRA store, creating it first if it does not exist, since a
    /// store that does not exist cannot be frozen.
    fun freeze_primary_store(
        recipient: address,
        freeze_cap: &FreezeCapability<SupraCoin>,
    ) acquires Escrow {
        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        primary_fungible_store::ensure_primary_store_exists(recipient, metadata);
        let (transfer_ref, receipt) = coin::get_paired_transfer_ref(freeze_cap);
        primary_fungible_store::set_frozen_flag(&transfer_ref, recipient, true);
        coin::return_paired_transfer_ref(transfer_ref, receipt);
    }

    #[test_only]
    /// Remove the watermark, reproducing a chain whose escrow was created before the watermark
    /// existed. Destructuring is available here because the resource is declared in this module.
    fun remove_watermark_for_test() acquires SettlementWatermark {
        let SettlementWatermark { highest_applied: _, highest_burned_block: _ } =
            move_from<SettlementWatermark>(@supra_framework);
    }

    #[test_only]
    /// Apply exactly one inbound credit, at block 7, transaction 0, settlement `index`.
    fun apply_one_inbound(
        supra_framework: &signer,
        index: u64,
        sender: EvmAddress,
        recipient: address,
        amount: u64,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7],
            vector[0],
            vector[index],
            vector[evm_address_bytes(&sender)],
            vector[recipient],
            vector[amount],
            vector[],
        );
    }

    #[test_only]
    /// The number of entries in a batch that were returned to their sender instead of paid.
    fun refund_count(applied: &vector<InboundSettlementApplied>): u64 {
        let refunds = 0;
        let i = 0;
        while (i < vector::length(applied)) {
            if (option::is_some(&vector::borrow(applied, i).refund)) {
                refunds = refunds + 1;
            };
            i = i + 1;
        };
        refunds
    }

    #[test_only]
    fun fund(user: &signer, amount: u64, mint_cap: &MintCapability<SupraCoin>) {
        let addr = signer::address_of(user);
        account::create_account_for_test(addr);
        coin::register<SupraCoin>(user);
        coin::deposit(addr, coin::mint<SupraCoin>(amount, mint_cap));
    }

    #[test_only]
    fun cleanup(burn_cap: BurnCapability<SupraCoin>, mint_cap: MintCapability<SupraCoin>) {
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework)]
    fun test_initialize_creates_self_owned_concurrent_escrow(supra_framework: &signer) acquires Escrow {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);

        assert!(is_initialized(), 0);
        let authority = escrow_authority_address();
        let store = borrow_global<Escrow>(@supra_framework).store;
        assert!(escrow_store_address() == object::object_address(&store), 1);
        // Requirement: the balance is an aggregator, not the store's plain `u64` field.
        assert!(fungible_asset::concurrent_balance_exists(escrow_store_address()), 2);
        assert!(escrow_is_concurrent(), 3);
        assert!(escrow_balance() == 0, 4);
        // The escrow store is owned by the authority object, and the authority object owns itself,
        // so no account is anywhere in the ownership chain.
        assert!(object::owner(store) == authority, 5);
        assert!(
            object::owner(object::address_to_object<object::ObjectCore>(authority)) == authority,
            6,
        );
        assert!(
            !object::ungated_transfer_allowed(object::address_to_object<object::ObjectCore>(authority)),
            7,
        );

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x20006, location = supra_framework::object)]
    /// The central security property: escrowed value does not move for any signer outside this
    /// module, including the framework's own.
    ///
    /// The escrow store's owner check walks the ownership chain, which runs from the store to the
    /// authority object and then to the authority object again, so it reaches no account and
    /// terminates by aborting on the nesting bound. The withdrawal does not happen either way; the
    /// abort is the framework's, not this module's, which is why the expected code belongs to
    /// `object` rather than `fungible_asset`.
    fun test_supra_framework_signer_cannot_withdraw_from_escrow(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x06));
        cleanup(burn_cap, mint_cap);

        let escrowed = fungible_asset::withdraw(
            supra_framework,
            borrow_global<Escrow>(@supra_framework).store,
            500,
        );
        primary_fungible_store::deposit(signer::address_of(supra_framework), escrowed);
    }

    #[test(supra_framework = @supra_framework)]
    /// `initialize` takes the escrow's capability from `transaction_fee` itself, and the escrow
    /// can burn with it.
    fun test_initialize_copies_the_burn_capability_from_transaction_fee(
        supra_framework: &signer,
    ) acquires Escrow {
        let (burn_cap, mint_cap) = setup(supra_framework);
        transaction_fee::store_supra_coin_burn_cap(supra_framework, burn_cap);
        initialize(supra_framework);

        assert!(is_initialized(), 0);
        let supply_before = option::destroy_some(coin::supply<SupraCoin>());
        let minted = coin::mint<SupraCoin>(25, &mint_cap);
        coin::burn(minted, &borrow_global<Escrow>(@supra_framework).burn_cap);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == supply_before, 1);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework)]
    #[expected_failure(abort_code = 0x60006, location = supra_framework::transaction_fee)]
    fun test_initialize_without_a_transaction_fee_burn_capability_aborts(supra_framework: &signer) {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize(supra_framework);
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework)]
    #[expected_failure(abort_code = 0x80001, location = Self)]
    fun test_initialize_twice_aborts(supra_framework: &signer) {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        initialize_with_burn_cap(supra_framework, burn_cap);
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    fun test_deposit_escrows_and_records(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);

        let id = deposit(user, 400, test_evm_address(0xab));

        assert!(escrow_balance() == 400, 0);
        assert!(coin::balance<SupraCoin>(signer::address_of(user)) == 600, 1);

        let record_address = settlement_record_address(&id);
        assert!(record_exists(record_address), 2);
        let record = option::destroy_some(record_at(record_address));
        assert!(record.source_domain == DOMAIN_MOVE, 3);
        assert!(record.destination_domain == DOMAIN_SEVM, 4);
        assert!(record.amount == 400, 5);
        assert!(record.id == id, 6);
        assert!(record.sender == signer::address_of(user), 14);
        assert!(record.epoch == reconfiguration::current_epoch(), 7);
        assert!(record.recipient.domain == DOMAIN_SEVM, 8);
        assert!(
            evm_address_bytes(&option::destroy_some(record.recipient.evm_address))
                == evm_address_bytes(&test_evm_address(0xab)),
            9,
        );
        assert!(option::is_none(&record.refund_reason), 10);

        // The record is deletable, and deleting it leaves nothing behind.
        let taken = take_record(record_address);
        assert!(option::is_some(&taken), 11);
        assert!(!record_exists(record_address), 12);
        assert!(option::is_none(&take_record(record_address)), 13);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    fun test_deposit_to_evm_entry(supra_framework: &signer, user: &signer) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);

        deposit_to_evm(user, 250, evm_address_bytes(&test_evm_address(0x07)));

        assert!(escrow_balance() == 250, 0);
        assert!(coin::balance<SupraCoin>(signer::address_of(user)) == 750, 1);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_deposit_to_evm_rejects_a_short_address(supra_framework: &signer, user: &signer) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit_to_evm(user, 250, vector[0x01, 0x02]);
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    fun test_settlement_ids_are_unique_without_a_counter(supra_framework: &signer, user: &signer) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);

        // Two crossings by the same sender within one transaction.
        let first = deposit(user, 100, test_evm_address(0x01));
        let second = deposit(user, 100, test_evm_address(0x01));
        assert!(settlement_id_bytes(&first) != settlement_id_bytes(&second), 0);
        assert!(settlement_record_address(&first) != settlement_record_address(&second), 1);
        assert!(record_exists(settlement_record_address(&first)), 2);
        assert!(record_exists(settlement_record_address(&second)), 3);
        assert!(escrow_balance() == 200, 4);

        // A settlement id is the address of its record, both ways round.
        assert!(settlement_id_at(settlement_record_address(&first)) == first, 5);
        assert!(vector::length(&settlement_id_bytes(&first)) == 32, 6);
        assert!(
            settlement_record_address(&first)
                == settlement_record_address_from_id_bytes(settlement_id_bytes(&first)),
            7,
        );
        // A record allocated by the settlement-applying side of the module gets an id that is
        // distinct from every deposit's, without consulting any shared state.
        let inbound = record_settlement(
            DOMAIN_SEVM,
            DOMAIN_MOVE,
            reconfiguration::current_epoch(),
            @supra_framework,
            recipient_move(@0xb0b),
            42,
            option::some(SETTLEMENT_RECIPIENT_FROZEN),
        );
        assert!(settlement_id_bytes(&inbound) != settlement_id_bytes(&first), 9);
        assert!(settlement_id_bytes(&inbound) != settlement_id_bytes(&second), 10);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// Applying a settlement removes the record and the object that held it, so a settled
    /// crossing leaves nothing behind in state.
    fun test_take_record_leaves_nothing_behind(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);

        let id = deposit(user, 100, test_evm_address(0x09));
        let record_address = settlement_record_address(&id);
        assert!(record_exists(record_address), 0);
        assert!(object::is_object(record_address), 1);

        let taken = option::destroy_some(take_record(record_address));
        assert!(taken.amount == 100, 2);
        assert!(!record_exists(record_address), 3);
        assert!(!exists<SettlementRecordDeleteRef>(record_address), 4);
        assert!(!object::is_object(record_address), 5);
        // Taking it twice is a no-op rather than an abort.
        assert!(option::is_none(&take_record(record_address)), 6);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce, recipient = @0xb0b)]
    fun test_release_pays_recipient(
        supra_framework: &signer,
        user: &signer,
        recipient: address,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x02));

        assert!(release(recipient, 200) == SETTLEMENT_OK, 0);
        assert!(escrow_balance() == 300, 1);
        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(recipient, metadata) == 200, 2);

        // Over-release reports a status instead of aborting, and moves nothing.
        assert!(release(recipient, 10_000) == SETTLEMENT_INSUFFICIENT_ESCROW, 3);
        assert!(release(recipient, 0) == SETTLEMENT_ZERO_AMOUNT, 4);
        assert!(escrow_balance() == 300, 5);

        assert!(release_to_recipient(&recipient_move(recipient), 100) == SETTLEMENT_OK, 6);
        assert!(escrow_balance() == 200, 7);
        // A record naming an SEVM recipient cannot be paid out on the Move side, and says so
        // instead of aborting.
        assert!(
            release_to_recipient(&recipient_evm(test_evm_address(0x05)), 100) == SETTLEMENT_WRONG_DOMAIN,
            8,
        );
        assert!(escrow_balance() == 200, 9);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    fun test_burn_retires_escrowed_supply(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x03));

        let supply_before = option::destroy_some(coin::supply<SupraCoin>());
        assert!(burn(100) == SETTLEMENT_OK, 4);
        assert!(escrow_balance() == 400, 5);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == supply_before - 100, 6);

        assert!(burn(10_000) == SETTLEMENT_INSUFFICIENT_ESCROW, 7);
        assert!(burn(0) == SETTLEMENT_ZERO_AMOUNT, 8);
        assert!(escrow_balance() == 400, 9);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// The burn path does not depend on the `BurnRef` paired with `SupraCoin`, so a chain that has
    /// moved that ref out of the pairing can still retire escrowed value.
    fun test_burn_does_not_need_the_paired_burn_ref(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x08));

        // Take the paired `BurnRef` permanently out of the pairing, as
        // `transaction_fee::convert_to_aptos_fa_burn_ref` does.
        let taken = coin::convert_and_take_paired_burn_ref<SupraCoin>(
            *&borrow_global<Escrow>(@supra_framework).burn_cap
        );
        assert!(!coin::paired_burn_ref_exists<SupraCoin>(), 0);

        let supply_before = option::destroy_some(coin::supply<SupraCoin>());
        assert!(burn(100) == SETTLEMENT_OK, 1);
        assert!(escrow_balance() == 400, 2);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == supply_before - 100, 3);

        fungible_asset::burn(&taken, fungible_asset::zero(borrow_global<Escrow>(@supra_framework).metadata));
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A settlement may not pay out to the escrow authority: the escrow is the authority's own
    /// store, so such a payment would report the settlement as paid without the value leaving.
    fun test_release_to_the_escrow_authority_is_rejected(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x0a));

        let authority = escrow_authority_address();
        assert!(release(authority, 100) == SETTLEMENT_INVALID_RECIPIENT, 0);
        // Nothing moved: the escrow still holds everything it did before.
        assert!(escrow_balance() == 500, 1);
        // The same address routed through a record's recipient is refused for the same reason.
        assert!(
            release_to_recipient(&recipient_move(authority), 100) == SETTLEMENT_INVALID_RECIPIENT,
            2,
        );
        assert!(escrow_balance() == 500, 3);
        // A different recipient is still paid, so the guard is specific to the authority.
        assert!(release(@0xb0b, 100) == SETTLEMENT_OK, 4);
        assert!(escrow_balance() == 400, 5);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// The escrow store is a primary store at a derivable address, so value can arrive without
    /// going through `deposit`. This pins that behaviour: the balance grows and no settlement is
    /// recorded, which is why the balance is only a lower bound on what can be paid out.
    fun test_escrow_accepts_unsolicited_deposits(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);

        let coins = coin::withdraw<SupraCoin>(user, 300);
        primary_fungible_store::deposit(escrow_authority_address(), coin::coin_to_fungible_asset(coins));

        assert!(escrow_balance() == 300, 0);
        assert!(vector::length(&event::emitted_events<SettlementRecorded>()) == 0, 1);

        // A real crossing on top of the surplus records exactly one settlement, and the balance is
        // the sum of both.
        deposit(user, 200, test_evm_address(0x0b));
        assert!(escrow_balance() == 500, 2);
        assert!(vector::length(&event::emitted_events<SettlementRecorded>()) == 1, 3);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x60002, location = Self)]
    fun test_deposit_before_initialize_aborts(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 100, test_evm_address(0x0c));
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x10005, location = Self)]
    fun test_deposit_of_zero_aborts(supra_framework: &signer, user: &signer) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        enable_settlements(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit(user, 0, test_evm_address(0x0d));
        cleanup(burn_cap, mint_cap);
    }

    #[test]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_evm_zero_address_is_rejected() {
        new_evm_address(x"0000000000000000000000000000000000000000");
    }

    #[test]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_evm_address_length_is_enforced() {
        new_evm_address(vector[0x01, 0x02]);
    }

    #[test]
    fun test_recipient_domains() {
        // A recipient carries an address on exactly one domain, and the tag says which.
        let move_recipient = recipient_move(@0xb0b);
        assert!(move_recipient.domain == DOMAIN_MOVE, 0);
        assert!(option::destroy_some(move_recipient.move_address) == @0xb0b, 1);
        assert!(option::is_none(&move_recipient.evm_address), 2);

        let evm_recipient = recipient_evm(test_evm_address(0x04));
        assert!(evm_recipient.domain == DOMAIN_SEVM, 3);
        assert!(option::is_none(&evm_recipient.move_address), 4);
        assert!(
            evm_address_bytes(&option::destroy_some(evm_recipient.evm_address))
                == evm_address_bytes(&test_evm_address(0x04)),
            5,
        );
    }
    #[test(supra_framework = @supra_framework, user = @0xa11ce, recipient = @0xb0b)]
    /// The plain inbound case: a credit that originated on the SEVM is paid to an account that
    /// already exists, out of escrow, with no refund.
    fun test_apply_pays_an_existing_account(
        supra_framework: &signer,
        user: &signer,
        recipient: address,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x11));
        account::create_account_for_test(recipient);

        apply_one_inbound(supra_framework, 0, test_evm_address(0x11), recipient, 200);

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(recipient, metadata) == 200, 0);
        assert!(escrow_balance() == 300, 1);

        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 1, 2);
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_OK, 3);
        assert!(refund_count(&applied) == 0, 4);
        // Nothing but the deposit recorded a settlement, so no refund record was written.
        assert!(vector::length(&event::emitted_events<SettlementRecorded>()) == 1, 5);
        // The watermark now sits at the credit that was applied.
        let watermark = option::destroy_some(
            borrow_global<SettlementWatermark>(@supra_framework).highest_applied
        );
        assert!(watermark.block_height == 7, 6);
        assert!(watermark.transaction_index == 0, 7);
        assert!(watermark.settlement_index == 0, 8);
        // The event names the crossing by the id derived from the order it was applied at.
        let order = SettlementOrder { block_height: 7, transaction_index: 0, settlement_index: 0 };
        assert!(vector::borrow(&applied, 0).id == inbound_settlement_id(&order), 9);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce, recipient = @0xb0b)]
    /// A credit is often the first value an address sees on this side, so a recipient without an
    /// account gets one, as `supra_account::transfer` does.
    fun test_apply_creates_a_missing_account(
        supra_framework: &signer,
        user: &signer,
        recipient: address,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x12));
        assert!(!account::exists_at(recipient), 0);

        apply_one_inbound(supra_framework, 0, test_evm_address(0x12), recipient, 200);

        assert!(account::exists_at(recipient), 1);
        assert!(coin::is_account_registered<SupraCoin>(recipient), 2);
        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(recipient, metadata) == 200, 3);
        assert!(escrow_balance() == 300, 4);
        assert!(refund_count(&event::emitted_events<InboundSettlementApplied>()) == 0, 5);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce, recipient = @0xb0b)]
    /// A credit to a frozen recipient is returned to its SEVM sender rather than aborting or being
    /// dropped, and moves nothing out of escrow.
    fun test_apply_refunds_a_frozen_recipient(
        supra_framework: &signer,
        user: &signer,
        recipient: address,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, freeze_cap, mint_cap) = setup_with_freeze_cap(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x13));
        freeze_primary_store(recipient, &freeze_cap);

        apply_one_inbound(supra_framework, 0, test_evm_address(0x13), recipient, 200);

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(recipient, metadata) == 0, 0);
        assert!(escrow_balance() == 500, 1);
        // A refunded credit leaves no account behind either.
        assert!(!account::exists_at(recipient), 2);

        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 1, 3);
        let entry = vector::borrow(&applied, 0);
        assert!(entry.status == SETTLEMENT_RECIPIENT_FROZEN, 4);
        assert!(refund_count(&applied) == 1, 5);
        // A returned credit is named by its own derived id, not by the id of its refund record.
        let order = SettlementOrder { block_height: 7, transaction_index: 0, settlement_index: 0 };
        assert!(entry.id == inbound_settlement_id(&order), 12);
        assert!(entry.id != *option::borrow(&entry.refund), 13);

        // The refund is a Move -> SEVM record owed back to the sender of the credit.
        let refund_id = *option::borrow(&entry.refund);
        let refund = option::destroy_some(record_at(settlement_record_address(&refund_id)));
        assert!(refund.source_domain == DOMAIN_MOVE, 6);
        assert!(refund.destination_domain == DOMAIN_SEVM, 7);
        assert!(refund.amount == 200, 8);
        assert!(refund.sender == @supra_framework, 9);
        assert!(option::destroy_some(refund.refund_reason) == SETTLEMENT_RECIPIENT_FROZEN, 10);
        assert!(
            evm_address_bytes(&option::destroy_some(refund.recipient.evm_address))
                == evm_address_bytes(&test_evm_address(0x13)),
            11,
        );

        coin::destroy_freeze_cap(freeze_cap);
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A credit naming the escrow authority is refunded like any other credit that cannot be paid:
    /// paying it would report the settlement as paid while the value stayed in the escrow.
    fun test_apply_refunds_the_escrow_authority(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x14));

        let authority = escrow_authority_address();
        apply_one_inbound(supra_framework, 0, test_evm_address(0x14), authority, 200);

        assert!(escrow_balance() == 500, 0);
        // No account was created for it either.
        assert!(!account::exists_at(authority), 1);

        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 1, 2);
        let entry = vector::borrow(&applied, 0);
        assert!(entry.status == SETTLEMENT_INVALID_RECIPIENT, 3);
        assert!(refund_count(&applied) == 1, 4);

        let refund_id = *option::borrow(&entry.refund);
        let refund = option::destroy_some(record_at(settlement_record_address(&refund_id)));
        assert!(refund.amount == 200, 5);
        assert!(option::destroy_some(refund.refund_reason) == SETTLEMENT_INVALID_RECIPIENT, 6);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// Clearing an applied Move -> SEVM crossing removes the record and its object, so Move state
    /// does not grow by one resource per crossing, and clearing it again is a no-op.
    fun test_apply_clears_an_applied_record(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);

        let id = deposit(user, 400, test_evm_address(0x15));
        let record_address = settlement_record_address(&id);
        assert!(record_exists(record_address), 0);

        apply_settlements(
            supra_framework,
            0,
            0,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[record_address],
        );

        assert!(!record_exists(record_address), 1);
        assert!(!exists<SettlementRecordDeleteRef>(record_address), 2);
        assert!(!object::is_object(record_address), 3);
        // Clearing a record pays nothing: the value was escrowed by the crossing and is mirrored
        // on the SEVM.
        assert!(escrow_balance() == 400, 4);

        let cleared = event::emitted_events<OutboundSettlementCleared>();
        assert!(vector::length(&cleared) == 1, 5);
        assert!(vector::borrow(&cleared, 0).removed, 6);

        // Re-applying the same batch removes nothing twice.
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[record_address],
        );
        let cleared = event::emitted_events<OutboundSettlementCleared>();
        assert!(vector::length(&cleared) == 2, 7);
        assert!(!vector::borrow(&cleared, 1).removed, 8);
        assert!(escrow_balance() == 400, 9);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// One credit that cannot be applied must not stop the rest of the batch, because an abort here
    /// would halt the block. Of four entries two are unappliable: the other two apply, exactly two
    /// refunds are recorded, and the record in the same batch is still cleared.
    fun test_one_unappliable_settlement_does_not_stop_the_batch(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, freeze_cap, mint_cap) = setup_with_freeze_cap(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);

        let id = deposit(user, 1000, test_evm_address(0x16));
        let record_address = settlement_record_address(&id);
        account::create_account_for_test(@0xb0b);
        freeze_primary_store(@0xbad, &freeze_cap);

        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7, 7, 7, 7],
            vector[0, 0, 1, 1],
            vector[0, 1, 0, 1],
            vector[
                evm_address_bytes(&test_evm_address(0x21)),
                evm_address_bytes(&test_evm_address(0x22)),
                evm_address_bytes(&test_evm_address(0x23)),
                evm_address_bytes(&test_evm_address(0x24)),
            ],
            // An existing account, a frozen recipient, an account that does not exist yet, and the
            // escrow authority's own address.
            vector[@0xb0b, @0xbad, @0xcafe, escrow_authority_address()],
            vector[100, 200, 300, 400],
            vector[record_address],
        );

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        // Every appliable entry was paid, whatever its position relative to the failure.
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 100, 0);
        assert!(primary_fungible_store::balance(@0xcafe, metadata) == 300, 1);
        assert!(account::exists_at(@0xcafe), 2);
        // The frozen recipient and the authority were paid nothing.
        assert!(primary_fungible_store::balance(@0xbad, metadata) == 0, 3);
        assert!(escrow_balance() == 1000 - 100 - 300, 4);

        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 4, 5);
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_OK, 6);
        assert!(vector::borrow(&applied, 1).status == SETTLEMENT_RECIPIENT_FROZEN, 7);
        assert!(vector::borrow(&applied, 2).status == SETTLEMENT_OK, 8);
        assert!(vector::borrow(&applied, 3).status == SETTLEMENT_INVALID_RECIPIENT, 9);
        // Exactly the two unappliable entries were returned, and nothing else was.
        assert!(refund_count(&applied) == 2, 10);

        // The cleanup half of the same batch still ran.
        assert!(!record_exists(record_address), 11);
        let cleared = event::emitted_events<OutboundSettlementCleared>();
        assert!(vector::length(&cleared) == 1, 12);
        assert!(vector::borrow(&cleared, 0).removed, 13);

        coin::destroy_freeze_cap(freeze_cap);
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// Each row's columns must stay together. Every value is distinct and no two columns hold the
    /// same values, so pairing row `i` of one column with row `j` of another shows up as a wrong
    /// payment or a wrong event rather than passing quietly.
    fun test_apply_pairs_each_row_across_all_columns(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0x50));
        account::create_account_for_test(@0xb0b);

        apply_settlements(
            supra_framework,
            0,
            0,
            vector[11, 12, 13],
            vector[2, 3, 5],
            vector[17, 18, 19],
            vector[
                evm_address_bytes(&test_evm_address(0x51)),
                evm_address_bytes(&test_evm_address(0x52)),
                evm_address_bytes(&test_evm_address(0x53)),
            ],
            vector[@0xb0b, @0xcafe, @0xdad],
            vector[101, 202, 303],
            vector[],
        );

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 101, 0);
        assert!(primary_fungible_store::balance(@0xcafe, metadata) == 202, 1);
        assert!(primary_fungible_store::balance(@0xdad, metadata) == 303, 2);
        assert!(escrow_balance() == 1000 - 101 - 202 - 303, 3);

        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 3, 4);

        let first = vector::borrow(&applied, 0);
        assert!(first.order.block_height == 11, 5);
        assert!(first.order.transaction_index == 2, 6);
        assert!(first.order.settlement_index == 17, 7);
        assert!(
            first.id == inbound_settlement_id(
                &SettlementOrder { block_height: 11, transaction_index: 2, settlement_index: 17 }
            ),
            23,
        );
        assert!(first.recipient == @0xb0b, 8);
        assert!(first.amount == 101, 9);
        assert!(
            evm_address_bytes(&first.sender) == evm_address_bytes(&test_evm_address(0x51)),
            10,
        );

        let second = vector::borrow(&applied, 1);
        assert!(second.order.block_height == 12, 11);
        assert!(second.order.transaction_index == 3, 12);
        assert!(second.order.settlement_index == 18, 13);
        assert!(
            second.id == inbound_settlement_id(
                &SettlementOrder { block_height: 12, transaction_index: 3, settlement_index: 18 }
            ),
            24,
        );
        assert!(second.recipient == @0xcafe, 14);
        assert!(second.amount == 202, 15);
        assert!(
            evm_address_bytes(&second.sender) == evm_address_bytes(&test_evm_address(0x52)),
            16,
        );

        let third = vector::borrow(&applied, 2);
        assert!(third.order.block_height == 13, 17);
        assert!(third.order.transaction_index == 5, 18);
        assert!(third.order.settlement_index == 19, 19);
        assert!(
            third.id == inbound_settlement_id(
                &SettlementOrder { block_height: 13, transaction_index: 5, settlement_index: 19 }
            ),
            25,
        );
        assert!(third.recipient == @0xdad, 20);
        assert!(third.amount == 303, 21);
        assert!(
            evm_address_bytes(&third.sender) == evm_address_bytes(&test_evm_address(0x53)),
            22,
        );

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// Replaying a whole batch pays nothing a second time: every entry in it is at or below the
    /// watermark, so all of them are reported as already processed and none moves any value.
    fun test_apply_skips_a_replayed_batch(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0x60));
        account::create_account_for_test(@0xb0b);

        let heights = vector[7, 7];
        let transactions = vector[0, 1];
        let settlements = vector[0, 0];
        let senders = vector[
            evm_address_bytes(&test_evm_address(0x61)),
            evm_address_bytes(&test_evm_address(0x62)),
        ];
        let recipients = vector[@0xb0b, @0xcafe];
        let amounts = vector[100, 200];

        apply_settlements(
            supra_framework, 0, 0, heights, transactions, settlements, senders, recipients,
            amounts, vector[],
        );

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 100, 0);
        assert!(primary_fungible_store::balance(@0xcafe, metadata) == 200, 1);
        assert!(escrow_balance() == 700, 2);

        // The identical batch again.
        apply_settlements(
            supra_framework, 0, 0, heights, transactions, settlements, senders, recipients,
            amounts, vector[],
        );

        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 100, 3);
        assert!(primary_fungible_store::balance(@0xcafe, metadata) == 200, 4);
        assert!(escrow_balance() == 700, 5);
        // The second pass processed nothing and reported both entries as already processed.
        assert!(vector::length(&event::emitted_events<InboundSettlementApplied>()) == 2, 6);
        let skipped = event::emitted_events<InboundSettlementAlreadyProcessed>();
        assert!(vector::length(&skipped) == 2, 7);
        assert!(vector::borrow(&skipped, 0).recipient == @0xb0b, 8);
        assert!(vector::borrow(&skipped, 1).recipient == @0xcafe, 9);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A batch that overlaps an earlier one applies exactly the entries above the watermark, so a
    /// queue that was only partly drained resumes where it stopped instead of restarting.
    fun test_apply_resumes_a_partly_applied_queue(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0x70));
        account::create_account_for_test(@0xb0b);

        // The first two of three settlements recorded by block 7.
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7, 7],
            vector[0, 0],
            vector[0, 1],
            vector[
                evm_address_bytes(&test_evm_address(0x71)),
                evm_address_bytes(&test_evm_address(0x72)),
            ],
            vector[@0xb0b, @0xcafe],
            vector[100, 200],
            vector[],
        );
        assert!(escrow_balance() == 700, 0);

        // All three, of which only the third is above the watermark.
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7, 7, 7],
            vector[0, 0, 0],
            vector[0, 1, 2],
            vector[
                evm_address_bytes(&test_evm_address(0x71)),
                evm_address_bytes(&test_evm_address(0x72)),
                evm_address_bytes(&test_evm_address(0x73)),
            ],
            vector[@0xb0b, @0xcafe, @0xdad],
            vector[100, 200, 300],
            vector[],
        );

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 100, 1);
        assert!(primary_fungible_store::balance(@0xcafe, metadata) == 200, 2);
        assert!(primary_fungible_store::balance(@0xdad, metadata) == 300, 3);
        assert!(escrow_balance() == 400, 4);
        assert!(vector::length(&event::emitted_events<InboundSettlementApplied>()) == 3, 5);
        assert!(
            vector::length(&event::emitted_events<InboundSettlementAlreadyProcessed>()) == 2,
            6,
        );

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A credit that was returned has still been processed, so the watermark advances past it and a
    /// replay records no second refund. Without that, a replayed unappliable credit would mint a
    /// fresh refund on every attempt.
    fun test_apply_advances_the_watermark_past_a_refund(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x80));

        let authority = escrow_authority_address();
        apply_one_inbound(supra_framework, 0, test_evm_address(0x81), authority, 200);
        // The deposit and one refund.
        assert!(vector::length(&event::emitted_events<SettlementRecorded>()) == 2, 0);

        apply_one_inbound(supra_framework, 0, test_evm_address(0x81), authority, 200);
        // Still the deposit and one refund: the replay recorded nothing.
        assert!(vector::length(&event::emitted_events<SettlementRecorded>()) == 2, 1);
        assert!(vector::length(&event::emitted_events<InboundSettlementApplied>()) == 1, 2);
        assert!(
            vector::length(&event::emitted_events<InboundSettlementAlreadyProcessed>()) == 1,
            3,
        );
        assert!(escrow_balance() == 500, 4);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A credit larger than the escrow is returned rather than paid, so the escrow can never be
    /// overdrawn and the value is not lost.
    fun test_apply_refunds_a_credit_the_escrow_cannot_cover(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 100, test_evm_address(0x17));

        apply_one_inbound(supra_framework, 0, test_evm_address(0x17), @0xb0b, 10_000);

        assert!(escrow_balance() == 100, 0);
        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_INSUFFICIENT_ESCROW, 1);
        assert!(refund_count(&applied) == 1, 2);

        cleanup(burn_cap, mint_cap);
    }

    #[test_only]
    /// Raise the outstanding-record count by `count`, so that a test can reach the bound without
    /// writing `MAX_OUTSTANDING_CROSSINGS` records.
    fun add_outstanding_for_test(count: u64) acquires SettlementBacklog {
        aggregator_v2::add(
            &mut borrow_global_mut<SettlementBacklog>(@supra_framework).outstanding,
            count,
        );
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x9000A, location = Self)]
    /// A crossing started while the backlog is full is refused.
    fun test_deposit_at_the_backlog_bound_aborts(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);

        add_outstanding_for_test(MAX_OUTSTANDING_CROSSINGS);
        assert!(outstanding_crossings() == MAX_OUTSTANDING_CROSSINGS, 0);

        cleanup(burn_cap, mint_cap);
        deposit(user, 100, test_evm_address(0x31));
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// Clearing a record makes room for another crossing, so the bound is a backlog and not a
    /// lifetime quota.
    fun test_clearing_a_record_admits_another_crossing(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord,
        SettlementRecordDeleteRef, SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);

        // One real record, and the rest of the bound filled in.
        let id = deposit(user, 100, test_evm_address(0x32));
        assert!(outstanding_crossings() == 1, 0);
        add_outstanding_for_test(MAX_OUTSTANDING_CROSSINGS - 1);
        assert!(outstanding_crossings() == MAX_OUTSTANDING_CROSSINGS, 1);

        // Clearing the record puts the backlog back under the bound.
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[], vector[], vector[], vector[], vector[], vector[],
            vector[settlement_record_address(&id)],
        );
        assert!(outstanding_crossings() == MAX_OUTSTANDING_CROSSINGS - 1, 2);

        // ... and another crossing is admitted, which the test above shows it would not have been.
        deposit(user, 100, test_evm_address(0x33));
        assert!(outstanding_crossings() == MAX_OUTSTANDING_CROSSINGS, 3);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A refund is recorded even with the backlog full.
    ///
    /// The bound governs crossings that are starting, and a refund is not one: its value has
    /// already left the SEVM, and the record is the only thing that can return it. Refusing one
    /// would strand that value, so the count is raised by a refund without being consulted first.
    fun test_a_refund_is_recorded_with_the_backlog_full(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord,
        SettlementRecordDeleteRef, SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 100, test_evm_address(0x34));
        add_outstanding_for_test(MAX_OUTSTANDING_CROSSINGS - 1);
        assert!(outstanding_crossings() == MAX_OUTSTANDING_CROSSINGS, 0);

        // A credit the escrow cannot cover, which is returned rather than paid.
        apply_one_inbound(supra_framework, 0, test_evm_address(0x35), @0xb0b, 10_000);

        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(refund_count(&applied) == 1, 1);
        // The refund is a record like any other and is counted, so the backlog is now over its
        // bound - which refuses new crossings and nothing else.
        assert!(outstanding_crossings() == MAX_OUTSTANDING_CROSSINGS + 1, 2);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// An escrow that runs out partway through a batch pays what it can, returns what it cannot,
    /// and keeps paying afterwards.
    ///
    /// A batch draws its funds from the escrow in one withdrawal, so this pins that the funds it
    /// holds are spent exactly as the escrow would have been: a credit is measured against what is
    /// left when it is reached, not against what the batch started with, and a credit too large to
    /// pay takes nothing, so a smaller one behind it is still paid. The entries are independent,
    /// and running out of funds is one more per-entry outcome rather than the end of the batch.
    fun test_apply_pays_around_a_credit_the_escrow_runs_out_on(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 300, test_evm_address(0x21));

        // 300 escrowed against credits of 200, 200 and 50, in that order.
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7, 7, 7],
            vector[0, 0, 0],
            vector[0, 1, 2],
            vector[
                evm_address_bytes(&test_evm_address(0x22)),
                evm_address_bytes(&test_evm_address(0x23)),
                evm_address_bytes(&test_evm_address(0x24)),
            ],
            vector[@0xb0b, @0xcafe, @0xdad],
            vector[200, 200, 50],
            vector[],
        );

        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 3, 0);
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_OK, 1);
        assert!(vector::borrow(&applied, 1).status == SETTLEMENT_INSUFFICIENT_ESCROW, 2);
        // The credit behind the one that could not be paid is still paid.
        assert!(vector::borrow(&applied, 2).status == SETTLEMENT_OK, 3);
        assert!(refund_count(&applied) == 1, 4);

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 200, 5);
        assert!(primary_fungible_store::balance(@0xcafe, metadata) == 0, 6);
        assert!(primary_fungible_store::balance(@0xdad, metadata) == 50, 7);
        // What the batch drew and did not pay out is back where it came from.
        assert!(escrow_balance() == 50, 8);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce, recipient = @0xb0b)]
    /// A credit that moves no value has nothing to return, so it is recorded and skipped rather
    /// than refunded.
    fun test_apply_skips_a_zero_credit_without_refunding_it(
        supra_framework: &signer,
        user: &signer,
        recipient: address,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 100, test_evm_address(0x18));

        apply_one_inbound(supra_framework, 0, test_evm_address(0x18), recipient, 0);

        assert!(escrow_balance() == 100, 0);
        assert!(!account::exists_at(recipient), 1);
        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_ZERO_AMOUNT, 2);
        assert!(refund_count(&applied) == 0, 3);
        // Only the deposit recorded a settlement.
        assert!(vector::length(&event::emitted_events<SettlementRecorded>()) == 1, 4);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A credit to one of the addresses `account::create_account` reserves is still paid: the
    /// account creation is skipped rather than attempted, because attempting it would abort and
    /// take the whole batch with it, and the release does not need an account to land.
    fun test_apply_pays_a_reserved_address_without_creating_an_account(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x1b));
        assert!(!account::exists_at(@aptos_token), 0);

        apply_one_inbound(supra_framework, 0, test_evm_address(0x1b), @aptos_token, 200);

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@aptos_token, metadata) == 200, 1);
        assert!(escrow_balance() == 300, 2);
        assert!(!account::exists_at(@aptos_token), 3);
        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_OK, 4);
        assert!(refund_count(&applied) == 0, 5);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework)]
    /// Settlement is deliberately not gated on the feature, so that disabling it drains the
    /// outstanding crossings instead of stranding them. Applying with the feature off is therefore
    /// not an error.
    fun test_apply_while_disabled_is_allowed(
        supra_framework: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
        );
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x30008, location = Self)]
    /// The Move-side half of the feature gate, on the initiating side: no new crossing may start
    /// while the feature is off, so the sender keeps their SUPRA rather than escrowing it against
    /// a settlement that is not running.
    fun test_deposit_while_disabled_aborts(
        supra_framework: &signer,
        user: &signer,
    ) acquires Escrow, SettlementBacklog {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        fund(user, 1000, &mint_cap);
        deposit(user, 100, test_evm_address(0x0e));
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, other = @0xa11ce)]
    #[expected_failure(abort_code = 0x50003, location = supra_framework::system_addresses)]
    /// Only the framework signer applies settlements. A wrong signer is a programming error, not a
    /// per-settlement condition, so it aborts.
    fun test_apply_by_another_signer_aborts(
        supra_framework: &signer,
        other: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        apply_settlements(
            other,
            0,
            0,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
        );
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x10007, location = Self)]
    /// A batch whose columns disagree is malformed, so it aborts having applied nothing, rather
    /// than applying the prefix the shortest column covers.
    fun test_apply_with_mismatched_batch_lengths_aborts(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x19));

        apply_settlements(
            supra_framework,
            0,
            0,
            // One block height for two settlements.
            vector[7],
            vector[0, 0],
            vector[0, 1],
            vector[
                evm_address_bytes(&test_evm_address(0x19)),
                evm_address_bytes(&test_evm_address(0x19)),
            ],
            vector[@0xb0b, @0xcafe],
            vector[100, 200],
            vector[],
        );
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    /// A batch out of settlement order is malformed. Applying it as given would let an earlier
    /// entry carry the watermark past a later one, which would then be skipped as though it had
    /// already been paid.
    fun test_apply_with_an_unordered_batch_aborts(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x1c));

        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7, 7],
            vector[0, 0],
            // Descending, and so not a valid order.
            vector[1, 0],
            vector[
                evm_address_bytes(&test_evm_address(0x1c)),
                evm_address_bytes(&test_evm_address(0x1c)),
            ],
            vector[@0xb0b, @0xcafe],
            vector[100, 200],
            vector[],
        );
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    /// The same settlement twice in one batch is out of order too, since the order must strictly
    /// increase, so a batch cannot pay one credit twice by naming it twice.
    fun test_apply_with_a_repeated_settlement_in_one_batch_aborts(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0x1d));

        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7, 7],
            vector[0, 0],
            vector[0, 0],
            vector[
                evm_address_bytes(&test_evm_address(0x1d)),
                evm_address_bytes(&test_evm_address(0x1d)),
            ],
            vector[@0xb0b, @0xb0b],
            vector[100, 100],
            vector[],
        );
        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A credit whose sender is not a usable EVM address is skipped and reported, and the entries
    /// around it in the same batch are paid as normal. It is not refunded, because a refund would
    /// have no address to name.
    fun test_apply_skips_an_unusable_sender_and_applies_the_rest(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0x90));
        account::create_account_for_test(@0xb0b);

        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7, 7, 7, 7],
            vector[0, 0, 0, 0],
            vector[0, 1, 2, 3],
            vector[
                evm_address_bytes(&test_evm_address(0x91)),
                // The zero address, which no one can claim a mirrored balance at.
                EVM_ZERO_ADDRESS,
                // Too few bytes to be an address at all.
                vector[0x01, 0x02],
                evm_address_bytes(&test_evm_address(0x94)),
            ],
            vector[@0xb0b, @0xcafe, @0xdad, @0xf00d],
            vector[100, 200, 300, 400],
            vector[],
        );

        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        // The entries before and after the two unusable senders were both paid.
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 100, 0);
        assert!(primary_fungible_store::balance(@0xf00d, metadata) == 400, 1);
        // The two unusable ones moved nothing, and created no account.
        assert!(primary_fungible_store::balance(@0xcafe, metadata) == 0, 2);
        assert!(primary_fungible_store::balance(@0xdad, metadata) == 0, 3);
        assert!(!account::exists_at(@0xcafe), 4);
        assert!(!account::exists_at(@0xdad), 5);
        assert!(escrow_balance() == 1000 - 100 - 400, 6);

        // Only the two appliable entries reached the escrow, and neither rejected entry was
        // returned: the deposit is still the only settlement on record.
        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 2, 7);
        assert!(refund_count(&applied) == 0, 8);
        assert!(vector::length(&event::emitted_events<SettlementRecorded>()) == 1, 9);

        let rejected = event::emitted_events<InboundSettlementSenderRejected>();
        assert!(vector::length(&rejected) == 2, 10);
        let first = vector::borrow(&rejected, 0);
        assert!(first.status == SETTLEMENT_INVALID_SENDER, 11);
        assert!(first.sender_bytes == EVM_ZERO_ADDRESS, 12);
        assert!(first.recipient == @0xcafe, 13);
        assert!(first.amount == 200, 14);
        assert!(first.order.settlement_index == 1, 15);
        assert!(
            first.id == inbound_settlement_id(
                &SettlementOrder { block_height: 7, transaction_index: 0, settlement_index: 1 }
            ),
            20,
        );
        let second = vector::borrow(&rejected, 1);
        assert!(second.status == SETTLEMENT_INVALID_SENDER, 16);
        assert!(second.sender_bytes == vector[0x01, 0x02], 17);
        assert!(second.recipient == @0xdad, 18);
        assert!(
            second.id == inbound_settlement_id(
                &SettlementOrder { block_height: 7, transaction_index: 0, settlement_index: 2 }
            ),
            21,
        );

        // A skipped entry has still been processed, so the watermark is past the whole batch and a
        // replay of it applies nothing.
        let watermark = option::destroy_some(
            borrow_global<SettlementWatermark>(@supra_framework).highest_applied
        );
        assert!(watermark.settlement_index == 3, 19);

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework)]
    /// Applying a credit on a chain that has no escrow returns it rather than paying it or aborting,
    /// so a settlement injected before `initialize` has run is not lost.
    fun test_apply_refunds_when_the_escrow_is_not_initialized(
        supra_framework: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord,
        SettlementRecordDeleteRef, SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        // Deliberately no `initialize`.
        enable_settlements(supra_framework);
        assert!(!is_initialized(), 0);

        apply_one_inbound(supra_framework, 0, test_evm_address(0xa1), @0xb0b, 200);

        // Nothing was paid and no account was created for the recipient.
        assert!(!account::exists_at(@0xb0b), 1);
        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::length(&applied) == 1, 2);
        let entry = vector::borrow(&applied, 0);
        assert!(entry.status == SETTLEMENT_NOT_INITIALIZED, 3);
        assert!(refund_count(&applied) == 1, 4);

        // The refund is on record and owed back to the sender of the credit.
        let refund_id = *option::borrow(&entry.refund);
        let refund = option::destroy_some(record_at(settlement_record_address(&refund_id)));
        assert!(refund.amount == 200, 5);
        assert!(option::destroy_some(refund.refund_reason) == SETTLEMENT_NOT_INITIALIZED, 6);
        assert!(
            evm_address_bytes(&option::destroy_some(refund.recipient.evm_address))
                == evm_address_bytes(&test_evm_address(0xa1)),
            7,
        );

        cleanup(burn_cap, mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// An escrow without a watermark gets one, so applying settlements on a chain whose escrow
    /// predates the watermark records a watermark and pays the credit rather than halting.
    fun test_apply_creates_a_missing_watermark(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 1000, &mint_cap);
        deposit(user, 500, test_evm_address(0xb1));
        account::create_account_for_test(@0xb0b);

        remove_watermark_for_test();
        assert!(!exists<SettlementWatermark>(@supra_framework), 0);
        assert!(is_initialized(), 1);

        apply_one_inbound(supra_framework, 4, test_evm_address(0xb1), @0xb0b, 200);

        // The credit was paid, and the watermark now exists and sits at it.
        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 200, 2);
        assert!(escrow_balance() == 300, 3);
        assert!(exists<SettlementWatermark>(@supra_framework), 4);
        let watermark = option::destroy_some(
            borrow_global<SettlementWatermark>(@supra_framework).highest_applied
        );
        assert!(watermark.block_height == 7, 5);
        assert!(watermark.settlement_index == 4, 6);

        cleanup(burn_cap, mint_cap);
    }

    #[test]
    /// `is_valid_evm_address` and `new_evm_address` are the same rule, so the applier's status and
    /// the constructor's abort cannot come to disagree about what an address is.
    fun test_evm_address_validity_matches_the_constructor() {
        // Accepted by both: `new_evm_address` returns rather than aborting for this one, which the
        // tests below cannot say of the others.
        let valid = evm_address_bytes(&test_evm_address(0x2a));
        assert!(is_valid_evm_address(&valid), 0);
        assert!(evm_address_bytes(&new_evm_address(valid)) == valid, 1);
        // Rejected by both. `test_evm_zero_address_is_rejected` and
        // `test_evm_address_length_is_enforced` pin the aborts these predict.
        assert!(!is_valid_evm_address(&EVM_ZERO_ADDRESS), 2);
        assert!(!is_valid_evm_address(&vector[0x01, 0x02]), 3);
        assert!(!is_valid_evm_address(&vector::empty<u8>()), 4);
        let too_long = valid;
        vector::push_back(&mut too_long, 0x00);
        assert!(!is_valid_evm_address(&too_long), 5);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A burn retires escrowed value and reduces the total supply of SUPRA by the same amount, which
    /// is what keeps the escrow level with what the SEVM still mirrors.
    fun test_apply_burn_retires_escrow_and_supply(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0xc1));

        let supply_before = option::destroy_some(coin::supply<SupraCoin>());
        apply_settlements(
            supra_framework,
            9,
            250,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
        );

        assert!(escrow_balance() == 750, 0);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == supply_before - 250, 1);

        let burns = event::emitted_events<SettlementBurnApplied>();
        assert!(vector::length(&burns) == 1, 2);
        let entry = vector::borrow(&burns, 0);
        assert!(entry.block_height == 9, 3);
        assert!(entry.amount == 250, 4);
        assert!(entry.status == SETTLEMENT_OK, 5);
        // The cursor now sits at the block that was retired.
        let cursor = borrow_global<SettlementWatermark>(@supra_framework).highest_burned_block;
        assert!(option::destroy_some(cursor) == 9, 6);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A burn the escrow cannot cover reports the shortfall and moves nothing, rather than aborting
    /// or draining what is left. Refusing it is the conservative outcome, and the cursor does not
    /// advance, so the burn is not recorded as done.
    fun test_apply_burn_the_escrow_cannot_cover_reports_and_moves_nothing(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 100, test_evm_address(0xc2));

        let supply_before = option::destroy_some(coin::supply<SupraCoin>());
        apply_settlements(
            supra_framework,
            9,
            10_000,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
        );

        assert!(escrow_balance() == 100, 0);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == supply_before, 1);
        let burns = event::emitted_events<SettlementBurnApplied>();
        assert!(vector::borrow(&burns, 0).status == SETTLEMENT_INSUFFICIENT_ESCROW, 2);
        // Not retired, so not recorded as retired: the same block can be requested again.
        let cursor = borrow_global<SettlementWatermark>(@supra_framework).highest_burned_block;
        assert!(option::is_none(&cursor), 3);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A block with no fees to retire asks for a burn of zero. That succeeds and does nothing, and
    /// is still reported, so a consumer reconciling per block does not have to tell a zero request
    /// apart from a missing event.
    fun test_apply_burn_of_zero_is_a_no_op_that_succeeds(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0xc4));

        let supply_before = option::destroy_some(coin::supply<SupraCoin>());
        apply_settlements(
            supra_framework,
            9,
            0,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
        );

        assert!(escrow_balance() == 1000, 0);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == supply_before, 1);
        let burns = event::emitted_events<SettlementBurnApplied>();
        assert!(vector::length(&burns) == 1, 2);
        assert!(vector::borrow(&burns, 0).amount == 0, 3);
        assert!(vector::borrow(&burns, 0).status == SETTLEMENT_OK, 4);
        // Nothing was retired, so nothing is recorded as retired.
        let cursor = borrow_global<SettlementWatermark>(@supra_framework).highest_burned_block;
        assert!(option::is_none(&cursor), 5);
        // `burn` was not reached, so it reported nothing of its own.
        assert!(vector::length(&event::emitted_events<EscrowBurned>()) == 0, 6);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// The burn does not depend on there being any crossings. A block that burns and crosses nothing
    /// is the common case, and it must retire the value all the same.
    fun test_apply_burn_with_no_settlements_at_all(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0xc5));

        apply_settlements(
            supra_framework,
            9,
            400,
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
        );

        assert!(escrow_balance() == 600, 0);
        // Nothing else happened: no credit was applied and no record was cleared.
        assert!(vector::length(&event::emitted_events<InboundSettlementApplied>()) == 0, 1);
        assert!(vector::length(&event::emitted_events<OutboundSettlementCleared>()) == 0, 2);
        assert!(vector::borrow(&event::emitted_events<SettlementBurnApplied>(), 0).status
            == SETTLEMENT_OK, 3);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// A burn that succeeded is not retired twice. Re-requesting the same block reports it as
    /// already applied and moves nothing, which is what a replayed batch looks like.
    fun test_apply_burn_is_not_retired_twice(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0xc6));

        apply_settlements(
            supra_framework, 9, 250, vector[], vector[], vector[], vector[], vector[], vector[],
            vector[],
        );
        assert!(escrow_balance() == 750, 0);
        let supply_after_first = option::destroy_some(coin::supply<SupraCoin>());

        // The same block again.
        apply_settlements(
            supra_framework, 9, 250, vector[], vector[], vector[], vector[], vector[], vector[],
            vector[],
        );
        assert!(escrow_balance() == 750, 1);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == supply_after_first, 2);
        assert!(vector::length(&event::emitted_events<SettlementBurnApplied>()) == 1, 3);
        let skipped = event::emitted_events<SettlementBurnAlreadyApplied>();
        assert!(vector::length(&skipped) == 1, 4);
        assert!(vector::borrow(&skipped, 0).block_height == 9, 5);
        assert!(vector::borrow(&skipped, 0).amount == 250, 6);

        // An earlier block is refused for the same reason, and a later one still applies.
        apply_settlements(
            supra_framework, 8, 100, vector[], vector[], vector[], vector[], vector[], vector[],
            vector[],
        );
        assert!(escrow_balance() == 750, 7);
        assert!(vector::length(&event::emitted_events<SettlementBurnAlreadyApplied>()) == 2, 8);

        apply_settlements(
            supra_framework, 10, 100, vector[], vector[], vector[], vector[], vector[], vector[],
            vector[],
        );
        assert!(escrow_balance() == 650, 9);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// The burn runs before the credits, so when the escrow cannot cover both it is the credit that
    /// is returned. That is the recoverable half: the SEVM re-credits a returned credit, while an
    /// unretired burn needs an operator.
    fun test_apply_burn_takes_precedence_over_a_credit(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 300, test_evm_address(0xc7));

        // The escrow holds 300; the burn wants all of it and the credit wants 200 more.
        apply_settlements(
            supra_framework,
            9,
            300,
            vector[7],
            vector[0],
            vector[0],
            vector[evm_address_bytes(&test_evm_address(0xc8))],
            vector[@0xb0b],
            vector[200],
            vector[],
        );

        // The burn took the escrow.
        assert!(escrow_balance() == 0, 0);
        assert!(vector::borrow(&event::emitted_events<SettlementBurnApplied>(), 0).status
            == SETTLEMENT_OK, 1);
        // The credit was returned rather than paid, and is on its way back to the SEVM.
        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_INSUFFICIENT_ESCROW, 2);
        assert!(refund_count(&applied) == 1, 3);
        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 0, 4);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test_only]
    /// Disable `COIN_TO_FUNGIBLE_ASSET_MIGRATION`.
    fun disable_coin_to_fungible_asset_migration(supra_framework: &signer) {
        features::change_feature_flags_for_testing(
            supra_framework,
            vector[],
            vector[features::get_coin_to_fungible_asset_migration_feature()],
        );
    }

    #[test_only]
    /// The current value of the supply counter of the fungible asset paired with `SupraCoin`.
    fun paired_fungible_supply(): u128 acquires Escrow {
        option::destroy_some(fungible_asset::supply(borrow_global<Escrow>(@supra_framework).metadata))
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// Burns and credits apply with the coin-to-fungible-asset migration feature disabled. The burn
    /// retires its amount from the escrow and from the paired fungible asset's supply, and the credit
    /// in the same batch is paid. See #4135.
    fun test_apply_with_the_migration_feature_disabled_burns_and_pays(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        let (burn_cap, mint_cap) = setup(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        fund(user, 10_000, &mint_cap);
        deposit(user, 1000, test_evm_address(0xc9));
        disable_coin_to_fungible_asset_migration(supra_framework);

        let fungible_supply_before = paired_fungible_supply();
        let coin_supply_before = option::destroy_some(coin::coin_supply<SupraCoin>());
        apply_settlements(
            supra_framework,
            9,
            250,
            vector[7],
            vector[0],
            vector[0],
            vector[evm_address_bytes(&test_evm_address(0xca))],
            vector[@0xb0b],
            vector[300],
            vector[],
        );

        // The burn was retired and recorded as retired.
        let burns = event::emitted_events<SettlementBurnApplied>();
        assert!(vector::length(&burns) == 1, 0);
        assert!(vector::borrow(&burns, 0).status == SETTLEMENT_OK, 1);
        let cursor = borrow_global<SettlementWatermark>(@supra_framework).highest_burned_block;
        assert!(option::destroy_some(cursor) == 9, 2);
        // The burn took 250 out of existence and the credit paid 300 out of the escrow.
        assert!(escrow_balance() == 450, 3);
        assert!(paired_fungible_supply() == fungible_supply_before - 250, 4);
        assert!(option::destroy_some(coin::coin_supply<SupraCoin>()) == coin_supply_before, 5);
        let applied = event::emitted_events<InboundSettlementApplied>();
        assert!(vector::borrow(&applied, 0).status == SETTLEMENT_OK, 6);
        assert!(refund_count(&applied) == 0, 7);
        let metadata = borrow_global<Escrow>(@supra_framework).metadata;
        assert!(primary_fungible_store::balance(@0xb0b, metadata) == 300, 8);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// With the supply ceiling active, a burn lowers `coin::supply` by exactly its amount, and a
    /// credit and a deposit leave it unchanged, since both only move value between forms or
    /// holders. The coin-side counter is untouched by the burn.
    fun test_apply_burn_lowers_the_ceiling_bearing_supply_by_its_amount(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        features::change_feature_flags_for_testing(
            supra_framework,
            vector[features::get_concurrent_fungible_assets_feature()],
            vector[],
        );
        let (burn_cap, mint_cap) = setup(supra_framework);
        fund(user, 10_000, &mint_cap);
        supra_coin::initialize_supply_ceiling(supra_framework);
        let total = option::destroy_some(coin::supply<SupraCoin>());
        assert!(total == 10_000, 0);

        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        deposit(user, 1000, test_evm_address(0xcb));
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == total, 1);

        apply_settlements(
            supra_framework,
            9,
            250,
            vector[7],
            vector[0],
            vector[0],
            vector[evm_address_bytes(&test_evm_address(0xcc))],
            vector[@0xb0b],
            vector[300],
            vector[],
        );

        assert!(escrow_balance() == 450, 2);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == total - 250, 3);
        assert!(paired_fungible_supply() == total - 250, 4);
        // The coin-side counter holds only the coin form: what was minted, less what was deposited.
        assert!(option::destroy_some(coin::coin_supply<SupraCoin>()) == 9_000, 5);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test(supra_framework = @supra_framework, user = @0xa11ce)]
    /// With the supply ceiling active, a burn lowers `coin::supply` by exactly its amount whether or
    /// not the coin-to-fungible-asset migration feature is enabled. See #4135.
    fun test_apply_burn_with_the_ceiling_active_and_the_migration_feature_disabled(
        supra_framework: &signer,
        user: &signer,
    ) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        features::change_feature_flags_for_testing(
            supra_framework,
            vector[features::get_concurrent_fungible_assets_feature()],
            vector[],
        );
        let (burn_cap, mint_cap) = setup(supra_framework);
        fund(user, 10_000, &mint_cap);
        supra_coin::initialize_supply_ceiling(supra_framework);
        initialize_with_burn_cap(supra_framework, burn_cap);
        enable_settlements(supra_framework);
        deposit(user, 1000, test_evm_address(0xcd));
        let total = option::destroy_some(coin::supply<SupraCoin>());
        disable_coin_to_fungible_asset_migration(supra_framework);

        apply_settlements(
            supra_framework, 9, 250, vector[], vector[], vector[], vector[], vector[], vector[],
            vector[],
        );

        assert!(vector::borrow(&event::emitted_events<SettlementBurnApplied>(), 0).status
            == SETTLEMENT_OK, 0);
        assert!(escrow_balance() == 750, 1);
        assert!(option::destroy_some(coin::supply<SupraCoin>()) == total - 250, 2);
        assert!(option::destroy_some(coin::coin_supply<SupraCoin>()) == 9_000, 3);

        coin::destroy_mint_cap(mint_cap);
    }

    #[test]
    /// The settlement order is lexicographic over the triple, so it is a total order across blocks,
    /// across transactions in a block, and within one transaction.
    fun test_settlement_order_is_lexicographic() {
        let base = SettlementOrder { block_height: 7, transaction_index: 3, settlement_index: 2 };
        // A later block wins however the lower two fields compare.
        assert!(
            order_is_after(
                &SettlementOrder { block_height: 8, transaction_index: 0, settlement_index: 0 },
                &base,
            ),
            0,
        );
        assert!(
            !order_is_after(
                &SettlementOrder { block_height: 6, transaction_index: 99, settlement_index: 99 },
                &base,
            ),
            1,
        );
        // Then the transaction, then the settlement.
        assert!(
            order_is_after(
                &SettlementOrder { block_height: 7, transaction_index: 4, settlement_index: 0 },
                &base,
            ),
            2,
        );
        assert!(
            !order_is_after(
                &SettlementOrder { block_height: 7, transaction_index: 2, settlement_index: 99 },
                &base,
            ),
            3,
        );
        assert!(
            order_is_after(
                &SettlementOrder { block_height: 7, transaction_index: 3, settlement_index: 3 },
                &base,
            ),
            4,
        );
        // An order is not after itself, which is what makes a replay a skip.
        assert!(!order_is_after(&base, &base), 5);
        assert!(!order_is_unprocessed(&base, &option::some(base)), 6);
        // Before the first settlement, everything is unprocessed.
        assert!(order_is_unprocessed(&base, &option::none()), 7);
    }

    #[test]
    /// The id of an inbound crossing is laid out exactly as the node lays it out. The first vector is
    /// pinned by the node's test of its own `inbound_settlement_id` as well; do not change it here
    /// without changing it there.
    fun test_inbound_settlement_id_matches_the_node_derivation() {
        let id = inbound_settlement_id(&SettlementOrder {
            block_height: 0x0102030405060708,
            transaction_index: 0x090a0b0c,
            settlement_index: 0x0d0e0f10,
        });
        assert!(
            settlement_id_bytes(&id)
                == x"73757072613a7365766d2d3e6d6f76650102030405060708090a0b0c0d0e0f10",
            0,
        );
        // The largest indices the node can produce keep all four of their bytes.
        let id = inbound_settlement_id(&SettlementOrder {
            block_height: 0xffffffffffffffff,
            transaction_index: MAX_INBOUND_ID_INDEX,
            settlement_index: MAX_INBOUND_ID_INDEX,
        });
        assert!(
            settlement_id_bytes(&id)
                == x"73757072613a7365766d2d3e6d6f7665ffffffffffffffffffffffffffffffff",
            1,
        );
        let id = inbound_settlement_id(
            &SettlementOrder { block_height: 0, transaction_index: 0, settlement_index: 0 }
        );
        assert!(
            settlement_id_bytes(&id)
                == x"73757072613a7365766d2d3e6d6f766500000000000000000000000000000000",
            2,
        );
    }

    #[test]
    #[expected_failure(abort_code = 0x1000b, location = Self)]
    /// A transaction index wider than four bytes has no inbound settlement id.
    fun test_inbound_settlement_id_of_a_wide_transaction_index_aborts() {
        inbound_settlement_id(&SettlementOrder {
            block_height: 7,
            transaction_index: MAX_INBOUND_ID_INDEX + 1,
            settlement_index: 0,
        });
    }

    #[test]
    #[expected_failure(abort_code = 0x1000b, location = Self)]
    /// A settlement index wider than four bytes has no inbound settlement id.
    fun test_inbound_settlement_id_of_a_wide_settlement_index_aborts() {
        inbound_settlement_id(&SettlementOrder {
            block_height: 7,
            transaction_index: 0,
            settlement_index: MAX_INBOUND_ID_INDEX + 1,
        });
    }

    #[test(supra_framework = @supra_framework)]
    #[expected_failure(abort_code = 0x1000b, location = Self)]
    /// A batch carrying a transaction index wider than four bytes aborts, since the node's
    /// transaction indices are `u32` and the credit's settlement id has no room for a wider one. The call
    /// aborts when it derives the credit's id. Nothing the call does before that aborts on a chain
    /// without an escrow, so the test needs none.
    fun test_apply_with_a_wide_transaction_index_aborts(supra_framework: &signer) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7],
            vector[MAX_INBOUND_ID_INDEX + 1],
            vector[0],
            vector[evm_address_bytes(&test_evm_address(0x1e))],
            vector[@0xb0b],
            vector[100],
            vector[],
        );
    }

    #[test(supra_framework = @supra_framework)]
    #[expected_failure(abort_code = 0x1000b, location = Self)]
    /// A batch carrying a settlement index wider than four bytes aborts, since the node's
    /// settlement indices are `u32` and the credit's settlement id has no room for a wider one. The call
    /// aborts when it derives the credit's id. Nothing the call does before that aborts on a chain
    /// without an escrow, so the test needs none.
    fun test_apply_with_a_wide_settlement_index_aborts(supra_framework: &signer) acquires
        Escrow, SettlementBacklog, SettlementRecord, SettlementRecordDeleteRef,
        SettlementWatermark
    {
        apply_settlements(
            supra_framework,
            0,
            0,
            vector[7],
            vector[0],
            vector[MAX_INBOUND_ID_INDEX + 1],
            vector[evm_address_bytes(&test_evm_address(0x1f))],
            vector[@0xb0b],
            vector[100],
            vector[],
        );
    }
}

/// Delegated spending for fungible assets.
///
/// An account (the *grantor*) records how much of one fungible asset another account (the
/// *spender*) may move on its behalf and until when. The spender then calls `transfer_from` or
/// `transfer_from_store`, which withdraws from a store the grantor owns and deposits into a
/// destination store, charging the grant for whatever the withdrawal actually debited.
///
/// A grantor's grants live on an object whose address is derived from the grantor's address and
/// the module's registry object, in the way `primary_fungible_store` derives a store address from
/// an account. Any write creates that object on demand, so a grantor that has never sent a
/// transaction of its own can still have a grant installed for it from an off-chain signature by
/// whoever submits it, and that submitter pays the storage. `initialize` publishes the registry and
/// is called once, from genesis or from the framework upgrade that adds this module.
///
/// A grant is *live* only while it belongs to the grantor's current generation, its expiry is
/// still in the future and its remaining amount is above zero. Every read path applies the same
/// test, so a grant that has stopped being live reads exactly like one that was never made.
///
/// Every grant states its *scope*. `SCOPE_PRIMARY_STORE` confines it to the grantor's primary
/// store for that asset, and `SCOPE_ANY_OWNED_STORE` extends it to any store of that asset the
/// grantor directly owns. `transfer_from_store` names the store and consults the grant made by
/// that store's direct owner, then holds the withdrawal to the grant's scope.
///
/// Grants are created with `increase` or with the compare-and-set `replace`, never by overwriting
/// an amount outright, so that a grantor reducing a grant cannot have the old amount and the new
/// one spent one after the other. `apply_signed_grant` carries the same compare-and-set through an
/// off-chain signature, so a spender can install a grant without the grantor sending a
/// transaction and then spend it with `transfer_from`. A signed grant carries the generation it was
/// signed under, so `revoke_all` voids the signatures a grantor has handed out and not yet seen
/// submitted, along with the grants already on chain.
///
/// A grant nonce is one-shot per grantor: a signed grant is admissible only while its nonce is at
/// or above the grantor's nonce floor and has not been recorded. `cancel_nonce` records one nonce
/// without installing a grant, which kills one outstanding signature; `invalidate_nonces_below`
/// raises the floor, which kills every signature naming a lower nonce and makes their recorded
/// entries reclaimable with `remove_used_nonce_bucket`; `revoke_all` voids every grant and
/// signature at once.
///
/// Recorded grant nonces are held as a bitmap, one storage slot per block of `NONCES_PER_BUCKET`
/// consecutive nonces, so a grantor should allocate its nonces densely from a low counter --
/// taking the next value from `min_nonce` or from a client-side counter -- rather than choosing
/// them at random, which puts every nonce in a block of its own. Only the first nonce recorded in
/// a block creates a slot; the rest of that block carries no storage fee. Reclamation frees whole
/// blocks: once the floor has passed the top of a block, `remove_used_nonce_bucket` returns that
/// slot, and `reclaimable_bucket_limit` says which blocks are eligible without any off-chain
/// record of what was used.
///
/// `settle_upto` settles a one-shot transfer authorization, an `UptoAuthorization` the payer signs
/// off chain. It names a facilitator, a recipient, an asset, a maximum amount, a validity interval
/// and a 32-byte nonce, and the facilitator moves any amount up to the maximum from the payer's
/// primary store to the recipient's primary store, once. Settlement reads and writes no grant. The
/// signed payload is rebuilt with the transaction's signer as the facilitator, so only the
/// facilitator the payer named can settle. An authorization is admissible only while
/// `valid_after <= now < valid_before`, with `valid_before - valid_after` at most
/// `MAX_UPTO_SPAN_SECS`, and only under the payer's current generation, so `revoke_all` voids it
/// as well. The payer's store is debited at most the maximum, including any fee the asset's
/// withdraw hook takes. `verify_upto` reports, without aborting, whether `settle_upto` would
/// succeed and with which code it would abort otherwise.
///
/// Settlement nonces are separate from grant nonces. A settlement nonce is unique among the
/// payer's unexpired authorizations. Settling an authorization, or cancelling a nonce with
/// `cancel_upto`, records the nonce against the payer until a `valid_before`; once the block time
/// reaches it, anyone may remove the record with `remove_expired_upto_nonce` or
/// `remove_expired_upto_nonces`, and the storage refund goes to that transaction's gas payer. A
/// payer cancels an outstanding authorization by having one with the same nonce, a `max_amount` of
/// 0 and a `valid_before` at or after the original's settled, since the record it leaves lasts
/// until the original has expired. Two authorizations that share a nonce and both have a nonzero
/// `max_amount` are mutually exclusive only when their `valid_before` is equal.
///
/// Both signed paths, `apply_signed_grant` and `settle_upto`, accept an ed25519 (scheme 0) or
/// multi-ed25519 (scheme 1) signature over `ed25519::SignedMessage` of the payload. The public key
/// must derive the signer's authentication key, which is the key in its `Account` resource when it
/// has one and otherwise the BCS bytes of its address. An address that has only ever received
/// assets therefore signs with the key its address was derived from. A signature that fails any
/// of these checks aborts with `EINVALID_SIGNATURE`. Single-key, multi-key and keyless accounts
/// cannot use either signed path, and grant through the on-chain grantor entry points instead.
///
/// The owner of an asset's metadata object may block and unblock delegated spending of that asset
/// at any time with `set_allowances_disabled`, whether or not the asset was created with this
/// module in mind; `disable_allowances` does the same from a `ConstructorRef` at asset creation.
/// Blocking applies to settlement as well as to grants. The fungible asset paired with a coin has
/// its metadata object owned by the framework, so for that asset the holder of the coin's
/// `FreezeCapability` uses `set_paired_allowances_disabled`.
module supra_framework::fungible_asset_allowance {
    use std::bcs;
    use std::error;
    use std::option;
    use std::signer;
    use std::vector;

    use aptos_std::ed25519;
    use aptos_std::multi_ed25519;
    use aptos_std::table::{Self, Table};

    use supra_framework::account;
    use supra_framework::chain_id;
    use supra_framework::coin::{Self, FreezeCapability};
    use supra_framework::dispatchable_fungible_asset;
    use supra_framework::event;
    use supra_framework::fungible_asset::{Self, FungibleAsset, Metadata};
    use supra_framework::object::{Self, ConstructorRef, DeriveRef, Object};
    use supra_framework::primary_fungible_store;
    use supra_framework::system_addresses;
    use supra_framework::timestamp;

    /// No live allowance exists for this grantor, spender and asset.
    const EALLOWANCE_NOT_FOUND: u64 = 1;
    /// The live allowance is smaller than the amount the spender is moving.
    const EINSUFFICIENT_ALLOWANCE: u64 = 2;
    /// An allowance must expire strictly after the current block time.
    const EINVALID_EXPIRY: u64 = 3;
    /// An allowance may not expire more than `MAX_EXPIRY_HORIZON_SECS` after the current block time.
    const EEXPIRY_TOO_FAR: u64 = 4;
    /// The live remaining amount is not the one the caller expected.
    const EALLOWANCE_MISMATCH: u64 = 5;
    /// This grantor has already consumed a signed grant carrying this nonce.
    const ENONCE_ALREADY_USED: u64 = 6;
    /// Delegated spending is disabled for this asset.
    const EALLOWANCES_DISABLED: u64 = 7;
    /// The grantor has no primary store for this asset.
    const ESOURCE_STORE_MISSING: u64 = 8;
    /// The allowance being reclaimed is still live.
    const EGRANT_STILL_LIVE: u64 = 9;
    /// The amount must be greater than zero.
    const EAMOUNT_CANNOT_BE_ZERO: u64 = 10;
    /// The signer does not own the asset's metadata object.
    const ENOT_METADATA_OWNER: u64 = 11;
    /// The module's registry has not been published.
    const EMODULE_NOT_INITIALIZED: u64 = 12;
    /// The resulting allowance does not fit in a u64.
    const EALLOWANCE_OVERFLOW: u64 = 13;
    /// The signed grant or authorization was made under a different generation.
    const EGENERATION_MISMATCH: u64 = 14;
    /// The object is not a fungible asset's `Metadata` object.
    const ENOT_FUNGIBLE_ASSET_METADATA: u64 = 15;
    /// The scope is not one of the scopes this module defines.
    const EINVALID_SCOPE: u64 = 16;
    /// The live allowance has a different scope from the one the caller named.
    const EALLOWANCE_SCOPE_MISMATCH: u64 = 17;
    /// The store is outside the scope of the allowance being spent.
    const ESTORE_OUT_OF_SCOPE: u64 = 18;
    /// The nonce is below the grantor's nonce floor.
    const ENONCE_BELOW_FLOOR: u64 = 19;
    /// The new nonce floor is not above the current one.
    const EFLOOR_NOT_ADVANCED: u64 = 20;
    /// The bucket is not entirely below the grantor's nonce floor.
    const EBUCKET_NOT_INVALIDATED: u64 = 21;
    /// This grantor has no record of this nonce bucket.
    const EBUCKET_NOT_FOUND: u64 = 22;
    /// The coin type has no paired fungible asset.
    const ECOIN_NOT_PAIRED: u64 = 23;
    /// A settlement nonce is not `UPTO_NONCE_LENGTH` bytes long.
    const EUPTO_INVALID_NONCE: u64 = 24;
    /// The authorization's `valid_after` is later than the current block time.
    const EUPTO_NOT_YET_VALID: u64 = 25;
    /// The current block time is at or after the authorization's `valid_before`.
    const EUPTO_EXPIRED: u64 = 26;
    /// The authorization's `valid_before` is more than `MAX_UPTO_SPAN_SECS` after its
    /// `valid_after`.
    const EUPTO_SPAN_TOO_LONG: u64 = 27;
    /// The amount, or what the withdrawal debited the payer's store, is above the authorization's
    /// maximum.
    const EUPTO_AMOUNT_EXCEEDS_MAX: u64 = 28;
    /// The payer already has a record of this settlement nonce.
    const EUPTO_NONCE_USED: u64 = 29;
    /// The signature scheme is not ed25519 or multi-ed25519, the public key does not derive the
    /// signer's authentication key, or the signature does not verify.
    const EINVALID_SIGNATURE: u64 = 30;
    /// The block time has not reached the settlement nonce record's `valid_before`.
    const EUPTO_NONCE_NOT_EXPIRED: u64 = 31;
    /// The payer has no record of this settlement nonce.
    const EUPTO_NONCE_NOT_FOUND: u64 = 32;
    /// The payer's primary store holds less than the amount. Reported by `verify_upto`;
    /// `settle_upto` aborts inside `fungible_asset` instead.
    const EUPTO_INSUFFICIENT_BALANCE: u64 = 33;
    /// The payer's or the recipient's primary store is frozen. Reported by `verify_upto`;
    /// `settle_upto` aborts inside `fungible_asset` instead.
    const EUPTO_STORE_FROZEN: u64 = 34;
    /// The lists of payers and nonces have different lengths.
    const EUPTO_LENGTH_MISMATCH: u64 = 35;

    /// The longest time ahead of the current block time at which an allowance may be set to expire:
    /// 366 days.
    const MAX_EXPIRY_HORIZON_SECS: u64 = 31622400;

    /// The largest allowance that can be recorded.
    const MAX_U64: u64 = 18446744073709551615;

    /// An allowance of this scope may be spent only from the grantor's primary store.
    const SCOPE_PRIMARY_STORE: u8 = 0;

    /// An allowance of this scope may be spent from any store of the asset the grantor directly
    /// owns.
    const SCOPE_ANY_OWNED_STORE: u8 = 1;

    /// How many consecutive nonces one `used_nonces` entry records.
    const NONCES_PER_BUCKET: u64 = 128;

    /// How far to shift a nonce right to reach its bucket index.
    const BUCKET_SHIFT: u8 = 7;

    /// The part of a nonce that selects its bit within a bucket.
    const BUCKET_BIT_MASK: u64 = 127;

    /// The most an authorization's `valid_before` may exceed its `valid_after` by: 1 hour. It
    /// bounds how long a signature can be settled and how long its nonce record holds a storage
    /// deposit.
    const MAX_UPTO_SPAN_SECS: u64 = 3600;

    /// The length of a settlement nonce in bytes.
    const UPTO_NONCE_LENGTH: u64 = 32;

    /// `upto_nonce_state` of a nonce the payer has no record of.
    const UPTO_NONCE_NONE: u8 = 0;

    /// `upto_nonce_state` of a nonce recorded by settling an authorization.
    const UPTO_NONCE_SETTLED: u8 = 1;

    /// `upto_nonce_state` of a nonce recorded by `cancel_upto`.
    const UPTO_NONCE_CANCELLED: u8 = 2;

    /// The signature scheme identifier of an ed25519 key.
    const ED25519_SCHEME: u8 = 0;

    /// The signature scheme identifier of a multi-ed25519 key.
    const MULTI_ED25519_SCHEME: u8 = 1;

    /// The length of an ed25519 public key, and of each key in a multi-ed25519 public key.
    const ED25519_PUBLIC_KEY_LENGTH: u64 = 32;

    /// The length of an ed25519 signature, and of each signature in a multi-ed25519 signature.
    const ED25519_SIGNATURE_LENGTH: u64 = 64;

    /// The most keys a multi-ed25519 public key holds.
    const MULTI_ED25519_MAX_KEYS: u64 = 32;

    /// The length of the threshold that ends a multi-ed25519 public key.
    const MULTI_ED25519_THRESHOLD_LENGTH: u64 = 1;

    /// The length of the bitmap that ends a multi-ed25519 signature.
    const MULTI_ED25519_BITMAP_LENGTH: u64 = 4;

    /// The seed of the object every grantor's allowance object is derived from.
    const ALLOWANCES_POD_SEED: vector<u8> = b"fungible_asset_allowance::allowances";

    /// The seed of the object every asset's control object is derived from.
    const CONTROLS_POD_SEED: vector<u8> = b"fungible_asset_allowance::controls";

    /// Points at the two objects this module derives addresses from, and holds the settlement nonce
    /// records. The two objects are separate so that an address that is both a grantor and an
    /// asset's metadata object has one derived object of each kind rather than one shared between
    /// them.
    struct Registry has key {
        /// The address of the object whose ref addresses every grantor's allowance object.
        allowances_pod: address,
        /// The address of the object whose ref addresses every asset's control object.
        controls_pod: address,
        /// Every payer's settlement nonce records, keyed by payer and nonce. Each record is its own
        /// table item, so recording one writes that item and not this resource.
        upto_nonces: Table<UptoNonceKey, UptoNonceRecord>,
    }

    #[resource_group_member(group = supra_framework::object::ObjectGroup)]
    /// Holds the ref one family of this module's derived addresses is computed from.
    struct DeriveRefPod has key {
        /// The ref the addresses in this family are computed from.
        derive_ref: DeriveRef,
    }

    #[resource_group_member(group = supra_framework::object::ObjectGroup)]
    /// Every allowance granted by one grantor, on the object derived from that grantor's address.
    struct Allowances has key {
        /// Incremented by `revoke_all`. A grant recorded under an older generation is not live.
        generation: u64,
        /// The grants this grantor has made, one per spender and asset.
        grants: Table<GrantKey, Grant>,
        /// The signed-grant nonces this grantor has already recorded, as a bitmap: one entry per
        /// `NONCES_PER_BUCKET` consecutive nonces, keyed by bucket index.
        used_nonces: Table<u64, u128>,
        /// The lowest nonce a signed grant may still name. Raising it voids every signature
        /// naming a lower nonce, whatever that signature's expiry, generation or amount, and is
        /// what makes the recorded entries below it reclaimable.
        min_nonce: u64,
    }

    /// Identifies one grant within a grantor's `Allowances`.
    struct GrantKey has copy, drop, store {
        /// The account permitted to spend.
        spender: address,
        /// The address of the asset's `Metadata` object.
        metadata: address,
    }

    /// One allowance granted to one spender for one asset.
    struct Grant has store, drop {
        /// The amount of the asset the spender may still move.
        remaining: u64,
        /// The second from which the grant is no longer live.
        expiry_secs: u64,
        /// The grantor's generation at the time the grant was last written.
        generation: u64,
        /// Which of the grantor's stores of the asset the allowance may be spent from, either
        /// `SCOPE_PRIMARY_STORE` or `SCOPE_ANY_OWNED_STORE`.
        scope: u8,
    }

    #[resource_group_member(group = supra_framework::object::ObjectGroup)]
    /// One asset's issuer setting, on the object derived from that asset's metadata address.
    struct AllowanceControl has key {
        /// True while delegated spending of this asset is blocked.
        disabled: bool,
    }

    /// Identifies one settlement nonce record.
    struct UptoNonceKey has copy, drop, store {
        /// The account that signed the authorization.
        payer: address,
        /// The authorization's nonce.
        nonce: vector<u8>,
    }

    /// One settlement nonce recorded against a payer.
    struct UptoNonceRecord has copy, drop, store {
        /// The second from which the record may be removed.
        valid_before: u64,
        /// `UPTO_NONCE_SETTLED` or `UPTO_NONCE_CANCELLED`.
        state: u8,
    }

    /// The payload a payer signs off chain to authorise one transfer of up to `max_amount`.
    struct UptoAuthorization has copy, drop {
        /// The chain the authorization is valid on.
        chain_id: u8,
        /// The account whose primary store is debited.
        payer: address,
        /// The only account that may settle the authorization.
        facilitator: address,
        /// The account whose primary store is credited.
        pay_to: address,
        /// The address of the asset's `Metadata` object.
        metadata: address,
        /// The most the payer's store may be debited.
        max_amount: u64,
        /// The first second at which the authorization may be settled.
        valid_after: u64,
        /// The second from which the authorization may no longer be settled.
        valid_before: u64,
        /// A `UPTO_NONCE_LENGTH`-byte value unique among the payer's unexpired authorizations.
        nonce: vector<u8>,
        /// The payer's generation the authorization was made under.
        generation: u64,
    }

    /// The payload a grantor signs off chain to authorise a grant without sending a transaction.
    struct SignedGrant has copy, drop {
        /// The chain the grant is valid on.
        chain_id: u8,
        /// The account whose asset may be spent.
        grantor: address,
        /// The account permitted to spend.
        spender: address,
        /// The address of the asset's `Metadata` object.
        metadata: address,
        /// The live remaining amount the grantor expects the grant to have.
        expected_remaining: u64,
        /// The remaining amount the grant is set to.
        amount: u64,
        /// The second from which the grant is no longer live.
        expiry_secs: u64,
        /// A value the grantor may use once.
        nonce: u64,
        /// The grantor's generation the grant was authorised under.
        generation: u64,
        /// The scope the grant was authorised with.
        scope: u8,
    }

    #[event]
    /// Emitted whenever one grant's remaining amount or expiry is written.
    struct GrantChanged has drop, store {
        /// The account whose asset may be spent.
        grantor: address,
        /// The account permitted to spend.
        spender: address,
        /// The address of the asset's `Metadata` object.
        metadata: address,
        /// The remaining amount after the write; zero when the grant was removed.
        remaining: u64,
        /// The expiry after the write; zero when the grant was removed.
        expiry_secs: u64,
        /// The grantor's generation at the time of the write.
        generation: u64,
        /// The scope of the grant after the write.
        scope: u8,
    }

    #[event]
    /// Emitted for each delegated transfer.
    struct GrantConsumed has drop, store {
        /// The account whose asset was spent.
        grantor: address,
        /// The account that spent it.
        spender: address,
        /// The address of the asset's `Metadata` object.
        metadata: address,
        /// The address of the store the asset was withdrawn from.
        store: address,
        /// The address of the store the asset was deposited into.
        to: address,
        /// The amount that reached the destination store's deposit.
        transferred: u64,
        /// The amount taken off the grant, which is what the source store was debited.
        charged: u64,
        /// The amount left on the grant afterwards.
        remaining: u64,
    }

    #[event]
    /// Emitted for each settled authorization.
    struct UptoSettled has drop, store {
        /// The account whose primary store was debited.
        payer: address,
        /// The account that settled the authorization.
        facilitator: address,
        /// The account whose primary store was credited.
        pay_to: address,
        /// The address of the asset's `Metadata` object.
        metadata: address,
        /// The authorization's nonce.
        nonce: vector<u8>,
        /// The authorization's maximum.
        max_amount: u64,
        /// What the payer's store was debited.
        amount: u64,
        /// The amount that reached the recipient's store's deposit.
        received: u64,
    }

    #[event]
    /// Emitted when a payer cancels a settlement nonce with `cancel_upto`.
    struct UptoCancelled has drop, store {
        /// The account whose nonce was recorded.
        payer: address,
        /// The nonce that can no longer be settled until its record is removed.
        nonce: vector<u8>,
    }

    #[event]
    /// Emitted whenever a nonce is recorded against a grantor, and the only record that it was:
    /// nothing else in the event stream names a consumed nonce.
    struct NonceConsumed has drop, store {
        /// The account whose nonce was recorded.
        grantor: address,
        /// The nonce that can no longer be used by a signed grant.
        nonce: u64,
        /// True when the nonce was consumed by applying a signed grant, false when the grantor
        /// consumed it with `cancel_nonce` to withdraw a signature.
        installed_grant: bool,
    }

    #[event]
    /// Emitted when a grantor raises its nonce floor.
    struct NoncesInvalidated has drop, store {
        /// The account whose nonce floor moved.
        grantor: address,
        /// The lowest nonce a signed grant may still name.
        min_nonce: u64,
    }

    #[event]
    /// Emitted when a grantor voids every grant it has made.
    struct AllGrantsRevoked has drop, store {
        /// The account whose grants were voided.
        grantor: address,
        /// The generation that grants must now carry to be live.
        generation: u64,
    }

    #[event]
    /// Emitted when an asset's metadata owner blocks or unblocks delegated spending of the asset.
    struct AllowancesDisabledChanged has drop, store {
        /// The address of the asset's `Metadata` object.
        metadata: address,
        /// True when delegated spending is now blocked.
        disabled: bool,
    }

    /// Publish the module's registry and the two objects its derived addresses are computed from.
    /// Called once, from genesis or from the framework upgrade that adds this module; calling it
    /// again leaves the registry as it is, so the derived addresses never move.
    public fun initialize(supra_framework: &signer) {
        system_addresses::assert_supra_framework(supra_framework);
        if (!exists<Registry>(@supra_framework)) {
            let allowances_pod = create_pod(supra_framework, ALLOWANCES_POD_SEED);
            let controls_pod = create_pod(supra_framework, CONTROLS_POD_SEED);
            move_to(supra_framework, Registry {
                allowances_pod,
                controls_pod,
                upto_nonces: table::new<UptoNonceKey, UptoNonceRecord>(),
            });
        };
    }

    /// Add `by` to the grantor's allowance for `spender` on `metadata` and set the grant to expire
    /// at `expiry_secs`. Creates the grant when there is no live one. `scope` states which of the
    /// grantor's stores of the asset the allowance may be spent from: `SCOPE_PRIMARY_STORE` for
    /// the primary store alone, `SCOPE_ANY_OWNED_STORE` for any store the grantor directly owns.
    /// Adding to a live grant requires the same scope it already has, so a change of scope goes
    /// through `replace`.
    public entry fun increase(
        grantor: &signer,
        spender: address,
        metadata: Object<Metadata>,
        by: u64,
        expiry_secs: u64,
        scope: u8,
    ) acquires Registry, DeriveRefPod, Allowances {
        assert!(by > 0, error::invalid_argument(EAMOUNT_CANNOT_BE_ZERO));
        assert_scope_is_valid(scope);
        assert_expiry_is_valid(expiry_secs);
        let grantor_addr = signer::address_of(grantor);
        ensure_allowances(grantor_addr);
        let key = GrantKey { spender, metadata: object::object_address(&metadata) };
        let (remaining, _, live_scope) = live_grant(grantor_addr, key);
        assert!(
            remaining == 0 || live_scope == scope,
            error::invalid_state(EALLOWANCE_SCOPE_MISMATCH)
        );
        assert!(by <= MAX_U64 - remaining, error::out_of_range(EALLOWANCE_OVERFLOW));
        write_grant(grantor_addr, key, remaining + by, expiry_secs, scope);
    }

    /// Take `by` off the grantor's allowance for `spender` on `metadata`, keeping its expiry. The
    /// subtraction saturates at zero, and a grant reduced to zero is removed.
    public entry fun decrease(
        grantor: &signer,
        spender: address,
        metadata: Object<Metadata>,
        by: u64,
    ) acquires Registry, Allowances {
        let grantor_addr = signer::address_of(grantor);
        let key = GrantKey { spender, metadata: object::object_address(&metadata) };
        let (remaining, expiry_secs, scope) = live_grant(grantor_addr, key);
        assert!(remaining > 0, error::not_found(EALLOWANCE_NOT_FOUND));
        let new_remaining = if (by >= remaining) { 0 } else { remaining - by };
        write_grant(grantor_addr, key, new_remaining, expiry_secs, scope);
    }

    /// Set the grantor's allowance for `spender` on `metadata` to `amount` with scope `scope`,
    /// expiring at `expiry_secs`, but only while its live remaining amount is
    /// `expected_remaining`. Pass zero for `expected_remaining` to require that there is no live
    /// grant, and zero for `amount` to remove the grant. `scope` is `SCOPE_PRIMARY_STORE` for the
    /// grantor's primary store alone or `SCOPE_ANY_OWNED_STORE` for any store the grantor directly
    /// owns, and this is the call that changes the scope of an existing grant.
    public entry fun replace(
        grantor: &signer,
        spender: address,
        metadata: Object<Metadata>,
        expected_remaining: u64,
        amount: u64,
        expiry_secs: u64,
        scope: u8,
    ) acquires Registry, DeriveRefPod, Allowances {
        assert_scope_is_valid(scope);
        if (amount > 0) {
            assert_expiry_is_valid(expiry_secs);
        };
        let grantor_addr = signer::address_of(grantor);
        ensure_allowances(grantor_addr);
        let key = GrantKey { spender, metadata: object::object_address(&metadata) };
        let (remaining, _, _) = live_grant(grantor_addr, key);
        assert!(remaining == expected_remaining, error::invalid_state(EALLOWANCE_MISMATCH));
        write_grant(grantor_addr, key, amount, expiry_secs, scope);
    }

    /// Remove the grantor's allowance for `spender` on `metadata`. Does nothing when there is no
    /// live grant to remove.
    public entry fun revoke(
        grantor: &signer,
        spender: address,
        metadata: Object<Metadata>,
    ) acquires Registry, Allowances {
        let grantor_addr = signer::address_of(grantor);
        let key = GrantKey { spender, metadata: object::object_address(&metadata) };
        let (remaining, _, scope) = live_grant(grantor_addr, key);
        if (remaining > 0) {
            write_grant(grantor_addr, key, 0, 0, scope);
        };
    }

    /// Void every grant the grantor has made, on chain and off: a signed grant carries the
    /// generation it was authorised under, so a signature handed out before this call is no longer
    /// applicable. The entries stay in storage until they are reclaimed with `remove_dead`.
    public entry fun revoke_all(grantor: &signer) acquires Registry, DeriveRefPod, Allowances {
        let grantor_addr = signer::address_of(grantor);
        let allowances_addr = ensure_allowances(grantor_addr);
        let allowances = borrow_global_mut<Allowances>(allowances_addr);
        allowances.generation = allowances.generation + 1;
        let generation = allowances.generation;
        event::emit(AllGrantsRevoked { grantor: grantor_addr, generation });
    }

    /// Reclaim the storage of one grant that is no longer live. Anyone may call this, and the
    /// storage refund goes to the gas payer of the transaction that does, so the caller receives
    /// it. It aborts while the grant is live.
    public entry fun remove_dead(
        grantor: address,
        spender: address,
        metadata: Object<Metadata>,
    ) acquires Registry, Allowances {
        let allowances_addr = allowances_address(grantor);
        assert!(exists<Allowances>(allowances_addr), error::not_found(EALLOWANCE_NOT_FOUND));
        let key = GrantKey { spender, metadata: object::object_address(&metadata) };
        let now = timestamp::now_seconds();
        let allowances = borrow_global_mut<Allowances>(allowances_addr);
        assert!(table::contains(&allowances.grants, key), error::not_found(EALLOWANCE_NOT_FOUND));
        let generation = allowances.generation;
        let scope = {
            let grant = table::borrow(&allowances.grants, key);
            let dead =
                grant.generation != generation
                    || grant.expiry_secs <= now
                    || grant.remaining == 0;
            assert!(dead, error::invalid_state(EGRANT_STILL_LIVE));
            grant.scope
        };
        table::remove(&mut allowances.grants, key);
        event::emit(GrantChanged {
            grantor,
            spender: key.spender,
            metadata: key.metadata,
            remaining: 0,
            expiry_secs: 0,
            generation,
            scope,
        });
    }

    /// Apply a grant the grantor authorised off chain, submitted by anyone. The signature is
    /// checked against the grantor's current authentication key, which for an address with no
    /// `Account` resource is the address's BCS bytes; the grant must name the grantor's current
    /// generation, the nonce may be used once, and the grant is written only while its live
    /// remaining amount is `expected_remaining`. `scope` is part of the signed payload, so the
    /// grant reaches only the stores the grantor authorised and a submitter cannot widen it.
    ///
    /// A signature carrying `expected_remaining` of zero aborts with `EALLOWANCE_MISMATCH` while a
    /// previous grant for the same spender and asset still has a live remainder, and one carrying a
    /// non-zero `expected_remaining` aborts if that remainder expires between signing and
    /// submission, because a grant that is no longer live reads as zero. In both cases the remedy
    /// is a fresh signature against the current value from the `allowance` view.
    public entry fun apply_signed_grant(
        grantor: address,
        spender: address,
        metadata: Object<Metadata>,
        expected_remaining: u64,
        amount: u64,
        expiry_secs: u64,
        nonce: u64,
        generation: u64,
        scope: u8,
        account_scheme: u8,
        public_key: vector<u8>,
        signature: vector<u8>,
    ) acquires Registry, DeriveRefPod, Allowances {
        assert_scope_is_valid(scope);
        // Required whatever `amount` is, so that a signed revocation cannot be produced now and
        // applied years later.
        assert_expiry_is_valid(expiry_secs);
        let metadata_addr = object::object_address(&metadata);
        let payload = SignedGrant {
            chain_id: chain_id::get(),
            grantor,
            spender,
            metadata: metadata_addr,
            expected_remaining,
            amount,
            expiry_secs,
            nonce,
            generation,
            scope,
        };
        assert!(
            is_signature_valid(grantor, account_scheme, public_key, signature, payload),
            error::invalid_argument(EINVALID_SIGNATURE)
        );
        assert!(
            generation == current_generation(grantor),
            error::invalid_state(EGENERATION_MISMATCH)
        );
        // The transaction carrying this call pays for the grantor's allowance object when this is
        // the grantor's first grant.
        let allowances_addr = ensure_allowances(grantor);
        assert_nonce_is_admissible(allowances_addr, nonce);
        consume_nonce(allowances_addr, grantor, nonce, true);
        let key = GrantKey { spender, metadata: metadata_addr };
        let (remaining, _, _) = live_grant(grantor, key);
        assert!(remaining == expected_remaining, error::invalid_state(EALLOWANCE_MISMATCH));
        write_grant(grantor, key, amount, expiry_secs, scope);
    }

    /// Record `nonce` against the grantor without installing a grant, so that a signature the
    /// grantor has handed out carrying that nonce can no longer be applied. This leaves the
    /// grantor's other outstanding signatures alone, which `revoke_all` does not.
    public entry fun cancel_nonce(
        grantor: &signer,
        nonce: u64,
    ) acquires Registry, DeriveRefPod, Allowances {
        let grantor_addr = signer::address_of(grantor);
        // A grantor that has only ever signed off chain has no allowance object to record in yet.
        let allowances_addr = ensure_allowances(grantor_addr);
        assert_nonce_is_admissible(allowances_addr, nonce);
        consume_nonce(allowances_addr, grantor_addr, nonce, false);
    }

    /// Raise the grantor's nonce floor to `new_floor`, which voids every signature the grantor has
    /// handed out naming a lower nonce and leaves its grants untouched.
    public entry fun invalidate_nonces_below(
        grantor: &signer,
        new_floor: u64,
    ) acquires Registry, DeriveRefPod, Allowances {
        let grantor_addr = signer::address_of(grantor);
        let allowances_addr = ensure_allowances(grantor_addr);
        let allowances = borrow_global_mut<Allowances>(allowances_addr);
        assert!(
            new_floor > allowances.min_nonce,
            error::invalid_argument(EFLOOR_NOT_ADVANCED)
        );
        allowances.min_nonce = new_floor;
        event::emit(NoncesInvalidated { grantor: grantor_addr, min_nonce: new_floor });
    }

    /// Reclaim the storage of one bucket of recorded nonces that the grantor's nonce floor has
    /// passed entirely. Anyone may call this, and the storage refund goes to the gas payer of the
    /// transaction that does. A signed grant is admitted only while its nonce is at or above the
    /// floor, so every nonce the bucket covers is permanently inadmissible and the entry can no
    /// longer affect any decision.
    public entry fun remove_used_nonce_bucket(
        grantor: address,
        bucket: u64,
    ) acquires Registry, Allowances {
        let allowances_addr = allowances_address(grantor);
        assert!(exists<Allowances>(allowances_addr), error::not_found(EBUCKET_NOT_FOUND));
        let allowances = borrow_global_mut<Allowances>(allowances_addr);
        assert!(
            table::contains(&allowances.used_nonces, bucket),
            error::not_found(EBUCKET_NOT_FOUND)
        );
        assert!(
            bucket < nonce_bucket(allowances.min_nonce),
            error::invalid_state(EBUCKET_NOT_INVALIDATED)
        );
        table::remove(&mut allowances.used_nonces, bucket);
    }

    /// Move `amount` of `metadata` from the grantor's primary store to `to`'s primary store,
    /// against the allowance the grantor granted the spender. The primary store is within both
    /// scopes, so this works under either.
    public entry fun transfer_from(
        spender: &signer,
        grantor: address,
        metadata: Object<Metadata>,
        to: address,
        amount: u64,
    ) acquires Registry, Allowances, AllowanceControl {
        assert!(
            primary_fungible_store::primary_store_exists(grantor, metadata),
            error::not_found(ESOURCE_STORE_MISSING)
        );
        let from_store = primary_fungible_store::primary_store(grantor, metadata);
        let to_store = primary_fungible_store::ensure_primary_store_exists(to, metadata);
        transfer_from_store(spender, from_store, to_store, amount);
    }

    /// Move `amount` from `store` to `to_store` against the allowance the store's owner granted the
    /// spender. The grant consulted is the one made by `store`'s direct owner, so a store held
    /// through an intermediate object is spendable only under a grant made by that object, and the
    /// withdrawal is held to the grant's scope.
    public entry fun transfer_from_store<T: key>(
        spender: &signer,
        store: Object<T>,
        to_store: Object<T>,
        amount: u64,
    ) acquires Registry, Allowances, AllowanceControl {
        assert!(amount > 0, error::invalid_argument(EAMOUNT_CANNOT_BE_ZERO));
        let grantor = object::owner(store);
        let metadata = fungible_asset::store_metadata(store);
        let metadata_addr = object::object_address(&metadata);
        assert!(
            !allowances_disabled_at(metadata_addr),
            error::permission_denied(EALLOWANCES_DISABLED)
        );

        let spender_addr = signer::address_of(spender);
        let key = GrantKey { spender: spender_addr, metadata: metadata_addr };
        let (remaining, expiry_secs, scope) = live_grant(grantor, key);
        assert!(remaining > 0, error::not_found(EALLOWANCE_NOT_FOUND));
        if (scope == SCOPE_PRIMARY_STORE) {
            assert!(
                object::object_address(&store)
                    == primary_fungible_store::primary_store_address(grantor, metadata),
                error::permission_denied(ESTORE_OUT_OF_SCOPE)
            );
        };
        assert!(amount <= remaining, error::invalid_argument(EINSUFFICIENT_ALLOWANCE));

        // The grant is charged everything the withdrawal took out of the store, so an asset whose
        // withdraw hook takes a fee charges that fee to the grant as well.
        let (fa, charged, has_withdraw_hook) = withdraw_measuring_debit(store, amount);
        // A withdraw hook runs issuer code, so the grant to charge is the one standing when the
        // hook returns rather than the copy read before it.
        let write_remaining = remaining;
        let write_expiry = expiry_secs;
        let write_scope = scope;
        if (has_withdraw_hook) {
            let (fresh_remaining, fresh_expiry, fresh_scope) = live_grant(grantor, key);
            write_remaining = fresh_remaining;
            write_expiry = fresh_expiry;
            write_scope = fresh_scope;
        };
        assert!(charged <= write_remaining, error::invalid_argument(EINSUFFICIENT_ALLOWANCE));
        write_grant(grantor, key, write_remaining - charged, write_expiry, write_scope);

        let transferred = fungible_asset::amount(&fa);
        dispatchable_fungible_asset::deposit(to_store, fa);
        event::emit(GrantConsumed {
            grantor,
            spender: spender_addr,
            metadata: metadata_addr,
            store: object::object_address(&store),
            to: object::object_address(&to_store),
            transferred,
            charged,
            remaining: write_remaining - charged,
        });
    }

    /// Settle a one-shot transfer the payer authorised off chain, moving `amount` of `metadata`
    /// from the payer's primary store to `pay_to`'s. The caller must be the facilitator the payer
    /// named. See `settle_upto_internal` for the rules it applies and its effects.
    public entry fun settle_upto(
        facilitator: &signer,
        payer: address,
        pay_to: address,
        metadata: Object<Metadata>,
        max_amount: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: vector<u8>,
        generation: u64,
        account_scheme: u8,
        public_key: vector<u8>,
        signature: vector<u8>,
        amount: u64,
    ) acquires Registry, Allowances, AllowanceControl {
        settle_upto_internal(
            facilitator,
            payer,
            pay_to,
            metadata,
            max_amount,
            valid_after,
            valid_before,
            nonce,
            generation,
            account_scheme,
            public_key,
            signature,
            amount,
        );
    }

    /// Settle a one-shot transfer the payer authorised off chain and return what the payer's
    /// store was debited.
    ///
    /// The call is admitted only if, in this order: `initialize` has run; `nonce` is
    /// `UPTO_NONCE_LENGTH` bytes; `valid_after` is at or before the current block time; the
    /// current block time is before `valid_before`; `valid_before - valid_after` is at most
    /// `MAX_UPTO_SPAN_SECS`; `amount` is at most `max_amount`; `generation` is the payer's current
    /// generation; the payer has no record of `nonce`; the signature verifies over the
    /// `UptoAuthorization` rebuilt with the caller as the facilitator; delegated spending of the
    /// asset is not disabled; and, when `amount` is not zero, the payer has a primary store of the
    /// asset. The first rule that fails is the abort code.
    ///
    /// Its effects, in this order: the nonce is recorded as settled until `valid_before`; `amount`
    /// is withdrawn from the payer's primary store through the delegated path; what the store was
    /// debited, which includes any fee the asset's withdraw hook takes, must be at most
    /// `max_amount`; the withdrawn asset is deposited into `pay_to`'s primary store, which is
    /// created when absent; `UptoSettled` is emitted. With `amount` zero the nonce is recorded and
    /// nothing is withdrawn, deposited or created. A frozen store on either side, or a payer
    /// balance below `amount`, aborts inside `fungible_asset`.
    public fun settle_upto_internal(
        facilitator: &signer,
        payer: address,
        pay_to: address,
        metadata: Object<Metadata>,
        max_amount: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: vector<u8>,
        generation: u64,
        account_scheme: u8,
        public_key: vector<u8>,
        signature: vector<u8>,
        amount: u64,
    ): u64 acquires Registry, Allowances, AllowanceControl {
        let facilitator_addr = signer::address_of(facilitator);
        let rejection = upto_rejection(
            facilitator_addr,
            payer,
            pay_to,
            metadata,
            max_amount,
            valid_after,
            valid_before,
            &nonce,
            generation,
            account_scheme,
            public_key,
            signature,
            amount,
        );
        assert!(rejection == 0, rejection);

        // The authorization is consumed before the withdrawal, so it is already spent while a
        // withdraw hook runs issuer code.
        record_upto_nonce(payer, nonce, valid_before, UPTO_NONCE_SETTLED);
        let debited = 0;
        let received = 0;
        if (amount > 0) {
            let from_store = primary_fungible_store::primary_store(payer, metadata);
            let to_store = primary_fungible_store::ensure_primary_store_exists(pay_to, metadata);
            let (fa, store_debit, _) = withdraw_measuring_debit(from_store, amount);
            assert!(store_debit <= max_amount, error::invalid_argument(EUPTO_AMOUNT_EXCEEDS_MAX));
            debited = store_debit;
            received = fungible_asset::amount(&fa);
            dispatchable_fungible_asset::deposit(to_store, fa);
        };
        event::emit(UptoSettled {
            payer,
            facilitator: facilitator_addr,
            pay_to,
            metadata: object::object_address(&metadata),
            nonce,
            max_amount,
            amount: debited,
            received,
        });
        debited
    }

    /// Record `nonce` as cancelled against the payer without moving anything, so that no
    /// authorization the payer signed with it can be settled while the record exists. The record
    /// may be removed from the later of `valid_before` and the current block time, so pass the
    /// latest `valid_before` among the authorizations being cancelled. Aborts when the payer
    /// already has a record of `nonce`.
    public entry fun cancel_upto(
        payer: &signer,
        nonce: vector<u8>,
        valid_before: u64,
    ) acquires Registry {
        assert_initialized();
        assert!(
            vector::length(&nonce) == UPTO_NONCE_LENGTH,
            error::invalid_argument(EUPTO_INVALID_NONCE)
        );
        let payer_addr = signer::address_of(payer);
        assert!(
            !upto_nonce_recorded(payer_addr, &nonce),
            error::invalid_argument(EUPTO_NONCE_USED)
        );
        let now = timestamp::now_seconds();
        let record_until = if (valid_before > now) { valid_before } else { now };
        record_upto_nonce(payer_addr, nonce, record_until, UPTO_NONCE_CANCELLED);
        event::emit(UptoCancelled { payer: payer_addr, nonce });
    }

    /// Remove the payer's record of `nonce` once the current block time has reached the record's
    /// `valid_before`. Anyone may call this, and the storage refund goes to the gas payer of the
    /// transaction that does. Aborts when there is no record or it has not expired.
    public entry fun remove_expired_upto_nonce(
        payer: address,
        nonce: vector<u8>,
    ) acquires Registry {
        assert_initialized();
        let key = UptoNonceKey { payer, nonce };
        let upto_nonces = &mut borrow_global_mut<Registry>(@supra_framework).upto_nonces;
        assert!(table::contains(upto_nonces, key), error::not_found(EUPTO_NONCE_NOT_FOUND));
        assert!(
            timestamp::now_seconds() >= table::borrow(upto_nonces, key).valid_before,
            error::invalid_state(EUPTO_NONCE_NOT_EXPIRED)
        );
        table::remove(upto_nonces, key);
    }

    /// Remove every record named by a position in `payers` and `nonces` whose `valid_before` the
    /// current block time has reached, skipping positions with no record or an unexpired one.
    /// Anyone may call this, and the storage refunds go to the gas payer of the transaction that
    /// does. Aborts when the two lists differ in length.
    public entry fun remove_expired_upto_nonces(
        payers: vector<address>,
        nonces: vector<vector<u8>>,
    ) acquires Registry {
        assert_initialized();
        let count = vector::length(&payers);
        assert!(
            count == vector::length(&nonces),
            error::invalid_argument(EUPTO_LENGTH_MISMATCH)
        );
        let now = timestamp::now_seconds();
        let upto_nonces = &mut borrow_global_mut<Registry>(@supra_framework).upto_nonces;
        let i = 0;
        while (i < count) {
            let key = UptoNonceKey {
                payer: *vector::borrow(&payers, i),
                nonce: *vector::borrow(&nonces, i),
            };
            if (table::contains(upto_nonces, key)
                && now >= table::borrow(upto_nonces, key).valid_before) {
                table::remove(upto_nonces, key);
            };
            i = i + 1;
        };
    }

    /// Block delegated spending of the asset being created. The metadata object must already
    /// carry `Metadata`, so call this after `fungible_asset::add_fungibility` on the same
    /// constructor ref.
    public fun disable_allowances(
        constructor_ref: &ConstructorRef,
    ) acquires Registry, DeriveRefPod, AllowanceControl {
        let metadata_addr = object::address_from_constructor_ref(constructor_ref);
        assert!(
            object::object_exists<Metadata>(metadata_addr),
            error::invalid_argument(ENOT_FUNGIBLE_ASSET_METADATA)
        );
        set_control(metadata_addr, true);
    }

    /// Block or unblock delegated spending of an asset, for the owner of its metadata object.
    public entry fun set_allowances_disabled(
        owner: &signer,
        metadata: Object<Metadata>,
        disabled: bool,
    ) acquires Registry, DeriveRefPod, AllowanceControl {
        assert!(
            object::owns(metadata, signer::address_of(owner)),
            error::permission_denied(ENOT_METADATA_OWNER)
        );
        set_control(object::object_address(&metadata), disabled);
    }

    /// Block or unblock delegated spending of the fungible asset paired with `CoinType`, for the
    /// holder of the coin's `FreezeCapability`. The pairing must already exist.
    ///
    /// Blocking delegated spending restricts how holders' balances move, which for a coin is the
    /// authority the `FreezeCapability` carries: it is also what `coin::get_paired_transfer_ref`
    /// requires for the paired asset's `TransferRef`. An issuer that has destroyed its
    /// `FreezeCapability` therefore cannot block delegated spending either.
    public fun set_paired_allowances_disabled<CoinType>(
        _freeze_cap: &FreezeCapability<CoinType>,
        disabled: bool,
    ) acquires Registry, DeriveRefPod, AllowanceControl {
        let metadata = coin::paired_metadata<CoinType>();
        assert!(option::is_some(&metadata), error::not_found(ECOIN_NOT_PAIRED));
        set_control(object::object_address(&option::destroy_some(metadata)), disabled);
    }

    #[view]
    /// The live remaining amount, expiry and scope of the grantor's allowance for `spender` on
    /// `metadata`, or `(0, 0, SCOPE_PRIMARY_STORE)` when there is no live grant.
    public fun allowance(
        grantor: address,
        spender: address,
        metadata: Object<Metadata>,
    ): (u64, u64, u8) acquires Registry, Allowances {
        live_grant(grantor, GrantKey { spender, metadata: object::object_address(&metadata) })
    }

    #[view]
    /// The generation a grant must carry to be live for this grantor.
    public fun generation(grantor: address): u64 acquires Registry, Allowances {
        current_generation(grantor)
    }

    #[view]
    /// Whether a signed grant from this grantor naming `nonce` can no longer be admitted, either
    /// because the nonce is below the grantor's floor or because it is already recorded.
    public fun is_nonce_used(grantor: address, nonce: u64): bool acquires Registry, Allowances {
        if (!exists<Registry>(@supra_framework)) {
            return false
        };
        let allowances_addr = allowances_address(grantor);
        if (!exists<Allowances>(allowances_addr)) {
            false
        } else {
            let allowances = borrow_global<Allowances>(allowances_addr);
            nonce < allowances.min_nonce || is_nonce_recorded(allowances, nonce)
        }
    }

    #[view]
    /// The lowest nonce a signed grant from this grantor may still name.
    public fun min_nonce(grantor: address): u64 acquires Registry, Allowances {
        if (!exists<Registry>(@supra_framework)) {
            return 0
        };
        let allowances_addr = allowances_address(grantor);
        if (!exists<Allowances>(allowances_addr)) {
            0
        } else {
            borrow_global<Allowances>(allowances_addr).min_nonce
        }
    }

    #[view]
    /// The recorded-nonce bits of one bucket. A bucket is created by setting a bit and no bit is
    /// ever cleared, so a bucket that reads 0 holds nothing and is indistinguishable from one that
    /// was never created; a reclaimer can skip it.
    public fun nonce_bucket_bits(
        grantor: address,
        bucket: u64,
    ): u128 acquires Registry, Allowances {
        if (!exists<Registry>(@supra_framework)) {
            return 0
        };
        let allowances_addr = allowances_address(grantor);
        if (!exists<Allowances>(allowances_addr)) {
            return 0
        };
        let allowances = borrow_global<Allowances>(allowances_addr);
        if (!table::contains(&allowances.used_nonces, bucket)) {
            0
        } else {
            *table::borrow(&allowances.used_nonces, bucket)
        }
    }

    #[view]
    /// The exclusive upper bound on reclaimable bucket indices: every bucket below it lies wholly
    /// under the grantor's nonce floor and may be passed to `remove_used_nonce_bucket`. Reading
    /// this and the floor is all a reclaimer needs, with no record of which nonces were used.
    public fun reclaimable_bucket_limit(grantor: address): u64 acquires Registry, Allowances {
        nonce_bucket(min_nonce(grantor))
    }

    #[view]
    /// Whether delegated spending of this asset is blocked.
    public fun allowances_disabled(
        metadata: Object<Metadata>,
    ): bool acquires Registry, AllowanceControl {
        allowances_disabled_at(object::object_address(&metadata))
    }

    #[view]
    /// The address of the object holding this grantor's grants, whether or not it exists yet.
    public fun allowances_object_address(grantor: address): address acquires Registry {
        allowances_address(grantor)
    }

    #[view]
    /// The address of the object holding this asset's issuer setting, whether or not it exists yet.
    public fun control_object_address(metadata: Object<Metadata>): address acquires Registry {
        control_address(object::object_address(&metadata))
    }

    #[view]
    /// The bytes a grantor signs to authorise the described grant off chain.
    public fun grant_signing_message(
        grantor: address,
        spender: address,
        metadata: Object<Metadata>,
        expected_remaining: u64,
        amount: u64,
        expiry_secs: u64,
        nonce: u64,
        generation: u64,
        scope: u8,
    ): vector<u8> {
        let payload = SignedGrant {
            chain_id: chain_id::get(),
            grantor,
            spender,
            metadata: object::object_address(&metadata),
            expected_remaining,
            amount,
            expiry_secs,
            nonce,
            generation,
            scope,
        };
        bcs::to_bytes(&ed25519::new_signed_message(payload))
    }

    #[view]
    /// Whether `settle_upto` signed by `facilitator` with these arguments would succeed:
    /// `(true, 0)` when it would, and otherwise `false` with the abort code, including its error
    /// category, that it would raise. It applies `settle_upto_internal`'s admission rules in the
    /// same order and does not abort, including on malformed nonce, key or signature bytes.
    ///
    /// For a non-zero `amount` it also reports, after the admission rules and in this order, a
    /// frozen payer store as `EUPTO_STORE_FROZEN`, a payer balance below `amount` as
    /// `EUPTO_INSUFFICIENT_BALANCE` and a frozen recipient store as `EUPTO_STORE_FROZEN`, where
    /// `settle_upto` aborts inside `fungible_asset`. A withdraw or deposit hook runs issuer code
    /// that this view does not, so for an asset with a hook `settle_upto` can still abort after
    /// `(true, 0)`, with `EUPTO_AMOUNT_EXCEEDS_MAX` when the hook's fee takes the debit above
    /// `max_amount` or with the hook's own code.
    public fun verify_upto(
        facilitator: address,
        payer: address,
        pay_to: address,
        metadata: Object<Metadata>,
        max_amount: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: vector<u8>,
        generation: u64,
        account_scheme: u8,
        public_key: vector<u8>,
        signature: vector<u8>,
        amount: u64,
    ): (bool, u64) acquires Registry, Allowances, AllowanceControl {
        let rejection = upto_rejection(
            facilitator,
            payer,
            pay_to,
            metadata,
            max_amount,
            valid_after,
            valid_before,
            &nonce,
            generation,
            account_scheme,
            public_key,
            signature,
            amount,
        );
        if (rejection == 0 && amount > 0) {
            rejection = upto_store_rejection(payer, pay_to, metadata, amount);
        };
        (rejection == 0, rejection)
    }

    #[view]
    /// The bytes a payer signs to authorise the described transfer off chain.
    public fun upto_signing_message(
        payer: address,
        facilitator: address,
        pay_to: address,
        metadata: Object<Metadata>,
        max_amount: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: vector<u8>,
        generation: u64,
    ): vector<u8> {
        let payload = UptoAuthorization {
            chain_id: chain_id::get(),
            payer,
            facilitator,
            pay_to,
            metadata: object::object_address(&metadata),
            max_amount,
            valid_after,
            valid_before,
            nonce,
            generation,
        };
        bcs::to_bytes(&ed25519::new_signed_message(payload))
    }

    #[view]
    /// The state of the payer's record of `nonce`: `UPTO_NONCE_NONE` (0) when there is no record,
    /// `UPTO_NONCE_SETTLED` (1) when an authorization carrying it was settled, and
    /// `UPTO_NONCE_CANCELLED` (2) when the payer cancelled it with `cancel_upto`. A record that has
    /// been removed after its `valid_before` also reads 0, so a caller deciding whether an
    /// authorization can still be settled compares its `valid_before` with the current block time
    /// as well.
    public fun upto_nonce_state(payer: address, nonce: vector<u8>): u8 acquires Registry {
        if (!exists<Registry>(@supra_framework)) {
            return UPTO_NONCE_NONE
        };
        let upto_nonces = &borrow_global<Registry>(@supra_framework).upto_nonces;
        let key = UptoNonceKey { payer, nonce };
        if (!table::contains(upto_nonces, key)) {
            UPTO_NONCE_NONE
        } else {
            table::borrow(upto_nonces, key).state
        }
    }

    /// Create one object this module derives addresses from, and return its address.
    fun create_pod(supra_framework: &signer, seed: vector<u8>): address {
        let pod_ref = object::create_named_object(supra_framework, seed);
        let pod_signer = object::generate_signer(&pod_ref);
        move_to(&pod_signer, DeriveRefPod {
            derive_ref: object::generate_derive_ref(&pod_ref),
        });
        object::address_from_constructor_ref(&pod_ref)
    }

    /// The generation a grant must carry to be live for this grantor, which is zero until the
    /// grantor's allowance object exists.
    fun current_generation(grantor: address): u64 acquires Registry, Allowances {
        if (!exists<Registry>(@supra_framework)) {
            return 0
        };
        let allowances_addr = allowances_address(grantor);
        if (!exists<Allowances>(allowances_addr)) {
            0
        } else {
            borrow_global<Allowances>(allowances_addr).generation
        }
    }

    /// Require that `initialize` has run.
    fun assert_initialized() {
        assert!(
            exists<Registry>(@supra_framework),
            error::not_found(EMODULE_NOT_INITIALIZED)
        );
    }

    /// The address of the object every grantor's allowance object is derived from.
    fun allowances_pod(): address acquires Registry {
        assert_initialized();
        borrow_global<Registry>(@supra_framework).allowances_pod
    }

    /// The address of the object every asset's control object is derived from.
    fun controls_pod(): address acquires Registry {
        assert_initialized();
        borrow_global<Registry>(@supra_framework).controls_pod
    }

    /// The address of the object holding `grantor`'s grants.
    fun allowances_address(grantor: address): address acquires Registry {
        object::create_user_derived_object_address(grantor, allowances_pod())
    }

    /// The address of the object holding the issuer setting for the asset at `metadata_addr`.
    fun control_address(metadata_addr: address): address acquires Registry {
        object::create_user_derived_object_address(metadata_addr, controls_pod())
    }

    /// The signer of the object `source` derives from `pod`, creating that object first.
    fun derived_object_signer(pod: address, source: address): signer acquires DeriveRefPod {
        let derive_ref = &borrow_global<DeriveRefPod>(pod).derive_ref;
        let constructor_ref = object::create_user_derived_object(source, derive_ref);
        object::disable_ungated_transfer_at_creation(&constructor_ref);
        object::generate_signer(&constructor_ref)
    }

    /// Create `grantor`'s allowance object when it is not there yet, and return its address.
    fun ensure_allowances(grantor: address): address acquires Registry, DeriveRefPod {
        let allowances_addr = allowances_address(grantor);
        if (!exists<Allowances>(allowances_addr)) {
            let object_signer = derived_object_signer(allowances_pod(), grantor);
            move_to(&object_signer, Allowances {
                generation: 0,
                grants: table::new<GrantKey, Grant>(),
                used_nonces: table::new<u64, u128>(),
                min_nonce: 0,
            });
        };
        allowances_addr
    }

    /// Require that a scope is one this module defines.
    fun assert_scope_is_valid(scope: u8) {
        assert!(
            scope == SCOPE_PRIMARY_STORE || scope == SCOPE_ANY_OWNED_STORE,
            error::invalid_argument(EINVALID_SCOPE)
        );
    }

    /// Require that an expiry is in the future and within `MAX_EXPIRY_HORIZON_SECS`.
    fun assert_expiry_is_valid(expiry_secs: u64) {
        let now = timestamp::now_seconds();
        assert!(expiry_secs > now, error::invalid_argument(EINVALID_EXPIRY));
        assert!(
            expiry_secs - now <= MAX_EXPIRY_HORIZON_SECS,
            error::invalid_argument(EEXPIRY_TOO_FAR)
        );
    }

    /// The remaining amount, expiry and scope of a live grant, or `(0, 0, SCOPE_PRIMARY_STORE)`
    /// when it is absent, expired or from an older generation.
    fun live_grant(grantor: address, key: GrantKey): (u64, u64, u8) acquires Registry, Allowances {
        if (!exists<Registry>(@supra_framework)) {
            return (0, 0, SCOPE_PRIMARY_STORE)
        };
        let allowances_addr = allowances_address(grantor);
        if (!exists<Allowances>(allowances_addr)) {
            return (0, 0, SCOPE_PRIMARY_STORE)
        };
        let allowances = borrow_global<Allowances>(allowances_addr);
        if (!table::contains(&allowances.grants, key)) {
            return (0, 0, SCOPE_PRIMARY_STORE)
        };
        let generation = allowances.generation;
        let now = timestamp::now_seconds();
        let grant = table::borrow(&allowances.grants, key);
        if (grant.generation != generation || grant.expiry_secs <= now || grant.remaining == 0) {
            return (0, 0, SCOPE_PRIMARY_STORE)
        };
        (grant.remaining, grant.expiry_secs, grant.scope)
    }

    /// Write a grant into the grantor's current generation, removing it when `remaining` is zero.
    fun write_grant(
        grantor: address,
        key: GrantKey,
        remaining: u64,
        expiry_secs: u64,
        scope: u8,
    ) acquires Registry, Allowances {
        let allowances_addr = allowances_address(grantor);
        let allowances = borrow_global_mut<Allowances>(allowances_addr);
        let generation = allowances.generation;
        if (remaining == 0) {
            if (table::contains(&allowances.grants, key)) {
                table::remove(&mut allowances.grants, key);
            };
            expiry_secs = 0;
        } else if (table::contains(&allowances.grants, key)) {
            let grant = table::borrow_mut(&mut allowances.grants, key);
            grant.remaining = remaining;
            grant.expiry_secs = expiry_secs;
            grant.generation = generation;
            grant.scope = scope;
        } else {
            table::add(
                &mut allowances.grants,
                key,
                Grant { remaining, expiry_secs, generation, scope },
            );
        };
        event::emit(GrantChanged {
            grantor,
            spender: key.spender,
            metadata: key.metadata,
            remaining,
            expiry_secs,
            generation,
            scope,
        });
    }

    /// Require that `nonce` is at or above the nonce floor on this allowance object.
    fun assert_nonce_is_admissible(allowances_addr: address, nonce: u64) acquires Allowances {
        assert!(
            nonce >= borrow_global<Allowances>(allowances_addr).min_nonce,
            error::invalid_argument(ENONCE_BELOW_FLOOR)
        );
    }

    /// The index of the bucket recording `nonce`.
    fun nonce_bucket(nonce: u64): u64 {
        nonce >> BUCKET_SHIFT
    }

    /// The bit within its bucket that records `nonce`.
    fun nonce_bit(nonce: u64): u128 {
        1u128 << (((nonce & BUCKET_BIT_MASK) as u8))
    }

    /// Whether `nonce` is recorded in this grantor's bitmap.
    fun is_nonce_recorded(allowances: &Allowances, nonce: u64): bool {
        let bucket = nonce_bucket(nonce);
        if (!table::contains(&allowances.used_nonces, bucket)) {
            false
        } else {
            *table::borrow(&allowances.used_nonces, bucket) & nonce_bit(nonce) != 0
        }
    }

    /// Record `nonce` on this allowance object, aborting when it is already recorded, and emit the
    /// record of it that off-chain readers follow.
    fun consume_nonce(
        allowances_addr: address,
        grantor: address,
        nonce: u64,
        installed_grant: bool,
    ) acquires Allowances {
        let allowances = borrow_global_mut<Allowances>(allowances_addr);
        assert!(
            !is_nonce_recorded(allowances, nonce),
            error::invalid_argument(ENONCE_ALREADY_USED)
        );
        let bucket = nonce_bucket(nonce);
        let bit = nonce_bit(nonce);
        if (table::contains(&allowances.used_nonces, bucket)) {
            let bits = table::borrow_mut(&mut allowances.used_nonces, bucket);
            *bits = *bits | bit;
        } else {
            table::add(&mut allowances.used_nonces, bucket, bit);
        };
        event::emit(NonceConsumed { grantor, nonce, installed_grant });
    }

    /// Whether delegated spending of the asset at this metadata address is blocked.
    fun allowances_disabled_at(
        metadata_addr: address,
    ): bool acquires Registry, AllowanceControl {
        if (!exists<Registry>(@supra_framework)) {
            return false
        };
        let control_addr = control_address(metadata_addr);
        exists<AllowanceControl>(control_addr)
            && borrow_global<AllowanceControl>(control_addr).disabled
    }

    /// Set one asset's issuer setting, creating its control object when it is not there yet.
    fun set_control(
        metadata_addr: address,
        disabled: bool,
    ) acquires Registry, DeriveRefPod, AllowanceControl {
        let control_addr = control_address(metadata_addr);
        if (!exists<AllowanceControl>(control_addr)) {
            if (!disabled) {
                // Delegated spending is permitted unless an asset says otherwise, so the default
                // needs no object to record it.
                return
            };
            let object_signer = derived_object_signer(controls_pod(), metadata_addr);
            move_to(&object_signer, AllowanceControl { disabled });
        } else {
            borrow_global_mut<AllowanceControl>(control_addr).disabled = disabled;
        };
        event::emit(AllowancesDisabledChanged { metadata: metadata_addr, disabled });
    }

    /// Withdraw `amount` from `store` through the delegated path, and return the withdrawn asset,
    /// what the store was debited and whether the asset registers a withdraw hook. The debit is the
    /// larger of `amount` and the fall in the store's balance, so it includes a fee the withdraw
    /// hook takes out of the store. A store whose asset registers no withdraw hook is debited
    /// exactly `amount`, so the balance is read only when there is a hook: reading it resolves the
    /// aggregator of a store holding a `ConcurrentFungibleBalance`.
    fun withdraw_measuring_debit<T: key>(
        store: Object<T>,
        amount: u64,
    ): (FungibleAsset, u64, bool) {
        let withdraw_hook = fungible_asset::withdraw_dispatch_function(store);
        let has_withdraw_hook = option::is_some(&withdraw_hook);
        let before = if (has_withdraw_hook) { fungible_asset::balance(store) } else { 0 };
        let fa = dispatchable_fungible_asset::withdraw_delegated(store, amount);
        let debited = if (has_withdraw_hook) {
            let after = fungible_asset::balance(store);
            let fall = if (before > after) { before - after } else { 0 };
            if (fall > amount) { fall } else { amount }
        } else {
            amount
        };
        (fa, debited, has_withdraw_hook)
    }

    /// The abort code, including its error category, of the first of `settle_upto_internal`'s
    /// admission rules these arguments fail, or 0 when they pass every one. `settle_upto_internal`
    /// and `verify_upto` both apply the rules through this function, so the two cannot differ in
    /// which rules they check or in what order. It does not abort.
    fun upto_rejection(
        facilitator: address,
        payer: address,
        pay_to: address,
        metadata: Object<Metadata>,
        max_amount: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: &vector<u8>,
        generation: u64,
        account_scheme: u8,
        public_key: vector<u8>,
        signature: vector<u8>,
        amount: u64,
    ): u64 acquires Registry, Allowances, AllowanceControl {
        if (!exists<Registry>(@supra_framework)) {
            return error::not_found(EMODULE_NOT_INITIALIZED)
        };
        if (vector::length(nonce) != UPTO_NONCE_LENGTH) {
            return error::invalid_argument(EUPTO_INVALID_NONCE)
        };
        let now = timestamp::now_seconds();
        if (valid_after > now) {
            return error::invalid_state(EUPTO_NOT_YET_VALID)
        };
        if (now >= valid_before) {
            return error::invalid_state(EUPTO_EXPIRED)
        };
        // `valid_after <= now < valid_before` holds here, so the subtraction cannot underflow.
        if (valid_before - valid_after > MAX_UPTO_SPAN_SECS) {
            return error::invalid_argument(EUPTO_SPAN_TOO_LONG)
        };
        if (amount > max_amount) {
            return error::invalid_argument(EUPTO_AMOUNT_EXCEEDS_MAX)
        };
        if (generation != current_generation(payer)) {
            return error::invalid_state(EGENERATION_MISMATCH)
        };
        if (upto_nonce_recorded(payer, nonce)) {
            return error::invalid_argument(EUPTO_NONCE_USED)
        };
        let metadata_addr = object::object_address(&metadata);
        let payload = UptoAuthorization {
            chain_id: chain_id::get(),
            payer,
            facilitator,
            pay_to,
            metadata: metadata_addr,
            max_amount,
            valid_after,
            valid_before,
            nonce: *nonce,
            generation,
        };
        if (!is_signature_valid(payer, account_scheme, public_key, signature, payload)) {
            return error::invalid_argument(EINVALID_SIGNATURE)
        };
        if (allowances_disabled_at(metadata_addr)) {
            return error::permission_denied(EALLOWANCES_DISABLED)
        };
        if (amount > 0 && !primary_fungible_store::primary_store_exists(payer, metadata)) {
            return error::not_found(ESOURCE_STORE_MISSING)
        };
        0
    }

    /// The code `verify_upto` reports for a store condition under which `settle_upto_internal`
    /// aborts inside `fungible_asset`, checked in the order the withdrawal and deposit reach them,
    /// or 0 when there is none. The payer's primary store must exist.
    fun upto_store_rejection(
        payer: address,
        pay_to: address,
        metadata: Object<Metadata>,
        amount: u64,
    ): u64 {
        if (primary_fungible_store::is_frozen(payer, metadata)) {
            return error::permission_denied(EUPTO_STORE_FROZEN)
        };
        if (primary_fungible_store::balance(payer, metadata) < amount) {
            return error::invalid_argument(EUPTO_INSUFFICIENT_BALANCE)
        };
        if (primary_fungible_store::is_frozen(pay_to, metadata)) {
            return error::permission_denied(EUPTO_STORE_FROZEN)
        };
        0
    }

    /// Whether the payer has a record of `nonce`. `initialize` must have run.
    fun upto_nonce_recorded(payer: address, nonce: &vector<u8>): bool acquires Registry {
        table::contains(
            &borrow_global<Registry>(@supra_framework).upto_nonces,
            UptoNonceKey { payer, nonce: *nonce },
        )
    }

    /// Record `nonce` against the payer in `state` until `valid_before`. The payer must have no
    /// record of it.
    fun record_upto_nonce(
        payer: address,
        nonce: vector<u8>,
        valid_before: u64,
        state: u8,
    ) acquires Registry {
        table::add(
            &mut borrow_global_mut<Registry>(@supra_framework).upto_nonces,
            UptoNonceKey { payer, nonce },
            UptoNonceRecord { valid_before, state },
        );
    }

    /// The authentication key a signature from `addr` is checked against: the key in `addr`'s
    /// `Account` resource when it has one, and otherwise the BCS bytes of `addr`. The second is the
    /// rule `account::get_authentication_key` applies on the aptos-core v1.34 framework when
    /// `default_account_resource` is enabled.
    fun authentication_key(addr: address): vector<u8> {
        if (account::exists_at(addr)) {
            account::get_authentication_key(addr)
        } else {
            bcs::to_bytes(&addr)
        }
    }

    /// Whether `signature` is a signature in `account_scheme` by `public_key` over
    /// `ed25519::SignedMessage` of `message`, and `public_key` derives `signer_addr`'s
    /// authentication key. `account_scheme` is `ED25519_SCHEME` or `MULTI_ED25519_SCHEME`; any
    /// other value gives false. The lengths of the key and signature are checked before either is
    /// parsed, so malformed bytes give false rather than an abort.
    fun is_signature_valid<T: drop>(
        signer_addr: address,
        account_scheme: u8,
        public_key: vector<u8>,
        signature: vector<u8>,
        message: T,
    ): bool {
        let auth_key = authentication_key(signer_addr);
        if (account_scheme == ED25519_SCHEME) {
            if (vector::length(&public_key) != ED25519_PUBLIC_KEY_LENGTH
                || vector::length(&signature) != ED25519_SIGNATURE_LENGTH) {
                return false
            };
            let pk = ed25519::new_unvalidated_public_key_from_bytes(public_key);
            if (ed25519::unvalidated_public_key_to_authentication_key(&pk) != auth_key) {
                return false
            };
            let sig = ed25519::new_signature_from_bytes(signature);
            ed25519::signature_verify_strict_t(&sig, &pk, message)
        } else if (account_scheme == MULTI_ED25519_SCHEME) {
            let pk_length = vector::length(&public_key);
            if (pk_length / ED25519_PUBLIC_KEY_LENGTH > MULTI_ED25519_MAX_KEYS
                || pk_length % ED25519_PUBLIC_KEY_LENGTH != MULTI_ED25519_THRESHOLD_LENGTH
                || vector::length(&signature) % ED25519_SIGNATURE_LENGTH
                    != MULTI_ED25519_BITMAP_LENGTH) {
                return false
            };
            let pk = multi_ed25519::new_unvalidated_public_key_from_bytes(public_key);
            if (multi_ed25519::unvalidated_public_key_to_authentication_key(&pk) != auth_key) {
                return false
            };
            let sig = multi_ed25519::new_signature_from_bytes(signature);
            multi_ed25519::signature_verify_strict_t(&sig, &pk, message)
        } else {
            false
        }
    }

    #[test_only]
    use std::hash;
    #[test_only]
    use aptos_std::from_bcs;
    #[test_only]
    use supra_framework::fungible_asset::{TestToken, MintRef, TransferRef};

    #[test_only]
    /// The block time every test starts at.
    const START_TIME_SECS: u64 = 1000000;

    #[test_only]
    const DAY_SECS: u64 = 86400;

    #[test_only]
    fun setup_without_registry(
        supra_framework: &signer,
        creator: &signer,
    ): (ConstructorRef, Object<Metadata>, MintRef, TransferRef) {
        timestamp::set_time_has_started_for_testing(supra_framework);
        timestamp::update_global_time_for_test_secs(START_TIME_SECS);
        chain_id::initialize_for_test(supra_framework, 4);
        let (creator_ref, token_object) = fungible_asset::create_test_token(creator);
        let (mint_ref, transfer_ref, _) =
            primary_fungible_store::init_test_metadata_with_primary_store_enabled(&creator_ref);
        (creator_ref, object::convert<TestToken, Metadata>(token_object), mint_ref, transfer_ref)
    }

    #[test_only]
    fun setup(
        supra_framework: &signer,
        creator: &signer,
    ): (ConstructorRef, Object<Metadata>, MintRef, TransferRef) {
        let (creator_ref, metadata, mint_ref, transfer_ref) =
            setup_without_registry(supra_framework, creator);
        initialize(supra_framework);
        (creator_ref, metadata, mint_ref, transfer_ref)
    }

    #[test_only]
    fun payload_for(
        grantor: address,
        spender: address,
        metadata: Object<Metadata>,
        expected_remaining: u64,
        amount: u64,
        expiry_secs: u64,
        nonce: u64,
        generation: u64,
        scope: u8,
        chain: u8,
    ): SignedGrant {
        SignedGrant {
            chain_id: chain,
            grantor,
            spender,
            metadata: object::object_address(&metadata),
            expected_remaining,
            amount,
            expiry_secs,
            nonce,
            generation,
            scope,
        }
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_increase_creates_and_stacks(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        let expiry = START_TIME_SECS + DAY_SECS;

        increase(alice, @0xb0b, metadata, 30, expiry, SCOPE_PRIMARY_STORE);
        let (remaining, expires_at, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 30, 1);
        assert!(expires_at == expiry, 2);

        increase(alice, @0xb0b, metadata, 20, expiry + 10, SCOPE_PRIMARY_STORE);
        let (remaining, expires_at, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 50, 3);
        assert!(expires_at == expiry + 10, 4);
        assert!(generation(alice_addr) == 0, 5);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_increase_by_zero_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        increase(alice, @0xb0b, metadata, 0, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x2000d, location = Self)]
    fun test_increase_past_the_u64_ceiling_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let expiry = START_TIME_SECS + DAY_SECS;
        increase(alice, @0xb0b, metadata, MAX_U64, expiry, SCOPE_PRIMARY_STORE);
        increase(alice, @0xb0b, metadata, 1, expiry, SCOPE_PRIMARY_STORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x6000c, location = Self)]
    fun test_a_write_before_the_registry_exists_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup_without_registry(supra_framework, creator);
        increase(alice, @0xb0b, metadata, 10, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_decrease_saturates_and_removes(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        let expiry = START_TIME_SECS + DAY_SECS;

        increase(alice, @0xb0b, metadata, 50, expiry, SCOPE_PRIMARY_STORE);
        decrease(alice, @0xb0b, metadata, 20);
        let (remaining, expires_at, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 30, 1);
        assert!(expires_at == expiry, 2);

        decrease(alice, @0xb0b, metadata, 100);
        let (remaining, expires_at, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 0, 3);
        assert!(expires_at == 0, 4);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_decrease_without_a_live_grant_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        decrease(alice, @0xb0b, metadata, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_replace_sets_and_removes(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        let expiry = START_TIME_SECS + DAY_SECS;

        replace(alice, @0xb0b, metadata, 0, 40, expiry, SCOPE_PRIMARY_STORE);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 40, 1);

        replace(alice, @0xb0b, metadata, 40, 10, expiry, SCOPE_PRIMARY_STORE);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 10, 2);

        replace(alice, @0xb0b, metadata, 10, 0, 0, SCOPE_PRIMARY_STORE);
        let (remaining, expires_at, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 0, 3);
        assert!(expires_at == 0, 4);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x30005, location = Self)]
    fun test_replace_with_a_stale_expectation_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let expiry = START_TIME_SECS + DAY_SECS;
        increase(alice, @0xb0b, metadata, 40, expiry, SCOPE_PRIMARY_STORE);
        replace(alice, @0xb0b, metadata, 50, 10, expiry, SCOPE_PRIMARY_STORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_revoke_removes_the_grant(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        increase(alice, @0xb0b, metadata, 40, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);
        revoke(alice, @0xb0b, metadata);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 0, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_revoke_without_a_live_grant_does_nothing(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        revoke(alice, @0xb0b, metadata);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 0, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_revoke_all_voids_grants_and_a_new_grant_is_live(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        let expiry = START_TIME_SECS + DAY_SECS;

        increase(alice, @0xb0b, metadata, 50, expiry, SCOPE_PRIMARY_STORE);
        revoke_all(alice);
        assert!(generation(alice_addr) == 1, 1);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 0, 2);

        increase(alice, @0xb0b, metadata, 20, expiry, SCOPE_PRIMARY_STORE);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 20, 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x30009, location = Self)]
    fun test_remove_dead_refuses_a_live_grant(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        increase(alice, @0xb0b, metadata, 50, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);
        remove_dead(signer::address_of(alice), @0xb0b, metadata);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_remove_dead_reclaims_an_expired_grant(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        increase(alice, @0xb0b, metadata, 50, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);
        timestamp::update_global_time_for_test_secs(START_TIME_SECS + DAY_SECS + 1);
        remove_dead(alice_addr, @0xb0b, metadata);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 0, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_remove_dead_reclaims_an_old_generation_grant(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        increase(alice, @0xb0b, metadata, 50, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);
        revoke_all(alice);
        remove_dead(alice_addr, @0xb0b, metadata);
        let (remaining, _, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 0, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_expiry_in_the_past_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        increase(alice, @0xb0b, metadata, 10, START_TIME_SECS - 1, SCOPE_PRIMARY_STORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_expiry_at_the_current_second_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        increase(alice, @0xb0b, metadata, 10, START_TIME_SECS, SCOPE_PRIMARY_STORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    fun test_expiry_at_the_horizon_is_accepted(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        increase(
            alice,
            @0xb0b,
            metadata,
            10,
            START_TIME_SECS + MAX_EXPIRY_HORIZON_SECS,
            SCOPE_PRIMARY_STORE,
        );
        let (remaining, expires_at, _) = allowance(alice_addr, @0xb0b, metadata);
        assert!(remaining == 10, 1);
        assert!(expires_at == START_TIME_SECS + MAX_EXPIRY_HORIZON_SECS, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x10004, location = Self)]
    fun test_expiry_beyond_the_horizon_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        increase(
            alice,
            @0xb0b,
            metadata,
            10,
            START_TIME_SECS + MAX_EXPIRY_HORIZON_SECS + 1,
            SCOPE_PRIMARY_STORE,
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    fun test_transfer_from_moves_between_primary_stores(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        let bob_addr = signer::address_of(bob);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(alice, bob_addr, metadata, 60, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);

        transfer_from(bob, alice_addr, metadata, @0xdd, 25);

        assert!(primary_fungible_store::balance(alice_addr, metadata) == 75, 1);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 25, 2);
        let (remaining, _, _) = allowance(alice_addr, bob_addr, metadata);
        assert!(remaining == 35, 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    fun test_transfer_from_removes_a_fully_spent_grant(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        let bob_addr = signer::address_of(bob);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(alice, bob_addr, metadata, 30, START_TIME_SECS + DAY_SECS, SCOPE_PRIMARY_STORE);

        transfer_from(bob, alice_addr, metadata, @0xdd, 30);

        let (remaining, expires_at, _) = allowance(alice_addr, bob_addr, metadata);
        assert!(remaining == 0, 1);
        assert!(expires_at == 0, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_transfer_from_beyond_the_allowance_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            30,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        transfer_from(bob, alice_addr, metadata, @0xdd, 31);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_transfer_from_without_a_grant_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        transfer_from(bob, alice_addr, metadata, @0xdd, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x60008, location = Self)]
    fun test_transfer_from_without_a_source_store_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            30,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_transfer_from_after_expiry_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );

        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
        timestamp::update_global_time_for_test_secs(START_TIME_SECS + DAY_SECS + 1);
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_transfer_from_after_revoke_all_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        revoke_all(alice);
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_transfer_from_of_zero_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        transfer_from(bob, alice_addr, metadata, @0xdd, 0);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50003, location = supra_framework::fungible_asset)]
    fun test_transfer_from_a_frozen_store_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, transfer_ref) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        primary_fungible_store::set_frozen_flag(&transfer_ref, alice_addr, true);
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50003, location = supra_framework::fungible_asset)]
    fun test_transfer_from_to_a_frozen_store_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, transfer_ref) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        primary_fungible_store::set_frozen_flag(&transfer_ref, @0xdd, true);
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50007, location = Self)]
    fun test_transfer_from_a_disabled_asset_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (creator_ref, metadata, mint_ref, _) = setup(supra_framework, creator);
        disable_allowances(&creator_ref);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50007, location = Self)]
    fun test_the_owner_of_an_existing_asset_can_disable_allowances(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        // The asset is created without any call into this module, as a live asset would have been.
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 10, 1);

        set_allowances_disabled(creator, metadata, true);
        assert!(allowances_disabled(metadata), 2);
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    fun test_issuer_can_unblock_and_reblock_allowances(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (creator_ref, metadata, mint_ref, _) = setup(supra_framework, creator);
        disable_allowances(&creator_ref);
        assert!(allowances_disabled(metadata), 1);

        set_allowances_disabled(creator, metadata, false);
        assert!(!allowances_disabled(metadata), 2);

        let alice_addr = signer::address_of(alice);
        primary_fungible_store::mint(&mint_ref, alice_addr, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        transfer_from(bob, alice_addr, metadata, @0xdd, 10);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 10, 3);

        set_allowances_disabled(creator, metadata, true);
        assert!(allowances_disabled(metadata), 4);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_one_address_can_be_both_a_grantor_and_a_controlled_asset(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (creator_ref, metadata, _, _) = setup(supra_framework, creator);
        let metadata_addr = object::object_address(&metadata);
        // The metadata object grants an allowance of its own asset, so the same address is the
        // source of both a grantor's allowance object and an asset's control object.
        let metadata_signer = object::generate_signer(&creator_ref);

        increase(
            &metadata_signer,
            @0xb0b,
            metadata,
            30,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );
        set_allowances_disabled(creator, metadata, true);

        let (remaining, _, _) = allowance(metadata_addr, @0xb0b, metadata);
        assert!(remaining == 30, 1);
        assert!(allowances_disabled(metadata), 2);
        assert!(
            allowances_object_address(metadata_addr) != control_object_address(metadata),
            3,
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x5000b, location = Self)]
    fun test_only_the_metadata_owner_may_toggle_allowances(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, AllowanceControl {
        let (creator_ref, metadata, _, _) = setup(supra_framework, creator);
        disable_allowances(&creator_ref);
        set_allowances_disabled(alice, metadata, false);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    fun test_transfer_from_store_moves_between_secondary_stores(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_store = fungible_asset::create_test_store(alice, metadata);
        let bob_store = fungible_asset::create_test_store(bob, metadata);
        fungible_asset::mint_to(&mint_ref, alice_store, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_ANY_OWNED_STORE,
        );

        transfer_from_store(bob, alice_store, bob_store, 40);

        assert!(fungible_asset::balance(alice_store) == 60, 1);
        assert!(fungible_asset::balance(bob_store) == 40, 2);
        let (
            remaining,
            _,
            _) = allowance(signer::address_of(alice),
            signer::address_of(bob),
            metadata,
        );
        assert!(remaining == 20, 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_transfer_from_store_consults_the_stores_direct_owner(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        account::create_account_for_test(signer::address_of(alice));
        let holder_ref = object::create_object_from_account(alice);
        let holder_signer = object::generate_signer(&holder_ref);
        let store_ref = object::create_object_from_object(&holder_signer);
        let held_store = fungible_asset::create_store(&store_ref, metadata);
        fungible_asset::mint_to(&mint_ref, held_store, 100);
        let bob_store = fungible_asset::create_test_store(bob, metadata);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_ANY_OWNED_STORE,
        );

        transfer_from_store(bob, held_store, bob_store, 10);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_apply_signed_grant(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );

        let (remaining, expires_at, _) = allowance(grantor_addr, @0xb0b, metadata);
        assert!(remaining == 40, 1);
        assert!(expires_at == expiry, 2);
        assert!(is_nonce_used(grantor_addr, 7), 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_signed_grant_installs_and_spends_for_an_untouched_grantor(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        primary_fungible_store::mint(&mint_ref, grantor_addr, 100);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
        transfer_from(bob, grantor_addr, metadata, @0xdd, 25);

        assert!(primary_fungible_store::balance(grantor_addr, metadata) == 75, 1);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 25, 2);
        let (remaining, _, _) = allowance(grantor_addr, @0xb0b, metadata);
        assert!(remaining == 15, 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_signed_grant_for_another_chain_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            1,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_signed_grant_redirected_to_another_spender_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        apply_signed_grant(
            grantor_addr, @0xdd, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_signed_grant_submitted_with_a_larger_amount_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 50, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_signed_grant_nonce_is_consumed_once(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        let signature_bytes = ed25519::signature_to_bytes(&signature);

        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            signature_bytes,
        );
        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            signature_bytes,
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_signed_grant_is_checked_against_the_current_authentication_key(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let (other_sk, other_pk) = ed25519::generate_keys();
        let other_pk_bytes = ed25519::validated_public_key_to_bytes(&other_pk);
        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&other_sk, payload);

        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            other_pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x30005, location = Self)]
    fun test_signed_grant_with_a_stale_expectation_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let first = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let first_sig = ed25519::sign_struct(&sk, first);
        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&first_sig),
        );

        let second = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            8,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let second_sig = ed25519::sign_struct(&sk, second);
        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 8, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&second_sig),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x3000e, location = Self)]
    fun test_a_signature_authorised_before_revoke_all_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        revoke_all(&grantor);

        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_a_signature_carrying_the_new_generation_is_accepted(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        revoke_all(&grantor);
        assert!(generation(grantor_addr) == 1, 1);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            1,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 1, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );

        let (remaining, _, _) = allowance(grantor_addr, @0xb0b, metadata);
        assert!(remaining == 40, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_a_signed_grant_from_an_address_without_an_account_is_applied(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        // The address is the key's derived authentication key, holds the asset and has no
        // `Account` resource.
        let grantor_addr =
            from_bcs::to_address(ed25519::validated_public_key_to_authentication_key(&pk));
        primary_fungible_store::mint(&mint_ref, grantor_addr, 100);
        assert!(!account::exists_at(grantor_addr), 1);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
        transfer_from(bob, grantor_addr, metadata, @0xdd, 25);

        assert!(primary_fungible_store::balance(@0xdd, metadata) == 25, 2);
        let (remaining, _, _) = allowance(grantor_addr, @0xb0b, metadata);
        assert!(remaining == 15, 3);
        assert!(!account::exists_at(grantor_addr), 4);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_a_signed_grant_for_an_address_without_an_account_needs_its_derived_key(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        // The address holds the asset, has no `Account` resource and is not derived from the key.
        primary_fungible_store::mint(&mint_ref, @0xdd, 10);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            @0xdd,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        apply_signed_grant(
            @0xdd, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_the_root_owner_of_a_nested_metadata_object_may_toggle_allowances(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, AllowanceControl {
        let (_, _, _, _) = setup(supra_framework, creator);
        let holder_ref = object::create_object_from_account(creator);
        let holder_signer = object::generate_signer(&holder_ref);
        let token_ref = object::create_named_object(&holder_signer, b"NESTED");
        primary_fungible_store::init_test_metadata_with_primary_store_enabled(&token_ref);
        let nested = object::address_to_object<Metadata>(
            object::address_from_constructor_ref(&token_ref)
        );

        // The default needs no object to record it.
        set_allowances_disabled(creator, nested, false);
        assert!(!allowances_disabled(nested), 1);

        set_allowances_disabled(creator, nested, true);
        assert!(allowances_disabled(nested), 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x1000f, location = Self)]
    fun test_disable_allowances_on_a_plain_object_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, AllowanceControl {
        let (_, _, _, _) = setup(supra_framework, creator);
        let plain_ref = object::create_named_object(creator, b"PLAIN");
        disable_allowances(&plain_ref);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50012, location = Self)]
    fun test_a_primary_scope_grant_is_rejected_on_a_secondary_store(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let alice_store = fungible_asset::create_test_store(alice, metadata);
        let bob_store = fungible_asset::create_test_store(bob, metadata);
        fungible_asset::mint_to(&mint_ref, alice_store, 100);
        increase(
            alice,
            signer::address_of(bob),
            metadata,
            60,
            START_TIME_SECS + DAY_SECS,
            SCOPE_PRIMARY_STORE,
        );

        transfer_from_store(bob, alice_store, bob_store, 40);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x30011, location = Self)]
    fun test_increase_with_a_different_scope_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let bob_addr = signer::address_of(bob);
        let expiry = START_TIME_SECS + DAY_SECS;
        increase(alice, bob_addr, metadata, 30, expiry, SCOPE_PRIMARY_STORE);
        increase(alice, bob_addr, metadata, 10, expiry, SCOPE_ANY_OWNED_STORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce, bob = @0xb0b)]
    fun test_replace_changes_the_scope(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let alice_addr = signer::address_of(alice);
        let bob_addr = signer::address_of(bob);
        let expiry = START_TIME_SECS + DAY_SECS;
        increase(alice, bob_addr, metadata, 30, expiry, SCOPE_PRIMARY_STORE);
        let (_, _, scope) = allowance(alice_addr, bob_addr, metadata);
        assert!(scope == SCOPE_PRIMARY_STORE, 1);

        replace(alice, bob_addr, metadata, 30, 30, expiry, SCOPE_ANY_OWNED_STORE);
        let (remaining, _, scope) = allowance(alice_addr, bob_addr, metadata);
        assert!(remaining == 30, 2);
        assert!(scope == SCOPE_ANY_OWNED_STORE, 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x10010, location = Self)]
    fun test_an_undefined_scope_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        increase(alice, @0xb0b, metadata, 30, START_TIME_SECS + DAY_SECS, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_a_signed_grant_carries_its_scope(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        let grantor_store = fungible_asset::create_test_store(&grantor, metadata);
        let bob_store = fungible_asset::create_test_store(bob, metadata);
        fungible_asset::mint_to(&mint_ref, grantor_store, 100);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_ANY_OWNED_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_ANY_OWNED_STORE,
            0,
            pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );

        transfer_from_store(bob, grantor_store, bob_store, 25);
        assert!(fungible_asset::balance(bob_store) == 25, 1);
        let (remaining, _, scope) = allowance(grantor_addr, @0xb0b, metadata);
        assert!(remaining == 15, 2);
        assert!(scope == SCOPE_ANY_OWNED_STORE, 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_a_submitter_cannot_widen_the_signed_scope(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_ANY_OWNED_STORE,
            0,
            pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_a_cancelled_nonce_makes_its_signature_inadmissible(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        let expiry = START_TIME_SECS + DAY_SECS;
        increase(&grantor, @0xdd, metadata, 5, expiry, SCOPE_PRIMARY_STORE);

        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        cancel_nonce(&grantor, 7);

        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_cancel_nonce_works_without_a_prior_on_chain_write(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);

        // The grantor has never written on chain, so this creates its allowance object.
        cancel_nonce(&grantor, 7);
        assert!(is_nonce_used(grantor_addr, 7), 1);

        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_cancelling_an_already_recorded_nonce_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        cancel_nonce(&grantor, 7);
        cancel_nonce(&grantor, 7);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10013, location = Self)]
    fun test_a_signature_below_the_nonce_floor_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        invalidate_nonces_below(&grantor, 10);
        assert!(min_nonce(grantor_addr) == 10, 1);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10013, location = Self)]
    fun test_raising_the_floor_kills_an_outstanding_signature(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        assert!(!is_nonce_used(grantor_addr, 7), 1);

        invalidate_nonces_below(&grantor, 8);
        assert!(is_nonce_used(grantor_addr, 7), 2);

        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10014, location = Self)]
    fun test_the_nonce_floor_must_advance(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        invalidate_nonces_below(&grantor, 5);
        invalidate_nonces_below(&grantor, 5);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x30015, location = Self)]
    fun test_reclaiming_a_bucket_the_floor_sits_inside_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        cancel_nonce(&grantor, 7);
        invalidate_nonces_below(&grantor, 8);
        remove_used_nonce_bucket(grantor_addr, 0);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_one_bucket_records_a_whole_block_of_nonces(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        assert!(nonce_bucket_bits(grantor_addr, 0) == 0, 1);
        cancel_nonce(&grantor, 3);
        cancel_nonce(&grantor, 9);
        assert!(nonce_bucket_bits(grantor_addr, 0) == (1u128 << 3) + (1u128 << 9), 2);
        assert!(nonce_bucket_bits(grantor_addr, 1) == 0, 3);
        assert!(is_nonce_used(grantor_addr, 3), 4);
        assert!(is_nonce_used(grantor_addr, 9), 5);
        assert!(!is_nonce_used(grantor_addr, 4), 6);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_a_block_boundary_splits_two_buckets(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        cancel_nonce(&grantor, 127);
        cancel_nonce(&grantor, 128);
        assert!(nonce_bucket_bits(grantor_addr, 0) == 1u128 << 127, 1);
        assert!(nonce_bucket_bits(grantor_addr, 1) == 1u128, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_a_high_nonce_lands_in_its_own_bucket(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        cancel_nonce(&grantor, 1000000);
        assert!(nonce_bucket_bits(grantor_addr, 7812) == 1u128 << 64, 1);
        assert!(is_nonce_used(grantor_addr, 1000000), 2);
        assert!(!is_nonce_used(grantor_addr, 999999), 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_reclaimable_bucket_limit_follows_the_floor(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        assert!(reclaimable_bucket_limit(grantor_addr) == 0, 1);
        invalidate_nonces_below(&grantor, 300);
        assert!(reclaimable_bucket_limit(grantor_addr) == 2, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_a_cancelled_nonce_is_reclaimable_once_the_floor_passes_its_block(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        cancel_nonce(&grantor, 7);
        invalidate_nonces_below(&grantor, NONCES_PER_BUCKET);
        assert!(reclaimable_bucket_limit(grantor_addr) == 1, 1);
        remove_used_nonce_bucket(grantor_addr, 0);
        assert!(nonce_bucket_bits(grantor_addr, 0) == 0, 2);
        // The floor keeps the nonce unusable with no entry left to pay for.
        assert!(is_nonce_used(grantor_addr, 7), 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_a_nonce_below_the_floor_reads_used_without_an_entry(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, _, _, _) = setup(supra_framework, creator);
        let (_, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);
        assert!(!is_nonce_used(grantor_addr, 3), 1);
        invalidate_nonces_below(&grantor, 4);
        assert!(is_nonce_used(grantor_addr, 3), 2);
        assert!(!is_nonce_used(grantor_addr, 4), 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10013, location = Self)]
    fun test_a_reclaimed_nonce_stays_inadmissible(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let payload = payload_for(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            4,
        );
        let signature = ed25519::sign_struct(&sk, payload);
        let signature_bytes = ed25519::signature_to_bytes(&signature);
        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            signature_bytes,
        );

        invalidate_nonces_below(&grantor, NONCES_PER_BUCKET);
        remove_used_nonce_bucket(grantor_addr, 0);
        assert!(nonce_bucket_bits(grantor_addr, 0) == 0, 1);

        // The floor, not the table entry, is what keeps the signature out.
        apply_signed_grant(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
            0,
            pk_bytes,
            signature_bytes,
        );
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_grant_signing_message_matches_the_verified_payload(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry, DeriveRefPod, Allowances {
        let (_, metadata, _, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        let pk_bytes = ed25519::validated_public_key_to_bytes(&pk);
        let grantor = account::create_account_from_ed25519_public_key(pk_bytes);
        let grantor_addr = signer::address_of(&grantor);

        let expiry = START_TIME_SECS + DAY_SECS;
        let message = grant_signing_message(
            grantor_addr,
            @0xb0b,
            metadata,
            0,
            40,
            expiry,
            7,
            0,
            SCOPE_PRIMARY_STORE,
        );
        let signature = ed25519::sign_arbitrary_bytes(&sk, message);

        apply_signed_grant(
            grantor_addr, @0xb0b, metadata, 0, 40, expiry, 7, 0, SCOPE_PRIMARY_STORE, 0, pk_bytes,
            ed25519::signature_to_bytes(&signature),
        );
        let (remaining, _, _) = allowance(grantor_addr, @0xb0b, metadata);
        assert!(remaining == 40, 1);
    }

    #[test_only]
    /// The `valid_before` of the authorization most settlement tests sign: 600 seconds after the
    /// start time.
    const UPTO_VALID_BEFORE: u64 = 1000600;

    #[test_only]
    /// The arguments of one `settle_upto` call other than the facilitator.
    struct UptoCall has copy, drop {
        payer: address,
        pay_to: address,
        metadata: Object<Metadata>,
        max_amount: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: vector<u8>,
        generation: u64,
        account_scheme: u8,
        public_key: vector<u8>,
        signature: vector<u8>,
        amount: u64,
    }

    #[test_only]
    /// A settlement nonce of `UPTO_NONCE_LENGTH` bytes, distinct for each `seed`.
    fun upto_nonce(seed: u8): vector<u8> {
        hash::sha3_256(vector[seed])
    }

    #[test_only]
    /// The payload `call` carries when `facilitator` settles it on chain `chain`.
    fun upto_payload_for(facilitator: address, call: &UptoCall, chain: u8): UptoAuthorization {
        UptoAuthorization {
            chain_id: chain,
            payer: call.payer,
            facilitator,
            pay_to: call.pay_to,
            metadata: object::object_address(&call.metadata),
            max_amount: call.max_amount,
            valid_after: call.valid_after,
            valid_before: call.valid_before,
            nonce: call.nonce,
            generation: call.generation,
        }
    }

    #[test_only]
    /// Sign `call` with `sk` for `facilitator` on the test chain and store the signature in it.
    fun sign_upto(sk: &ed25519::SecretKey, facilitator: address, call: &mut UptoCall) {
        let payload = upto_payload_for(facilitator, call, 4);
        call.signature = ed25519::signature_to_bytes(&ed25519::sign_struct(sk, payload));
    }

    #[test_only]
    /// A payer with an `Account` resource and `balance` in its primary store (none when zero),
    /// with its signed authorization of up to 100 to @0xdd for @0xb0b to settle, valid for 600
    /// seconds from the start time, carrying nonce seed 1 and generation 0, and settling `amount`.
    fun upto_fixture(
        mint_ref: &MintRef,
        metadata: Object<Metadata>,
        balance: u64,
        amount: u64,
    ): (UptoCall, ed25519::SecretKey) {
        let (sk, pk) = ed25519::generate_keys();
        let public_key = ed25519::validated_public_key_to_bytes(&pk);
        let payer_signer = account::create_account_from_ed25519_public_key(public_key);
        let payer = signer::address_of(&payer_signer);
        if (balance > 0) {
            primary_fungible_store::mint(mint_ref, payer, balance);
        };
        let call = UptoCall {
            payer,
            pay_to: @0xdd,
            metadata,
            max_amount: 100,
            valid_after: START_TIME_SECS,
            valid_before: UPTO_VALID_BEFORE,
            nonce: upto_nonce(1),
            generation: 0,
            account_scheme: ED25519_SCHEME,
            public_key,
            signature: vector[],
            amount,
        };
        sign_upto(&sk, @0xb0b, &mut call);
        (call, sk)
    }

    #[test_only]
    fun settle_call(
        facilitator: &signer,
        call: UptoCall,
    ): u64 acquires Registry, Allowances, AllowanceControl {
        settle_upto_internal(
            facilitator,
            call.payer,
            call.pay_to,
            call.metadata,
            call.max_amount,
            call.valid_after,
            call.valid_before,
            call.nonce,
            call.generation,
            call.account_scheme,
            call.public_key,
            call.signature,
            call.amount,
        )
    }

    #[test_only]
    fun verify_call(
        facilitator: address,
        call: UptoCall,
    ): (bool, u64) acquires Registry, Allowances, AllowanceControl {
        verify_upto(
            facilitator,
            call.payer,
            call.pay_to,
            call.metadata,
            call.max_amount,
            call.valid_after,
            call.valid_before,
            call.nonce,
            call.generation,
            call.account_scheme,
            call.public_key,
            call.signature,
            call.amount,
        )
    }

    #[test_only]
    /// Require that `verify_upto` accepts `call` from `facilitator`.
    fun assert_upto_accepted(
        facilitator: address,
        call: UptoCall,
    ) acquires Registry, Allowances, AllowanceControl {
        let (accepted, code) = verify_call(facilitator, call);
        assert!(accepted, 1000);
        assert!(code == 0, 1001);
    }

    #[test_only]
    /// Require that `verify_upto` rejects `call` from `facilitator` with `code`.
    fun assert_upto_rejected(
        facilitator: address,
        call: UptoCall,
        code: u64,
    ) acquires Registry, Allowances, AllowanceControl {
        let (accepted, reported) = verify_call(facilitator, call);
        assert!(!accepted, 1002);
        assert!(reported == code, 1003);
    }

    #[test_only]
    /// The `valid_before` stored in the payer's record of `nonce`.
    fun upto_record_valid_before(payer: address, nonce: vector<u8>): u64 acquires Registry {
        table::borrow(
            &borrow_global<Registry>(@supra_framework).upto_nonces,
            UptoNonceKey { payer, nonce },
        ).valid_before
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_settle_upto_moves_the_settled_amount_and_records_the_nonce(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        assert_upto_accepted(@0xb0b, call);

        settle_upto(
            bob,
            call.payer,
            call.pay_to,
            call.metadata,
            call.max_amount,
            call.valid_after,
            call.valid_before,
            call.nonce,
            call.generation,
            call.account_scheme,
            call.public_key,
            call.signature,
            call.amount,
        );

        assert!(primary_fungible_store::balance(call.payer, metadata) == 60, 1);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 40, 2);
        assert!(upto_nonce_state(call.payer, call.nonce) == UPTO_NONCE_SETTLED, 3);
        assert!(upto_record_valid_before(call.payer, call.nonce) == UPTO_VALID_BEFORE, 4);
        // Settlement leaves no grant behind, and does not create the payer's allowance object.
        let (remaining, _, _) = allowance(call.payer, @0xb0b, metadata);
        assert!(remaining == 0, 5);
        assert!(!exists<Allowances>(allowances_address(call.payer)), 6);
        assert!(event::was_event_emitted(&UptoSettled {
            payer: call.payer,
            facilitator: @0xb0b,
            pay_to: @0xdd,
            metadata: object::object_address(&metadata),
            nonce: call.nonce,
            max_amount: 100,
            amount: 40,
            received: 40,
        }), 7);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001d, location = Self)]
    fun test_settling_the_maximum_consumes_the_nonce(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 100);
        assert!(settle_call(bob, call) == 100, 1);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 100, 2);

        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EUPTO_NONCE_USED));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001d, location = Self)]
    fun test_settling_zero_consumes_the_nonce_and_moves_nothing(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 0);
        assert_upto_accepted(@0xb0b, call);
        assert!(settle_call(bob, call) == 0, 1);

        assert!(primary_fungible_store::balance(call.payer, metadata) == 100, 2);
        assert!(!primary_fungible_store::primary_store_exists(@0xdd, metadata), 3);
        assert!(upto_nonce_state(call.payer, call.nonce) == UPTO_NONCE_SETTLED, 4);
        assert!(event::was_event_emitted(&UptoSettled {
            payer: call.payer,
            facilitator: @0xb0b,
            pay_to: @0xdd,
            metadata: object::object_address(&metadata),
            nonce: call.nonce,
            max_amount: 100,
            amount: 0,
            received: 0,
        }), 5);

        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EUPTO_NONCE_USED));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, alice = @0xa11ce)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_settled_by_another_facilitator_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        alice: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        // The authorization names @0xb0b as its facilitator.
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        assert_upto_rejected(@0xa11ce, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(alice, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_redirected_to_another_recipient_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.pay_to = @0xee;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_submitted_against_another_payer_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        let (other, _) = upto_fixture(&mint_ref, metadata, 0, 40);
        call.payer = other.payer;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_submitted_for_another_asset_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let other_ref = object::create_named_object(creator, b"OTHER");
        let (other_mint_ref, _, _) =
            primary_fungible_store::init_test_metadata_with_primary_store_enabled(&other_ref);
        let other_metadata =
            object::address_to_object<Metadata>(object::address_from_constructor_ref(&other_ref));
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        primary_fungible_store::mint(&other_mint_ref, call.payer, 100);
        call.metadata = other_metadata;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_submitted_with_a_larger_maximum_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.max_amount = 200;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_submitted_with_an_earlier_valid_after_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.valid_after = START_TIME_SECS - 1;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_submitted_with_a_later_valid_before_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.valid_before = UPTO_VALID_BEFORE + 1;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_submitted_with_another_nonce_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.nonce = upto_nonce(2);
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_submitted_under_another_generation_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        // The submitted generation is the payer's current one, so the generation check passes and
        // the signature, made under generation 0, is what rejects the call.
        revoke_all(&account::create_signer_for_test(call.payer));
        call.generation = 1;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_for_another_chain_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 40);
        let payload = upto_payload_for(@0xb0b, &call, 1);
        call.signature = ed25519::signature_to_bytes(&ed25519::sign_struct(&sk, payload));
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001c, location = Self)]
    fun test_upto_above_the_maximum_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 101);
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EUPTO_AMOUNT_EXCEEDS_MAX));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x30019, location = Self)]
    fun test_upto_before_valid_after_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.valid_after = START_TIME_SECS + 1;
        call.valid_before = START_TIME_SECS + 601;
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_rejected(@0xb0b, call, error::invalid_state(EUPTO_NOT_YET_VALID));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x3001a, location = Self)]
    fun test_upto_at_valid_before_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        timestamp::update_global_time_for_test_secs(UPTO_VALID_BEFORE);
        assert_upto_rejected(@0xb0b, call, error::invalid_state(EUPTO_EXPIRED));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001b, location = Self)]
    fun test_upto_spanning_more_than_the_maximum_span_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.valid_before = START_TIME_SECS + MAX_UPTO_SPAN_SECS + 1;
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EUPTO_SPAN_TOO_LONG));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_upto_is_accepted_at_each_boundary_of_its_validity(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 10);

        // Settled at the second given as `valid_after`.
        assert_upto_accepted(@0xb0b, call);
        settle_call(bob, call);

        // Settled in the last second before `valid_before`.
        call.nonce = upto_nonce(2);
        call.valid_before = START_TIME_SECS + 1;
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_accepted(@0xb0b, call);
        settle_call(bob, call);

        // A span of exactly `MAX_UPTO_SPAN_SECS`.
        call.nonce = upto_nonce(3);
        call.valid_before = START_TIME_SECS + MAX_UPTO_SPAN_SECS;
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_accepted(@0xb0b, call);
        settle_call(bob, call);

        assert!(primary_fungible_store::balance(@0xdd, metadata) == 30, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x10018, location = Self)]
    fun test_upto_with_a_nonce_of_the_wrong_length_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 40);
        let code = error::invalid_argument(EUPTO_INVALID_NONCE);

        call.nonce = vector[];
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_rejected(@0xb0b, call, code);

        let long = upto_nonce(1);
        vector::push_back(&mut long, 0);
        call.nonce = long;
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_rejected(@0xb0b, call, code);

        let short = upto_nonce(1);
        vector::pop_back(&mut short);
        call.nonce = short;
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_rejected(@0xb0b, call, code);
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x3000e, location = Self)]
    fun test_upto_authorised_before_revoke_all_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        revoke_all(&account::create_signer_for_test(call.payer));
        assert_upto_rejected(@0xb0b, call, error::invalid_state(EGENERATION_MISMATCH));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_upto_carrying_the_new_generation_is_settled(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 40);
        revoke_all(&account::create_signer_for_test(call.payer));
        call.generation = 1;
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_accepted(@0xb0b, call);
        assert!(settle_call(bob, call) == 40, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001d, location = Self)]
    fun test_a_cancelled_upto_nonce_cannot_be_settled(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        cancel_upto(&account::create_signer_for_test(call.payer), call.nonce, UPTO_VALID_BEFORE);

        assert!(upto_nonce_state(call.payer, call.nonce) == UPTO_NONCE_CANCELLED, 1);
        assert!(upto_record_valid_before(call.payer, call.nonce) == UPTO_VALID_BEFORE, 2);
        let cancelled = UptoCancelled { payer: call.payer, nonce: call.nonce };
        assert!(event::was_event_emitted(&cancelled), 3);
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EUPTO_NONCE_USED));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    fun test_cancel_upto_records_no_earlier_than_the_current_time(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry {
        let (_, _, _, _) = setup(supra_framework, creator);
        let payer = account::create_account_for_test(@0xa11ce);
        timestamp::update_global_time_for_test_secs(START_TIME_SECS + 50);

        cancel_upto(&payer, upto_nonce(1), START_TIME_SECS);
        assert!(upto_record_valid_before(@0xa11ce, upto_nonce(1)) == START_TIME_SECS + 50, 1);
        cancel_upto(&payer, upto_nonce(2), START_TIME_SECS + 51);
        assert!(upto_record_valid_before(@0xa11ce, upto_nonce(2)) == START_TIME_SECS + 51, 2);

        remove_expired_upto_nonce(@0xa11ce, upto_nonce(1));
        assert!(upto_nonce_state(@0xa11ce, upto_nonce(1)) == UPTO_NONCE_NONE, 3);
        assert!(upto_nonce_state(@0xa11ce, upto_nonce(2)) == UPTO_NONCE_CANCELLED, 4);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001d, location = Self)]
    fun test_cancelling_a_recorded_upto_nonce_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        settle_call(bob, call);
        cancel_upto(&account::create_signer_for_test(call.payer), call.nonce, UPTO_VALID_BEFORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10018, location = Self)]
    fun test_cancel_upto_with_a_nonce_of_the_wrong_length_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry {
        let (_, _, _, _) = setup(supra_framework, creator);
        let payer = account::create_account_for_test(@0xa11ce);
        cancel_upto(&payer, b"short", UPTO_VALID_BEFORE);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x3001a, location = Self)]
    fun test_an_upto_cancelled_by_reusing_its_nonce_stays_inadmissible_after_removal(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (original, sk) = upto_fixture(&mint_ref, metadata, 100, 40);

        // A zero-amount authorization with the original's nonce and the same `valid_before`.
        let cancelling = original;
        cancelling.amount = 0;
        cancelling.max_amount = 0;
        sign_upto(&sk, @0xb0b, &mut cancelling);
        settle_call(bob, cancelling);
        assert_upto_rejected(@0xb0b, original, error::invalid_argument(EUPTO_NONCE_USED));

        timestamp::update_global_time_for_test_secs(UPTO_VALID_BEFORE);
        remove_expired_upto_nonce(original.payer, original.nonce);
        assert!(upto_nonce_state(original.payer, original.nonce) == UPTO_NONCE_NONE, 1);

        // The original's own `valid_before`, not the record, keeps it out.
        assert_upto_rejected(@0xb0b, original, error::invalid_state(EUPTO_EXPIRED));
        settle_call(bob, original);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x3001f, location = Self)]
    fun test_removing_an_unexpired_upto_nonce_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        settle_call(bob, call);
        timestamp::update_global_time_for_test_secs(UPTO_VALID_BEFORE - 1);
        remove_expired_upto_nonce(call.payer, call.nonce);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_an_upto_nonce_is_removable_from_valid_before(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        settle_call(bob, call);
        timestamp::update_global_time_for_test_secs(UPTO_VALID_BEFORE);
        remove_expired_upto_nonce(call.payer, call.nonce);
        assert!(upto_nonce_state(call.payer, call.nonce) == UPTO_NONCE_NONE, 1);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x60020, location = Self)]
    fun test_removing_an_absent_upto_nonce_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry {
        let (_, _, _, _) = setup(supra_framework, creator);
        remove_expired_upto_nonce(@0xa11ce, upto_nonce(1));
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_batched_removal_skips_absent_and_unexpired_records(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 10);
        let payer = call.payer;
        settle_call(bob, call);
        call.nonce = upto_nonce(2);
        call.valid_before = UPTO_VALID_BEFORE + 100;
        sign_upto(&sk, @0xb0b, &mut call);
        settle_call(bob, call);
        let canceller = account::create_account_for_test(@0xa11ce);
        cancel_upto(&canceller, upto_nonce(1), START_TIME_SECS);

        timestamp::update_global_time_for_test_secs(UPTO_VALID_BEFORE);
        remove_expired_upto_nonces(
            vector[payer, payer, payer, @0xa11ce, payer],
            vector[upto_nonce(1), upto_nonce(2), upto_nonce(3), upto_nonce(1), upto_nonce(1)],
        );

        assert!(upto_nonce_state(payer, upto_nonce(1)) == UPTO_NONCE_NONE, 1);
        assert!(upto_nonce_state(payer, upto_nonce(2)) == UPTO_NONCE_SETTLED, 2);
        assert!(upto_nonce_state(@0xa11ce, upto_nonce(1)) == UPTO_NONCE_NONE, 3);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe)]
    #[expected_failure(abort_code = 0x10023, location = Self)]
    fun test_batched_removal_with_lists_of_different_lengths_is_rejected(
        supra_framework: &signer,
        creator: &signer,
    ) acquires Registry {
        let (_, _, _, _) = setup(supra_framework, creator);
        remove_expired_upto_nonces(vector[@0xa11ce, @0xb0b], vector[upto_nonce(1)]);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_an_address_without_an_account_settles_upto(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (sk, pk) = ed25519::generate_keys();
        // The address is the key's derived authentication key, holds the asset and has no
        // `Account` resource.
        let payer = from_bcs::to_address(ed25519::validated_public_key_to_authentication_key(&pk));
        primary_fungible_store::mint(&mint_ref, payer, 100);
        assert!(!account::exists_at(payer), 1);
        let call = UptoCall {
            payer,
            pay_to: @0xdd,
            metadata,
            max_amount: 100,
            valid_after: START_TIME_SECS,
            valid_before: UPTO_VALID_BEFORE,
            nonce: upto_nonce(1),
            generation: 0,
            account_scheme: ED25519_SCHEME,
            public_key: ed25519::validated_public_key_to_bytes(&pk),
            signature: vector[],
            amount: 60,
        };
        sign_upto(&sk, @0xb0b, &mut call);
        assert_upto_accepted(@0xb0b, call);

        assert!(settle_call(bob, call) == 60, 2);
        assert!(primary_fungible_store::balance(payer, metadata) == 40, 3);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 60, 4);
        assert!(!account::exists_at(payer), 5);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_a_multi_ed25519_payer_settles_upto(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (sk, pk) = multi_ed25519::generate_keys(2, 3);
        let payer =
            from_bcs::to_address(multi_ed25519::validated_public_key_to_authentication_key(&pk));
        primary_fungible_store::mint(&mint_ref, payer, 100);
        let call = UptoCall {
            payer,
            pay_to: @0xdd,
            metadata,
            max_amount: 100,
            valid_after: START_TIME_SECS,
            valid_before: UPTO_VALID_BEFORE,
            nonce: upto_nonce(1),
            generation: 0,
            account_scheme: MULTI_ED25519_SCHEME,
            public_key: multi_ed25519::validated_public_key_to_bytes(&pk),
            signature: vector[],
            amount: 60,
        };
        let payload = upto_payload_for(@0xb0b, &call, 4);
        let signature = multi_ed25519::sign_struct(&sk, payload);
        call.signature = multi_ed25519::signature_to_bytes(&signature);
        assert_upto_accepted(@0xb0b, call);
        assert!(settle_call(bob, call) == 60, 1);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 60, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_under_an_undefined_scheme_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        call.account_scheme = 2;
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EINVALID_SIGNATURE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x1001e, location = Self)]
    fun test_upto_with_malformed_key_or_signature_bytes_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        let code = error::invalid_argument(EINVALID_SIGNATURE);

        let short_key = call;
        vector::pop_back(&mut short_key.public_key);
        assert_upto_rejected(@0xb0b, short_key, code);

        let long_signature = call;
        vector::push_back(&mut long_signature.signature, 0);
        assert_upto_rejected(@0xb0b, long_signature, code);

        let empty_multi = call;
        empty_multi.account_scheme = MULTI_ED25519_SCHEME;
        empty_multi.public_key = vector[];
        empty_multi.signature = vector[];
        assert_upto_rejected(@0xb0b, empty_multi, code);

        let malformed_multi = call;
        malformed_multi.account_scheme = MULTI_ED25519_SCHEME;
        assert_upto_rejected(@0xb0b, malformed_multi, code);

        settle_call(bob, short_key);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50007, location = Self)]
    fun test_upto_of_a_disabled_asset_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, DeriveRefPod, Allowances, AllowanceControl {
        let (creator_ref, metadata, mint_ref, _) = setup(supra_framework, creator);
        disable_allowances(&creator_ref);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        assert_upto_rejected(@0xb0b, call, error::permission_denied(EALLOWANCES_DISABLED));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x60008, location = Self)]
    fun test_upto_from_a_payer_without_a_store_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 0, 40);
        assert_upto_rejected(@0xb0b, call, error::not_found(ESOURCE_STORE_MISSING));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50003, location = supra_framework::fungible_asset)]
    fun test_upto_from_a_frozen_store_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, transfer_ref) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        primary_fungible_store::set_frozen_flag(&transfer_ref, call.payer, true);
        assert_upto_rejected(@0xb0b, call, error::permission_denied(EUPTO_STORE_FROZEN));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x50003, location = supra_framework::fungible_asset)]
    fun test_upto_to_a_frozen_store_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, transfer_ref) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        primary_fungible_store::set_frozen_flag(&transfer_ref, @0xdd, true);
        assert_upto_rejected(@0xb0b, call, error::permission_denied(EUPTO_STORE_FROZEN));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x10004, location = supra_framework::fungible_asset)]
    fun test_upto_beyond_the_payer_balance_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 30, 40);
        assert_upto_rejected(@0xb0b, call, error::invalid_argument(EUPTO_INSUFFICIENT_BALANCE));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    #[expected_failure(abort_code = 0x6000c, location = Self)]
    fun test_settle_upto_before_the_registry_exists_is_rejected(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup_without_registry(supra_framework, creator);
        let (call, _) = upto_fixture(&mint_ref, metadata, 100, 40);
        assert!(upto_nonce_state(call.payer, call.nonce) == UPTO_NONCE_NONE, 1);
        assert_upto_rejected(@0xb0b, call, error::not_found(EMODULE_NOT_INITIALIZED));
        settle_call(bob, call);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_upto_signing_message_matches_the_verified_payload(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (call, sk) = upto_fixture(&mint_ref, metadata, 100, 40);
        let message = upto_signing_message(
            call.payer,
            @0xb0b,
            call.pay_to,
            call.metadata,
            call.max_amount,
            call.valid_after,
            call.valid_before,
            call.nonce,
            call.generation,
        );
        let payload = upto_payload_for(@0xb0b, &call, 4);
        assert!(message == bcs::to_bytes(&ed25519::new_signed_message(payload)), 1);

        call.signature = ed25519::signature_to_bytes(&ed25519::sign_arbitrary_bytes(&sk, message));
        assert!(settle_call(bob, call) == 40, 2);
    }

    #[test(supra_framework = @supra_framework, creator = @0xcafe, bob = @0xb0b)]
    fun test_many_upto_authorizations_from_one_payer_settle_in_any_order(
        supra_framework: &signer,
        creator: &signer,
        bob: &signer,
    ) acquires Registry, Allowances, AllowanceControl {
        let (_, metadata, mint_ref, _) = setup(supra_framework, creator);
        let (template, sk) = upto_fixture(&mint_ref, metadata, 100, 2);
        let calls = vector::empty<UptoCall>();
        let seed = 0;
        while (seed < 50) {
            let call = template;
            call.nonce = upto_nonce(seed);
            sign_upto(&sk, @0xb0b, &mut call);
            vector::push_back(&mut calls, call);
            seed = seed + 1;
        };
        // Settle them in an order unrelated to the order they were signed in.
        let index = 0;
        while (index < 50) {
            let call = *vector::borrow(&calls, (index * 17) % 50);
            assert!(settle_call(bob, call) == 2, 1);
            index = index + 1;
        };
        assert!(primary_fungible_store::balance(template.payer, metadata) == 0, 2);
        assert!(primary_fungible_store::balance(@0xdd, metadata) == 100, 3);
    }
}

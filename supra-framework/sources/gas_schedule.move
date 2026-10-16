/// This module defines structs and methods to initialize the gas schedule, which dictates how much
/// it costs to execute Move on the network.
module supra_framework::gas_schedule {
    use std::bcs;
    use std::error;
    use std::features;
    use std::option;
    use std::string::{Self, String};
    use std::vector;
    use aptos_std::aptos_hash;
    use aptos_std::comparator;
    use supra_framework::chain_status;
    use supra_framework::config_buffer;

    use supra_framework::reconfiguration;
    use supra_framework::system_addresses;
    use supra_framework::util::from_bytes;
    use supra_framework::storage_gas::StorageGasConfig;
    use supra_framework::storage_gas;
    #[test_only]
    use std::bcs::to_bytes;

    friend supra_framework::genesis;
    friend supra_framework::reconfiguration_with_dkg;
    friend supra_framework::evm_config;
    friend supra_framework::evm_genesis_config;

    /// The provided gas schedule bytes are empty or invalid
    const EINVALID_GAS_SCHEDULE: u64 = 1;
    const EINVALID_GAS_FEATURE_VERSION: u64 = 2;
    const EINVALID_GAS_SCHEDULE_HASH: u64 = 3;
    /// The storage gas config cannot be applied immediately while feature `SUPRA_DKG` is enabled; use
    /// `set_storage_gas_config_for_next_epoch()` followed by `supra_governance::reconfigure()`.
    const ESET_STORAGE_GAS_CONFIG_DISABLED_WITH_DKG: u64 = 4;
    /// A `supra.evm.*` entry that the gas schedule's feature version requires is missing, or
    /// `txn.min_price_per_gas_unit`, which the EVM base fee is derived from, is missing
    const ESUPRA_EVM_GAS_ENTRY_MISSING: u64 = 5;
    /// A `supra.evm.*` entry is zero
    const ESUPRA_EVM_GAS_ENTRY_ZERO: u64 = 6;
    /// `supra.evm.gas_price_normalization_denom` is above `MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM`
    const ESUPRA_EVM_GAS_ENTRY_TOO_LARGE: u64 = 7;
    /// `supra.evm.gas_price_normalization_denom` times `txn.min_price_per_gas_unit`, the EVM base
    /// fee in wei, does not fit in a `u64`
    const ESUPRA_EVM_BASE_FEE_TOO_LARGE: u64 = 8;
    /// EVM configuration requires a published gas schedule at `SUPRA_EVM_GAS_FEATURE_VERSION` or
    /// above
    const ESUPRA_EVM_GAS_FEATURE_VERSION_TOO_OLD: u64 = 9;
    /// At `SUPRA_EVM_GAS_FEATURE_VERSION` or above, the schedule's keys are not in strictly
    /// increasing byte order, which a repeated key also breaks
    const EGAS_SCHEDULE_KEYS_NOT_IN_ORDER: u64 = 10;

    /// The gas feature version from which a schedule carries the `supra.evm.*` entries. It is
    /// `RELEASE_V1_16_SUPRA_V1_9_0` in `aptos-gas-schedule`, which binds both keys to it; a node
    /// decoding a schedule at this version or above requires both. A test in that crate checks this
    /// file against its own constants.
    const SUPRA_EVM_GAS_FEATURE_VERSION: u64 = 26;

    /// Key of the minimum price per gas unit, in quants, that the EVM base fee is derived from.
    const TXN_MIN_PRICE_PER_GAS_UNIT_KEY: vector<u8> = b"txn.min_price_per_gas_unit";

    /// The largest value a `u64` holds, which the EVM base fee in wei must not exceed.
    const MAX_U64: u128 = 18446744073709551615;

    /// Key of the largest `gas_limit` an EVM transaction may declare.
    const SUPRA_EVM_MAX_TRANSACTION_GAS_LIMIT_KEY: vector<u8> = b"supra.evm.max_transaction_gas_limit";

    /// Key of the factor that converts the quant-denominated `txn.min_price_per_gas_unit` into the
    /// wei-denominated EVM base fee.
    const SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY: vector<u8> = b"supra.evm.gas_price_normalization_denom";

    /// The largest accepted `supra.evm.gas_price_normalization_denom`: 10^10, the number of wei in
    /// one quant.
    ///
    /// A node computes the EVM block base fee in wei as this factor times `txn.min_price_per_gas_unit`.
    /// That product is checked on its own, against `MAX_U64`; this bound is a sanity limit on the
    /// factor alone, so that a factor above one quant's worth of wei is refused whatever the price.
    /// The compiled default is 10^10 divided by 3000. See Entropy-Foundation/smr-moonshot#4137.
    const MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM: u64 = 10_000_000_000;

    struct GasEntry has store, copy, drop {
        key: String,
        val: u64,
    }

    struct GasSchedule has key, copy, drop {
        entries: vector<GasEntry>
    }

    struct GasScheduleV2 has key, copy, drop, store {
        feature_version: u64,
        entries: vector<GasEntry>,
    }

    /// Only called during genesis.
    public(friend) fun initialize(supra_framework: &signer, gas_schedule_blob: vector<u8>) {
        system_addresses::assert_supra_framework(supra_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));

        // TODO(Gas): check if gas schedule is consistent
        let gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        validate_gas_schedule(&gas_schedule);
        move_to<GasScheduleV2>(supra_framework, gas_schedule);
    }

    /// Deprecated by `set_for_next_epoch()`.
    ///
    /// WARNING: calling this while randomness is enabled will trigger a new epoch without randomness!
    ///
    /// TODO: update all the tests that reference this function, then disable this function.
    public fun set_gas_schedule(supra_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasSchedule, GasScheduleV2 {
        system_addresses::assert_supra_framework(supra_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        chain_status::assert_genesis();

        if (exists<GasScheduleV2>(@supra_framework)) {
            let gas_schedule = borrow_global_mut<GasScheduleV2>(@supra_framework);
            let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
            assert!(new_gas_schedule.feature_version >= gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION));
            validate_gas_schedule(&new_gas_schedule);
            // TODO(Gas): check if gas schedule is consistent
            *gas_schedule = new_gas_schedule;
        }
        else {
            if (exists<GasSchedule>(@supra_framework)) {
                _ = move_from<GasSchedule>(@supra_framework);
            };
            let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
            validate_gas_schedule(&new_gas_schedule);
            // TODO(Gas): check if gas schedule is consistent
            move_to<GasScheduleV2>(supra_framework, new_gas_schedule);
        };

        // Need to trigger reconfiguration so validator nodes can sync on the updated gas schedule.
        reconfiguration::reconfigure();
    }

    /// Set the gas schedule for the next epoch, typically called by on-chain governance.
    /// Abort if the version of the given schedule is lower than the current version.
    ///
    /// Example usage:
    /// ```
    /// supra_framework::gas_schedule::set_for_next_epoch(&framework_signer, some_gas_schedule_blob);
    /// supra_framework::supra_governance::reconfigure(&framework_signer);
    /// ```
    public fun set_for_next_epoch(supra_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
        system_addresses::assert_supra_framework(supra_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        if (exists<GasScheduleV2>(@supra_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@supra_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
        validate_gas_schedule(&new_gas_schedule);
        config_buffer::upsert(new_gas_schedule);
    }

    /// Set the gas schedule for the next epoch, typically called by on-chain governance.
    /// Abort if the version of the given schedule is lower than the current version.
    /// Require a hash of the old gas schedule to be provided and will abort if the hashes mismatch.
    public fun set_for_next_epoch_check_hash(
        supra_framework: &signer,
        old_gas_schedule_hash: vector<u8>,
        new_gas_schedule_blob: vector<u8>
    ) acquires GasScheduleV2 {
        system_addresses::assert_supra_framework(supra_framework);
        assert!(!vector::is_empty(&new_gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));

        let new_gas_schedule: GasScheduleV2 = from_bytes(new_gas_schedule_blob);
        if (exists<GasScheduleV2>(@supra_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@supra_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
            let cur_gas_schedule_bytes = bcs::to_bytes(cur_gas_schedule);
            let cur_gas_schedule_hash = aptos_hash::sha3_512(cur_gas_schedule_bytes);
            assert!(
                cur_gas_schedule_hash == old_gas_schedule_hash,
                error::invalid_argument(EINVALID_GAS_SCHEDULE_HASH)
            );
        };
        validate_gas_schedule(&new_gas_schedule);

        config_buffer::upsert(new_gas_schedule);
    }

    /// Aborts unless `gas_schedule` is valid for its feature version.
    ///
    /// Below `SUPRA_EVM_GAS_FEATURE_VERSION` nothing is checked. At or above it:
    /// - the keys must be in strictly increasing byte order, so that each key appears once;
    /// - both `supra.evm.*` entries and `txn.min_price_per_gas_unit` must be present;
    /// - both `supra.evm.*` entries must be non-zero;
    /// - the normalization factor must be at most `MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM`;
    /// - the EVM base fee, the factor times `txn.min_price_per_gas_unit`, must fit in a `u64`.
    ///
    /// Every key must appear once so that every reader of a schedule, a node or anyone reading the
    /// published resource, reads one value for it. Requiring order rather than uniqueness alone makes
    /// the check one pass over the entries, and gives a schedule one encoding. A node reads the EVM
    /// values when an epoch applies the schedule and has no way to refuse one there, so they are
    /// checked here, when the schedule is set. `aptos_gas_schedule::validate_gas_schedule` states the
    /// same rule in Rust. See Entropy-Foundation/smr-moonshot#4137.
    fun validate_gas_schedule(gas_schedule: &GasScheduleV2) {
        if (gas_schedule.feature_version < SUPRA_EVM_GAS_FEATURE_VERSION) {
            return
        };
        let entries = &gas_schedule.entries;
        let len = vector::length(entries);
        let cap_key = string::utf8(SUPRA_EVM_MAX_TRANSACTION_GAS_LIMIT_KEY);
        let denom_key = string::utf8(SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY);
        let min_price_key = string::utf8(TXN_MIN_PRICE_PER_GAS_UNIT_KEY);
        let cap = option::none<u64>();
        let denom = option::none<u64>();
        let min_price = option::none<u64>();
        let i = 0;
        // One pass: each key is compared with the one before it, and the three values are collected.
        // Keys in strictly increasing order are unique, so each value is found at most once.
        while (i < len) {
            let entry = vector::borrow(entries, i);
            if (i > 0) {
                let previous_key = *string::bytes(&vector::borrow(entries, i - 1).key);
                let key = *string::bytes(&entry.key);
                assert!(
                    comparator::is_smaller_than(&comparator::compare_u8_vector(previous_key, key)),
                    error::invalid_argument(EGAS_SCHEDULE_KEYS_NOT_IN_ORDER)
                );
            };
            if (entry.key == cap_key) {
                cap = option::some(entry.val);
            } else if (entry.key == denom_key) {
                denom = option::some(entry.val);
            } else if (entry.key == min_price_key) {
                min_price = option::some(entry.val);
            };
            i = i + 1;
        };
        // The minimum price is not a `supra.evm.*` entry, but the base fee is derived from it, so a
        // schedule that lacks it is refused under the same code as one that lacks either EVM entry.
        assert!(
            option::is_some(&cap) && option::is_some(&denom) && option::is_some(&min_price),
            error::invalid_argument(ESUPRA_EVM_GAS_ENTRY_MISSING)
        );
        let cap = option::destroy_some(cap);
        let denom = option::destroy_some(denom);
        let min_price = option::destroy_some(min_price);
        assert!(cap > 0 && denom > 0, error::invalid_argument(ESUPRA_EVM_GAS_ENTRY_ZERO));
        assert!(
            denom <= MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM,
            error::invalid_argument(ESUPRA_EVM_GAS_ENTRY_TOO_LARGE)
        );
        // Computed in u128, where the product of two u64 values cannot overflow. A zero minimum
        // price gives a zero base fee, which is accepted.
        assert!(
            (denom as u128) * (min_price as u128) <= MAX_U64,
            error::invalid_argument(ESUPRA_EVM_BASE_FEE_TOO_LARGE)
        );
    }

    /// The feature version of the gas schedule currently in force, or 0 if none is published.
    ///
    /// A schedule buffered by `set_for_next_epoch` is not counted until `on_new_epoch` applies it.
    /// Read by `assert_supra_evm_gas_feature_version`, which the EVM configuration modules call.
    fun published_feature_version(): u64 acquires GasScheduleV2 {
        if (exists<GasScheduleV2>(@supra_framework)) {
            borrow_global<GasScheduleV2>(@supra_framework).feature_version
        } else {
            0
        }
    }

    /// Aborts unless the gas schedule in force is at `SUPRA_EVM_GAS_FEATURE_VERSION` or above.
    ///
    /// Every function that publishes or buffers EVM configuration calls this first. A node running
    /// the EVM reads the `supra.evm.*` entries from every epoch's schedule and refuses a schedule
    /// without them, so EVM configuration is accepted only once the schedule carries them. Only the
    /// published schedule counts: a gas schedule upgrade and EVM configuration are proposed in
    /// separate epochs, the upgrade first.
    public(friend) fun assert_supra_evm_gas_feature_version() acquires GasScheduleV2 {
        assert!(
            published_feature_version() >= SUPRA_EVM_GAS_FEATURE_VERSION,
            error::invalid_state(ESUPRA_EVM_GAS_FEATURE_VERSION_TOO_OLD)
        );
    }

    #[test_only]
    /// Publishes a gas schedule at `feature_version` carrying the default `supra.evm.*` entries, for
    /// tests of modules gated on `assert_supra_evm_gas_feature_version`.
    public fun initialize_for_test(supra_framework: &signer, feature_version: u64) {
        move_to(supra_framework, schedule_with_supra_evm_entries(feature_version, 16_777_216, 3_333_333));
    }

    /// Only used in reconfigurations to apply the pending `GasScheduleV2`, if there is any.
    public(friend) fun on_new_epoch(framework: &signer) acquires GasScheduleV2 {
        system_addresses::assert_supra_framework(framework);
        if (config_buffer::does_exist<GasScheduleV2>()) {
            let new_gas_schedule = config_buffer::extract_v2<GasScheduleV2>();
            if (exists<GasScheduleV2>(@supra_framework)) {
                *borrow_global_mut<GasScheduleV2>(@supra_framework) = new_gas_schedule;
            } else {
                move_to(framework, new_gas_schedule);
            }
        }
    }

    /// Set the storage gas config and end the epoch, so that the VM uses the new config from the next
    /// transaction.
    ///
    /// Aborts with `ESET_STORAGE_GAS_CONFIG_DISABLED_WITH_DKG` if feature `SUPRA_DKG` is enabled.
    /// With `SUPRA_DKG` enabled, a new epoch starts only after its DKG session completes; use
    /// `set_storage_gas_config_for_next_epoch()` followed by `supra_governance::reconfigure()`, which
    /// starts that session. See Entropy-Foundation/smr-moonshot#4134.
    public fun set_storage_gas_config(supra_framework: &signer, config: StorageGasConfig) {
        system_addresses::assert_supra_framework(supra_framework);
        assert!(
            !features::supra_dkg_enabled(),
            error::invalid_state(ESET_STORAGE_GAS_CONFIG_DISABLED_WITH_DKG)
        );
        storage_gas::set_config(supra_framework, config);
        // Need to trigger reconfiguration so the VM is guaranteed to load the new gas fee starting from the next
        // transaction.
        reconfiguration::reconfigure();
    }

    /// Set the storage gas config. The VM uses it from the next epoch, whose start recomputes `StorageGas`
    /// from it.
    public fun set_storage_gas_config_for_next_epoch(supra_framework: &signer, config: StorageGasConfig) {
        storage_gas::set_config(supra_framework, config);
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code=0x010002, location = Self)]
    fun set_for_next_epoch_should_abort_if_gas_version_is_too_old(fx: signer) acquires GasScheduleV2 {
        // Setup.
        let old_gas_schedule = GasScheduleV2 {
            feature_version: 1000,
            entries: vector[],
        };
        move_to(&fx, old_gas_schedule);

        // Setting an older version should not work.
        let new_gas_schedule = GasScheduleV2 {
            feature_version: 999,
            entries: vector[],
        };
        let new_bytes = to_bytes(&new_gas_schedule);
        set_for_next_epoch(&fx, new_bytes);
    }

    #[test_only]
    /// A schedule at `feature_version` carrying `cap` and `denom` under the two `supra.evm.*` keys and
    /// a minimum price per gas unit of 100 quants.
    fun schedule_with_supra_evm_entries(feature_version: u64, cap: u64, denom: u64): GasScheduleV2 {
        schedule_with_supra_evm_pricing(feature_version, cap, denom, 100)
    }

    #[test_only]
    /// A schedule at `feature_version` carrying `cap`, `denom` and `min_price`, in key order.
    fun schedule_with_supra_evm_pricing(
        feature_version: u64,
        cap: u64,
        denom: u64,
        min_price: u64
    ): GasScheduleV2 {
        GasScheduleV2 {
            feature_version,
            // In the byte order a schedule at version 26 or above must be in.
            entries: vector[
                GasEntry { key: string::utf8(SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY), val: denom },
                GasEntry { key: string::utf8(SUPRA_EVM_MAX_TRANSACTION_GAS_LIMIT_KEY), val: cap },
                GasEntry { key: string::utf8(TXN_MIN_PRICE_PER_GAS_UNIT_KEY), val: min_price },
            ],
        }
    }

    #[test_only]
    /// A schedule at `feature_version` whose only entry is `key` holding `val`.
    fun schedule_with_single_entry(feature_version: u64, key: vector<u8>, val: u64): GasScheduleV2 {
        GasScheduleV2 {
            feature_version,
            entries: vector[GasEntry { key: string::utf8(key), val }],
        }
    }

    #[test]
    /// The compiled defaults and the bounds themselves are accepted.
    fun test_supra_evm_entries_at_their_bounds_are_accepted() {
        validate_gas_schedule(&schedule_with_supra_evm_entries(26, 16_777_216, 3_333_333));
        validate_gas_schedule(&schedule_with_supra_evm_entries(26, 1, 1));
        validate_gas_schedule(
            &schedule_with_supra_evm_entries(26, 18446744073709551615, MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM)
        );
    }

    #[test]
    /// Below the feature version that introduces the entries, a node does not read them, so their
    /// absence or value is not checked.
    fun test_supra_evm_entries_below_their_feature_version_are_not_checked() {
        validate_gas_schedule(&GasScheduleV2 { feature_version: 25, entries: vector[] });
        validate_gas_schedule(&schedule_with_supra_evm_entries(25, 0, 0));
    }

    #[test]
    /// The bound is 10^10, and 10^10 times the compiled maximum price per gas unit, 10^9, fits in a
    /// u64.
    fun test_supra_evm_normalization_denom_bound() {
        assert!(MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM == 10_000_000_000, 0);
        assert!(
            (MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM as u128) * 1_000_000_000u128
                <= (18446744073709551615u64 as u128),
            0
        );
    }

    #[test]
    #[expected_failure(abort_code = 0x10005, location = Self)]
    /// error::invalid_argument(ESUPRA_EVM_GAS_ENTRY_MISSING) = 0x10005.
    fun test_supra_evm_schedule_without_the_cap_is_rejected() {
        validate_gas_schedule(
            &schedule_with_single_entry(26, SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY, 3_333_333)
        );
    }

    #[test]
    #[expected_failure(abort_code = 0x10005, location = Self)]
    fun test_supra_evm_schedule_without_the_denom_is_rejected() {
        validate_gas_schedule(
            &schedule_with_single_entry(26, SUPRA_EVM_MAX_TRANSACTION_GAS_LIMIT_KEY, 16_777_216)
        );
    }

    #[test]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    /// error::invalid_argument(ESUPRA_EVM_GAS_ENTRY_ZERO) = 0x10006.
    fun test_supra_evm_zero_cap_is_rejected() {
        validate_gas_schedule(&schedule_with_supra_evm_entries(26, 0, 3_333_333));
    }

    #[test]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_supra_evm_zero_denom_is_rejected() {
        validate_gas_schedule(&schedule_with_supra_evm_entries(26, 16_777_216, 0));
    }

    #[test]
    #[expected_failure(abort_code = 0x10007, location = Self)]
    /// error::invalid_argument(ESUPRA_EVM_GAS_ENTRY_TOO_LARGE) = 0x10007.
    fun test_supra_evm_denom_above_bound_is_rejected() {
        validate_gas_schedule(
            &schedule_with_supra_evm_entries(26, 16_777_216, MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM + 1)
        );
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    /// `initialize`, which genesis calls, applies the check.
    fun test_initialize_with_zero_supra_evm_denom_is_rejected(fx: signer) {
        initialize(&fx, to_bytes(&schedule_with_supra_evm_entries(26, 16_777_216, 0)));
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    /// `set_gas_schedule` applies the check.
    fun test_set_gas_schedule_with_zero_supra_evm_denom_is_rejected(
        fx: signer
    ) acquires GasSchedule, GasScheduleV2 {
        set_gas_schedule(&fx, to_bytes(&schedule_with_supra_evm_entries(26, 16_777_216, 0)));
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    /// `set_for_next_epoch` applies the check before anything is buffered.
    fun test_set_for_next_epoch_with_zero_supra_evm_denom_is_rejected(fx: signer) acquires GasScheduleV2 {
        set_for_next_epoch(&fx, to_bytes(&schedule_with_supra_evm_entries(26, 16_777_216, 0)));
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    /// `set_for_next_epoch_check_hash` applies the check before anything is buffered.
    fun test_set_for_next_epoch_check_hash_with_zero_supra_evm_denom_is_rejected(
        fx: signer
    ) acquires GasScheduleV2 {
        set_for_next_epoch_check_hash(
            &fx,
            vector[],
            to_bytes(&schedule_with_supra_evm_entries(26, 16_777_216, 0))
        );
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x010002, location = Self)]
    /// A schedule that is both older than the current one and missing the `supra.evm.*` entries is
    /// refused for its version, the check that already ran before this one.
    fun test_old_version_is_rejected_before_supra_evm_entries_are_checked(fx: signer) acquires GasScheduleV2 {
        move_to(&fx, schedule_with_supra_evm_entries(27, 16_777_216, 3_333_333));
        set_for_next_epoch(&fx, to_bytes(&GasScheduleV2 { feature_version: 26, entries: vector[] }));
    }

    #[test]
    /// A base fee of exactly `MAX_U64` wei is accepted, and so is a zero minimum price.
    fun test_supra_evm_base_fee_at_the_u64_bound_is_accepted() {
        validate_gas_schedule(&schedule_with_supra_evm_pricing(26, 16_777_216, 1, 18446744073709551615));
        // 10^10 * 1,844,674,407 = 18,446,744,070,000,000,000, the largest multiple of the bound
        // that fits.
        validate_gas_schedule(
            &schedule_with_supra_evm_pricing(26, 16_777_216, MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM, 1_844_674_407)
        );
        validate_gas_schedule(&schedule_with_supra_evm_pricing(26, 16_777_216, 3_333_333, 0));
    }

    #[test]
    #[expected_failure(abort_code = 0x10008, location = Self)]
    /// error::invalid_argument(ESUPRA_EVM_BASE_FEE_TOO_LARGE) = 0x10008. The factor is within its own
    /// bound; the minimum price is one above the largest whose product with it fits.
    fun test_supra_evm_base_fee_above_the_u64_bound_is_rejected() {
        validate_gas_schedule(
            &schedule_with_supra_evm_pricing(26, 16_777_216, MAX_EVM_GAS_PRICE_NORMALIZATION_DENOM, 1_844_674_408)
        );
    }

    #[test]
    #[expected_failure(abort_code = 0x10005, location = Self)]
    /// A schedule carrying both EVM entries but no minimum price is refused as incomplete.
    fun test_supra_evm_schedule_without_the_min_price_is_rejected() {
        validate_gas_schedule(&GasScheduleV2 {
            feature_version: 26,
            entries: vector[
                GasEntry { key: string::utf8(SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY), val: 3_333_333 },
                GasEntry { key: string::utf8(SUPRA_EVM_MAX_TRANSACTION_GAS_LIMIT_KEY), val: 16_777_216 },
            ],
        });
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x10008, location = Self)]
    /// `set_for_next_epoch`, the path governance proposals take, refuses a base fee that does not fit.
    fun test_set_for_next_epoch_with_an_oversized_base_fee_is_rejected(fx: signer) acquires GasScheduleV2 {
        set_for_next_epoch(
            &fx,
            to_bytes(&schedule_with_supra_evm_pricing(26, 16_777_216, 3_333_333, 10_000_000_000_000))
        );
    }

    #[test(fx = @0x1)]
    /// `published_feature_version` reads the published schedule, and is 0 when none is published.
    fun test_published_feature_version_reads_the_published_schedule(fx: signer) acquires GasScheduleV2 {
        assert!(published_feature_version() == 0, 0);
        initialize_for_test(&fx, 26);
        assert!(published_feature_version() == 26, 1);
    }

    #[test(fx = @0x1)]
    /// The gate accepts a schedule at the version that introduces the `supra.evm.*` entries.
    fun test_supra_evm_gate_accepts_the_introducing_version(fx: signer) acquires GasScheduleV2 {
        initialize_for_test(&fx, 26);
        assert_supra_evm_gas_feature_version();
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x30009, location = Self)]
    /// error::invalid_state(ESUPRA_EVM_GAS_FEATURE_VERSION_TOO_OLD) = 0x30009.
    fun test_supra_evm_gate_refuses_an_older_version(fx: signer) acquires GasScheduleV2 {
        initialize_for_test(&fx, 25);
        assert_supra_evm_gas_feature_version();
    }

    #[test]
    #[expected_failure(abort_code = 0x30009, location = Self)]
    /// With no gas schedule published, the gate refuses.
    fun test_supra_evm_gate_refuses_without_a_schedule() acquires GasScheduleV2 {
        assert_supra_evm_gas_feature_version();
    }

    #[test_only]
    /// The schedule of `schedule_with_supra_evm_entries(26, 16_777_216, 3_333_333)` with `key` holding
    /// `val` inserted right after its existing entry, or at the end if it has none, so that the
    /// schedule is in order apart from the repetition.
    fun schedule_with_repeated_entry(key: vector<u8>, val: u64): GasScheduleV2 {
        let schedule = schedule_with_supra_evm_entries(26, 16_777_216, 3_333_333);
        let key = string::utf8(key);
        let len = vector::length(&schedule.entries);
        let position = len;
        let i = 0;
        while (i < len) {
            if (vector::borrow(&schedule.entries, i).key == key) {
                position = i + 1;
            };
            i = i + 1;
        };
        vector::insert(&mut schedule.entries, position, GasEntry { key, val });
        schedule
    }

    #[test]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    /// error::invalid_argument(EGAS_SCHEDULE_KEYS_NOT_IN_ORDER) = 0x1000a. A repeated cap is refused
    /// even though both of its values are usable on their own.
    fun test_gas_schedule_repeated_cap_is_rejected() {
        validate_gas_schedule(&schedule_with_repeated_entry(SUPRA_EVM_MAX_TRANSACTION_GAS_LIMIT_KEY, 12_000_000));
    }

    #[test]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_gas_schedule_repeated_denom_is_rejected() {
        validate_gas_schedule(&schedule_with_repeated_entry(SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY, 1_000));
    }

    #[test]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_gas_schedule_repeated_min_price_is_rejected() {
        validate_gas_schedule(&schedule_with_repeated_entry(TXN_MIN_PRICE_PER_GAS_UNIT_KEY, 100));
    }

    #[test]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    /// Every key must appear once, not only the ones the EVM checks read.
    fun test_gas_schedule_repeated_key_outside_the_evm_entries_is_rejected() {
        let schedule = schedule_with_repeated_entry(b"txn.other_key", 1);
        vector::push_back(&mut schedule.entries, GasEntry { key: string::utf8(b"txn.other_key"), val: 2 });
        validate_gas_schedule(&schedule);
    }

    #[test]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    /// Unique keys out of byte order are refused.
    fun test_gas_schedule_keys_out_of_order_are_rejected() {
        let schedule = schedule_with_supra_evm_entries(26, 16_777_216, 3_333_333);
        vector::swap(&mut schedule.entries, 0, 1);
        validate_gas_schedule(&schedule);
    }

    #[test]
    /// Below the version that introduces the rule, a repetition and disorder are not checked.
    fun test_gas_schedule_order_below_the_feature_version_is_not_checked() {
        let old = schedule_with_repeated_entry(SUPRA_EVM_MAX_TRANSACTION_GAS_LIMIT_KEY, 1);
        vector::swap(&mut old.entries, 0, 2);
        old.feature_version = 25;
        validate_gas_schedule(&old);
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    /// `set_for_next_epoch`, the path governance proposals take, refuses a repeated key.
    fun test_set_for_next_epoch_with_a_repeated_key_is_rejected(fx: signer) acquires GasScheduleV2 {
        set_for_next_epoch(&fx, to_bytes(&schedule_with_repeated_entry(SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY, 1_000)));
    }

    #[test(fx = @0x1)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    /// `set_gas_schedule` on a chain still holding the original `GasSchedule` resource applies the
    /// check on its migration branch too.
    fun test_set_gas_schedule_migrating_from_the_original_resource_applies_the_check(
        fx: signer
    ) acquires GasSchedule, GasScheduleV2 {
        move_to(&fx, GasSchedule { entries: vector[] });
        set_gas_schedule(&fx, to_bytes(&schedule_with_supra_evm_entries(26, 16_777_216, 0)));
    }

    #[test]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    /// A schedule whose keys are out of order and that lacks the cap is refused for the order, as
    /// `aptos_gas_schedule::validate_gas_schedule` refuses it.
    fun test_gas_schedule_order_is_reported_before_an_absence() {
        validate_gas_schedule(&GasScheduleV2 {
            feature_version: 26,
            entries: vector[
                GasEntry { key: string::utf8(TXN_MIN_PRICE_PER_GAS_UNIT_KEY), val: 100 },
                GasEntry { key: string::utf8(SUPRA_EVM_GAS_PRICE_NORMALIZATION_DENOM_KEY), val: 3_333_333 },
                GasEntry { key: string::utf8(TXN_MIN_PRICE_PER_GAS_UNIT_KEY), val: 100 },
            ],
        });
    }
}

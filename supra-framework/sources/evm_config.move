module supra_framework::evm_config {

    use std::error;
    use std::signer;
    use std::string::String;
    use std::vector;
    use aptos_std::simple_map;
    use aptos_std::simple_map::SimpleMap;
    use aptos_std::bcs;
    use supra_framework::config_buffer;
    use supra_framework::event;
    use supra_framework::gas_schedule;
    use supra_framework::system_addresses;

    friend supra_framework::genesis;
    friend supra_framework::reconfiguration_with_dkg;

    /// Empty keys/values to update config.
    const EEMPTY_DATA: u64 = 1;

    /// Input keys and values should have the same amount of data
    const EKEYS_VALUES_MISMATCH: u64 = 2;

    /// Invalid EVM address, valid EVM address must fit in 20 bytes
    const EINVALID_EVM_ADDRESS: u64 = 3;

    /// Requested key does not exist in the map
    const EKEY_NOT_FOUND: u64 = 4;

    /// Resource already exist at address
    const ERESOURCE_ALREADY_EXISTS: u64 = 6;

    // Codes 5, 8 and 9 belonged to the retired scalar config (#4084) and are not reused, so that an
    // abort code seen on a chain always names one condition.

    /// The EVM spec code is 0. Codes start at 1, so 0 is never a spec.
    const EZERO_EVM_SPEC: u64 = 10;

    /// The EVM spec code is not above the published one. revm's specs are cumulative, so a chain
    /// only ever moves to a later spec.
    const EEVM_SPEC_DOWNGRADE: u64 = 11;

    /// EVM configuration was given before an EVM spec was published or pending. A node reads the spec
    /// with every other part of the EVM configuration, so none of it is accepted without one.
    const EMISSING_EVM_SPEC: u64 = 12;

    /// The EVM genesis config was given while no EVM spec is published. The EVM is activated by the
    /// reconfiguration that applies that config, and the node deploys the genesis contracts under the
    /// spec in force for that block, so the spec is published in an earlier epoch than the config.
    const EEVM_SPEC_NOT_PUBLISHED: u64 = 13;

    /// Evm and Move address length
    const EVM_ADDRESS_BYTE_LENGTH : u64 = 20;
    const MOVE_ADDRESS_BYTE_LENGTH: u64 = 32;

    #[event]
    struct EvmContractsDetails has key, copy, store, drop {
        details: SimpleMap<String, address>,
    }

    #[event]
    /// The EVM specification this chain executes, as a Supra-owned code: 1 is Prague, 2 is Osaka, and
    /// each later spec takes the next code (#4065).
    ///
    /// The code is Supra's own rather than revm's `SpecId` discriminant, which is positional and has
    /// been reordered upstream. A node maps the code to a `SpecId` when it builds an epoch's
    /// parameters and stops if its binary cannot map it, so a spec upgrade is rolled out as a binary
    /// first and activated here afterwards, at an epoch boundary, on every node at once.
    struct EvmSpec has key, copy, store, drop {
        code: u64,
    }

    /// Publishes the EVM spec at genesis.
    public(friend) fun initialize_spec(supra_framework: &signer, code: u64) {
        system_addresses::assert_supra_framework(supra_framework);
        gas_schedule::assert_supra_evm_gas_feature_version();
        assert!(code > 0, error::invalid_argument(EZERO_EVM_SPEC));
        assert!(!exists<EvmSpec>(@supra_framework), error::invalid_state(ERESOURCE_ALREADY_EXISTS));
        let evm_spec = EvmSpec { code };
        move_to(supra_framework, evm_spec);
        event::emit(evm_spec);
    }

    /// Used by on-chain governance to set the EVM spec for the next epoch.
    ///
    /// Once a spec is published, only a later one is accepted. A value still pending is replaced by a
    /// later call, as `version::set_for_next_epoch` does, and a chain that has none yet (one where
    /// the EVM was not configured at genesis) buffers its first value here.
    /// Example usage:
    /// ```
    /// supra_framework::evm_config::set_spec_for_next_epoch(&framework_signer, 2);
    /// supra_framework::supra_governance::reconfigure(&framework_signer);
    /// ```
    public fun set_spec_for_next_epoch(account: &signer, code: u64) acquires EvmSpec {
        system_addresses::assert_supra_framework(account);
        gas_schedule::assert_supra_evm_gas_feature_version();
        assert!(code > 0, error::invalid_argument(EZERO_EVM_SPEC));
        if (exists<EvmSpec>(@supra_framework)) {
            let current = borrow_global<EvmSpec>(@supra_framework).code;
            assert!(code > current, error::invalid_argument(EEVM_SPEC_DOWNGRADE));
        };
        config_buffer::upsert<EvmSpec>(EvmSpec { code });
    }

    #[view]
    /// Returns the EVM spec code in force. Aborts with EKEY_NOT_FOUND if none is published.
    public fun current_spec(): u64 acquires EvmSpec {
        assert!(exists<EvmSpec>(@supra_framework), error::not_found(EKEY_NOT_FOUND));
        borrow_global<EvmSpec>(@supra_framework).code
    }

    /// Whether an EVM spec is published, or buffered to be published at the next reconfiguration.
    public fun evm_spec_published_or_pending(): bool {
        exists<EvmSpec>(@supra_framework) || config_buffer::does_exist<EvmSpec>()
    }

    /// Aborts with EMISSING_EVM_SPEC unless an EVM spec is published or pending. Called by the
    /// functions that publish or buffer the EVM contract details, which a node reads together with
    /// the spec from the epoch that publishes them.
    public fun assert_evm_spec_published_or_pending() {
        assert!(evm_spec_published_or_pending(), error::invalid_state(EMISSING_EVM_SPEC));
    }

    /// Aborts with EEVM_SPEC_NOT_PUBLISHED unless an EVM spec is published; a pending one does not
    /// count. Called by the functions that publish or buffer the EVM genesis config, the way
    /// `gas_schedule::assert_supra_evm_gas_feature_version` counts only the published schedule: the
    /// spec is set in one epoch and the EVM activated in a later one, so the spec is in force for
    /// the block that activates it.
    public fun assert_evm_spec_published() {
        assert!(exists<EvmSpec>(@supra_framework), error::invalid_state(EEVM_SPEC_NOT_PUBLISHED));
    }

    #[test_only]
    /// Publishes the spec `code` for tests in other modules, which cannot call the genesis-only initializer.
    public fun initialize_spec_for_test(supra_framework: &signer, code: u64) {
        initialize_spec(supra_framework, code);
    }

    /// Publishes EVM contract address map.
    /// `contract_keys`/`contract_values` must be the same length and every address
    /// must be a valid 20-byte EVM address (upper 12 bytes of the 32-byte Move
    /// address must be zero).
    public(friend) fun initialize_contracts_details(
        supra_framework: &signer,
        contract_keys: vector<String>,
        contract_values: vector<address>,
    ) {
        system_addresses::assert_supra_framework(supra_framework);
        gas_schedule::assert_supra_evm_gas_feature_version();
        assert_evm_spec_published_or_pending();
        assert!(!vector::is_empty(&contract_keys), error::invalid_argument(EEMPTY_DATA));
        let supra_framework_addr = signer::address_of(supra_framework);
        assert!(!exists<EvmContractsDetails>(supra_framework_addr),error::invalid_state(ERESOURCE_ALREADY_EXISTS));
        assert!(
            vector::length(&contract_keys) == vector::length(&contract_values),
            error::invalid_argument(EKEYS_VALUES_MISMATCH)
        );

        // Check that no contract value is invalid EVM address
        let all_valid_evm_address = vector::all(&contract_values,
            |v|{ is_valid_evm_address(v) });
        assert!(all_valid_evm_address, error::invalid_argument(EINVALID_EVM_ADDRESS));

        let contract_details = EvmContractsDetails {
            details: simple_map::new_from(contract_keys, contract_values)
        };
        move_to(supra_framework, contract_details);
        event::emit(contract_details);
    }

    /// This can be called by on-chain governance to update on-chain evm contract
    /// details for the next epoch.
    /// Example usage:
    /// ```
    /// supra_framework::evm_config::upsert_evm_contract_details_for_next_epoch(
    ///     &framework_signer, vector["contract1_name"], vector[contract1_address]);
    /// supra_framework::supra_governance::reconfigure(&framework_signer);
    /// ```
    public fun upsert_evm_contract_details_for_next_epoch(
        account: &signer,
        keys: vector<String>,
        values: vector<address>
    ) acquires EvmContractsDetails {
        system_addresses::assert_supra_framework(account);
        gas_schedule::assert_supra_evm_gas_feature_version();
        assert_evm_spec_published_or_pending();
        assert!(!vector::is_empty(&keys), error::invalid_argument(EEMPTY_DATA));
        assert!(
            vector::length(&keys) == vector::length(&values),
            error::invalid_argument(EKEYS_VALUES_MISMATCH)
        );
        let all_valid_evm_address = vector::all(&values, |v| { is_valid_evm_address(v) });
        assert!(all_valid_evm_address, error::invalid_argument(EINVALID_EVM_ADDRESS));
        if (!exists<EvmContractsDetails>(@supra_framework)) {
            std::config_buffer::upsert<EvmContractsDetails>(
                EvmContractsDetails { details: simple_map::new_from(keys, values) }
            );
            return
        };
        let updated_config = *borrow_global<EvmContractsDetails>(@supra_framework);
        vector::zip(keys, values, |key, value| {
            simple_map::upsert(&mut updated_config.details, key, value);
        });
        std::config_buffer::upsert<EvmContractsDetails>(updated_config);
    }

    #[view]
    /// Returns the contract address stored under `key` in the EvmContractsDetails map.
    /// Aborts with EKEY_NOT_FOUND if the resource has not been initialised or the key
    /// is not present in the map.
    public fun get_contract_value(key: String): address acquires EvmContractsDetails {
        assert!(exists<EvmContractsDetails>(@supra_framework), error::not_found(EKEY_NOT_FOUND));
        let details = borrow_global<EvmContractsDetails>(@supra_framework);
        assert!(
            simple_map::contains_key(&details.details, &key),
            error::not_found(EKEY_NOT_FOUND)
        );
        *simple_map::borrow(&details.details, &key)
    }

    fun is_valid_evm_address(addr: &address): bool {
        // BCS serialises a Move `address` as a raw fixed-size 32-byte array in
        // big-endian order (most-significant byte first).  An EVM address is only
        // 20 bytes wide, so when a 20-byte EVM address is stored in a 32-byte Move
        // address the EVM bytes occupy the last 20 positions (indices 12-31) and the
        // leading 12 bytes (indices 0-11) must all be zero.
        // We iterate only over that prefix and bail immediately on the first non-zero
        // byte to avoid unnecessary work.
        let evm_addr_bytes = bcs::to_bytes(addr);

        // Sanity check: BCS encoding of an address is always 32 bytes. If somehow
        // the length differs, the address cannot be valid.
        if (vector::length(&evm_addr_bytes) != MOVE_ADDRESS_BYTE_LENGTH) {
            return false
        };

        // Check that all 12 high-order prefix bytes are zero.  A non-zero byte here
        // means the value cannot fit in 20 bytes and is therefore not a valid EVM address.
        let i = 0u64;
        let addr_length_diff = MOVE_ADDRESS_BYTE_LENGTH - EVM_ADDRESS_BYTE_LENGTH;
        while (i < addr_length_diff) {
            if (*vector::borrow(&evm_addr_bytes, i) != 0u8) {
                // Non-zero prefix byte found - not a valid 20-byte EVM address.
                return false
            };
            i = i + 1;
        };

        true
    }

    /// Only used in reconfigurations to apply a pending `EvmContractsDetails` config and a pending
    /// `EvmSpec`, if any. If supra_framework already holds a resource, overwrite it; otherwise move
    /// it in.
    public(friend) fun on_new_epoch(framework: &signer) acquires EvmContractsDetails, EvmSpec {
        system_addresses::assert_supra_framework(framework);
        if (config_buffer::does_exist<EvmContractsDetails>()) {
            let new_config = config_buffer::extract_v2<EvmContractsDetails>();
            if (!exists<EvmContractsDetails>(@supra_framework)) {
                move_to(framework, new_config);
            } else {
                let old_config = borrow_global_mut<EvmContractsDetails>(@supra_framework);
                *old_config = new_config;
            };
            event::emit(new_config)
        };
        if (config_buffer::does_exist<EvmSpec>()) {
            let new_spec = config_buffer::extract_v2<EvmSpec>();
            if (!exists<EvmSpec>(@supra_framework)) {
                move_to(framework, new_spec);
            } else {
                *borrow_global_mut<EvmSpec>(@supra_framework) = new_spec;
            };
            event::emit(new_spec)
        };
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    /// Verifies that a small address value (@0x1) is accepted as a valid EVM address.
    ///
    /// @0x1 is the 256-bit integer 1.  BCS serialises a Move address as a raw
    /// big-endian 32-byte array, so the most-significant byte is at index 0 and the
    /// least-significant byte (0x01) is at index 31.  The 12 leading bytes
    /// (indices 0-11) are therefore all zero, and the function must return true.
    fun test_valid_evm_address_small_value() {
        // BCS big-endian layout for @0x1 (32 bytes):
        //   index  0 : 0x00
        //   ...
        //   index 30 : 0x00
        //   index 31 : 0x01
        // Leading bytes 0-11 are all 0x00 -> valid 20-byte EVM address.
        assert!(is_valid_evm_address(&@0x1), 0);
    }

    #[test]
    /// Verifies that a full 32-byte address is rejected as an invalid EVM address.
    ///
    /// @0x1000...000 (64 hex digits, most-significant nibble = 1) is the 256-bit
    /// value 2^252.  BCS serialises it as a big-endian byte array, so the
    /// most-significant byte (0x10) lands at index 0 - which falls inside the
    /// leading window [0, 11] that must be entirely zero for a valid EVM address.
    /// The function must therefore return false.
    fun test_invalid_evm_address_full_32_bytes() {
        // BCS big-endian layout for @0x1000...000 (32 bytes):
        //   index  0 : 0x10   <- non-zero prefix byte -> invalid EVM address
        //   index  1 : 0x00
        //   ...
        //   index 31 : 0x00
        assert!(
            is_valid_evm_address(
                &@0x0000000000000000000000001000000000000000000000000000000000000001
            ),
            0
        );

        assert!(
            !is_valid_evm_address(
                &@0x1000000000000000000000000000000000000000000000000000000000000000
            ),
            0
        );
        assert!(
            !is_valid_evm_address(
                &@0x0000000000000000000000011000000000000000000000000000000000000001
            ),
            0
        );

    }

    #[test(supra_framework = @supra_framework)]
    /// Happy-path test: get_contract_value returns the value that was seeded into
    /// EvmContractsDetails.
    fun test_get_contract_value_success(supra_framework: signer) acquires EvmContractsDetails {
        let contract_key = std::string::utf8(b"usdc_contract");
        let contract_addr = @0xA550C18;
        move_to(&supra_framework, EvmContractsDetails {
            details: simple_map::new_from(vector[contract_key], vector[contract_addr])
        });

        assert!(get_contract_value(std::string::utf8(b"usdc_contract")) == contract_addr, 0);
    }

    #[test(supra_framework = @supra_framework)]
    /// Failure test: get_contract_value aborts when the requested key is absent.
    ///
    /// The expected abort code is error::not_found(EKEY_NOT_FOUND)
    /// = (NOT_FOUND_CATEGORY=6 << 16) | EKEY_NOT_FOUND=4 = 0x60004.
    #[expected_failure(abort_code = 0x60004, location = supra_framework::evm_config)]
    fun test_get_contract_value_key_not_found(supra_framework: signer) acquires EvmContractsDetails {
        move_to(&supra_framework, EvmContractsDetails {
            details: simple_map::new_from(
                vector[std::string::utf8(b"existing_key")],
                vector[@0x1]
            )
        });
        get_contract_value(std::string::utf8(b"nonexistent_key"));
    }

    #[test(supra_framework = @supra_framework)]
    /// Failure test: upsert_evm_contract_details_for_next_epoch aborts when any
    /// address in the values vector is not a valid EVM address.
    ///
    /// The call passes one valid address (@0x1, which fits in 20 bytes with all
    /// leading bytes zero) alongside one invalid address whose most-significant
    /// byte is non-zero (@0x1000...000).  The presence of the invalid address
    /// must trigger EINVALID_EVM_ADDRESS regardless of position in the vector.
    /// The expected abort code is error::invalid_argument(EINVALID_EVM_ADDRESS)
    /// = (INVALID_ARGUMENT_CATEGORY=1 << 16) | EINVALID_EVM_ADDRESS=3 = 0x10003.
    #[expected_failure(abort_code = 0x10003, location = supra_framework::evm_config)]
    fun test_upsert_evm_contract_details_mixed_invalid_address(supra_framework: signer) acquires EvmContractsDetails {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        initialize_spec(&supra_framework, 2);
        let keys = vector[
            std::string::utf8(b"valid_contract"),
            std::string::utf8(b"invalid_contract")
        ];
        let values = vector[
            @0x1,                                                                       // valid: fits in 20 bytes
            @0x1000000000000000000000000000000000000000000000000000000000000000         // invalid: high byte non-zero
        ];
        upsert_evm_contract_details_for_next_epoch(&supra_framework, keys, values);
    }

    #[test(supra_framework = @supra_framework)]
    /// A contracts-details upsert against an empty state buffers the whole map, since
    /// `EvmContractsDetails` does not exist yet to merge into.
    fun test_upsert_contract_details_buffers_when_unpublished(
        supra_framework: signer
    ) acquires EvmContractsDetails {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        initialize_spec(&supra_framework, 2);
        upsert_evm_contract_details_for_next_epoch(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );
        assert!(!exists<EvmContractsDetails>(@supra_framework), 0);
        assert!(config_buffer::does_exist<EvmContractsDetails>(), 0);
    }

    #[test(supra_framework = @supra_framework)]
    /// `on_new_epoch` publishes a buffered `EvmContractsDetails` that did not exist before.
    fun test_on_new_epoch_publishes_pending_contracts_details(
        supra_framework: signer
    ) acquires EvmContractsDetails, EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        initialize_spec(&supra_framework, 2);
        upsert_evm_contract_details_for_next_epoch(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );

        on_new_epoch(&supra_framework);

        assert!(exists<EvmContractsDetails>(@supra_framework), 0);
        assert!(get_contract_value(std::string::utf8(b"usdc_contract")) == @0xA550C18, 0);
        assert!(!config_buffer::does_exist<EvmContractsDetails>(), 0);
    }

    #[test(supra_framework = @supra_framework)]
    /// `on_new_epoch` leaves an already-published config alone when nothing is buffered.
    /// Every reconfiguration calls it, so the empty buffer is the common case.
    fun test_on_new_epoch_without_buffered_config_is_a_no_op(
        supra_framework: signer
    ) acquires EvmContractsDetails, EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        initialize_spec(&supra_framework, 2);
        initialize_contracts_details(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );

        on_new_epoch(&supra_framework);

        assert!(get_contract_value(std::string::utf8(b"usdc_contract")) == @0xA550C18, 0);
    }

    #[test(supra_framework = @supra_framework)]
    /// Publishing contract details is refused while the gas schedule is below the version that
    /// carries the `supra.evm.*` entries: gas_schedule's
    /// error::invalid_state(ESUPRA_EVM_GAS_FEATURE_VERSION_TOO_OLD) = 0x30009.
    #[expected_failure(abort_code = 0x30009, location = supra_framework::gas_schedule)]
    fun test_initialize_contracts_details_below_the_supra_evm_gas_feature_version(supra_framework: signer) {
        gas_schedule::initialize_for_test(&supra_framework, 25);
        initialize_contracts_details(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );
    }

    #[test(supra_framework = @supra_framework)]
    /// The same gate on the governance path.
    #[expected_failure(abort_code = 0x30009, location = supra_framework::gas_schedule)]
    fun test_upsert_contract_details_below_the_supra_evm_gas_feature_version(
        supra_framework: signer
    ) acquires EvmContractsDetails {
        config_buffer::initialize(&supra_framework);
        gas_schedule::initialize_for_test(&supra_framework, 25);
        upsert_evm_contract_details_for_next_epoch(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );
    }

    // --- EvmSpec (#4065) ---

    #[test(supra_framework = @supra_framework)]
    /// Genesis publishes the spec, and the view serves it.
    fun test_initialize_spec_publishes_it(supra_framework: signer) acquires EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        assert!(!evm_spec_published_or_pending(), 0);
        initialize_spec(&supra_framework, 1);
        assert!(current_spec() == 1, 1);
        assert!(evm_spec_published_or_pending(), 2);
    }

    #[test(supra_framework = @supra_framework)]
    /// error::invalid_argument(EZERO_EVM_SPEC) = 0x1000a.
    #[expected_failure(abort_code = 0x1000a, location = supra_framework::evm_config)]
    fun test_initialize_spec_refuses_zero(supra_framework: signer) {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        initialize_spec(&supra_framework, 0);
    }

    #[test(supra_framework = @supra_framework)]
    /// error::invalid_state(ERESOURCE_ALREADY_EXISTS) = 0x30006.
    #[expected_failure(abort_code = 0x30006, location = supra_framework::evm_config)]
    fun test_initialize_spec_twice_is_refused(supra_framework: signer) {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        initialize_spec(&supra_framework, 1);
        initialize_spec(&supra_framework, 2);
    }

    #[test(supra_framework = @supra_framework)]
    /// gas_schedule's error::invalid_state(ESUPRA_EVM_GAS_FEATURE_VERSION_TOO_OLD) = 0x30009.
    #[expected_failure(abort_code = 0x30009, location = supra_framework::gas_schedule)]
    fun test_initialize_spec_below_the_supra_evm_gas_feature_version(supra_framework: signer) {
        gas_schedule::initialize_for_test(&supra_framework, 25);
        initialize_spec(&supra_framework, 1);
    }

    #[test(supra_framework = @supra_framework)]
    /// The same gate on the governance path.
    #[expected_failure(abort_code = 0x30009, location = supra_framework::gas_schedule)]
    fun test_set_spec_below_the_supra_evm_gas_feature_version(supra_framework: signer) acquires EvmSpec {
        config_buffer::initialize(&supra_framework);
        gas_schedule::initialize_for_test(&supra_framework, 25);
        set_spec_for_next_epoch(&supra_framework, 1);
    }

    #[test(supra_framework = @supra_framework)]
    /// A later spec is buffered and takes effect at the next reconfiguration, not before.
    fun test_set_spec_upgrade_applies_at_the_next_epoch(
        supra_framework: signer
    ) acquires EvmContractsDetails, EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        initialize_spec(&supra_framework, 1);

        set_spec_for_next_epoch(&supra_framework, 2);
        assert!(current_spec() == 1, 0);

        on_new_epoch(&supra_framework);
        assert!(current_spec() == 2, 1);
        assert!(!config_buffer::does_exist<EvmSpec>(), 2);
    }

    #[test(supra_framework = @supra_framework)]
    /// Setting the published spec again is refused: error::invalid_argument(EEVM_SPEC_DOWNGRADE)
    /// = 0x1000b.
    #[expected_failure(abort_code = 0x1000b, location = supra_framework::evm_config)]
    fun test_set_spec_equal_is_refused(supra_framework: signer) acquires EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        initialize_spec(&supra_framework, 2);
        set_spec_for_next_epoch(&supra_framework, 2);
    }

    #[test(supra_framework = @supra_framework)]
    /// A spec below the published one is refused.
    #[expected_failure(abort_code = 0x1000b, location = supra_framework::evm_config)]
    fun test_set_spec_downgrade_is_refused(supra_framework: signer) acquires EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        initialize_spec(&supra_framework, 2);
        set_spec_for_next_epoch(&supra_framework, 1);
    }

    #[test(supra_framework = @supra_framework)]
    /// Zero is refused on the governance path as well.
    #[expected_failure(abort_code = 0x1000a, location = supra_framework::evm_config)]
    fun test_set_spec_zero_is_refused(supra_framework: signer) acquires EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        set_spec_for_next_epoch(&supra_framework, 0);
    }

    #[test(supra_framework = @supra_framework)]
    /// On a chain with no spec, governance buffers the first one, and a later proposal before the
    /// reconfiguration replaces it.
    fun test_set_spec_buffers_a_first_value_and_a_later_call_wins(
        supra_framework: signer
    ) acquires EvmContractsDetails, EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);

        set_spec_for_next_epoch(&supra_framework, 2);
        assert!(!exists<EvmSpec>(@supra_framework), 0);
        assert!(evm_spec_published_or_pending(), 1);
        set_spec_for_next_epoch(&supra_framework, 1);

        on_new_epoch(&supra_framework);
        assert!(current_spec() == 1, 2);
    }

    #[test]
    /// error::not_found(EKEY_NOT_FOUND) = 0x60004.
    #[expected_failure(abort_code = 0x60004, location = supra_framework::evm_config)]
    fun test_current_spec_without_one_aborts() acquires EvmSpec {
        current_spec();
    }

    #[test(supra_framework = @supra_framework)]
    /// Contract details are refused at genesis without a spec:
    /// error::invalid_state(EMISSING_EVM_SPEC) = 0x3000c.
    #[expected_failure(abort_code = 0x3000c, location = supra_framework::evm_config)]
    fun test_initialize_contracts_details_without_a_spec_is_refused(supra_framework: signer) {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        initialize_contracts_details(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );
    }

    #[test(supra_framework = @supra_framework)]
    /// And through governance.
    #[expected_failure(abort_code = 0x3000c, location = supra_framework::evm_config)]
    fun test_upsert_contract_details_without_a_spec_is_refused(
        supra_framework: signer
    ) acquires EvmContractsDetails {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        upsert_evm_contract_details_for_next_epoch(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );
    }

    #[test(supra_framework = @supra_framework)]
    /// A spec buffered in the same proposal satisfies the guard, and the reconfiguration publishes
    /// both together.
    fun test_upsert_contract_details_with_a_pending_spec_is_accepted(
        supra_framework: signer
    ) acquires EvmContractsDetails, EvmSpec {
        gas_schedule::initialize_for_test(&supra_framework, 26);
        config_buffer::initialize(&supra_framework);
        set_spec_for_next_epoch(&supra_framework, 2);
        upsert_evm_contract_details_for_next_epoch(
            &supra_framework,
            vector[std::string::utf8(b"usdc_contract")],
            vector[@0xA550C18]
        );

        on_new_epoch(&supra_framework);
        assert!(current_spec() == 2, 0);
        assert!(get_contract_value(std::string::utf8(b"usdc_contract")) == @0xA550C18, 1);
    }
}

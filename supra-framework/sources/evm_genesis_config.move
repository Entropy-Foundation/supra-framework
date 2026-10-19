module supra_framework::evm_genesis_config {
    use std::error;
    use std::vector;
    use supra_framework::config_buffer;
    use supra_framework::event;
    use supra_framework::evm_config;
    use supra_framework::gas_schedule;

    use supra_framework::system_addresses;

    friend supra_framework::genesis;
    friend supra_framework::reconfiguration_with_dkg;

    #[test_only]
    friend supra_framework::test_evm_genesis_config;

    /// The struct stores the on-chain EVM genesis configuration.
    // Note: Serialized bytes of `OnChainEvmGenesisConfig` in rust layer.
    struct EvmGenesisConfig has drop, key, store {
        config: vector<u8>
    }

    #[event]
    /// Event to signal EVM genesis config has been initialized or updated.
    struct EvmGenesisEvent has drop, store {}

    /// The provided on chain config bytes are empty or invalid
    const EINVALID_CONFIG: u64 = 1;

    /// Evm genesis config is already initialized, cannot be initialized again.
    const EALREADY_INITIALISED: u64 = 2;

    /// Publishes the EvmGenesisConfig config.
    public(friend) fun initialize(
        supra_framework: &signer, config: vector<u8>
    ) {
        system_addresses::assert_supra_framework(supra_framework);
        gas_schedule::assert_supra_evm_gas_feature_version();
        // The EVM executes under the spec in `evm_config`, so it is not configured without one.
        evm_config::assert_evm_spec_published();
        assert!(!vector::is_empty(&config), error::invalid_argument(EINVALID_CONFIG));
        move_to(supra_framework, EvmGenesisConfig { config });
        event::emit(EvmGenesisEvent {});
    }

    /// This can be called by on-chain governance to update on-chain evm configs for the next epoch.
    ///
    /// Note that once an EVM genesis config has been applied on-chain (via genesis or a prior
    /// reconfiguration), it cannot be replaced: this function will abort if the config already
    /// exists. Before that point, a value buffered by a call to this function is still pending
    /// and can be overwritten by a later call, as long as reconfiguration hasn't applied it yet.
    /// This Move-level guard is the only enforcement in this repository; any consensus or
    /// execution-layer handling of the EVM genesis config lives in a separate, private codebase
    /// and is out of scope here. EVM foundation owners maintaining the genesis contracts should
    /// keep that logic consistent with this guard when making future changes.
    /// Example usage:
    /// ```
    /// supra_framework::evm_genesis_config::set_for_next_epoch(&framework_signer, some_config_bytes);
    /// supra_framework::supra_governance::reconfigure(&framework_signer);
    /// ```
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_supra_framework(account);
        gas_schedule::assert_supra_evm_gas_feature_version();
        // This config activates the EVM when a reconfiguration applies it, and the genesis contracts
        // are deployed under the spec in force for that block. A spec still pending would only be
        // applied by that same reconfiguration, so it does not count (#4065).
        evm_config::assert_evm_spec_published();
        assert!(!vector::is_empty(&config), error::invalid_argument(EINVALID_CONFIG));
        assert!(!exists<EvmGenesisConfig>(@supra_framework), error::already_exists(EALREADY_INITIALISED));
        assert!(
            is_valid_evm_genesis_config_internal(config),
            error::invalid_argument(EINVALID_CONFIG)
        );
        std::config_buffer::upsert<EvmGenesisConfig>(EvmGenesisConfig { config });
    }

    /// Returns true iff `config_bytes` BCS-deserializes into `OnChainEvmGenesisConfig`
    /// (types/src/on_chain_config/evm_genesis_config.rs) AND the resulting config passes
    /// its semantic validity checks (non-zero chain ID, well-formed hex EVM addresses without 0x prefix).
    native fun is_valid_evm_genesis_config_internal(config_bytes: vector<u8>): bool;

    /// Only used in reconfigurations to apply the pending `EvmGenesisConfig` in buffer, if there is any.
    /// If supra_framework has a EvmGenesisConfig, the new config will be ignored and not applied.
    /// Otherwise, move the new config to supra_framework.
    public(friend) fun on_new_epoch(framework: &signer) {
        system_addresses::assert_supra_framework(framework);
        if (config_buffer::does_exist<EvmGenesisConfig>()) {
            let new_config = config_buffer::extract_v2<EvmGenesisConfig>();
            if (!exists<EvmGenesisConfig>(@supra_framework)) {
                move_to(framework, new_config);
                event::emit(EvmGenesisEvent {});
            };
        }
    }

    #[test_only]
    public fun evm_genesis_config_exists(): bool {
        exists<EvmGenesisConfig>(@supra_framework)
    }

    #[test_only]
    public fun get_config(): vector<u8> acquires EvmGenesisConfig {
        borrow_global<EvmGenesisConfig>(@supra_framework).config
    }
}

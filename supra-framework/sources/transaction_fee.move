/// This module provides an interface to burn or collect and redistribute transaction fees.
module supra_framework::transaction_fee {
    use supra_framework::coin::{Self, AggregatableCoin, BurnCapability, MintCapability};
    use supra_framework::supra_account;
    use supra_framework::supra_coin::SupraCoin;
    use supra_framework::fungible_asset::BurnRef;
    use supra_framework::system_addresses;
    use std::error;
    use std::features;
    use std::option::{Self, Option};
    use std::signer;
    use supra_framework::event;

    friend supra_framework::block;
    friend supra_framework::evm_settlement;
    friend supra_framework::genesis;
    friend supra_framework::reconfiguration;
    friend supra_framework::transaction_validation;

    /// No longer supported.
    const ENO_LONGER_SUPPORTED: u64 = 4;

    const EFA_GAS_CHARGING_NOT_ENABLED: u64 = 5;

    /// The `SupraCoin` burn capability is no longer held: `convert_to_aptos_fa_burn_ref` has
    /// converted it into the paired `BurnRef`.
    const ENO_SUPRA_COIN_BURN_CAPABILITY: u64 = 6;

    /// Stores burn capability to burn the gas fees.
    struct SupraCoinCapabilities has key {
        burn_cap: BurnCapability<SupraCoin>,
    }

    /// Stores burn capability to burn the gas fees.
    struct SupraFABurnCapabilities has key {
        burn_ref: BurnRef,
    }

    /// Stores mint capability to mint the refunds.
    struct SupraCoinMintCapability has key {
        mint_cap: MintCapability<SupraCoin>,
    }

    /// Retired with gas fee collection and distribution (`COLLECT_AND_DISTRIBUTE_GAS_FEES`,
    /// Entropy-Foundation/smr-moonshot#4786): it is no longer published or read, and is kept because a published
    /// struct cannot be removed.
    struct CollectedFeesPerBlock has key {
        amount: AggregatableCoin<SupraCoin>,
        proposer: Option<address>,
        burn_percentage: u8,
    }

    #[event]
    /// Breakdown of fee charge and refund for a transaction.
    /// The structure is:
    ///
    /// - Net charge or refund (not in the statement)
    ///    - total charge: total_charge_gas_units, matches `gas_used` in the on-chain `TransactionInfo`.
    ///      This is the sum of the sub-items below. Notice that there's potential precision loss when
    ///      the conversion between internal and external gas units and between native token and gas
    ///      units, so it's possible that the numbers don't add up exactly. -- This number is the final
    ///      charge, while the break down is merely informational.
    ///        - gas charge for execution (CPU time): `execution_gas_units`
    ///        - gas charge for IO (storage random access): `io_gas_units`
    ///        - storage fee charge (storage space): `storage_fee_quants`, to be included in
    ///          `total_charge_gas_unit`, this number is converted to gas units according to the user
    ///          specified `gas_unit_price` on the transaction.
    ///    - storage deletion refund: `storage_fee_refund_quants`, this is not included in `gas_used` or
    ///      `total_charge_gas_units`, the net charge / refund is calculated by
    ///      `total_charge_gas_units` * `gas_unit_price` - `storage_fee_refund_quants`.
    ///
    /// This is meant to emitted as a module event.
    struct FeeStatement has drop, store {
        /// Total gas charge.
        total_charge_gas_units: u64,
        /// Execution gas charge.
        execution_gas_units: u64,
        /// IO gas charge.
        io_gas_units: u64,
        /// Storage fee charge.
        storage_fee_quants: u64,
        /// Storage fee refund.
        storage_fee_refund_quants: u64,
    }

    #[event]
    /// Breakdown of the gas consumed by gas-fee-less (i.e. gasless) transactions.
    /// The consumed amounts serve as a record of the workload of the transaction and
    /// are not charged to the gas payer's account.
    struct GasAssessment has drop, store {
        /// Total gas assessed for transaction execution.
        total_assessed_gas_units: u64,
        /// Execution gas charge.
        execution_gas_units: u64,
        /// IO gas charge.
        io_gas_units: u64,
        /// Storage fee charge.
        storage_fee_quants: u64,
        /// Storage fee refund.
        storage_fee_refund_quants: u64,
    }

    #[deprecated]
    /// Gas fee collection and distribution (`COLLECT_AND_DISTRIBUTE_GAS_FEES`) is retired
    /// (Entropy-Foundation/smr-moonshot#4786): the transaction epilogue burns every fee.
    public fun initialize_fee_collection_and_distribution(_supra_framework: &signer, _burn_percentage: u8) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    #[deprecated]
    /// Gas fee collection and distribution is retired (Entropy-Foundation/smr-moonshot#4786), so there is no
    /// burn percentage to set.
    public fun upgrade_burn_percentage(
        _supra_framework: &signer,
        _new_burn_percentage: u8
    ) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    /// Burn transaction fees in epilogue.
    public(friend) fun burn_fee(account: address, fee: u64) acquires SupraFABurnCapabilities, SupraCoinCapabilities {
        if (exists<SupraFABurnCapabilities>(@supra_framework)) {
            let burn_ref = &borrow_global<SupraFABurnCapabilities>(@supra_framework).burn_ref;
            supra_account::burn_from_fungible_store(burn_ref, account, fee);
        } else {
            let burn_cap = &borrow_global<SupraCoinCapabilities>(@supra_framework).burn_cap;
            if (features::operations_default_to_fa_supra_store_enabled()) {
                let (burn_ref, burn_receipt) = coin::get_paired_burn_ref(burn_cap);
                supra_account::burn_from_fungible_store(&burn_ref, account, fee);
                coin::return_paired_burn_ref(burn_ref, burn_receipt);
            } else {
                coin::burn_from<SupraCoin>(
                    account,
                    fee,
                    burn_cap,
                );
            };
        };
    }

    /// Mint refund in epilogue.
    public(friend) fun mint_and_refund(account: address, refund: u64) acquires SupraCoinMintCapability {
        let mint_cap = &borrow_global<SupraCoinMintCapability>(@supra_framework).mint_cap;
        let refund_coin = coin::mint(refund, mint_cap);
        coin::force_deposit(account, refund_coin);
    }

    /// Only called during genesis.
    public(friend) fun store_supra_coin_burn_cap(supra_framework: &signer, burn_cap: BurnCapability<SupraCoin>) {
        system_addresses::assert_supra_framework(supra_framework);

        if (features::operations_default_to_fa_supra_store_enabled()) {
            let burn_ref = coin::convert_and_take_paired_burn_ref(burn_cap);
            move_to(supra_framework, SupraFABurnCapabilities { burn_ref });
        } else {
            move_to(supra_framework, SupraCoinCapabilities { burn_cap })
        }
    }

    /// A copy of the `SupraCoin` burn capability held by this module.
    ///
    /// `BurnCapability` is copyable, so a copy taken here leaves this module's own intact and
    /// deprives no other holder. This is the only way a module can be given the capability after
    /// genesis: `supra_coin::initialize` mints it once and cannot run again, and every other
    /// function that returns one is either restricted to genesis or test-only.
    ///
    /// Friend-only, so that the copy stays inside the framework: its one caller is
    /// `evm_settlement::initialize`, which stores it in the escrow it creates. A copy returned to
    /// a script could be stored anywhere, and a `BurnCapability` cannot be revoked.
    ///
    /// Aborts when this module holds no `SupraCoinCapabilities`, which is either of the two states
    /// in which it holds a `BurnRef` instead: `convert_to_aptos_fa_burn_ref` has run, or
    /// `store_supra_coin_burn_cap` took its `operations_default_to_fa_supra_store_enabled` branch
    /// at genesis. Neither is recoverable, because the conversion consumes the capability and none
    /// can be minted to replace it, so the abort reports a property of the chain rather than of
    /// the request.
    public(friend) fun copy_supra_coin_burn_cap(
        supra_framework: &signer
    ): BurnCapability<SupraCoin> acquires SupraCoinCapabilities {
        system_addresses::assert_supra_framework(supra_framework);
        assert!(
            exists<SupraCoinCapabilities>(@supra_framework),
            error::not_found(ENO_SUPRA_COIN_BURN_CAPABILITY),
        );
        borrow_global<SupraCoinCapabilities>(@supra_framework).burn_cap
    }

    public entry fun convert_to_aptos_fa_burn_ref(supra_framework: &signer) acquires SupraCoinCapabilities {
        assert!(features::operations_default_to_fa_supra_store_enabled(), EFA_GAS_CHARGING_NOT_ENABLED);
        system_addresses::assert_supra_framework(supra_framework);
        let SupraCoinCapabilities {
            burn_cap,
        } = move_from<SupraCoinCapabilities>(signer::address_of(supra_framework));
        let burn_ref = coin::convert_and_take_paired_burn_ref(burn_cap);
        move_to(supra_framework, SupraFABurnCapabilities { burn_ref });
    }

    /// Only called during genesis.
    public(friend) fun store_supra_coin_mint_cap(supra_framework: &signer, mint_cap: MintCapability<SupraCoin>) {
        system_addresses::assert_supra_framework(supra_framework);
        move_to(supra_framework, SupraCoinMintCapability { mint_cap })
    }

    #[deprecated]
    public fun initialize_storage_refund(_: &signer) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    // Called by the VM after epilogue.
    fun emit_fee_statement(fee_statement: FeeStatement) {
        event::emit(fee_statement)
    }

    // Called by the VM after epilogue for gas-less transactions to report fee assessment
    fun emit_gas_assessment(fee_statement: FeeStatement) {
        let FeeStatement {
            total_charge_gas_units,
            execution_gas_units,
            io_gas_units,
            storage_fee_quants,
            storage_fee_refund_quants,

        } = fee_statement;
        let gas_assesment = GasAssessment {
            total_assessed_gas_units: total_charge_gas_units,
            execution_gas_units,
            io_gas_units,
            storage_fee_quants,
            storage_fee_refund_quants,

        };
        event::emit(gas_assesment)
    }

    #[test(supra_framework = @supra_framework)]
    #[expected_failure(abort_code = 0xC0004, location = Self)]
    fun test_initialize_fee_collection_and_distribution_is_no_longer_supported(supra_framework: signer) {
        initialize_fee_collection_and_distribution(&supra_framework, 25);
    }

    #[test(supra_framework = @supra_framework)]
    #[expected_failure(abort_code = 0xC0004, location = Self)]
    fun test_upgrade_burn_percentage_is_no_longer_supported(supra_framework: signer) {
        upgrade_burn_percentage(&supra_framework, 25);
    }
}

/// Reconfiguration with DKG helper functions.
module supra_framework::reconfiguration_with_dkg {
    use std::features;
    use std::option;
    use std::vector;
    use supra_framework::evm_config;
    use supra_framework::automation_registry;
    use supra_framework::randomness;
    use supra_framework::consensus_config;
    use supra_framework::supra_dkg;
    use supra_framework::dkg_config;
    use supra_framework::execution_config;
    use supra_framework::gas_schedule;
    use supra_framework::jwk_consensus_config;
    use supra_framework::jwks;
    use supra_framework::keyless_account;
    use supra_framework::leader_ban_registry_config;
    use supra_framework::randomness_api_v0_config;
    use supra_framework::randomness_config;
    use supra_framework::randomness_config_seqnum;
    use supra_framework::reconfiguration;
    use supra_framework::reconfiguration_state;
    use supra_framework::stake;
    use supra_framework::supra_config;
    use supra_framework::system_addresses;
    use supra_framework::evm_genesis_config;

    friend supra_framework::block;
    friend supra_framework::supra_governance;

    /// Trigger a reconfiguration with DKG.
    /// Do nothing if one is already in progress.
    public(friend) fun try_start() {
        let incomplete_dealer_epoch = supra_dkg::incomplete_session_dealer_epoch();
        if (option::is_some(&incomplete_dealer_epoch)) {
            if (*option::borrow(&incomplete_dealer_epoch)
                == reconfiguration::current_epoch()) { return }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        let randomness_seed = randomness::bytes(32);

        // Get DKG configuration (dealer threshold type and receiver committee configs)
        let config = dkg_config::current();
        let receiver_configs = dkg_config::get_receiver_committee_configs(&config);

        // Each receiver committee this function builds is given the same membership, the next
        // epoch's validators, and differs from the others only in its threshold type. So the set is
        // read once rather than per committee, which would repeat every stake pool read it entails.
        //
        // That is a choice made here, not a property of receiver committees. One thing currently
        // depends on it and would have to change to draw a committee from a subset:
        // `supra_dkg::finish` installs the DKG output keys of every committee against a single
        // ordering. See smr-moonshot#3362.
        let target_validators = stake::next_epoch_validator_consensus_infos_for_dkg();

        // Build receiver committees from config
        let receiver_committees = vector[];
        let i = 0;
        let len = vector::length(&receiver_configs);
        while (i < len) {
            let rc = vector::borrow(&receiver_configs, i);
            vector::push_back(
                &mut receiver_committees,
                supra_dkg::new_receiver_committee_v2(
                    dkg_config::get_is_resharing(rc),
                    dkg_config::get_dkg_threshold_type(rc),
                    supra_dkg::new_dkg_committee_v2_from_validator_consensus_info(
                        target_validators, dkg_config::get_committee_threshold_type(rc)
                    )
                )
            );
            i = i + 1;
        };

        // DKG for configured receiver committees
        supra_dkg::start_v2(
            cur_epoch,
            randomness_seed,
            supra_dkg::new_dkg_committee_v2_from_validator_consensus_info(
                stake::cur_validator_consensus_infos(),
                dkg_config::get_dealer_committee_threshold_type(&config)
            ),
            receiver_committees
        );
    }

    fun set_dkg_meta(dkg_meta: vector<u8>) {
        supra_dkg::set_dkg_meta(dkg_meta);
    }

    /// Clear incomplete DKG session, if it exists.
    /// Apply buffered on-chain configs (except for ValidatorSet, which is done inside `reconfiguration::reconfigure()`).
    /// Re-enable validator set changes.
    /// Run the default reconfiguration to enter the new epoch.
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_supra_framework(framework);
        supra_dkg::try_clear_incomplete_session(framework);
        consensus_config::on_new_epoch(framework);
        execution_config::on_new_epoch(framework);
        supra_config::on_new_epoch(framework);
        gas_schedule::on_new_epoch(framework);
        std::version::on_new_epoch(framework);
        features::on_new_epoch(framework);
        automation_registry::on_new_epoch();
        jwk_consensus_config::on_new_epoch(framework);
        jwks::on_new_epoch(framework);
        keyless_account::on_new_epoch(framework);
        leader_ban_registry_config::on_new_epoch(framework);
        randomness_config_seqnum::on_new_epoch(framework);
        randomness_config::on_new_epoch(framework);
        randomness_api_v0_config::on_new_epoch(framework);
        evm_genesis_config::on_new_epoch(framework);
        dkg_config::on_new_epoch(framework);
        evm_config::on_new_epoch(framework);
        // `staking_config::on_new_epoch` is deliberately absent from this list: the epoch
        // transition itself reads the staking config, so it is applied at the tail of
        // `reconfiguration::reconfigure()` - after `stake::on_new_epoch` - which also covers
        // the six other epoch-transition paths that do not route through this function.
        reconfiguration::reconfigure();
    }

    /// Complete the current reconfiguration with DKG.
    /// Abort if no DKG is in progress.
    fun finish_with_dkg_result(account: &signer, dkg_result: vector<u8>) {
        // `supra_dkg::finish` declines a session that has no DKG meta transcript yet, changing
        // nothing. There is then no DKG output to reconfigure against, so the epoch must not
        // advance either: the session stays in progress for the producer to complete once the
        // meta has landed. See smr-moonshot#3645.
        if (!supra_dkg::finish(dkg_result)) { return };
        finish(account);
    }
}

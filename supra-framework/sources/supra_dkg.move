// Copyright (c) 2024 Supra.
/// DKG on-chain states and helper functions.
module supra_framework::supra_dkg {
    use std::dkg_committee::{
        DkgCommittee,
        DkgCommitteeOutput,
        ReceiverCommittee,
        get_dkg_committee_output_keys,
        new_dkg_committee_output
    };
    use std::error;
    use std::option;
    use std::option::{Option};
    use std::vector;
    use supra_framework::create_signer::create_signer;
    use supra_framework::event::emit;
    use supra_framework::util;
    use supra_framework::system_addresses;
    use supra_framework::timestamp;
    use supra_framework::stake;
    use supra_framework::validator_consensus_info;
    use supra_framework::validator_consensus_info::ValidatorConsensusInfo;
    use supra_framework::validator_public_keys;
    use supra_framework::validator_public_keys::CertificateThresholdType;

    friend supra_framework::block;
    friend supra_framework::reconfiguration_with_dkg;

    const EDKG_NOT_IN_PROGRESS: u64 = 1;
    const EDKG_META_ALREADY_SET: u64 = 2;
    /// Retained so the code is not reused.
    const EDKG_META_NOT_SET: u64 = 3;
    const EDKG_INVALID_PK_SHARES: u64 = 4;
    /// A session was started without any target committee, so there is no member ordering to
    /// install the DKG output keys against.
    const EDKG_NO_TARGET_COMMITTEE: u64 = 5;
    /// A committee was built with no members.
    const EDKG_EMPTY_COMMITTEE: u64 = 6;
    /// A commitment in the DKG output carries no evaluations, so it has no committee public key at
    /// index 0 and no key shares after it.
    const EDKG_EMPTY_COMMITMENT_EVALS: u64 = 7;
    /// A commitment in the DKG output names a threshold type that
    /// `validator_public_keys::rotate_supra_bls_threshold_key_by_type` does not install a key for.
    const EDKG_UNINSTALLABLE_THRESHOLD_TYPE: u64 = 8;
    /// A commitment in the DKG output carries a number of key shares other than the number of
    /// members in the session's target committee.
    const EDKG_SHARE_COUNT_MISMATCH: u64 = 9;

    #[event]
    struct DKGStartEvent has drop, store {
        session_metadata: DKGSessionMetadata,
        start_time_us: u64
    }

    #[event]
    /// Announces that a DKG session has started. Supersedes `DKGStartEvent`, which embedded a third
    /// full copy of the session's committees; validators only ever read the epoch from it and take
    /// the committees from the session resource itself.
    struct DKGStartEventV2 has drop, store {
        dealer_epoch: u64,
        start_time_us: u64
    }

    #[event]
    struct DKGMetaSetEvent has drop, store {
        dkg_meta_transcript: vector<u8>
    }

    #[event]
    struct DKGFinishEvent has drop, store {
        target_committees_public_key_shares: vector<u8>
    }

    #[event]
    /// Announces that a `finish` call declined because the in-progress session, in whichever slot
    /// holds it, has no DKG meta transcript. The declined call changed nothing.
    struct DKGFinishDeferredEvent has drop, store {
        dealer_epoch: u64
    }

    /// This can be considered as the public input of DKG.
    struct DKGSessionMetadata has copy, drop, store {
        dealer_epoch: u64,
        randomness_seed: vector<u8>,
        dealer_committee: DkgCommittee,
        target_committees: vector<ReceiverCommittee>
    }

    /// The input and output of a DKG session.
    /// The validator set of epoch `x` works together for an DKG output for the target validator set of epoch `x+1`.
    struct DKGSessionState has copy, store, drop {
        metadata: DKGSessionMetadata,
        start_time_us: u64,
        dkg_meta_transcript: vector<u8>,
        target_committees_public_key_shares: vector<u8>
    }

    /// The completed and in-progress DKG sessions.
    ///
    /// Superseded by `DkgSessionInProgress` and `DkgSessionLastCompleted`. Retained because it holds
    /// any session that was already running when those were introduced, and because removing a
    /// published resource is not an upgrade-compatible change. Once both of its slots are `none` it
    /// stays that way forever.
    struct DKGState has key {
        last_completed: Option<DKGSessionState>,
        in_progress: Option<DKGSessionState>
    }

    /// A DKG committee, as the validators that comprise it.
    ///
    /// Only the members are recorded, not their keys. `ValidatorSet` already holds each validator's
    /// configuration for the duration of an epoch, and `stake::PreviousValidatorSet` keeps the
    /// preceding epoch's, which together cover every epoch a session refers to. Copying the keys in
    /// here as well would make the validator set no longer the single record of them, and would cost
    /// ~1.4 KB per member per committee - enough that a session outgrew the per-item write limit.
    ///
    /// The order of `members` is load-bearing, not incidental: it is the index basis that
    /// `stake::set_dkg_output_keys_for_members` uses to match DKG output key shares to validators,
    /// and that the consensus layer reproduces when it assigns each validator its DKG node number.
    ///
    /// Which validators a committee holds is up to whoever builds it. Every committee in a session
    /// happens to be built from the same membership today, but that is a property of
    /// `reconfiguration_with_dkg::try_start`, not of this type.
    struct DkgCommitteeV2 has copy, drop, store {
        members: vector<address>,
        /// The threshold type for the committee's Byzantine fault tolerance.
        threshold_type: CertificateThresholdType
    }

    struct ReceiverCommitteeV2 has copy, drop, store {
        is_resharing: bool,
        /// The threshold type for the output key of the DKG process.
        dkg_threshold_type: CertificateThresholdType,
        committee: DkgCommitteeV2
    }

    /// The public input of a DKG session.
    ///
    /// Supersedes `DKGSessionMetadata`. The committees record only which validators comprise them;
    /// their keys stay in the validator set, which retains them for the whole epoch and which
    /// `stake::PreviousValidatorSet` extends back over the epoch that dealt a completed session.
    /// Copying them in here instead cost ~1.4 KB per member per committee, which is what pushed a
    /// session past the per-item write limit.
    struct DKGSessionMetadataV2 has copy, drop, store {
        dealer_epoch: u64,
        randomness_seed: vector<u8>,
        dealer_committee: DkgCommitteeV2,
        /// The committees this session deals to, each with its own threshold type.
        ///
        /// A committee's membership is whatever its caller passed; the type does not constrain it
        /// to any particular set of validators. What the current *installation* path constrains is
        /// narrower: `finish` hands `stake::set_dkg_output_keys_for_members` one ordering for all
        /// of them, so it is only correct while every entry carries the same membership - which is
        /// how `reconfiguration_with_dkg::try_start` builds them today. Committees drawn from
        /// different memberships need that path to carry one per committee first; see
        /// smr-moonshot#3362.
        target_committees: vector<ReceiverCommitteeV2>
    }

    /// The input and output of a DKG session. Supersedes `DKGSessionState`.
    /// The validator set of epoch `x` works together for an DKG output for the target validator set of epoch `x+1`.
    struct DKGSessionStateV2 has copy, store, drop {
        metadata: DKGSessionMetadataV2,
        start_time_us: u64,
        dkg_meta_transcript: vector<u8>,
        target_committees_public_key_shares: vector<u8>
    }

    /// The running DKG session, if any.
    ///
    /// Held separately from `DkgSessionLastCompleted` so that the two sessions are distinct state
    /// items with their own write-op size budgets, and so that starting a session does not rewrite
    /// the previous one.
    struct DkgSessionInProgress has key {
        session: Option<DKGSessionStateV2>
    }

    /// The most recently completed DKG session, if any.
    struct DkgSessionLastCompleted has key {
        session: Option<DKGSessionStateV2>
    }

    struct OnChainAggregateCommitment has copy, drop {
        bls12381_commitment_g: vector<u8>,
        bls12381_commitment_evals: vector<vector<u8>>,
        dealer_ids: vector<u32>,
        committee_index: u32,
        epoch: u64,
        chain_id: u8,
        threshold_type: u8
    }

    struct OnChainAggregateCommitmentAllCommittees has copy, drop {
        commitments: vector<OnChainAggregateCommitment>
    }

    /// Called in genesis to initialize on-chain states when DKG is active from genesis,
    /// otherwise, must be called from a governance script before the DKG feature flag
    /// is activated.
    public fun initialize(supra_framework: &signer) acquires DKGState {
        system_addresses::assert_supra_framework(supra_framework);
        if (!exists<DKGState>(@supra_framework)) {
            move_to<DKGState>(
                supra_framework,
                DKGState {
                    last_completed: std::option::none(),
                    in_progress: std::option::none()
                }
            );
        };
        // Not while a session that predates this slot is still running. The VM's validator for DKG
        // transactions takes the mere existence of `DkgSessionInProgress` as the signal that the new
        // layout is authoritative, so creating it early would make it reject that session's own
        // `set_dkg_meta` and `finish` - transactions this module would still accept, down the legacy
        // branch. `start_v2` creates the slot and retires the legacy session in one transaction, so
        // the two never disagree when it is left to do the work.
        if (!exists<DkgSessionInProgress>(@supra_framework) && !has_legacy_in_progress()) {
            move_to<DkgSessionInProgress>(
                supra_framework, DkgSessionInProgress { session: option::none() }
            );
        };
        if (!exists<DkgSessionLastCompleted>(@supra_framework)) {
            move_to<DkgSessionLastCompleted>(
                supra_framework, DkgSessionLastCompleted { session: option::none() }
            );
        };
    }

    /// Create the session resources if they are absent, as they are on any chain whose `DKGState`
    /// predates them.
    ///
    /// Sessions are driven from the block prologue and from VM-dispatched validator transactions,
    /// neither of which carries a framework signer, so this cannot wait to be handed one.
    fun ensure_initialized_v2() {
        if (!exists<DkgSessionInProgress>(@supra_framework)) {
            move_to<DkgSessionInProgress>(
                &create_signer(@supra_framework),
                DkgSessionInProgress { session: option::none() }
            );
        };
        if (!exists<DkgSessionLastCompleted>(@supra_framework)) {
            move_to<DkgSessionLastCompleted>(
                &create_signer(@supra_framework),
                DkgSessionLastCompleted { session: option::none() }
            );
        };
    }

    /// Whether a session started before `DkgSessionInProgress` existed is still running.
    ///
    /// While one is, `set_dkg_meta` and `finish` must keep driving it through the superseded slot:
    /// its committees only exist in the old layout, and abandoning it would leave the epoch unable
    /// to advance.
    fun has_legacy_in_progress(): bool acquires DKGState {
        exists<DKGState>(@supra_framework)
            && option::is_some(&borrow_global<DKGState>(@supra_framework).in_progress)
    }

    fun clear_legacy_in_progress() acquires DKGState {
        if (exists<DKGState>(@supra_framework)) {
            let dkg_state = borrow_global_mut<DKGState>(@supra_framework);
            if (option::is_some(&dkg_state.in_progress)) {
                dkg_state.in_progress = option::none();
            }
        }
    }

    fun clear_legacy_last_completed() acquires DKGState {
        if (exists<DKGState>(@supra_framework)) {
            let dkg_state = borrow_global_mut<DKGState>(@supra_framework);
            if (option::is_some(&dkg_state.last_completed)) {
                dkg_state.last_completed = option::none();
            }
        }
    }

    /// Build a committee from a validator set, keeping its order.
    ///
    /// Only the addresses are taken. Each validator's keys stay in the validator set they came from,
    /// which retains them for the whole epoch, and consumers resolve them from there.
    public(friend) fun new_dkg_committee_v2_from_validator_consensus_info(
        validator_committee: vector<ValidatorConsensusInfo>,
        threshold_type: CertificateThresholdType
    ): DkgCommitteeV2 {
        assert!(
            vector::length(&validator_committee) > 0,
            error::invalid_argument(EDKG_EMPTY_COMMITTEE)
        );

        let members = vector[];
        vector::for_each_ref(
            &validator_committee,
            |validator| vector::push_back(
                &mut members, validator_consensus_info::get_addr(validator)
            )
        );
        DkgCommitteeV2 { members, threshold_type }
    }

    public(friend) fun new_receiver_committee_v2(
        is_resharing: bool,
        dkg_threshold_type: CertificateThresholdType,
        committee: DkgCommitteeV2
    ): ReceiverCommitteeV2 {
        ReceiverCommitteeV2 { is_resharing, dkg_threshold_type, committee }
    }

    /// Mark on-chain DKG state as in-progress. Notify validators to start DKG.
    ///
    /// Supersedes `start`. The committees passed in record only their members; consumers resolve
    /// those members' keys from the validator set.
    public(friend) fun start_v2(
        dealer_epoch: u64,
        randomness_seed: vector<u8>,
        dealer_committee: DkgCommitteeV2,
        target_committees: vector<ReceiverCommitteeV2>
    ) acquires DKGState, DkgSessionInProgress {
        assert!(
            vector::length(&target_committees) > 0,
            error::invalid_argument(EDKG_NO_TARGET_COMMITTEE)
        );
        ensure_initialized_v2();

        let start_time_us = timestamp::now_microseconds();
        borrow_global_mut<DkgSessionInProgress>(@supra_framework).session = option::some(
            DKGSessionStateV2 {
                metadata: DKGSessionMetadataV2 {
                    dealer_epoch,
                    randomness_seed,
                    dealer_committee,
                    target_committees
                },
                start_time_us,
                dkg_meta_transcript: vector[],
                target_committees_public_key_shares: vector[]
            }
        );

        // A session left in the superseded slot would send this session's `set_dkg_meta` and
        // `finish` down the pre-upgrade path, so drop it. This is cheap: a write op is charged for
        // the size of the value written, and an emptied option is a few bytes.
        clear_legacy_in_progress();

        emit(DKGStartEventV2 { dealer_epoch, start_time_us });
    }

    /// Mark on-chain DKG state as in-progress. Notify validators to start DKG.
    /// Abort if a DKG is already in progress.
    ///
    /// Superseded by `start_v2`, which does not store a separate copy of every member's keys per
    /// committee. Retained because removing a published function is not an upgrade-compatible
    /// change; nothing calls it.
    public(friend) fun start(
        dealer_epoch: u64,
        randomness_seed: vector<u8>,
        dealer_committee: DkgCommittee,
        target_committees: vector<ReceiverCommittee>
    ) acquires DKGState {
        let dkg_state = borrow_global_mut<DKGState>(@supra_framework);
        let new_session_metadata = DKGSessionMetadata {
            dealer_epoch,
            randomness_seed,
            dealer_committee,
            target_committees
        };
        let start_time_us = timestamp::now_microseconds();
        dkg_state.in_progress = std::option::some(
            DKGSessionState {
                metadata: new_session_metadata,
                start_time_us,
                dkg_meta_transcript: vector[],
                target_committees_public_key_shares: vector[]
            }
        );

        emit(DKGStartEvent { start_time_us, session_metadata: new_session_metadata });
    }

    /// Family Node sets the DKGMeta for the in-progress DKG session
    /// The dkg transcript is assumed to have been already verified by the aptos VM in `process_dkg_result` method
    public(friend) fun set_dkg_meta(
        dkg_meta_all_committees: vector<u8>
    ) acquires DKGState, DkgSessionInProgress {
        if (has_legacy_in_progress()) {
            let dkg_state = borrow_global_mut<DKGState>(@supra_framework);
            // we only add the first DKG Meta proposed and ignore the rest
            let session = option::extract(&mut dkg_state.in_progress);
            assert!(
                vector::length(&session.dkg_meta_transcript) == 0,
                error::already_exists(EDKG_META_ALREADY_SET)
            );
            session.dkg_meta_transcript = dkg_meta_all_committees;
            dkg_state.in_progress = option::some(session);
        } else {
            // ensure dkg is in progress
            assert!(
                exists<DkgSessionInProgress>(@supra_framework),
                error::invalid_state(EDKG_NOT_IN_PROGRESS)
            );
            let slot = borrow_global_mut<DkgSessionInProgress>(@supra_framework);
            assert!(
                option::is_some(&slot.session),
                error::invalid_state(EDKG_NOT_IN_PROGRESS)
            );

            // we only add the first DKG Meta proposed and ignore the rest
            let session = option::extract(&mut slot.session);
            assert!(
                vector::length(&session.dkg_meta_transcript) == 0,
                error::already_exists(EDKG_META_ALREADY_SET)
            );
            session.dkg_meta_transcript = dkg_meta_all_committees;
            slot.session = option::some(session);
        };

        emit(DKGMetaSetEvent { dkg_meta_transcript: dkg_meta_all_committees });
    }

    /// Family Node sets the `target_committees_public_key_shares` for the in-progress DKG session and
    /// marks the incomplete DKG session completed.
    ///The `target_committees_public_key_shares` is assumed to be verified by the aptos VM before calling this function
    ///
    /// Returns whether the session was completed. `false` means the call declined and changed
    /// nothing, so the caller must not go on to complete the reconfiguration either.
    public(friend) fun finish(
        target_committees_public_key_shares: vector<u8>
    ): bool acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        if (has_legacy_in_progress()) {
            let dkg_state = borrow_global_mut<DKGState>(@supra_framework);
            // `finish` is total on a session with no DKG meta transcript: it declines and
            // leaves the session in place for the producer. See smr-moonshot#3645.
            if (vector::is_empty(
                &option::borrow(&dkg_state.in_progress).dkg_meta_transcript
            )) {
                emit(DKGFinishDeferredEvent {
                    dealer_epoch: option::borrow(&dkg_state.in_progress).metadata.dealer_epoch
                });
                return false
            };
            // Decode and validate the DKG output before the session is modified. The share count
            // is checked by `stake::set_dkg_output_keys`, against the validator set it computes.
            let committee_outputs =
                build_committee_outputs(target_committees_public_key_shares);

            let session = option::extract(&mut dkg_state.in_progress);

            session.target_committees_public_key_shares = target_committees_public_key_shares;
            dkg_state.last_completed = option::some(session);
            dkg_state.in_progress = option::none();

            // Set all keys for all threshold types
            stake::set_dkg_output_keys(committee_outputs);
        } else {
            // ensure dkg is in progress
            assert!(
                exists<DkgSessionInProgress>(@supra_framework),
                error::invalid_state(EDKG_NOT_IN_PROGRESS)
            );
            let slot = borrow_global_mut<DkgSessionInProgress>(@supra_framework);
            assert!(
                option::is_some(&slot.session),
                error::invalid_state(EDKG_NOT_IN_PROGRESS)
            );

            // Decline when the meta is not set, as in the legacy arm above.
            if (vector::is_empty(&option::borrow(&slot.session).dkg_meta_transcript)) {
                emit(DKGFinishDeferredEvent {
                    dealer_epoch: option::borrow(&slot.session).metadata.dealer_epoch
                });
                return false
            };

            // Install the keys against the membership this session pinned when it started, not
            // against a set recomputed now. The two are produced by different code paths, and a
            // disagreement between them aborts in `stake`, which fails the block on every node.
            let members =
                target_committee_member_addrs(&option::borrow(&slot.session).metadata);

            // Decode and validate the DKG output, including that every committee's share count is
            // the one `stake::set_dkg_output_keys_for_members` installs against `members`, before
            // the session is modified.
            let committee_outputs =
                build_committee_outputs(target_committees_public_key_shares);
            assert_share_counts(&committee_outputs, vector::length(&members));

            let session = option::extract(&mut slot.session);

            session.target_committees_public_key_shares = target_committees_public_key_shares;

            borrow_global_mut<DkgSessionLastCompleted>(@supra_framework).session = option::some(
                session
            );
            // Retire the superseded slot only now that the session is recorded in its replacement,
            // so that no reader ever sees a chain with no last completed session at all.
            clear_legacy_last_completed();

            // Set all keys for all threshold types
            stake::set_dkg_output_keys_for_members(members, committee_outputs);
        };

        emit(DKGFinishEvent { target_committees_public_key_shares });
        true
    }

    /// Decode the DKG output and split it into one `DkgCommitteeOutput` per committee.
    ///
    /// Every commitment is validated by `assert_commitments_installable` before any is split.
    fun build_committee_outputs(
        target_committees_public_key_shares: vector<u8>
    ): vector<DkgCommitteeOutput> {
        let public_key_shares_all_comms =
            util::from_bytes<OnChainAggregateCommitmentAllCommittees>(
                target_committees_public_key_shares
            );
        assert_commitments_installable(&public_key_shares_all_comms.commitments);

        // Build a vector of DkgCommitteeOutput for all committees
        let committee_outputs = vector[];
        let i = 0;
        let len = vector::length(&public_key_shares_all_comms.commitments);
        while (i < len) {
            let commitment = vector::borrow(&public_key_shares_all_comms.commitments, i);
            // As the first index contains the committee's threshold public key, we can skip that
            let evals = vector::slice(
                &commitment.bls12381_commitment_evals,
                1,
                vector::length(&commitment.bls12381_commitment_evals)
            );

            vector::push_back(
                &mut committee_outputs,
                new_dkg_committee_output(commitment.threshold_type, evals)
            );
            i = i + 1;
        };
        committee_outputs
    }

    /// Abort unless every commitment has the structure `build_committee_outputs` and
    /// `stake::set_dkg_output_keys_for_members` rely on: at least one evaluation, since index 0 is
    /// the committee public key and the shares follow it, and a threshold type that a key can be
    /// installed for. See Entropy-Foundation/smr-moonshot#3238.
    fun assert_commitments_installable(commitments: &vector<OnChainAggregateCommitment>) {
        vector::for_each_ref(
            commitments,
            |commitment| {
                let commitment: &OnChainAggregateCommitment = commitment;
                assert!(
                    !vector::is_empty(&commitment.bls12381_commitment_evals),
                    error::invalid_argument(EDKG_EMPTY_COMMITMENT_EVALS)
                );
                assert!(
                    validator_public_keys::is_installable_threshold_type(
                        commitment.threshold_type
                    ),
                    error::invalid_argument(EDKG_UNINSTALLABLE_THRESHOLD_TYPE)
                );
            }
        );
    }

    /// Abort unless every committee output carries exactly one key share per member of the
    /// committee it is installed against.
    fun assert_share_counts(
        committee_outputs: &vector<DkgCommitteeOutput>, num_members: u64
    ) {
        vector::for_each_ref(
            committee_outputs,
            |output| {
                assert!(
                    vector::length(&get_dkg_committee_output_keys(output)) == num_members,
                    error::invalid_argument(EDKG_SHARE_COUNT_MISMATCH)
                );
            }
        );
    }

    /// The ordering that this session's DKG output key shares are indexed by, as the members of its
    /// first target committee.
    ///
    /// Reading only the first is what limits `finish` to committees that share a membership:
    /// `stake::set_dkg_output_keys_for_members` takes a single ordering and applies every
    /// committee's shares against it, checking only that the share count matches its length. Two
    /// committees over different validators of the same size would therefore be installed against
    /// each other's members, with nothing to catch it. Nothing constructs such a session today -
    /// `reconfiguration_with_dkg::try_start` builds every entry from one membership - and giving
    /// committees their own memberships means changing both this and the installation path
    /// together. Tracked in smr-moonshot#3362.
    fun target_committee_member_addrs(metadata: &DKGSessionMetadataV2): vector<address> {
        assert!(
            vector::length(&metadata.target_committees) > 0,
            error::invalid_state(EDKG_NO_TARGET_COMMITTEE)
        );
        vector::borrow(&metadata.target_committees, 0).committee.members
    }

    /// Delete the currently incomplete session, if it exists.
    ///
    /// Both slots are cleared. Leaving a stale session in the superseded one would make
    /// `has_legacy_in_progress` true again, sending the next session's `set_dkg_meta` and `finish`
    /// down the pre-upgrade path.
    public fun try_clear_incomplete_session(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress {
        system_addresses::assert_supra_framework(fx);
        clear_legacy_in_progress();
        if (exists<DkgSessionInProgress>(@supra_framework)) {
            let slot = borrow_global_mut<DkgSessionInProgress>(@supra_framework);
            if (option::is_some(&slot.session)) {
                slot.session = option::none();
            }
        }
    }

    /// Return the incomplete DKG session state, if it exists.
    public fun incomplete_session_v2(): Option<DKGSessionStateV2> acquires DkgSessionInProgress {
        if (exists<DkgSessionInProgress>(@supra_framework)) {
            borrow_global<DkgSessionInProgress>(@supra_framework).session
        } else {
            option::none()
        }
    }

    /// Return the last completed DKG session state, if it exists.
    public fun last_completed_session_v2(): Option<DKGSessionStateV2> acquires DkgSessionLastCompleted {
        if (exists<DkgSessionLastCompleted>(@supra_framework)) {
            borrow_global<DkgSessionLastCompleted>(@supra_framework).session
        } else {
            option::none()
        }
    }

    #[view]
    /// Return the dealer epoch of the incomplete DKG session, if there is one.
    ///
    /// Callers that need only the epoch must use this rather than `incomplete_session`, which copies
    /// the entire session out of storage: the epoch-timeout check in the block prologue runs on
    /// every block for as long as a session is open.
    public fun incomplete_session_dealer_epoch(): Option<u64> acquires DKGState, DkgSessionInProgress {
        if (exists<DkgSessionInProgress>(@supra_framework)) {
            let session = &borrow_global<DkgSessionInProgress>(@supra_framework).session;
            if (option::is_some(session)) {
                return option::some(option::borrow(session).metadata.dealer_epoch)
            }
        };
        if (exists<DKGState>(@supra_framework)) {
            let session = &borrow_global<DKGState>(@supra_framework).in_progress;
            if (option::is_some(session)) {
                return option::some(option::borrow(session).metadata.dealer_epoch)
            }
        };
        option::none()
    }

    /// Return the incomplete DKG session state, if it exists.
    ///
    /// Superseded by `incomplete_session_v2`; retained because removing a published function is not
    /// an upgrade-compatible change.
    public fun incomplete_session(): Option<DKGSessionState> acquires DKGState {
        if (exists<DKGState>(@supra_framework)) {
            borrow_global<DKGState>(@supra_framework).in_progress
        } else {
            option::none()
        }
    }

    /// Return the last completed DKG session state, if it exists.
    public fun last_completed_session(): Option<DKGSessionState> acquires DKGState {
        if (exists<DKGState>(@supra_framework)) {
            borrow_global<DKGState>(@supra_framework).last_completed
        } else {
            option::none()
        }
    }

    /// Return the dealer epoch of a `DKGSessionState`.
    public fun session_dealer_epoch(session: &DKGSessionState): u64 {
        session.metadata.dealer_epoch
    }

    #[test_only]
    use std::dkg_committee::{
        new_dkg_committee_from_validator_consensus_info,
        new_receiver_committee
    };
    #[test_only]
    use supra_framework::event;
    #[test_only]
    use supra_framework::validator_public_keys::{
        quorum_certificate_type,
        validity_certificate_type
    };

    #[test_only]
    /// Create only `DKGState`, standing in for a chain whose DKG predates the session resources.
    fun initialize_legacy_only_for_test(fx: &signer) {
        system_addresses::assert_supra_framework(fx);
        move_to<DKGState>(
            fx,
            DKGState { last_completed: option::none(), in_progress: option::none() }
        );
    }

    #[test_only]
    fun test_validators(): vector<validator_consensus_info::ValidatorConsensusInfo> {
        vector[
            validator_consensus_info::new(@0x1, vector[10u8], 1),
            validator_consensus_info::new(@0x2, vector[20u8], 1)
        ]
    }

    #[test_only]
    /// Start a session in the superseded layout, as one that was already running at upgrade time is.
    fun start_legacy_for_test(dealer_epoch: u64) acquires DKGState {
        let committee =
            new_dkg_committee_from_validator_consensus_info(
                test_validators(), quorum_certificate_type()
            );
        let receiver =
            new_receiver_committee(false, quorum_certificate_type(), committee);
        start(dealer_epoch, vector[7u8], committee, vector[receiver]);
    }

    #[test_only]
    fun start_v2_for_test(dealer_epoch: u64) acquires DKGState, DkgSessionInProgress {
        let committee =
            new_dkg_committee_v2_from_validator_consensus_info(
                test_validators(), quorum_certificate_type()
            );
        let receiver =
            new_receiver_committee_v2(false, quorum_certificate_type(), committee);
        start_v2(dealer_epoch, vector[7u8], committee, vector[receiver]);
    }

    #[test(fx = @supra_framework)]
    /// `initialize` must not create the in-progress slot while a session that predates it is still
    /// running. The VM's validator for DKG transactions treats the slot's mere existence as meaning
    /// the new layout is authoritative, so it would then reject that session's own `set_dkg_meta`
    /// and `finish` - which this module would still accept, down the legacy branch. `initialize` is
    /// public and documented as callable from a governance script, so the ordering is not ours to
    /// choose.
    fun test_initialize_leaves_a_running_legacy_session_alone(fx: &signer) acquires DKGState {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);

        start_legacy_for_test(1);
        assert!(option::is_some(&incomplete_session()), 1);

        initialize(fx);

        // The completed-session slot is safe to create: nothing keys off its existence.
        assert!(exists<DkgSessionLastCompleted>(@supra_framework), 2);
        assert!(!exists<DkgSessionInProgress>(@supra_framework), 3);
        // ...and the running session is still where its own transactions expect to find it.
        assert!(option::is_some(&incomplete_session()), 4);

        // Once no legacy session is running, the slot is created as normal.
        clear_legacy_in_progress();
        initialize(fx);
        assert!(exists<DkgSessionInProgress>(@supra_framework), 5);
    }

    #[test(fx = @supra_framework)]
    /// Starting a session under the current layout retires any session left in the superseded slot.
    /// Leaving one there would send this session's `set_dkg_meta` and `finish` down the pre-upgrade
    /// path.
    fun test_start_v2_clears_the_superseded_slot(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);

        start_legacy_for_test(1);
        assert!(option::is_some(&incomplete_session()), 1);

        start_v2_for_test(2);
        assert!(option::is_none(&incomplete_session()), 2);
        let session = incomplete_session_v2();
        assert!(option::is_some(&session), 3);
        assert!(option::borrow(&session).metadata.dealer_epoch == 2, 4);
    }

    #[test(fx = @supra_framework)]
    /// A session that was already running when the session resources were introduced runs to
    /// completion in the slot it started in. Abandoning it would leave the epoch unable to advance.
    fun test_set_dkg_meta_drives_a_pre_upgrade_session_on_the_old_path(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        start_legacy_for_test(7);

        set_dkg_meta(vector[1u8, 2u8, 3u8]);

        let session = incomplete_session();
        assert!(option::is_some(&session), 1);
        assert!(option::borrow(&session).dkg_meta_transcript == vector[1u8, 2u8, 3u8], 2);
        // The current layout's resources are untouched, so the session is still the old one.
        assert!(!exists<DkgSessionInProgress>(@supra_framework), 3);
    }

    #[test(fx = @supra_framework)]
    /// Clearing an incomplete session clears both slots.
    fun test_try_clear_incomplete_session_clears_both_slots(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);

        start_v2_for_test(2);
        // Put a session back in the superseded slot as well, so that a clear covering only one slot
        // would leave the other behind.
        start_legacy_for_test(3);
        assert!(option::is_some(&incomplete_session()), 1);
        assert!(option::is_some(&incomplete_session_v2()), 2);

        try_clear_incomplete_session(fx);

        assert!(option::is_none(&incomplete_session()), 3);
        assert!(option::is_none(&incomplete_session_v2()), 4);
    }

    #[test(fx = @supra_framework)]
    /// The epoch-timeout check sees a session in either slot, and prefers the current layout's.
    fun test_incomplete_session_dealer_epoch_covers_both_slots(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        assert!(option::is_none(&incomplete_session_dealer_epoch()), 1);

        start_legacy_for_test(5);
        assert!(*option::borrow(&incomplete_session_dealer_epoch()) == 5, 2);

        start_v2_for_test(6);
        assert!(*option::borrow(&incomplete_session_dealer_epoch()) == 6, 3);

        start_legacy_for_test(9);
        assert!(*option::borrow(&incomplete_session_dealer_epoch()) == 6, 4);
    }

    #[test(fx = @supra_framework)]
    #[expected_failure(abort_code = 0x30001, location = Self)]
    /// With no session in either slot there is nothing to attach a transcript to.
    fun test_set_dkg_meta_aborts_without_a_session(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        set_dkg_meta(vector[1u8]);
    }

    #[test(fx = @supra_framework)]
    /// `finish` is total on a session whose DKG meta transcript is not set: it declines, leaves
    /// the session in place, and records no output. Legacy slot. See smr-moonshot#3645.
    fun test_finish_declines_without_a_meta_on_the_legacy_path(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        start_legacy_for_test(1);

        // Not a valid DKG output: the decline is required to precede any read of the payload,
        // so a decode would fail this test.
        assert!(!finish(vector[9u8]), 1);

        let deferred = event::emitted_events<DKGFinishDeferredEvent>();
        assert!(vector::length(&deferred) == 1, 2);
        assert!(vector::borrow(&deferred, 0).dealer_epoch == 1, 3);
        // The session is still running, still without a transcript, and still has no output.
        let session = incomplete_session();
        assert!(option::is_some(&session), 4);
        assert!(vector::is_empty(&option::borrow(&session).dkg_meta_transcript), 5);
        assert!(
            vector::is_empty(
                &option::borrow(&session).target_committees_public_key_shares
            ),
            6
        );
        assert!(option::is_none(&last_completed_session()), 7);
    }

    #[test(fx = @supra_framework)]
    /// As `test_finish_declines_without_a_meta_on_the_legacy_path`, for the current layout's slot.
    fun test_finish_declines_without_a_meta_on_the_v2_path(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        start_v2_for_test(2);
        assert!(!has_legacy_in_progress(), 1);

        assert!(!finish(vector[9u8]), 2);

        let deferred = event::emitted_events<DKGFinishDeferredEvent>();
        assert!(vector::length(&deferred) == 1, 3);
        assert!(vector::borrow(&deferred, 0).dealer_epoch == 2, 4);
        let session = incomplete_session_v2();
        assert!(option::is_some(&session), 5);
        assert!(vector::is_empty(&option::borrow(&session).dkg_meta_transcript), 6);
        assert!(
            vector::is_empty(
                &option::borrow(&session).target_committees_public_key_shares
            ),
            7
        );
        assert!(option::is_none(&last_completed_session_v2()), 8);
    }

    #[test]
    /// A committee records its validators in the order they were given, and nothing else. The order
    /// is what DKG output key shares are indexed by, so it has to survive verbatim.
    fun test_committee_keeps_validator_order() {
        let validators = vector[
            validator_consensus_info::new(@0x3, vector[30u8], 1),
            validator_consensus_info::new(@0x1, vector[10u8], 1),
            validator_consensus_info::new(@0x2, vector[20u8], 1)
        ];
        let committee =
            new_dkg_committee_v2_from_validator_consensus_info(
                validators, quorum_certificate_type()
            );

        assert!(committee.members == vector[@0x3, @0x1, @0x2], 1);
    }

    #[test]
    /// The validators' keys are not copied into the committee. They stay in the validator set, which
    /// remains the single record of them. Under the superseded layout each committee carried its own
    /// copy of every member's ~1.4 KB key blob, so configuring a further threshold type multiplied
    /// the size of the session instead of leaving it flat.
    fun test_committee_does_not_carry_validator_keys() {
        let validators = test_validators();
        let quorum =
            new_dkg_committee_v2_from_validator_consensus_info(
                validators, quorum_certificate_type()
            );
        let validity =
            new_dkg_committee_v2_from_validator_consensus_info(
                validators, validity_certificate_type()
            );

        assert!(quorum.members == validity.members, 1);
        // Two addresses, a threshold type and the vector length prefixes, and nothing that could
        // hold a key blob.
        assert!(vector::length(&std::bcs::to_bytes(&quorum)) < 2 * 32 + 16, 2);
        assert!(
            vector::length(&std::bcs::to_bytes(&quorum))
                == vector::length(&std::bcs::to_bytes(&validity)),
            3
        );
    }

    #[test]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_new_committee_rejects_an_empty_validator_set() {
        new_dkg_committee_v2_from_validator_consensus_info(
            vector[], quorum_certificate_type()
        );
    }

    #[test_only]
    use aptos_std::bls12381;
    #[test_only]
    use std::features;

    #[test_only]
    /// A threshold type tag with no entry in `validator_public_keys`.
    const UNINSTALLABLE_THRESHOLD_TYPE_FOR_TEST: u8 = 7;

    #[test_only]
    /// A DKG output carrying one commitment with the given evaluations and threshold type.
    fun dkg_output_for_test(
        bls12381_commitment_evals: vector<vector<u8>>, threshold_type: u8
    ): vector<u8> {
        std::bcs::to_bytes(
            &OnChainAggregateCommitmentAllCommittees {
                commitments: vector[
                    OnChainAggregateCommitment {
                        bls12381_commitment_g: vector[],
                        bls12381_commitment_evals,
                        dealer_ids: vector[],
                        committee_index: 0,
                        epoch: 2,
                        chain_id: 4,
                        threshold_type
                    }]
            }
        )
    }

    #[test_only]
    /// A session in the current layout, over `test_validators`, with its DKG meta set.
    fun start_v2_with_meta_for_test(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        start_v2_for_test(2);
        set_dkg_meta(vector[1u8]);
    }

    #[test(fx = @supra_framework)]
    #[expected_failure(abort_code = 0x10007, location = Self)]
    fun test_finish_rejects_empty_commitment_evals(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        start_v2_with_meta_for_test(fx);
        finish(dkg_output_for_test(vector[], 1));
    }

    #[test(fx = @supra_framework)]
    #[expected_failure(abort_code = 0x10007, location = Self)]
    /// As `test_finish_rejects_empty_commitment_evals`, for a session in the superseded slot.
    fun test_finish_rejects_empty_commitment_evals_on_the_legacy_path(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        start_legacy_for_test(1);
        set_dkg_meta(vector[1u8]);
        finish(dkg_output_for_test(vector[], 1));
    }

    #[test(fx = @supra_framework)]
    #[expected_failure(abort_code = 0x10008, location = Self)]
    fun test_finish_rejects_uninstallable_threshold_type(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        start_v2_with_meta_for_test(fx);
        finish(
            dkg_output_for_test(
                vector[vector[0u8], vector[1u8], vector[2u8]],
                UNINSTALLABLE_THRESHOLD_TYPE_FOR_TEST
            )
        );
    }

    #[test(fx = @supra_framework)]
    #[expected_failure(abort_code = 0x10008, location = Self)]
    /// As `test_finish_rejects_uninstallable_threshold_type`, for a session in the superseded slot.
    fun test_finish_rejects_uninstallable_threshold_type_on_the_legacy_path(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        initialize_legacy_only_for_test(fx);
        timestamp::set_time_has_started_for_testing(fx);
        start_legacy_for_test(1);
        set_dkg_meta(vector[1u8]);
        finish(
            dkg_output_for_test(
                vector[vector[0u8], vector[1u8], vector[2u8]],
                UNINSTALLABLE_THRESHOLD_TYPE_FOR_TEST
            )
        );
    }

    #[test(fx = @supra_framework)]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    /// The session's target committee has two members; the output carries one share.
    fun test_finish_rejects_a_share_count_other_than_the_member_count(
        fx: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        start_v2_with_meta_for_test(fx);
        finish(dkg_output_for_test(vector[vector[0u8], vector[1u8]], 1));
    }

    #[test(fx = @supra_framework, validator = @0x123)]
    /// A well-formed DKG output completes the session, records the output, and installs each
    /// member's share as that member's key for the commitment's threshold type.
    fun test_finish_installs_a_well_formed_output(
        fx: &signer, validator: &signer
    ) acquires DKGState, DkgSessionInProgress, DkgSessionLastCompleted {
        initialize_legacy_only_for_test(fx);
        stake::initialize_for_test(fx);
        features::change_feature_flags_for_testing(
            fx,
            vector[features::get_supra_validator_identity_v2_feature()],
            vector[]
        );
        let (_sk, pk) = stake::generate_identity();
        stake::initialize_test_validator(&pk, validator, 100, true, true);
        let validator_address = std::signer::address_of(validator);

        let committee =
            new_dkg_committee_v2_from_validator_consensus_info(
                vector[validator_consensus_info::new(validator_address, vector[], 1)],
                quorum_certificate_type()
            );
        let receiver =
            new_receiver_committee_v2(false, quorum_certificate_type(), committee);
        start_v2(2, vector[7u8], committee, vector[receiver]);
        set_dkg_meta(vector[1u8]);

        let (_committee_sk, committee_pop_pk) = bls12381::generate_keys();
        let committee_key = bls12381::public_key_with_pop_to_normal(&committee_pop_pk);
        let (_share_sk, share_pop_pk) = bls12381::generate_keys();
        let share = bls12381::public_key_with_pop_to_normal(&share_pop_pk);
        let output =
            dkg_output_for_test(
                vector[
                    bls12381::public_key_to_bytes(&committee_key),
                    bls12381::public_key_to_bytes(&share)
                ],
                1
            );

        assert!(finish(output), 1);

        assert!(option::is_none(&incomplete_session_v2()), 2);
        let completed = last_completed_session_v2();
        assert!(
            option::borrow(&completed).target_committees_public_key_shares == output,
            3
        );
        let (stored_bytes, _net, _fn) = stake::get_validator_config(validator_address);
        let stored =
            validator_public_keys::validator_public_keys_from_bytes(stored_bytes);
        let installed =
            validator_public_keys::get_supra_bls_threshold_key_by_type(&stored, 1);
        assert!(option::extract(&mut installed) == share, 4);
    }
}

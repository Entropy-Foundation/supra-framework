/// This module provides access to *instant* randomness supplied by Supra consensus. The Move API
/// and its test-and-abort threat model follow
/// [AIP-41](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-041-move-apis-for-public-randomness-generation.md),
/// which leaves the randomness source out of scope. Aptos fills that gap with the weighted VUF of
/// [AIP-79](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-079-implementation-of-instant-on-chain-randomness.md);
/// Supra does not use that mechanism.
///
/// On Supra the per-block seed exists only while the `SUPRA_DKG` feature is enabled and is one of:
/// * the 96-byte BLS threshold signature on the committed block's quorum certificate, when the
///   committee that certified the block holds DKG threshold keys. The signature is the same for
///   every subset of signers that reconstructs it, and computing it takes as many committee members
///   as the certificate's signing threshold, each member counting once regardless of stake. While
///   fewer members than that threshold collude, the seed can be neither predicted before the block
///   is certified nor biased by the proposer's choice of contents. Only this case carries the
///   guarantee below;
/// * the 32-byte committed block hash, when the certifying committee holds no threshold keys. A
///   committee holds keys only for an epoch that follows an epoch in which `SUPRA_DKG` was enabled,
///   because the DKG runs at the end of an epoch to produce the next epoch's keys, and it never
///   runs at the end of the genesis epoch. With `SUPRA_DKG` enabled, the block hash is therefore
///   the seed for exactly:
///   - the genesis epoch and the epoch after it, on a network whose genesis enables `SUPRA_DKG`;
///   - the first epoch after governance enables `SUPRA_DKG`, including a re-enablement after it
///     was disabled.
///   The hash is known to validators before the block commits and depends on contents the proposer
///   chose, so it is predictable and biasable. This module still serves draws from it, and no Move
///   function reports which of the two seeds the current block has. The Supra EVM randomness
///   precompile refuses this seed instead of serving it. Supra mainnet and Supra testnet have both
///   run with `SUPRA_DKG` enabled beyond their first DKG epoch, so neither serves this seed.
///
/// With `SUPRA_DKG` disabled consensus supplies no seed and every draw aborts (see
/// `next_32_bytes`).
///
/// Each draw is `SHA3-256("SUPRA_RANDOMNESS" || seed || transaction hash || transaction-local
/// counter)`. When the seed is a threshold signature, the randomness can be neither predicted ahead
/// of time nor biased by validators, developers, or users, provided that fewer committee members
/// than the signing threshold collude and that the calling transaction satisfies `is_unbiasable`.
///
/// The unbiasable mark stops code outside the entry function from wrapping it and aborting on an
/// unfavourable draw. It does not constrain what the entry function does after a draw, so a
/// consumer must meet two further requirements:
/// * No code that can abort after observing a draw may run in the same transaction unless the
///   consumer's author controls it. A call after a draw into code the sender can supply, such as
///   the dispatch functions of a fungible asset the sender created, lets that code abort on an
///   outcome the sender rejects.
/// * The gas a transaction spends after a draw must not be larger for an outcome the sender would
///   reject than for one the sender would accept. The sender chooses the gas limit, and running out
///   of gas aborts the transaction exactly as an explicit abort does.
/// Recording the outcome and acting on it in a later transaction satisfies both requirements.
///
/// From gas feature version 26, an entry function annotated `#[randomness(min_remaining_gas = N)]`
/// requires `N` gas to remain from the transaction's `max_gas_amount` when the first draw is
/// requested in a transaction whose payload is that entry function; a first draw requested with
/// less aborts with code 2. The annotation can add `min_remaining_execution_gas = M`, at most `N`,
/// which requires `M` gas to remain under each of the per-transaction execution and IO limits at
/// that draw; a first draw requested with less aborts with code 4. Later draws are not checked. A
/// draw requested by a fungible asset's dispatch function, through `dispatchable_fungible_asset`,
/// before the first draw aborts with code 3 and leaves the minimums pending, so the draw that is
/// checked is not made by a dispatch function. The VM also rejects an automation registration
/// whose task `max_gas_amount` is below `N`.
///
/// The minimums cover what is charged against those budgets after the first draw. `N` satisfies
/// the second requirement when it covers everything the transaction does from the first draw to
/// its end, at the largest input the entry function accepts, together with the IO gas and storage
/// fees of every write the transaction makes, before or after the draw, which are charged after
/// the entry function returns. `M` covers the execution and IO gas of the same work, and is needed
/// when the execution or IO gas spent before the first draw depends on the transaction's
/// arguments. Neither covers the memory quota or the dependency limits.
/// `#[randomness(max_gas = N)]` is accepted and not enforced.
module supra_framework::randomness {
    use std::hash;
    use std::option;
    use std::option::Option;
    use std::vector;
    use supra_framework::event;
    use supra_framework::system_addresses;
    use supra_framework::transaction_context;
    #[test_only]
    use aptos_std::debug;
    #[test_only]
    use aptos_std::table_with_length;

    friend supra_framework::block;

    const DST: vector<u8> = b"SUPRA_RANDOMNESS";

    /// The calling transaction is not marked unbiasable. The VM marks a transaction whose payload
    /// is a private or `public(friend)` entry function annotated `#[randomness]`, and, while
    /// `SUPRA_DKG` is enabled, an approved governance script or the block-metadata transaction. Any
    /// other caller could observe a draw and abort selectively, so randomness is refused.
    const E_API_USE_IS_BIASIBLE: u64 = 1;

    const MAX_U256: u256 =
        115792089237316195423570985008687907853269984665640564039457584007913129639935;

    /// The randomness seed for the current block. Each block prologue updates this resource when
    /// it exists; if genesis omitted it, there is nothing to update until governance publishes it
    /// (see `next_32_bytes`). `seed` is the 96-byte BLS threshold signature of the committed
    /// block's quorum certificate when that certificate carries one, the 32-byte committed block
    /// hash when it does not, and `none` when consensus supplied no seed, as when `SUPRA_DKG` is
    /// disabled.
    struct PerBlockRandomness has drop, key {
        epoch: u64,
        round: u64,
        seed: Option<vector<u8>>
    }

    #[event]
    /// Emitted once per successful call to `bytes`, to a `*_integer` or `*_range` wrapper, or to
    /// `permutation`, however many 32-byte draws the call made, including `bytes(0)`,
    /// `permutation(0)` and `permutation(1)`, which draw nothing. The public `u64_range_internal`
    /// emits nothing. The event counts completed wrapper calls, not draws and not every use of this
    /// module.
    struct RandomnessGeneratedEvent has store, drop {}

    /// Called in genesis.move.
    /// Must be called in tests to initialize the `PerBlockRandomness` resource.
    public fun initialize(framework: &signer) {
        system_addresses::assert_supra_framework(framework);
        if (!exists<PerBlockRandomness>(@supra_framework)) {
            move_to(
                framework,
                PerBlockRandomness { epoch: 0, round: 0, seed: option::none() }
            );
        }
    }

    #[test_only]
    public fun initialize_for_testing(framework: &signer) acquires PerBlockRandomness {
        initialize(framework);
        set_seed(x"0000000000000000000000000000000000000000000000000000000000000000");
    }

    /// Invoked in block prologues to update the block-level randomness seed.
    public(friend) fun on_new_block(
        vm: &signer,
        epoch: u64,
        round: u64,
        seed_for_new_block: Option<vector<u8>>
    ) acquires PerBlockRandomness {
        system_addresses::assert_vm(vm);
        if (exists<PerBlockRandomness>(@supra_framework)) {
            let randomness = borrow_global_mut<PerBlockRandomness>(@supra_framework);
            randomness.epoch = epoch;
            randomness.round = round;
            randomness.seed = seed_for_new_block;
        }
    }

    /// Generate the next 32 random bytes. Repeated calls will yield different results (assuming the collision-resistance
    /// of the hash function).
    /// Aborts, in this order: with `E_API_USE_IS_BIASIBLE` if the transaction is not marked
    /// unbiasable; with the VM's `MISSING_DATA` status if `PerBlockRandomness` has not been
    /// published (mainnet genesis, including a local network generated in mainnet genesis mode,
    /// does not publish it; testnet genesis does; governance can, through `initialize`); and with
    /// `std::option::EOPTION_NOT_SET` (`0x40001`) if the resource exists but `seed` is `none`, as
    /// when `SUPRA_DKG` is disabled; and with code 3, 2 or 4 from `fetch_and_increment_txn_counter`
    /// while the entry function's `min_remaining_gas` is pending, as that function's documentation
    /// describes.
    fun next_32_bytes(): vector<u8> acquires PerBlockRandomness {
        assert!(is_unbiasable(), E_API_USE_IS_BIASIBLE);

        let input = DST;
        let randomness = borrow_global<PerBlockRandomness>(@supra_framework);
        let seed = *option::borrow(&randomness.seed);

        vector::append(&mut input, seed);
        vector::append(&mut input, transaction_context::get_transaction_hash());
        vector::append(&mut input, fetch_and_increment_txn_counter());
        hash::sha3_256(input)
    }

    /// Generates a sequence of bytes uniformly at random
    public fun bytes(n: u64): vector<u8> acquires PerBlockRandomness {
        let v = vector[];
        let c = 0;
        while (c < n) {
            let blob = next_32_bytes();
            vector::reverse_append(&mut v, blob);

            c = c + 32;
        };

        if (c > n) {
            vector::trim(&mut v, n);
        };

        event::emit(RandomnessGeneratedEvent {});

        v
    }

    /// Generates an u8 uniformly at random.
    public fun u8_integer(): u8 acquires PerBlockRandomness {
        let raw = next_32_bytes();
        let ret: u8 = vector::pop_back(&mut raw);

        event::emit(RandomnessGeneratedEvent {});

        ret
    }

    /// Generates an u16 uniformly at random.
    public fun u16_integer(): u16 acquires PerBlockRandomness {
        let raw = next_32_bytes();
        let i = 0;
        let ret: u16 = 0;
        while (i < 2) {
            ret = ret * 256 + (vector::pop_back(&mut raw) as u16);
            i = i + 1;
        };

        event::emit(RandomnessGeneratedEvent {});

        ret
    }

    /// Generates an u32 uniformly at random.
    public fun u32_integer(): u32 acquires PerBlockRandomness {
        let raw = next_32_bytes();
        let i = 0;
        let ret: u32 = 0;
        while (i < 4) {
            ret = ret * 256 + (vector::pop_back(&mut raw) as u32);
            i = i + 1;
        };

        event::emit(RandomnessGeneratedEvent {});

        ret
    }

    /// Generates an u64 uniformly at random.
    public fun u64_integer(): u64 acquires PerBlockRandomness {
        let raw = next_32_bytes();
        let i = 0;
        let ret: u64 = 0;
        while (i < 8) {
            ret = ret * 256 + (vector::pop_back(&mut raw) as u64);
            i = i + 1;
        };

        event::emit(RandomnessGeneratedEvent {});

        ret
    }

    /// Generates an u128 uniformly at random.
    public fun u128_integer(): u128 acquires PerBlockRandomness {
        let raw = next_32_bytes();
        let i = 0;
        let ret: u128 = 0;
        while (i < 16) {
            ret = ret * 256 + (vector::pop_back(&mut raw) as u128);
            i = i + 1;
        };

        event::emit(RandomnessGeneratedEvent {});

        ret
    }

    /// Generates a u256 uniformly at random.
    public fun u256_integer(): u256 acquires PerBlockRandomness {
        event::emit(RandomnessGeneratedEvent {});
        u256_integer_internal()
    }

    /// Generates a u256 uniformly at random.
    fun u256_integer_internal(): u256 acquires PerBlockRandomness {
        let raw = next_32_bytes();
        let i = 0;
        let ret: u256 = 0;
        while (i < 32) {
            ret = ret * 256 + (vector::pop_back(&mut raw) as u256);
            i = i + 1;
        };
        ret
    }

    /// Generates a number $n \in [min_incl, max_excl)$ uniformly at random.
    ///
    /// NOTE: The uniformity is not perfect, but it can be proved that the bias is negligible.
    /// If you need perfect uniformity, consider implement your own via rejection sampling.
    public fun u8_range(min_incl: u8, max_excl: u8): u8 acquires PerBlockRandomness {
        let range = ((max_excl - min_incl) as u256);
        let sample = ((u256_integer_internal() % range) as u8);

        event::emit(RandomnessGeneratedEvent {});

        min_incl + sample
    }

    /// Generates a number $n \in [min_incl, max_excl)$ uniformly at random.
    ///
    /// NOTE: The uniformity is not perfect, but it can be proved that the bias is negligible.
    /// If you need perfect uniformity, consider implement your own via rejection sampling.
    public fun u16_range(min_incl: u16, max_excl: u16): u16 acquires PerBlockRandomness {
        let range = ((max_excl - min_incl) as u256);
        let sample = ((u256_integer_internal() % range) as u16);

        event::emit(RandomnessGeneratedEvent {});

        min_incl + sample
    }

    /// Generates a number $n \in [min_incl, max_excl)$ uniformly at random.
    ///
    /// NOTE: The uniformity is not perfect, but it can be proved that the bias is negligible.
    /// If you need perfect uniformity, consider implement your own via rejection sampling.
    public fun u32_range(min_incl: u32, max_excl: u32): u32 acquires PerBlockRandomness {
        let range = ((max_excl - min_incl) as u256);
        let sample = ((u256_integer_internal() % range) as u32);

        event::emit(RandomnessGeneratedEvent {});

        min_incl + sample
    }

    /// Generates a number $n \in [min_incl, max_excl)$ uniformly at random.
    ///
    /// NOTE: The uniformity is not perfect, but it can be proved that the bias is negligible.
    /// If you need perfect uniformity, consider implement your own via rejection sampling.
    public fun u64_range(min_incl: u64, max_excl: u64): u64 acquires PerBlockRandomness {
        event::emit(RandomnessGeneratedEvent {});

        u64_range_internal(min_incl, max_excl)
    }

    /// Same computation as `u64_range` without emitting `RandomnessGeneratedEvent`. Application
    /// code should call `u64_range`.
    public fun u64_range_internal(min_incl: u64, max_excl: u64): u64 acquires PerBlockRandomness {
        let range = ((max_excl - min_incl) as u256);
        let sample = ((u256_integer_internal() % range) as u64);

        min_incl + sample
    }

    /// Generates a number $n \in [min_incl, max_excl)$ uniformly at random.
    ///
    /// NOTE: The uniformity is not perfect, but it can be proved that the bias is negligible.
    /// If you need perfect uniformity, consider implement your own via rejection sampling.
    public fun u128_range(min_incl: u128, max_excl: u128): u128 acquires PerBlockRandomness {
        let range = ((max_excl - min_incl) as u256);
        let sample = ((u256_integer_internal() % range) as u128);

        event::emit(RandomnessGeneratedEvent {});

        min_incl + sample
    }

    /// Generates a number $n \in [min_incl, max_excl)$ uniformly at random.
    ///
    /// NOTE: The uniformity is not perfect, but it can be proved that the bias is negligible.
    /// If you need perfect uniformity, consider implement your own with `u256_integer()` + rejection sampling.
    public fun u256_range(min_incl: u256, max_excl: u256): u256 acquires PerBlockRandomness {
        let range = max_excl - min_incl;
        let r0 = u256_integer_internal();
        let r1 = u256_integer_internal();

        // Will compute sample := (r0 + r1*2^256) % range.

        let sample = r1 % range;
        let i = 0;
        while ({
            spec {};
            i < 256
        }) {
            sample = safe_add_mod(sample, sample, range);
            i = i + 1;
        };

        let sample = safe_add_mod(sample, r0 % range, range);
        spec {};

        event::emit(RandomnessGeneratedEvent {});

        min_incl + sample
    }

    /// Generate a permutation of `[0, 1, ..., n-1]` uniformly at random.
    /// If n is 0, returns the empty vector.
    /// `n = 0` and `n = 1` make no draw; `n >= 2` makes `n - 1` draws.
    public fun permutation(n: u64): vector<u64> acquires PerBlockRandomness {
        event::emit(RandomnessGeneratedEvent {});

        let values = vector[];

        if (n == 0) {
            return vector[]
        };

        // Initialize into [0, 1, ..., n-1].
        let i = 0;
        while ({
            spec {};
            i < n
        }) {
            std::vector::push_back(&mut values, i);
            i = i + 1;
        };
        spec {};

        // Shuffle.
        let tail = n - 1;
        while ({
            spec {};
            tail > 0
        }) {
            let pop_position = u64_range_internal(0, tail + 1);
            spec {};
            std::vector::swap(&mut values, pop_position, tail);
            tail = tail - 1;
        };

        values
    }

    #[test_only]
    public fun set_seed(seed: vector<u8>) acquires PerBlockRandomness {
        assert!(vector::length(&seed) == 32, 0);
        let randomness = borrow_global_mut<PerBlockRandomness>(@supra_framework);
        randomness.seed = option::some(seed);
    }

    /// Compute `(a + b) % m`, assuming `m >= 1, 0 <= a < m, 0<= b < m`.
    fun safe_add_mod(a: u256, b: u256, m: u256): u256 {
        let a_clone = a;
        let neg_b = m - b;
        let a_less = a < neg_b;
        take_first(
            if (a_less) { a + b }
            else {
                a_clone - neg_b
            },
            if (!a_less) {
                a_clone - neg_b
            } else { a + b }
        )
    }

    fun take_first(x: u256, _y: u256): u256 {
        x
    }

    #[verify_only]
    fun safe_add_mod_for_verification(a: u256, b: u256, m: u256): u256 {
        let neg_b = m - b;
        if (a < neg_b) { a + b }
        else {
            a - neg_b
        }
    }

    /// Returns the transaction-local 8-byte little-endian draw counter, then increments it
    /// (wrapping modulo 2^64). Aborts with code 1, the value of `E_API_USE_IS_BIASIBLE`, if the
    /// transaction is not marked unbiasable; `next_32_bytes` performs that check first. While the
    /// entry function's `min_remaining_gas` is pending, that is, before the transaction's first
    /// draw, aborts with code 3 if a `dispatchable_fungible_asset` function is on the call stack,
    /// leaving the minimums pending. Otherwise the draw is the first draw, and aborts with code 2
    /// if less gas remains from the transaction's `max_gas_amount` than `min_remaining_gas`, and
    /// then with code 4 if less remains under the execution or IO limit than
    /// `min_remaining_execution_gas` (see the module documentation).
    native fun fetch_and_increment_txn_counter(): vector<u8>;

    /// Returns whether the VM marked this transaction unbiasable. The VM does so for:
    ///  1. a private or `public(friend)` entry-function payload annotated `#[randomness]`,
    ///     including the entry function of an automated task;
    ///  2. an approved governance script, while `SUPRA_DKG` is enabled; governance is trusted not
    ///     to test and abort;
    ///  3. the block-metadata transaction, while `SUPRA_DKG` is enabled.
    /// The mark protects the transaction boundary against test-and-abort. It says nothing about
    /// the strength of the block seed itself.
    native fun is_unbiasable(): bool;

    #[test]
    fun test_safe_add_mod() {
        assert!(2 == safe_add_mod(3, 4, 5), 1);
        assert!(2 == safe_add_mod(4, 3, 5), 1);
        assert!(7 == safe_add_mod(3, 4, 9), 1);
        assert!(7 == safe_add_mod(4, 3, 9), 1);
        assert!(
            0xfffffffffffffffffffffffffffffffffffffffffffffffe
                == safe_add_mod(
                    0xfffffffffffffffffffffffffffffffffffffffffffffffd,
                    0x000000000000000000000000000000000000000000000001,
                    0xffffffffffffffffffffffffffffffffffffffffffffffff
                ),
            1
        );
        assert!(
            0xfffffffffffffffffffffffffffffffffffffffffffffffe
                == safe_add_mod(
                    0x000000000000000000000000000000000000000000000001,
                    0xfffffffffffffffffffffffffffffffffffffffffffffffd,
                    0xffffffffffffffffffffffffffffffffffffffffffffffff
                ),
            1
        );
        assert!(
            0x000000000000000000000000000000000000000000000000
                == safe_add_mod(
                    0xfffffffffffffffffffffffffffffffffffffffffffffffd,
                    0x000000000000000000000000000000000000000000000002,
                    0xffffffffffffffffffffffffffffffffffffffffffffffff
                ),
            1
        );
        assert!(
            0x000000000000000000000000000000000000000000000000
                == safe_add_mod(
                    0x000000000000000000000000000000000000000000000002,
                    0xfffffffffffffffffffffffffffffffffffffffffffffffd,
                    0xffffffffffffffffffffffffffffffffffffffffffffffff
                ),
            1
        );
        assert!(
            0x000000000000000000000000000000000000000000000001
                == safe_add_mod(
                    0xfffffffffffffffffffffffffffffffffffffffffffffffd,
                    0x000000000000000000000000000000000000000000000003,
                    0xffffffffffffffffffffffffffffffffffffffffffffffff
                ),
            1
        );
        assert!(
            0x000000000000000000000000000000000000000000000001
                == safe_add_mod(
                    0x000000000000000000000000000000000000000000000003,
                    0xfffffffffffffffffffffffffffffffffffffffffffffffd,
                    0xffffffffffffffffffffffffffffffffffffffffffffffff
                ),
            1
        );
        assert!(
            0xfffffffffffffffffffffffffffffffffffffffffffffffd
                == safe_add_mod(
                    0xfffffffffffffffffffffffffffffffffffffffffffffffe,
                    0xfffffffffffffffffffffffffffffffffffffffffffffffe,
                    0xffffffffffffffffffffffffffffffffffffffffffffffff
                ),
            1
        );
    }

    #[test(fx = @supra_framework)]
    fun randomness_smoke_test(fx: signer) acquires PerBlockRandomness {
        initialize(&fx);
        set_seed(x"0000000000000000000000000000000000000000000000000000000000000000");
        // Test cases should always have no bias for any randomness call.
        assert!(is_unbiasable(), 0);
        let num = u64_integer();
        debug::print(&num);
    }

    #[test_only]
    fun assert_event_count_equals(count: u64) {
        let events = event::emitted_events<RandomnessGeneratedEvent>();
        assert!(vector::length(&events) == count, 0);
    }

    #[test(fx = @supra_framework)]
    fun test_emit_events(fx: signer) acquires PerBlockRandomness {
        initialize_for_testing(&fx);

        let c = 0;
        assert_event_count_equals(c);

        let _ = bytes(1);
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u8_integer();
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u16_integer();
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u32_integer();
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u64_integer();
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u128_integer();
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u256_integer();
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u8_range(0, 255);
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u16_range(0, 255);
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u32_range(0, 255);
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u64_range(0, 255);
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u128_range(0, 255);
        c = c + 1;
        assert_event_count_equals(c);

        let _ = u256_range(0, 255);
        c = c + 1;
        assert_event_count_equals(c);

        let _ = permutation(6);
        c = c + 1;
        assert_event_count_equals(c);
    }

    #[test(fx = @supra_framework)]
    fun test_bytes(fx: signer) acquires PerBlockRandomness {
        initialize_for_testing(&fx);

        let v = bytes(0);
        assert!(vector::length(&v) == 0, 0);

        let v = bytes(1);
        assert!(vector::length(&v) == 1, 0);
        let v = bytes(2);
        assert!(vector::length(&v) == 2, 0);
        let v = bytes(3);
        assert!(vector::length(&v) == 3, 0);
        let v = bytes(4);
        assert!(vector::length(&v) == 4, 0);
        let v = bytes(30);
        assert!(vector::length(&v) == 30, 0);
        let v = bytes(31);
        assert!(vector::length(&v) == 31, 0);
        let v = bytes(32);
        assert!(vector::length(&v) == 32, 0);

        let v = bytes(33);
        assert!(vector::length(&v) == 33, 0);
        let v = bytes(50);
        assert!(vector::length(&v) == 50, 0);
        let v = bytes(63);
        assert!(vector::length(&v) == 63, 0);
        let v = bytes(64);
        assert!(vector::length(&v) == 64, 0);
    }

    #[test_only]
    fun is_permutation(v: &vector<u64>): bool {
        let present = vector[];

        // Mark all elements from 0 to n-1 as not present
        let n = vector::length(v);
        for (i in 0..n) {
            vector::push_back(&mut present, false);
        };

        for (i in 0..n) {
            let e = vector::borrow(v, i);
            let bit = vector::borrow_mut(&mut present, *e);
            *bit = true;
        };

        for (i in 0..n) {
            let bit = vector::borrow(&present, i);
            if (*bit == false) {
                return false
            };
        };

        true
    }

    #[test(fx = @supra_framework)]
    fun test_permutation(fx: signer) acquires PerBlockRandomness {
        initialize_for_testing(&fx);

        let v = permutation(0);
        assert!(vector::length(&v) == 0, 0);

        test_permutation_internal(1);
        test_permutation_internal(2);
        test_permutation_internal(3);
        test_permutation_internal(4);
    }

    #[test_only]
    /// WARNING: Do not call this with a large `size`, since execution time will be \Omega(size!), where ! is the factorial
    /// operator.
    fun test_permutation_internal(size: u64) acquires PerBlockRandomness {
        let num_permutations = 1;
        let c = 1;
        for (i in 0..size) {
            num_permutations = num_permutations * c;
            c = c + 1;
        };

        let permutations = table_with_length::new<vector<u64>, bool>();

        // This loop will not exit until all permutations are created
        while (table_with_length::length(&permutations) < num_permutations) {
            let v = permutation(size);
            assert!(vector::length(&v) == size, 0);
            assert!(is_permutation(&v), 0);

            if (table_with_length::contains(&permutations, v) == false) {
                table_with_length::add(&mut permutations, v, true);
            }
        };

        table_with_length::drop_unchecked(permutations);
    }
}

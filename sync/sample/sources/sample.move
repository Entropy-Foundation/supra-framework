/// A package that depends on the generated framework, compiled and tested by the
/// sync workflow before it pushes a network branch. It calls into each of the four
/// packages, so compiling it builds the modules it reaches in each of them.
module sample::sample {
    use std::hash;
    use std::option;
    use std::signer;
    use std::string::{Self, String};
    use std::vector;
    use aptos_std::math64;
    use aptos_std::simple_map;
    use aptos_std::table::{Self, Table};
    use aptos_std::type_info;
    use supra_std::enumerable_map::{Self, EnumerableMap};
    use supra_framework::account;
    use supra_framework::coin;
    use supra_framework::event;
    use supra_framework::object;
    use supra_framework::primary_fungible_store;
    use supra_framework::supra_coin::SupraCoin;
    use supra_framework::timestamp;

    struct Counter has key {
        value: u64,
        history: Table<u64, u64>,
        values: EnumerableMap<u64, u64>,
    }

    #[event]
    struct Incremented has drop, store {
        account: address,
        value: u64,
    }

    public entry fun create(account: &signer) {
        move_to(account, Counter { value: 0, history: table::new(), values: enumerable_map::new_map() });
    }

    public entry fun increment(account: &signer) acquires Counter {
        let addr = signer::address_of(account);
        let counter = borrow_global_mut<Counter>(addr);
        counter.value = counter.value + 1;
        table::add(&mut counter.history, counter.value, timestamp::now_seconds());
        enumerable_map::add_value(&mut counter.values, counter.value, counter.value);
        event::emit(Incremented { account: addr, value: counter.value });
    }

    #[view]
    public fun value(addr: address): u64 acquires Counter {
        borrow_global<Counter>(addr).value
    }

    #[view]
    public fun balances(addr: address): (u64, u64) {
        let metadata = option::destroy_some(coin::paired_metadata<SupraCoin>());
        (coin::balance<SupraCoin>(addr), primary_fungible_store::balance(addr, metadata))
    }

    public fun named_object(creator: &signer, seed: vector<u8>): address {
        object::address_from_constructor_ref(&object::create_named_object(creator, seed))
    }

    public fun describe(values: vector<u64>): (String, vector<u8>, u64) {
        let map = simple_map::new<u64, u64>();
        let largest = 0;
        let i = 0;
        while (i < vector::length(&values)) {
            let value = *vector::borrow(&values, i);
            simple_map::upsert(&mut map, i, value);
            largest = math64::max(largest, value);
            i = i + 1;
        };
        assert!(simple_map::length(&map) == vector::length(&values), 0);
        let total = 0;
        vector::for_each_ref(&values, |value| total = total + *value);
        let doubled = option::map(option::some(total), |t| t * 2);
        assert!(option::destroy_some(doubled) == 2 * total, 5);
        let digest = hash::sha3_256(*string::bytes(&string::utf8(b"sample")));
        (type_info::type_name<Counter>(), digest, largest)
    }

    #[test(account = @0xCAFE)]
    fun increment_counts(account: signer) acquires Counter {
        account::create_account_for_test(@0xCAFE);
        timestamp::set_time_has_started_for_testing(&account::create_signer_for_test(@supra_framework));
        create(&account);
        increment(&account);
        assert!(value(@0xCAFE) == 1, 0);
        assert!(enumerable_map::length(&borrow_global<Counter>(@0xCAFE).values) == 1, 4);
        let (_, digest, largest) = describe(vector[3, 9, 4]);
        assert!(largest == 9, 1);
        assert!(vector::length(&digest) == 32, 2);
        assert!(account::exists_at(@0xCAFE), 3);
    }
}

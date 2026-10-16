/// A package that depends on the generated framework, compiled and tested by the
/// sync workflow before it pushes a network branch.
module sample::sample {
    use std::signer;

    struct Counter has key {
        value: u64,
    }

    public entry fun create(account: &signer) {
        move_to(account, Counter { value: 0 });
    }

    public entry fun increment(account: &signer) acquires Counter {
        let counter = borrow_global_mut<Counter>(signer::address_of(account));
        counter.value = counter.value + 1;
    }

    #[view]
    public fun value(addr: address): u64 acquires Counter {
        borrow_global<Counter>(addr).value
    }

    #[test(account = @0xCAFE)]
    fun increment_counts(account: signer) acquires Counter {
        supra_framework::account::create_account_for_test(@0xCAFE);
        create(&account);
        increment(&account);
        assert!(value(@0xCAFE) == 1, 0);
    }
}

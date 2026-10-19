/// This module is unused.
module supra_framework::network_address {
    use std::error;

    /// The functions in this module are unused and must not be called.
    const EDISABLED: u64 = 2;

    public fun is_well_formed_network_addresses(_bytes: &vector<u8>): bool {
        abort error::unavailable(EDISABLED)
    }

    public fun assert_well_formed_network_addresses(_bytes: &vector<u8>) {
        abort error::unavailable(EDISABLED)
    }
}

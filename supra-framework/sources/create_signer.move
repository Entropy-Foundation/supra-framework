/// Provides a common place for exporting `create_signer` across the Supra Framework.
///
/// To use create_signer, add the module below, such that:
/// `friend supra_framework::friend_wants_create_signer`
/// where `friend_wants_create_signer` is the module that needs `create_signer`.
///
/// Note, that this is only available within the Supra Framework.
///
/// This exists to make auditing straight forward and to limit the need to depend
/// on account to have access to this.
module supra_framework::create_signer {
    friend supra_framework::account;
    friend supra_framework::supra_account;
    friend supra_framework::coin;
    friend supra_framework::fungible_asset;
    friend supra_framework::genesis;
    friend supra_framework::multisig_account;
    friend supra_framework::object;
    friend supra_framework::automation_registry;
    // `supra_dkg` creates its session resources on first use rather than at genesis, because a
    // chain that predates them has no other opportunity to acquire a framework signer: DKG sessions
    // are driven from the block prologue and from VM-dispatched validator transactions, neither of
    // which carries one.
    friend supra_framework::supra_dkg;
    // `stake` preserves the outgoing epoch's validator set from `on_new_epoch`, which takes no
    // signer, and creates that archive on first use rather than at genesis so that a chain which
    // predates it does not need a migration.
    friend supra_framework::stake;

    public(friend) native fun create_signer(addr: address): signer;
}

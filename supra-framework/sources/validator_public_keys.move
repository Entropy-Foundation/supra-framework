// Copyright (c) 2024 Supra.
module supra_framework::validator_public_keys {
    use std::bcs;
    use std::error;
    use std::option;
    use aptos_std::bls12381;
    use aptos_std::ed25519;
    use supra_framework::util;
    use supra_std::class_groups;
    use std::vector;
    #[test_only]
    use aptos_std::bls12381::public_key_with_pop_to_normal;
    #[test_only]
    use supra_framework::validator_public_keys;

    /// The integer should match the Rust enum value representation in `CertificateThresholdType`.
    /// f+1, given there are f Byzantine nodes in the [Committee].
    const CERTIFICATE_THRESHOLD_TYPE_VALIDITY: u8 = 0;
    /// The integer should match the Rust enum value representation in `CertificateThresholdType`.
    /// 2f+1, given there are f Byzantine nodes in the [Committee] and n >= 3f + 1 nodes in total.
    const CERTIFICATE_THRESHOLD_TYPE_QUORUM: u8 = 1;
    /// The integer should match the Rust enum value representation in `CertificateThresholdType`.
    /// n, where n is the total number of nodes in the [Committee].
    const CERTIFICATE_THRESHOLD_TYPE_UNANIMOUS: u8 = 2;
    /// The integer should match the Rust enum value representation in `CertificateThresholdType`.
    /// f+1, given there are f Byzantine nodes and c crash-only nodes in the [Committee] with n >= 3f + 2c + 1 nodes.
    const CERTIFICATE_THRESHOLD_TYPE_BCFT_VALIDITY: u8 = 3;
    /// The integer should match the Rust enum value representation in `CertificateThresholdType`
    /// 2f + c + 1, given there are f Byzantine nodes and c crash-only nodes in the [Committee] with n >= 3f + 2c + 1 nodes.
    const CERTIFICATE_THRESHOLD_TYPE_BCFT_QUORUM: u8 = 4;
    /// The integer should match the Rust enum value representation in `CertificateThresholdType`.
    /// n - f - c, given there are f Byzantine nodes and c crash-only nodes in the [Committee] with n >= 3f + 2c + 1 nodes.
    const CERTIFICATE_THRESHOLD_TYPE_BCFT_FALLBACK_VIEW_CHANGE: u8 = 5;
    /// The integer should match the Rust enum value representation in `CertificateThresholdType`.
    /// f+1, given there are f Byzantine nodes in the [Committee] with n >= 2f + 1 nodes.
    // The largest tag defined here. `aptos_types::dkg::payloads` carries it as
    // `MAX_CERTIFICATE_THRESHOLD_TYPE`, to reject a DKG payload naming a tag that no key can be
    // installed for, and `dkg_types` asserts the two agree. A tag added here has to be added there
    // in the same release, or binaries carrying the old bound reject payloads this module accepts.
    const CERTIFICATE_THRESHOLD_TYPE_CLAN_MAJORITY: u8 = 6;

    /// Error: Unknown certificate threshold type.
    const EUNKNOWN_THRESHOLD_TYPE: u64 = 1;
    /// Error: A consensus key blob is too short to contain an appended BLS proof-of-possession.
    const EINVALID_POP_LENGTH: u64 = 2;

    /// Internal tag wrapper
    struct CertificateThresholdType has copy, drop, store {
        tag: u8
    }

    public fun validity_certificate_type(): CertificateThresholdType {
        CertificateThresholdType { tag: CERTIFICATE_THRESHOLD_TYPE_VALIDITY }
    }

    public fun quorum_certificate_type(): CertificateThresholdType {
        CertificateThresholdType { tag: CERTIFICATE_THRESHOLD_TYPE_QUORUM }
    }

    public fun unanimous_certificate_type(): CertificateThresholdType {
        CertificateThresholdType { tag: CERTIFICATE_THRESHOLD_TYPE_UNANIMOUS }
    }

    public fun bcft_validity_certificate_type(): CertificateThresholdType {
        CertificateThresholdType { tag: CERTIFICATE_THRESHOLD_TYPE_BCFT_VALIDITY }
    }

    public fun bcft_quorum_certificate_type(): CertificateThresholdType {
        CertificateThresholdType { tag: CERTIFICATE_THRESHOLD_TYPE_BCFT_QUORUM }
    }

    public fun bcft_fallback_view_change_certificate_type(): CertificateThresholdType {
        CertificateThresholdType {
            tag: CERTIFICATE_THRESHOLD_TYPE_BCFT_FALLBACK_VIEW_CHANGE
        }
    }

    public fun clan_majority_certificate_type(): CertificateThresholdType {
        CertificateThresholdType { tag: CERTIFICATE_THRESHOLD_TYPE_CLAN_MAJORITY }
    }

    public fun is_validity_certificate_type(t: &CertificateThresholdType): bool {
        t.tag == CERTIFICATE_THRESHOLD_TYPE_VALIDITY
    }

    public fun is_quorum_certificate_type(t: &CertificateThresholdType): bool {
        t.tag == CERTIFICATE_THRESHOLD_TYPE_QUORUM
    }

    public fun is_unanimous_certificate_type(
        t: &CertificateThresholdType
    ): bool {
        t.tag == CERTIFICATE_THRESHOLD_TYPE_UNANIMOUS
    }

    public fun is_bcft_validity_certificate_type(
        t: &CertificateThresholdType
    ): bool {
        t.tag == CERTIFICATE_THRESHOLD_TYPE_BCFT_VALIDITY
    }

    public fun is_bcft_quorum_certificate_type(
        t: &CertificateThresholdType
    ): bool {
        t.tag == CERTIFICATE_THRESHOLD_TYPE_BCFT_QUORUM
    }

    public fun is_bcft_fallback_view_change_certificate_type(
        t: &CertificateThresholdType
    ): bool {
        t.tag == CERTIFICATE_THRESHOLD_TYPE_BCFT_FALLBACK_VIEW_CHANGE
    }

    public fun is_clan_majority_certificate_type(
        t: &CertificateThresholdType
    ): bool {
        t.tag == CERTIFICATE_THRESHOLD_TYPE_CLAN_MAJORITY
    }

    /// Returns true iff `threshold_type` is a tag that `rotate_supra_bls_threshold_key_by_type`
    /// installs a key for. The two must name the same set of tags: a tag added to one is added to
    /// the other.
    public fun is_installable_threshold_type(threshold_type: u8): bool {
        threshold_type == CERTIFICATE_THRESHOLD_TYPE_VALIDITY
            || threshold_type == CERTIFICATE_THRESHOLD_TYPE_QUORUM
            || threshold_type == CERTIFICATE_THRESHOLD_TYPE_UNANIMOUS
            || threshold_type == CERTIFICATE_THRESHOLD_TYPE_BCFT_VALIDITY
            || threshold_type == CERTIFICATE_THRESHOLD_TYPE_BCFT_QUORUM
            || threshold_type == CERTIFICATE_THRESHOLD_TYPE_BCFT_FALLBACK_VIEW_CHANGE
            || threshold_type == CERTIFICATE_THRESHOLD_TYPE_CLAN_MAJORITY
    }

    /// The size of a serialized ed25519 public key, in bytes.
    const ED25519_PUBLIC_KEY_NUM_BYTES: u64 = 32;
    /// The size of a serialized bls12381 G1 public key, in bytes.
    const BLS12381_G1_PUBLIC_KEY_NUM_BYTES: u64 = 48;
    /// The size of a serialized bls12381 proof-of-possession (a G2 signature), in bytes.
    const BLS12381_POP_NUM_BYTES: u64 = 96;

    /// InternalPublicKeys consists of:
    /// 1. bls multisig key
    /// 2. bls threshold key shares for various certificate types
    /// 3. classgroup key
    /// 4. ed25519 key
    struct InternalPublicKeys has copy, drop, store {
        bls_multisig_key: bls12381::PublicKey,
        bls_threshold_validity_certificate_key: option::Option<bls12381::PublicKey>,
        bls_threshold_quorum_certificate_key: option::Option<bls12381::PublicKey>,
        bls_threshold_unanimous_certificate_key: option::Option<bls12381::PublicKey>,
        bls_threshold_bcft_validity_certificate_key: option::Option<bls12381::PublicKey>,
        bls_threshold_bcft_quorum_certificate_key: option::Option<bls12381::PublicKey>,
        bls_threshold_bcft_fallback_view_change_certificate_key: option::Option<bls12381::PublicKey>,
        bls_threshold_clan_majority_certificate_key: option::Option<bls12381::PublicKey>,
        class_group_key: class_groups::CGPublicKey,
        ed25519_key: ed25519::ValidatedPublicKey
    }

    /// ValidatorPublicKeys consists of:
    /// 1. network key
    /// 2. supra's internal keys
    struct ValidatorPublicKeys has copy, drop, store {
        network_key: ed25519::ValidatedPublicKey,
        supra_keys: InternalPublicKeys
    }

    #[test_only]
    /// This struct holds calidator secret key that can be used during testing.
    struct ValidatorSecretKeys has drop {
        network_key: ed25519::SecretKey,
        supra_bls_multi_sig_bls_key: bls12381::SecretKey,
        supra_bls_threshold_validity_key: option::Option<bls12381::SecretKey>,
        supra_bls_threshold_quorum_key: option::Option<bls12381::SecretKey>,
        supra_bls_threshold_unanimous_key: option::Option<bls12381::SecretKey>,
        supra_bls_threshold_bcft_validity_key: option::Option<bls12381::SecretKey>,
        supra_bls_threshold_bcft_quorum_key: option::Option<bls12381::SecretKey>,
        supra_bls_threshold_bcft_fallback_view_change_key: option::Option<bls12381::SecretKey>,
        supra_bls_threshold_clan_majority_key: option::Option<bls12381::SecretKey>,
        cg_key: class_groups::SecretKey,
        supra_ed_key: ed25519::SecretKey
    }

    public fun validator_public_keys_from_bytes(bytes: vector<u8>): ValidatorPublicKeys {
        util::from_bytes<ValidatorPublicKeys>(bytes)
    }

    public fun public_key_to_bytes(pk: ValidatorPublicKeys): vector<u8> {
        // bcs deserialization
        bcs::to_bytes<ValidatorPublicKeys>(&pk)
    }

    public fun get_network_key(pk: &ValidatorPublicKeys): ed25519::ValidatedPublicKey {
        pk.network_key
    }

    public fun get_supra_bls_multi_sig_pub_key(pk: &ValidatorPublicKeys): bls12381::PublicKey {
        pk.supra_keys.bls_multisig_key
    }

    public fun get_supra_cg_key(pk: &ValidatorPublicKeys): class_groups::CGPublicKey {
        pk.supra_keys.class_group_key
    }

    public fun get_supra_ed_key(pk: &ValidatorPublicKeys): ed25519::ValidatedPublicKey {
        pk.supra_keys.ed25519_key
    }

    /// Overwrites the four static keys of `target` (network_key, bls_multisig_key, class_group_key,
    /// ed25519_key) with those from `source`, leaving the DKG-managed BLS threshold key fields of
    /// `target` untouched. Used by `stake::rotate_consensus_key` so that an operator key rotation
    /// only changes the static keys and cannot clobber the threshold keys written by the DKG via
    /// `stake::set_dkg_output_keys`.
    public fun replace_static_keys(
        target: &mut ValidatorPublicKeys, source: &ValidatorPublicKeys
    ) {
        target.network_key = source.network_key;
        target.supra_keys.bls_multisig_key = source.supra_keys.bls_multisig_key;
        target.supra_keys.class_group_key = source.supra_keys.class_group_key;
        target.supra_keys.ed25519_key = source.supra_keys.ed25519_key;
    }

    /// Returns true iff `a` and `b` hold the same value for any one of the four static keys:
    /// the network key, the BLS multisig key, the class-group key or the ed25519 key. This is the
    /// same set of fields that `replace_static_keys` writes and `validate_static_keys` checks.
    public fun shares_any_static_key(
        a: &ValidatorPublicKeys, b: &ValidatorPublicKeys
    ): bool {
        a.network_key == b.network_key
            || a.supra_keys.bls_multisig_key == b.supra_keys.bls_multisig_key
            || a.supra_keys.class_group_key == b.supra_keys.class_group_key
            || a.supra_keys.ed25519_key == b.supra_keys.ed25519_key
    }

    /// Returns true iff the four static (non-DKG) public keys decode to cryptographically valid
    /// keys: the network key, the BLS multisig key, the class-group key and the ed25519 key.
    ///
    /// `validator_public_keys_from_bytes` reconstructs each key's raw bytes via BCS without
    /// running the per-key validation natives, so a registration blob can carry malformed keys
    /// (the `Validated*`/`PublicKey` types are a misnomer after deserialization). This re-runs
    /// each key's validating constructor on the recovered bytes to reject them.
    ///
    /// The DKG-managed BLS threshold key shares are not checked here, and are not reconstructed
    /// through a validating native either, so a caller that stores a submitted blob as the
    /// validator's consensus key must reject any that are present via `has_no_bls_threshold_keys`.
    /// Only `stake::set_dkg_output_keys` may populate them, and it validates what it writes.
    ///
    /// Proof-of-possession is not verified here either (no PoP is supplied at registration); only
    /// key well-formedness / subgroup membership is checked.
    public fun validate_static_keys(pk: &ValidatorPublicKeys): bool {
        is_valid_ed25519_key(&pk.network_key)
            && is_valid_bls12381_key(&pk.supra_keys.bls_multisig_key)
            && is_valid_cg_key(&pk.supra_keys.class_group_key)
            && is_valid_ed25519_key(&pk.supra_keys.ed25519_key)
    }

    /// Returns true iff every DKG-managed BLS threshold key share of `pk` is `option::none()`.
    ///
    /// These fields belong to the protocol: `stake::set_dkg_output_keys` is their only legitimate
    /// writer, it validates what it writes, and it overwrites only the threshold types the DKG
    /// produced. `validator_public_keys_from_bytes` rebuilds them from the bytes it is given
    /// without running any per-key validation native, so callers that store a submitted blob as the
    /// validator's consensus key must reject it unless this returns true.
    public fun has_no_bls_threshold_keys(pk: &ValidatorPublicKeys): bool {
        option::is_none(&pk.supra_keys.bls_threshold_validity_certificate_key)
            && option::is_none(&pk.supra_keys.bls_threshold_quorum_certificate_key)
            && option::is_none(&pk.supra_keys.bls_threshold_unanimous_certificate_key)
            && option::is_none(&pk.supra_keys.bls_threshold_bcft_validity_certificate_key)
            && option::is_none(&pk.supra_keys.bls_threshold_bcft_quorum_certificate_key)
            && option::is_none(
                &pk.supra_keys.bls_threshold_bcft_fallback_view_change_certificate_key
            )
            && option::is_none(&pk.supra_keys.bls_threshold_clan_majority_certificate_key)
    }

    fun is_valid_ed25519_key(pk: &ed25519::ValidatedPublicKey): bool {
        option::is_some(
            &ed25519::new_validated_public_key_from_bytes(
                ed25519::validated_public_key_to_bytes(pk)
            )
        )
    }

    fun is_valid_bls12381_key(pk: &bls12381::PublicKey): bool {
        option::is_some(
            &bls12381::public_key_from_bytes(bls12381::public_key_to_bytes(pk))
        )
    }

    fun is_valid_cg_key(pk: &class_groups::CGPublicKey): bool {
        option::is_some(
            &class_groups::public_key_from_bytes(class_groups::public_key_to_bytes(pk))
        )
    }

    /// Splits a submitted consensus key blob into its `ValidatorPublicKeys` bytes (the prefix) and
    /// the appended BLS12-381 proof-of-possession (the trailing `BLS12381_POP_NUM_BYTES` bytes).
    /// Operators submit the PoP appended to the key bytes so that the contract can verify it
    /// without a dedicated entry-function parameter (Move forbids changing public signatures).
    public fun split_consensus_key_and_pop(blob: vector<u8>): (vector<u8>, vector<u8>) {
        let len = vector::length(&blob);
        assert!(len >= BLS12381_POP_NUM_BYTES, error::invalid_argument(EINVALID_POP_LENGTH));
        let pop = vector::trim(&mut blob, len - BLS12381_POP_NUM_BYTES);
        (blob, pop)
    }

    /// Returns true iff `pop_bytes` is a valid BLS12-381 proof-of-possession for the BLS multisig
    /// key in `pk`. The multisig key is the only aggregatable (hence rogue-key-attackable) key an
    /// operator submits, so it is the only one that requires a PoP; the class-group key carries its
    /// own ZK PoP (verified by its `validate_pubkey_internal` native), the ed25519 keys are
    /// non-aggregated, and the BLS threshold shares are produced by the DKG.
    public fun verify_bls_multisig_pop(
        pk: &ValidatorPublicKeys, pop_bytes: vector<u8>
    ): bool {
        let pk_bytes = bls12381::public_key_to_bytes(&pk.supra_keys.bls_multisig_key);
        let pop = bls12381::proof_of_possession_from_bytes(pop_bytes);
        option::is_some(&bls12381::public_key_from_bytes_with_pop(pk_bytes, &pop))
    }

    #[test_only]
    /// Returns the BLS threshold key for the given threshold type, used by tests to assert that
    /// the DKG-managed threshold keys survive an operator key rotation.
    public fun get_supra_bls_threshold_key_by_type(
        pk: &ValidatorPublicKeys, threshold_type: u8
    ): option::Option<bls12381::PublicKey> {
        if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_VALIDITY) {
            pk.supra_keys.bls_threshold_validity_certificate_key
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_QUORUM) {
            pk.supra_keys.bls_threshold_quorum_certificate_key
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_UNANIMOUS) {
            pk.supra_keys.bls_threshold_unanimous_certificate_key
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_BCFT_VALIDITY) {
            pk.supra_keys.bls_threshold_bcft_validity_certificate_key
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_BCFT_QUORUM) {
            pk.supra_keys.bls_threshold_bcft_quorum_certificate_key
        } else if (threshold_type
            == CERTIFICATE_THRESHOLD_TYPE_BCFT_FALLBACK_VIEW_CHANGE) {
            pk.supra_keys.bls_threshold_bcft_fallback_view_change_certificate_key
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_CLAN_MAJORITY) {
            pk.supra_keys.bls_threshold_clan_majority_certificate_key
        } else {
            abort error::invalid_argument(EUNKNOWN_THRESHOLD_TYPE)
        }
    }

    public fun rotate_supra_bls_threshold_validity_key(
        pk: &mut ValidatorPublicKeys, new_bls_threshold_validity_key: bls12381::PublicKey
    ) {
        pk.supra_keys.bls_threshold_validity_certificate_key = option::some(
            new_bls_threshold_validity_key
        );
    }

    public fun rotate_supra_bls_threshold_quorum_key(
        pk: &mut ValidatorPublicKeys, new_bls_threshold_quorum_key: bls12381::PublicKey
    ) {
        pk.supra_keys.bls_threshold_quorum_certificate_key = option::some(
            new_bls_threshold_quorum_key
        );
    }

    public fun rotate_supra_bls_threshold_unanimous_key(
        pk: &mut ValidatorPublicKeys, new_key: bls12381::PublicKey
    ) {
        pk.supra_keys.bls_threshold_unanimous_certificate_key = option::some(new_key);
    }

    public fun rotate_supra_bls_threshold_bcft_validity_key(
        pk: &mut ValidatorPublicKeys, new_key: bls12381::PublicKey
    ) {
        pk.supra_keys.bls_threshold_bcft_validity_certificate_key = option::some(new_key);
    }

    public fun rotate_supra_bls_threshold_bcft_quorum_key(
        pk: &mut ValidatorPublicKeys, new_key: bls12381::PublicKey
    ) {
        pk.supra_keys.bls_threshold_bcft_quorum_certificate_key = option::some(new_key);
    }

    public fun rotate_supra_bls_threshold_bcft_fallback_view_change_key(
        pk: &mut ValidatorPublicKeys, new_key: bls12381::PublicKey
    ) {
        pk.supra_keys.bls_threshold_bcft_fallback_view_change_certificate_key = option::some(
            new_key
        );
    }

    public fun rotate_supra_bls_threshold_clan_majority_key(
        pk: &mut ValidatorPublicKeys, new_key: bls12381::PublicKey
    ) {
        pk.supra_keys.bls_threshold_clan_majority_certificate_key = option::some(new_key);
    }

    /// Rotate a threshold key based on the threshold type tag.
    /// threshold_type: 0=validity, 1=quorum, 2=unanimous, 3=bcft_validity, 4=bcft_quorum, 5=bcft_fallback_view_change, 6=clan_majority
    public fun rotate_supra_bls_threshold_key_by_type(
        pk: &mut ValidatorPublicKeys, threshold_type: u8, new_key: bls12381::PublicKey
    ) {
        if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_VALIDITY) {
            rotate_supra_bls_threshold_validity_key(pk, new_key);
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_QUORUM) {
            rotate_supra_bls_threshold_quorum_key(pk, new_key);
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_UNANIMOUS) {
            rotate_supra_bls_threshold_unanimous_key(pk, new_key);
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_BCFT_VALIDITY) {
            rotate_supra_bls_threshold_bcft_validity_key(pk, new_key);
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_BCFT_QUORUM) {
            rotate_supra_bls_threshold_bcft_quorum_key(pk, new_key);
        } else if (threshold_type
            == CERTIFICATE_THRESHOLD_TYPE_BCFT_FALLBACK_VIEW_CHANGE) {
            rotate_supra_bls_threshold_bcft_fallback_view_change_key(pk, new_key);
        } else if (threshold_type == CERTIFICATE_THRESHOLD_TYPE_CLAN_MAJORITY) {
            rotate_supra_bls_threshold_clan_majority_key(pk, new_key);
        } else {
            abort error::invalid_argument(EUNKNOWN_THRESHOLD_TYPE)
        };
    }

    #[test_only]
    /// Generates validator key pair for testing.
    public fun generate_keys(): (ValidatorSecretKeys, ValidatorPublicKeys) {
        let (network_key_sk, network_key_pk) = ed25519::generate_keys();
        let (supra_bls12381_multi_sig_sk, supra_bls12381_multi_sig_pk) =
            bls12381::generate_keys();
        let (supra_cg_sk, supra_cg_pk) = class_groups::generate_keys();
        let (supra_ed_key_sk, supra_ed_key_pk) = ed25519::generate_keys();

        let sk = ValidatorSecretKeys {
            network_key: network_key_sk,
            supra_bls_multi_sig_bls_key: supra_bls12381_multi_sig_sk,
            supra_bls_threshold_validity_key: option::none(),
            supra_bls_threshold_quorum_key: option::none(),
            supra_bls_threshold_unanimous_key: option::none(),
            supra_bls_threshold_bcft_validity_key: option::none(),
            supra_bls_threshold_bcft_quorum_key: option::none(),
            supra_bls_threshold_bcft_fallback_view_change_key: option::none(),
            supra_bls_threshold_clan_majority_key: option::none(),
            cg_key: supra_cg_sk,
            supra_ed_key: supra_ed_key_sk
        };

        let pk = ValidatorPublicKeys {
            network_key: network_key_pk,
            supra_keys: InternalPublicKeys {
                bls_multisig_key: public_key_with_pop_to_normal(
                    &supra_bls12381_multi_sig_pk
                ),
                bls_threshold_validity_certificate_key: option::none(),
                bls_threshold_quorum_certificate_key: option::none(),
                bls_threshold_unanimous_certificate_key: option::none(),
                bls_threshold_bcft_validity_certificate_key: option::none(),
                bls_threshold_bcft_quorum_certificate_key: option::none(),
                bls_threshold_bcft_fallback_view_change_certificate_key: option::none(),
                bls_threshold_clan_majority_certificate_key: option::none(),
                class_group_key: supra_cg_pk,
                ed25519_key: supra_ed_key_pk
            }
        };

        (sk, pk)
    }

    #[test_only]
    /// Overwrites only `target`'s network key with `source`'s. Lets a test build two validators that
    /// share exactly one static key and differ in the other three, which is the case
    /// `shares_any_static_key` exists to reject and which comparing whole key blobs does not catch.
    public fun copy_network_key_for_test(
        target: &mut ValidatorPublicKeys, source: &ValidatorPublicKeys
    ) {
        target.network_key = source.network_key;
    }

    #[test_only]
    /// Overwrites only `target`'s BLS multisig key with `source`'s. See `copy_network_key_for_test`.
    ///
    /// Note for callers that need a proof-of-possession: the PoP is over the BLS multisig key, so a
    /// blob built by `serialized_keys_with_pop_for_test` after this call must be given `source`'s
    /// secret keys, not `target`'s.
    public fun copy_bls_multisig_key_for_test(
        target: &mut ValidatorPublicKeys, source: &ValidatorPublicKeys
    ) {
        target.supra_keys.bls_multisig_key = source.supra_keys.bls_multisig_key;
    }

    #[test_only]
    /// Overwrites only `target`'s class-group key with `source`'s. See `copy_network_key_for_test`.
    public fun copy_class_group_key_for_test(
        target: &mut ValidatorPublicKeys, source: &ValidatorPublicKeys
    ) {
        target.supra_keys.class_group_key = source.supra_keys.class_group_key;
    }

    #[test_only]
    /// Overwrites only `target`'s ed25519 key with `source`'s. See `copy_network_key_for_test`.
    public fun copy_ed25519_key_for_test(
        target: &mut ValidatorPublicKeys, source: &ValidatorPublicKeys
    ) {
        target.supra_keys.ed25519_key = source.supra_keys.ed25519_key;
    }

    #[test]
    fun test_shares_any_static_key_detects_each_static_key() {
        let (_sk_a, pk_a) = generate_keys();
        let (_sk_b, pk_b) = generate_keys();
        assert!(!shares_any_static_key(&pk_a, &pk_b), 0);

        let shared_network = pk_b;
        copy_network_key_for_test(&mut shared_network, &pk_a);
        assert!(shares_any_static_key(&pk_a, &shared_network), 1);

        let shared_multisig = pk_b;
        copy_bls_multisig_key_for_test(&mut shared_multisig, &pk_a);
        assert!(shares_any_static_key(&pk_a, &shared_multisig), 2);

        let shared_class_group = pk_b;
        copy_class_group_key_for_test(&mut shared_class_group, &pk_a);
        assert!(shares_any_static_key(&pk_a, &shared_class_group), 3);

        let shared_ed25519 = pk_b;
        copy_ed25519_key_for_test(&mut shared_ed25519, &pk_a);
        assert!(shares_any_static_key(&pk_a, &shared_ed25519), 4);
    }

    #[test]
    /// Freshly generated keys carry no DKG-managed threshold shares, so every pair of validators
    /// holds `option::none()` for all seven of them. Two validators in that state share no static
    /// key, which pins the exclusion of the threshold shares from the comparison.
    fun test_shares_any_static_key_ignores_absent_threshold_keys() {
        let (_sk_a, pk_a) = generate_keys();
        let (_sk_b, pk_b) = generate_keys();
        assert!(option::is_none(&pk_a.supra_keys.bls_threshold_validity_certificate_key), 0);
        assert!(option::is_none(&pk_b.supra_keys.bls_threshold_validity_certificate_key), 1);
        assert!(!shares_any_static_key(&pk_a, &pk_b), 2);
    }

    #[test_only]
    /// Serializes `pk` and appends a valid BLS multisig proof-of-possession generated from `sk`,
    /// producing the exact blob an operator submits to `stake::rotate_consensus_key` under the v2
    /// identity format.
    public fun serialized_keys_with_pop_for_test(
        sk: &ValidatorSecretKeys, pk: &ValidatorPublicKeys
    ): vector<u8> {
        let pop = bls12381::generate_proof_of_possession(&sk.supra_bls_multi_sig_bls_key);
        let blob = public_key_to_bytes(*pk);
        vector::append(&mut blob, bls12381::proof_of_possession_to_bytes(&pop));
        blob
    }

    #[test]
    fun test_verify_bls_multisig_pop() {
        let (sk, pk) = validator_public_keys::generate_keys();
        // A PoP generated from the matching secret verifies.
        let pop = bls12381::generate_proof_of_possession(&sk.supra_bls_multi_sig_bls_key);
        assert!(
            verify_bls_multisig_pop(&pk, bls12381::proof_of_possession_to_bytes(&pop)),
            5001
        );
        // A PoP for a different key does not.
        let (other_sk, _other_pk) = validator_public_keys::generate_keys();
        let other_pop =
            bls12381::generate_proof_of_possession(&other_sk.supra_bls_multi_sig_bls_key);
        assert!(
            !verify_bls_multisig_pop(&pk, bls12381::proof_of_possession_to_bytes(&other_pop)),
            5002
        );
    }

    #[test]
    fun test_split_consensus_key_and_pop_roundtrip() {
        let (sk, pk) = validator_public_keys::generate_keys();
        let keys_bytes = public_key_to_bytes(pk);
        let blob = serialized_keys_with_pop_for_test(&sk, &pk);
        let (split_keys, split_pop) = split_consensus_key_and_pop(blob);
        // The prefix is exactly the original key bytes...
        assert!(split_keys == keys_bytes, 5101);
        // ...and the suffix is a PoP that verifies against the multisig key.
        assert!(verify_bls_multisig_pop(&pk, split_pop), 5102);
    }

    #[test]
    fun test_serde_roundtrip() {
        // Generate full keypair
        let (_sk, pk) = validator_public_keys::generate_keys();

        // Serialize
        let bytes = validator_public_keys::public_key_to_bytes(pk);

        // Parse
        let parsed = validator_public_keys::validator_public_keys_from_bytes(bytes);

        // Compare network key
        let ed0 = get_network_key(&pk);
        let ed1 = get_network_key(&parsed);
        assert!(ed0 == ed1, 1001);

        // BLS multi sig equal
        let b0 = get_supra_bls_multi_sig_pub_key(&pk);
        let b1 = get_supra_bls_multi_sig_pub_key(&parsed);
        assert!(b0 == b1, 1002);

        // CG key equal
        let c0 = get_supra_cg_key(&pk);
        let c1 = get_supra_cg_key(&parsed);
        assert!(c0 == c1, 1003);

        // Compare ED bytes
        let ed0 = get_supra_ed_key(&pk);
        let ed1 = get_supra_ed_key(&parsed);
        assert!(ed0 == ed1, 1004);
    }

    #[test]
    fun test_replace_static_keys_preserves_threshold_keys() {
        // `target` carries a DKG-style threshold key; `source` carries only static keys (its
        // threshold fields are `none`, modelling an operator's rotation payload).
        let (_sk_a, pk_a) = validator_public_keys::generate_keys();
        let (_sk_b, pk_b) = validator_public_keys::generate_keys();

        let (_t_sk, t_pop_pk) = bls12381::generate_keys();
        let threshold_key = public_key_with_pop_to_normal(&t_pop_pk);
        rotate_supra_bls_threshold_validity_key(&mut pk_a, threshold_key);

        replace_static_keys(&mut pk_a, &pk_b);

        // The four static keys now equal those of `source`.
        assert!(get_network_key(&pk_a) == get_network_key(&pk_b), 2001);
        assert!(
            get_supra_bls_multi_sig_pub_key(&pk_a)
                == get_supra_bls_multi_sig_pub_key(&pk_b),
            2002
        );
        assert!(get_supra_cg_key(&pk_a) == get_supra_cg_key(&pk_b), 2003);
        assert!(get_supra_ed_key(&pk_a) == get_supra_ed_key(&pk_b), 2004);

        // The DKG-managed threshold key was preserved (it was `none` in `source`).
        let preserved =
            get_supra_bls_threshold_key_by_type(
                &pk_a, CERTIFICATE_THRESHOLD_TYPE_VALIDITY
            );
        assert!(option::is_some(&preserved), 2005);
        assert!(option::extract(&mut preserved) == threshold_key, 2006);
    }

    #[test]
    /// Every tag `is_installable_threshold_type` accepts is one `rotate_supra_bls_threshold_key_by_type`
    /// installs a key for, and it accepts no tag above the largest defined one.
    fun test_installable_threshold_types_are_the_rotatable_ones() {
        let (_sk, pk) = validator_public_keys::generate_keys();
        let (_t_sk, t_pop_pk) = bls12381::generate_keys();
        let threshold_key = public_key_with_pop_to_normal(&t_pop_pk);

        let tag: u64 = 0;
        while (tag <= 255) {
            let threshold_type = (tag as u8);
            if (threshold_type <= CERTIFICATE_THRESHOLD_TYPE_CLAN_MAJORITY) {
                assert!(is_installable_threshold_type(threshold_type), 2101);
                rotate_supra_bls_threshold_key_by_type(
                    &mut pk, threshold_type, threshold_key
                );
                let installed =
                    get_supra_bls_threshold_key_by_type(&pk, threshold_type);
                assert!(option::extract(&mut installed) == threshold_key, 2102);
            } else {
                assert!(!is_installable_threshold_type(threshold_type), 2103);
            };
            tag = tag + 1;
        };
    }

    #[test_only]
    /// Rewrites a serialized `ValidatorPublicKeys` blob so its network key is malformed (replaced
    /// with an empty byte vector) while keeping the BCS framing intact, so it still deserializes via
    /// `validator_public_keys_from_bytes` yet fails `validate_static_keys`.
    fun with_empty_network_key(bytes: vector<u8>): vector<u8> {
        // The network key is the first BCS field: a 32-byte vector encoded as `0x20 ++ 32 bytes`.
        // Replace it with an empty vector (`0x00`) and keep the remaining fields untouched.
        let corrupt = vector::empty<u8>();
        vector::push_back(&mut corrupt, 0);
        let i = 33; // skip the original length byte (0x20) plus the 32 key bytes.
        let len = vector::length(&bytes);
        while (i < len) {
            vector::push_back(&mut corrupt, *vector::borrow(&bytes, i));
            i = i + 1;
        };
        corrupt
    }

    #[test_only]
    /// Returns a malformed (empty network key) `ValidatorPublicKeys` blob with no appended PoP. Used
    /// to exercise `validate_static_keys` directly.
    public fun serialized_keys_with_invalid_network_key_for_test(): vector<u8> {
        let (_sk, pk) = validator_public_keys::generate_keys();
        with_empty_network_key(public_key_to_bytes(pk))
    }

    #[test_only]
    /// Returns a malformed (empty network key) blob with a *valid* BLS multisig PoP appended -- the
    /// shape an operator submits under v2. PoP verification passes (the multisig key is untouched),
    /// so `stake::validate_consensus_public_key` reaches and fails the static-key check, exercising
    /// the full registration path.
    public fun serialized_keys_with_invalid_network_key_and_pop_for_test(): vector<u8> {
        let (sk, pk) = validator_public_keys::generate_keys();
        let corrupt = with_empty_network_key(public_key_to_bytes(pk));
        let pop = bls12381::generate_proof_of_possession(&sk.supra_bls_multi_sig_bls_key);
        vector::append(&mut corrupt, bls12381::proof_of_possession_to_bytes(&pop));
        corrupt
    }

    #[test]
    fun test_validate_static_keys_rejects_malformed_key() {
        // Freshly generated keys are valid.
        let (_sk, pk) = validator_public_keys::generate_keys();
        assert!(validate_static_keys(&pk), 4001);

        // A blob carrying a malformed (empty) network key deserializes but fails validation.
        let corrupt = serialized_keys_with_invalid_network_key_for_test();
        let bad = validator_public_keys_from_bytes(corrupt);
        assert!(!validate_static_keys(&bad), 4002);
    }

    #[test]
    fun test_has_no_bls_threshold_keys_detects_each_field() {
        let (_t_sk, t_pop_pk) = bls12381::generate_keys();
        let threshold_key = public_key_with_pop_to_normal(&t_pop_pk);

        // Freshly generated keys carry no threshold shares.
        let (_sk, clean_pk) = validator_public_keys::generate_keys();
        assert!(has_no_bls_threshold_keys(&clean_pk), 6001);

        // Each of the seven threshold fields is detected on its own, and survives the BCS round
        // trip a submitted blob goes through, so `validator_public_keys_from_bytes` cannot be used
        // to smuggle one past the check.
        let threshold_type = 0;
        while (threshold_type < 7) {
            let (_sk, pk) = validator_public_keys::generate_keys();
            rotate_supra_bls_threshold_key_by_type(&mut pk, threshold_type, threshold_key);
            assert!(!has_no_bls_threshold_keys(&pk), 6002);
            let parsed = validator_public_keys_from_bytes(public_key_to_bytes(pk));
            assert!(!has_no_bls_threshold_keys(&parsed), 6003);
            threshold_type = threshold_type + 1;
        };
    }
}

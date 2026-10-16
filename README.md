# Supra Framework

This repository holds the Move framework packages deployed at address `0x1` on each Supra network: `MoveStdlib`, `AptosStdlib`, `SupraStdlib` and `SupraFramework`. The source is read from each network's on-chain `0x1::code::PackageRegistry`, so a network's branch holds the framework that network is running.

## Using the framework as a dependency

Add the framework to your package's `Move.toml`:

```toml
[dependencies]
SupraFramework = { git = "https://github.com/Entropy-Foundation/supra-framework.git", rev = "mainnet", subdir = "supra-framework" }
```

`SupraFramework` depends on the other three packages, so they need no entries of their own. To depend on one of them directly, use the same `git` and `rev` with `subdir` set to `move-stdlib`, `aptos-stdlib` or `supra-stdlib`.

## Branches

| Branch | Network | Chain ID |
|---|---|---|
| `mainnet` | Mainnet | 8 |
| `testnet` | Testnet | 6 |
| `devnet` | Devnet | 50 |

A scheduled workflow reads each network's registry every hour and regenerates that network's branch. When the generated files change, the workflow commits them to the branch, and it tags each registry state it has not seen before.

`main` holds this README and the workflow that generates the network branches.

## Tags

Each registry state is tagged `<network>-<hash>`, for example `mainnet-0f0b6eac260e`. `<hash>` is the first 12 hex characters of the SHA-256 of the registry's BCS encoding, as the network's RPC returns it:

```sh
curl -s -H 'Accept: application/x-bcs' \
  'https://rpc-mainnet.supra.com/rpc/v3/accounts/0x1/resources/0x1::code::PackageRegistry' | sha256sum
```

The registry includes each package's `upgrade_number`, which increases with every upgrade of that package, so every framework upgrade produces a new tag, including one that deploys source the network ran before. A network reset that recreates a registry byte for byte reuses the existing tag.

A tag points at the first commit generated from its registry state and is never moved. A later commit generated from the same registry state, after a change to the generator, can differ in the generated files listed below, and carries no new tag. `registry.json` records the full SHA-256 of the registry each commit was generated from.

To build against a fixed version of the framework, use a tag as `rev`:

```toml
SupraFramework = { git = "https://github.com/Entropy-Foundation/supra-framework.git", rev = "mainnet-0f0b6eac260e", subdir = "supra-framework" }
```

## Contents of a network branch

Each package directory holds `Move.toml` and `sources/`. Every module source and every `Move.toml` is byte-identical to the on-chain registry. The following files are not on chain and are generated:

- `move-stdlib/sources/unit_test.move`: the `#[test_only]` module `std::unit_test`, which `supra move tool test` requires. Test-only modules are not published.
- An empty `#[test_only]` module for each `#[test_only] friend` declaration in the framework that names a module not on chain. Each one carries a comment stating that it is generated.
- `registry.json`: the network, its chain ID, the SHA-256 of the registry's BCS encoding, and each package's `upgrade_number` and `source_digest`.
- `README.md`: a description of the branch.

The branches do not contain the framework's own tests, its `.spec.move` specification files or its generated documentation, because these are not stored on chain. Packages that depend on the framework compile and test without them. Compiling the framework as the root package, or running the Move Prover on it, needs the `.spec.move` files.

## CLI versions

`supra move tool test` runs native functions that are built into the `supra` CLI. Use a CLI release that matches the network whose branch you depend on.

## Support

This repository is generated and does not accept changes to the framework. Report problems to support@supra.com.

## License

Apache-2.0. See [LICENSE](LICENSE).

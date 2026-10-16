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

A scheduled workflow reads each network's registry every hour. When the registry changes, the workflow commits the new source to that network's branch and tags the commit.

`main` holds this README and the workflow that generates the network branches.

## Tags

Each commit on a network branch is tagged `<network>-<hash>`, for example `mainnet-6cf4ea6656ed`. `<hash>` is the first 12 hex characters of the SHA-256 of the four packages' on-chain `source_digest`s, concatenated in the order `MoveStdlib`, `AptosStdlib`, `SupraStdlib`, `SupraFramework`.

A tag always names the same source. If a network returns to source it ran before, for example after a reset, the existing tag is reused.

To build against a fixed version of the framework, use a tag as `rev`:

```toml
SupraFramework = { git = "https://github.com/Entropy-Foundation/supra-framework.git", rev = "mainnet-6cf4ea6656ed", subdir = "supra-framework" }
```

## Contents of a network branch

Each package directory holds `Move.toml` and `sources/`. Every module source and every `Move.toml` is byte-identical to the on-chain registry. The following files are not on chain and are generated:

- `move-stdlib/sources/unit_test.move`: the `#[test_only]` module `std::unit_test`, which `supra move tool test` requires. Test-only modules are not published.
- An empty `#[test_only]` module for each `#[test_only] friend` declaration in the framework that names a module not on chain. Each one carries a comment stating that it is generated.
- `registry.json`: the network, its chain ID, and each package's `upgrade_number` and `source_digest`.

The branches do not contain the framework's own tests, its `.spec.move` specification files or its generated documentation, because these are not stored on chain. Packages that depend on the framework compile and test without them. Compiling the framework as the root package, or running the Move Prover on it, needs the `.spec.move` files.

## CLI versions

`supra move tool test` runs native functions that are built into the `supra` CLI. Use a CLI release that matches the network whose branch you depend on.

## Support

This repository is generated and does not accept changes to the framework. Report problems to support@supra.com.

## License

Apache-2.0. See [LICENSE](LICENSE).

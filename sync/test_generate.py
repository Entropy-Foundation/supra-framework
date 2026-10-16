import contextlib
import gzip
import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

import generate


def generate_tag(*args, **kwargs):
    return generate.generate(*args, **kwargs)[0]


def uleb128(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def bcs_bytes(data):
    return uleb128(len(data)) + data


def bcs_string(text):
    return bcs_bytes(text.encode())


def bcs_vector(items):
    return uleb128(len(items)) + b"".join(items)


def bcs_option_any(value):
    if value is None:
        return b"\x00"
    type_name, data = value
    return b"\x01" + bcs_string(type_name) + bcs_bytes(data)


GENESIS = "0x" + "ab" * 32


def digest(seed):
    return hashlib.sha256(seed.encode()).hexdigest().upper()


def package(name, modules, manifest=None, upgrade_number=1, source_digest=None, gzip_sources=True):
    return {
        "name": name,
        "upgrade_policy": 1,
        "upgrade_number": upgrade_number,
        "source_digest": source_digest or digest(name),
        "manifest": gzip.compress((manifest or f'[package]\nname = "{name}"\n').encode()),
        "modules": [
            {
                "name": module_name,
                "source": gzip.compress(source.encode()) if gzip_sources else source.encode(),
                "source_map": b"",
                "extension": None,
            }
            for module_name, source in modules.items()
        ],
        "deps": [{"account": bytes(31) + b"\x01", "package_name": "MoveStdlib"}],
        "extension": None,
    }


def encode_package(p):
    return b"".join(
        [
            bcs_string(p["name"]),
            bytes([p["upgrade_policy"]]),
            p["upgrade_number"].to_bytes(8, "little"),
            bcs_string(p["source_digest"]),
            bcs_bytes(p["manifest"]),
            bcs_vector(
                [
                    bcs_string(m["name"]) + bcs_bytes(m["source"]) + bcs_bytes(m["source_map"])
                    + bcs_option_any(m["extension"])
                    for m in p["modules"]
                ]
            ),
            bcs_vector([d["account"] + bcs_string(d["package_name"]) for d in p["deps"]]),
            bcs_option_any(p["extension"]),
        ]
    )


STAKE_SOURCE = """\
module supra_framework::stake {
    friend supra_framework::genesis;
    #[test_only]
    friend supra_framework::stake_tests;
    #[test_only]
    friend supra_framework::genesis;
    #[verify_only, test_only]
    friend supra_framework::combined_tests;
    // #[test_only] friend supra_framework::in_line_comment;
    /* #[test_only] friend supra_framework::in_block_comment;
       /* nested */ #[test_only] friend supra_framework::after_nested_comment; */
    const URL: vector<u8> = b"https://example.com/*";
    #[test_only]
    friend supra_framework::after_string;
}
"""


def packages(**overrides):
    result = {
        "MoveStdlib": package("MoveStdlib", {"vector": "module std::vector {}\n"}),
        "AptosStdlib": package("AptosStdlib", {"table": "module aptos_std::table {}\n"}),
        "SupraStdlib": package("SupraStdlib", {"eth_trie": "module supra_std::eth_trie {}\n"}),
        "SupraFramework": package(
            "SupraFramework",
            {"stake": STAKE_SOURCE, "genesis": "module supra_framework::genesis {}\n"},
        ),
    }
    result.update(overrides)
    return list(result.values())


def registry(pkgs=None):
    return bcs_vector([encode_package(p) for p in (packages() if pkgs is None else pkgs)])


class BcsTest(unittest.TestCase):
    def test_round_trip(self):
        pkgs = packages()
        parsed = generate.parse_registry(registry(pkgs))
        for p in pkgs:
            self.assertEqual(parsed[p["name"]], p)

    def test_long_lengths(self):
        source = "module std::vector {}\n" + "// padding\n" * 2000
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": source}))
        parsed = generate.parse_registry(registry(pkgs))
        self.assertEqual(gzip.decompress(parsed["MoveStdlib"]["modules"][0]["source"]).decode(), source)

    def test_rejects_truncated_registry(self):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.parse_registry(registry()[:-1])
        self.assertIn("ends at byte", str(raised.exception))

    def test_rejects_trailing_bytes(self):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.parse_registry(registry() + b"\x00")
        self.assertIn("bytes after the packages", str(raised.exception))

    def test_rejects_invalid_option_flag(self):
        pkgs = packages()
        data = bytearray(registry(pkgs))
        # The last byte is the final package's `extension` option flag.
        data[-1] = 2
        with self.assertRaises(generate.RegistryError) as raised:
            generate.parse_registry(bytes(data))
        self.assertIn("option flag of 2", str(raised.exception))


class CodeOnlyTest(unittest.TestCase):
    def test_finds_test_only_friends_outside_comments_and_strings(self):
        self.assertEqual(
            generate.test_only_friends(generate.code_only(STAKE_SOURCE)),
            [
                ("supra_framework", "stake_tests"),
                ("supra_framework", "genesis"),
                ("supra_framework", "combined_tests"),
                ("supra_framework", "after_string"),
            ],
        )

    def test_preserves_length_and_line_breaks(self):
        stripped = generate.code_only(STAKE_SOURCE)
        self.assertEqual(len(stripped), len(STAKE_SOURCE))
        self.assertEqual(stripped.count("\n"), STAKE_SOURCE.count("\n"))


class GenerateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, "tree")

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, *parts):
        with open(os.path.join(self.out, *parts), "rb") as file:
            return file.read()

    def files(self):
        found = set()
        for root, dirs, names in os.walk(self.out):
            dirs[:] = [d for d in dirs if d != ".git"]
            for name in names:
                found.add(os.path.relpath(os.path.join(root, name), self.out))
        return found

    def test_writes_registry_content_byte_for_byte(self):
        pkgs = packages()
        generate.generate("mainnet", registry(pkgs), 8, GENESIS, [], self.out)
        for p in pkgs:
            directory = dict(generate.PACKAGES)[p["name"]]
            self.assertEqual(self.read(directory, "Move.toml"), gzip.decompress(p["manifest"]))
            for module in p["modules"]:
                self.assertEqual(
                    self.read(directory, "sources", module["name"] + ".move"),
                    gzip.decompress(module["source"]),
                )

    def test_writes_only_registry_and_generated_files(self):
        generate.generate("mainnet", registry(), 8, GENESIS, [], self.out)
        self.assertEqual(
            self.files(),
            {
                "README.md",
                "registry.json",
                "move-stdlib/Move.toml",
                "move-stdlib/sources/vector.move",
                "move-stdlib/sources/unit_test.move",
                "aptos-stdlib/Move.toml",
                "aptos-stdlib/sources/table.move",
                "supra-stdlib/Move.toml",
                "supra-stdlib/sources/eth_trie.move",
                "supra-framework/Move.toml",
                "supra-framework/sources/stake.move",
                "supra-framework/sources/genesis.move",
                "supra-framework/sources/stake_tests.move",
                "supra-framework/sources/combined_tests.move",
                "supra-framework/sources/after_string.move",
            },
        )

    def test_stub_content(self):
        generate.generate("mainnet", registry(), 8, GENESIS, [], self.out)
        stub = self.read("supra-framework", "sources", "stake_tests.move").decode()
        self.assertIn("#[test_only]\nmodule 0x1::stake_tests {}\n", stub)
        self.assertIn("Generated by sync/generate.py", stub)
        # `genesis` is on chain, so its own source is written and no stub replaces it.
        self.assertEqual(self.read("supra-framework", "sources", "genesis.move"), b"module supra_framework::genesis {}\n")

    def test_unit_test_module_is_the_static_copy(self):
        generate.generate("mainnet", registry(), 8, GENESIS, [], self.out)
        with open(os.path.join(generate.STATIC_DIR, "move-stdlib", "sources", "unit_test.move"), "rb") as file:
            self.assertEqual(self.read("move-stdlib", "sources", "unit_test.move"), file.read())

    def test_unit_test_module_from_chain_is_not_replaced(self):
        on_chain = "#[test_only]\nmodule std::unit_test {}\n"
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::vector {}\n", "unit_test": on_chain}))
        generate.generate("mainnet", registry(pkgs), 8, GENESIS, [], self.out)
        self.assertEqual(self.read("move-stdlib", "sources", "unit_test.move"), on_chain.encode())

    def test_registry_json(self):
        data = registry()
        generate.generate("testnet", data, 6, GENESIS, [], self.out)
        record = json.loads(self.read("registry.json"))
        self.assertEqual(record["network"], "testnet")
        self.assertEqual(record["chain_id"], 6)
        self.assertEqual(record["registry_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual([p["name"] for p in record["packages"]], [name for name, _ in generate.PACKAGES])
        self.assertEqual(record["packages"][3]["upgrade_number"], "1")
        self.assertEqual(record["packages"][3]["source_digest"], digest("SupraFramework"))

    def test_output_is_deterministic(self):
        first = generate_tag("mainnet", registry(), 8, GENESIS, [], self.out)
        snapshot = {path: self.read(path) for path in self.files()}
        second = generate_tag("mainnet", registry(), 8, GENESIS, [], self.out)
        self.assertEqual(first, second)
        self.assertEqual({path: self.read(path) for path in self.files()}, snapshot)

    def test_tag_is_the_hash_of_the_registry_bcs(self):
        data = registry()
        tag = generate_tag("devnet", data, 50, GENESIS, [], self.out)
        self.assertEqual(tag, "devnet-" + hashlib.sha256(data).hexdigest()[:12])

    def test_tag_changes_when_only_an_upgrade_number_changes(self):
        before = generate_tag("mainnet", registry(), 8, GENESIS, [], self.out)
        redeployed = packages(
            SupraFramework=package(
                "SupraFramework",
                {"stake": STAKE_SOURCE, "genesis": "module supra_framework::genesis {}\n"},
                upgrade_number=2,
            )
        )
        self.assertNotEqual(generate_tag("mainnet", registry(redeployed), 8, GENESIS, [], self.out), before)

    def test_removes_stale_files_and_keeps_git(self):
        os.makedirs(os.path.join(self.out, ".git"))
        with open(os.path.join(self.out, ".git", "HEAD"), "w") as file:
            file.write("ref: refs/heads/mainnet\n")
        os.makedirs(os.path.join(self.out, "supra-framework", "sources"))
        with open(os.path.join(self.out, "supra-framework", "sources", "removed.move"), "w") as file:
            file.write("module supra_framework::removed {}\n")
        generate.generate("mainnet", registry(), 8, GENESIS, [], self.out)
        self.assertNotIn("supra-framework/sources/removed.move", self.files())
        self.assertTrue(os.path.exists(os.path.join(self.out, ".git", "HEAD")))

    def assert_rejected(self, data, message, chain_id=8):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.generate("mainnet", data, chain_id, GENESIS, [], self.out)
        self.assertIn(message, str(raised.exception))

    def test_rejects_wrong_chain_id(self):
        self.assert_rejected(registry(), "chain ID is 6, expected 8", chain_id=6)

    def test_rejects_missing_package(self):
        self.assert_rejected(registry([p for p in packages() if p["name"] != "SupraStdlib"]), "expected")

    def test_rejects_extra_package(self):
        extra = packages() + [package("AptosToken", {"token": "module aptos_token::token {}\n"})]
        self.assert_rejected(registry(extra), "expected")

    def test_rejects_duplicate_package(self):
        pkgs = packages()
        self.assert_rejected(registry(pkgs + [pkgs[0]]), "appears twice")

    def test_rejects_module_name_that_is_not_an_identifier(self):
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"../escape": "module std::escape {}\n"}))
        self.assert_rejected(registry(pkgs), "invalid name")

    def test_rejects_duplicate_module(self):
        pkg = package("MoveStdlib", {"vector": "module std::vector {}\n"})
        pkg["modules"].append(pkg["modules"][0])
        self.assert_rejected(registry(packages(MoveStdlib=pkg)), "has module vector twice")

    def test_rejects_source_that_does_not_define_its_module(self):
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::option {}\n"}))
        self.assert_rejected(registry(pkgs), "does not define the module")

    def test_rejects_module_defined_only_in_a_comment(self):
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": "// module std::vector {}\nmodule std::other {}\n"}))
        self.assert_rejected(registry(pkgs), "does not define the module")

    def test_rejects_package_without_modules(self):
        self.assert_rejected(registry(packages(MoveStdlib=package("MoveStdlib", {}))), "has no modules")

    def test_rejects_invalid_source_digest(self):
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::vector {}\n"}, source_digest="00"))
        self.assert_rejected(registry(pkgs), "source_digest")

    def test_rejects_source_that_is_not_gzipped(self):
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::vector {}\n"}, gzip_sources=False))
        self.assert_rejected(registry(pkgs), "not gzipped")

    def test_commit_message(self):
        data = registry()
        tag = generate_tag("mainnet", data, 8, GENESIS, [], self.out)
        message = generate.commit_message("mainnet", tag, "new", None, json.loads(self.read("registry.json")))
        self.assertTrue(message.startswith(f"Mainnet framework as deployed at 0x1 ({tag})\n\n"))
        self.assertIn(f"Registry SHA-256: {hashlib.sha256(data).hexdigest()}", message)
        self.assertIn(f"SupraFramework: upgrade 1, source digest {digest('SupraFramework')}", message)

    def test_main_with_registry_file(self):
        path = os.path.join(self.tmp.name, "registry.bcs")
        with open(path, "wb") as file:
            file.write(registry())
        message = os.path.join(self.tmp.name, "message.txt")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            ok = generate.main(["--network", "mainnet", "--out", self.out, "--registry", path, "--chain-id", "8",
                                "--genesis-hash", GENESIS, "--message-file", message])
            mismatch = generate.main(["--network", "mainnet", "--out", self.out, "--registry", path,
                                      "--chain-id", "6", "--genesis-hash", GENESIS])
        self.assertEqual(ok, 0)
        self.assertEqual(mismatch, 1)
        self.assertTrue(stdout.getvalue().startswith("mainnet-"))
        self.assertTrue(os.path.exists(message))


def committee_body(genesis_hash=GENESIS, chain_id=8, epoch=0, version="V1"):
    data = {"epoch_id": {"chain_id": chain_id, "epoch": epoch}, "hash": genesis_hash}
    return json.dumps({version: {"authorization": {"certificate": {"data": data}}, "committee": {}}}).encode()


def record(genesis_hash=GENESIS, upgrades=(1, 1, 1, 1), registry_sha256="0" * 64, retired=()):
    return {
        "network": "devnet",
        "chain_id": 50,
        "genesis_hash": genesis_hash,
        "retired_genesis_hashes": list(retired),
        "registry_sha256": registry_sha256,
        "packages": [
            {"name": name, "upgrade_number": str(upgrade), "source_digest": digest(name)}
            for (name, _), upgrade in zip(generate.PACKAGES, upgrades)
        ],
    }


def upgrades(*numbers):
    names = [name for name, _ in generate.PACKAGES]
    return {name: {"upgrade_number": number} for name, number in zip(names, numbers)}


class CrossPackageStubTest(unittest.TestCase):
    def test_friend_in_another_package_is_not_stubbed(self):
        stdlib = package(
            "SupraStdlib",
            {"eth_trie": "module supra_std::eth_trie {\n    #[test_only]\n    friend supra_framework::genesis;\n}\n"},
        )
        with tempfile.TemporaryDirectory() as out:
            generate.generate("mainnet", registry(packages(SupraStdlib=stdlib)), 8, GENESIS, [], out)
            self.assertFalse(os.path.exists(os.path.join(out, "supra-stdlib", "sources", "genesis.move")))


class DuplicateStubTest(unittest.TestCase):
    def test_a_friend_named_in_two_packages_is_stubbed_once_in_the_earlier_package(self):
        friend = "    #[test_only]\n    friend supra_framework::shared_tests;\n"
        stdlib = package("SupraStdlib", {"eth_trie": "module supra_std::eth_trie {\n" + friend + "}\n"})
        framework = package(
            "SupraFramework",
            {"stake": "module supra_framework::stake {\n" + friend + "}\n", "genesis": "module supra_framework::genesis {}\n"},
        )
        with tempfile.TemporaryDirectory() as out:
            generate.generate("mainnet", registry(packages(SupraStdlib=stdlib, SupraFramework=framework)), 8, GENESIS, [], out)
            self.assertTrue(os.path.exists(os.path.join(out, "supra-stdlib", "sources", "shared_tests.move")))
            self.assertFalse(os.path.exists(os.path.join(out, "supra-framework", "sources", "shared_tests.move")))


class ManifestTest(unittest.TestCase):
    def assert_rejected_before_writing(self, pkg, message):
        with tempfile.TemporaryDirectory() as out:
            with open(os.path.join(out, "kept"), "w") as file:
                file.write("kept\n")
            with self.assertRaises(generate.RegistryError) as raised:
                generate.generate("mainnet", registry(packages(AptosStdlib=pkg)), 8, GENESIS, [], out)
            self.assertIn(message, str(raised.exception))
            self.assertEqual(os.listdir(out), ["kept"])

    def test_rejects_manifest_for_another_package(self):
        pkg = package("AptosStdlib", {"table": "module aptos_std::table {}\n"}, manifest='[package]\nname = "Other"\n')
        self.assert_rejected_before_writing(pkg, "does not name the package AptosStdlib")

    def test_rejects_manifest_that_is_not_gzipped(self):
        pkg = package("AptosStdlib", {"table": "module aptos_std::table {}\n"})
        pkg["manifest"] = b"[package]"
        self.assert_rejected_before_writing(pkg, "manifest is not gzipped")


class AttributeTest(unittest.TestCase):
    def test_stacked_attributes(self):
        source = (
            "module supra_framework::m {\n"
            "    #[test_only]\n    #[lint::skip(needless_mutable_reference)]\n    friend supra_framework::first;\n"
            "    #[lint::skip(x)]\n    #[test_only]\n    friend supra_framework::second;\n"
            "    #[lint::skip(x)]\n    friend supra_framework::not_test_only;\n"
            "    #[test_only_helper]\n    friend supra_framework::similar_name;\n"
            "}\n"
        )
        self.assertEqual(
            generate.test_only_friends(generate.code_only(source)),
            [("supra_framework", "first"), ("supra_framework", "second")],
        )


class DefinesModuleTest(unittest.TestCase):
    def test_accepted_forms(self):
        self.assertTrue("x" in generate.declared_modules(generate.code_only("module supra_framework::x {\n}\n")))
        self.assertTrue("x" in generate.declared_modules(generate.code_only("#[deprecated] module supra_framework::x {}\n")))
        self.assertTrue("x" in generate.declared_modules(generate.code_only("address 0x1 {\nmodule x {\n}\n}\n")))

    def test_rejected_forms(self):
        self.assertFalse("x" in generate.declared_modules(generate.code_only("module supra_framework::xy {}\n")))
        self.assertFalse("x" in generate.declared_modules(generate.code_only("module supra_framework::y { use supra_framework::x; }\n")))
        self.assertFalse("x" in generate.declared_modules(generate.code_only("/* module supra_framework::x {} */ module a::y {}\n")))


class GenesisHashTest(unittest.TestCase):
    def test_reads_either_version(self):
        for version in ("V0", "V1"):
            self.assertEqual(generate.parse_genesis_hash(committee_body(version=version), 8), GENESIS)

    def assert_rejected(self, body, message):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.parse_genesis_hash(body, 8)
        self.assertIn(message, str(raised.exception))

    def test_rejects_other_chain(self):
        self.assert_rejected(committee_body(chain_id=6), "expected epoch 0 of chain 8")

    def test_rejects_other_epoch(self):
        self.assert_rejected(committee_body(epoch=1), "expected epoch 0 of chain 8")

    def test_rejects_invalid_hash(self):
        self.assert_rejected(committee_body(genesis_hash="0x1234"), "invalid hash")

    def test_rejects_unexpected_shape(self):
        self.assert_rejected(b"not json", "unexpected shape")
        self.assert_rejected(json.dumps({"V0": {}, "V1": {}}).encode(), "unexpected shape")
        bad_epoch = {"V1": {"authorization": {"certificate": {"data": {"epoch_id": "0", "hash": GENESIS}}}}}
        self.assert_rejected(json.dumps(bad_epoch).encode(), "unexpected shape")


class ReadNetworkTest(unittest.TestCase):
    def fake(self, registries, genesis_hashes=(GENESIS, GENESIS), headers=None):
        calls, sleeps = [], []
        registries, genesis_hashes = list(registries), list(genesis_hashes)

        def fetch(url, accept):
            calls.append(url)
            if url.endswith(generate.GENESIS_COMMITTEE_PATH):
                return committee_body(genesis_hashes.pop(0)), {}
            return registries.pop(0), headers if headers is not None else {"x-supra-chain-id": "8"}

        return fetch, sleeps.append, calls, sleeps

    def test_new_branch_reads_the_registry_and_genesis_hash_twice(self):
        data = registry()
        fetch, sleep, calls, sleeps = self.fake([data, data])
        result = generate.read_network("mainnet", None, fetch, sleep)
        self.assertEqual(result[:3], (data, 8, GENESIS))
        self.assertEqual(result[4], "new")
        self.assertEqual(sleeps, [generate.STABLE_READ_DELAY_SECONDS])
        self.assertEqual(sum(url.endswith(generate.REGISTRY_PATH) for url in calls), 2)
        self.assertEqual(sum(url.endswith(generate.GENESIS_COMMITTEE_PATH) for url in calls), 2)

    def test_unchanged_registry_is_read_once(self):
        data = registry()
        fetch, sleep, calls, sleeps = self.fake([data])
        previous = record(registry_sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(generate.read_network("mainnet", previous, fetch, sleep)[4], "continue")
        self.assertEqual(sleeps, [])
        self.assertEqual(len(calls), 2)

    def test_registry_that_changes_between_reads_is_unstable(self):
        changed = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::vector {}\n"}, upgrade_number=2))
        fetch, sleep, _, _ = self.fake([registry(), registry(changed)])
        with self.assertRaises(generate.UnstableRegistry) as raised:
            generate.read_network("mainnet", record(), fetch, sleep)
        self.assertIn("registry changed", str(raised.exception))

    def test_genesis_hash_that_changes_between_reads_is_unstable(self):
        data = registry()
        fetch, sleep, _, _ = self.fake([data, data], genesis_hashes=(GENESIS, "0x" + "cd" * 32))
        with self.assertRaises(generate.UnstableRegistry) as raised:
            generate.read_network("mainnet", record(), fetch, sleep)
        self.assertIn("genesis hash changed", str(raised.exception))

    def test_older_registry_fails_before_the_second_read(self):
        fetch, sleep, calls, sleeps = self.fake([registry()])
        with self.assertRaises(generate.RegistryError) as raised:
            generate.read_network("mainnet", record(upgrades=(1, 1, 1, 9)), fetch, sleep)
        self.assertIn("older than the branch head", str(raised.exception))
        self.assertEqual(sleeps, [])
        self.assertEqual(len(calls), 2)

    def test_rejects_missing_chain_id_header(self):
        fetch, sleep, _, _ = self.fake([registry()], headers={})
        with self.assertRaises(generate.RegistryError) as raised:
            generate.read_network("mainnet", None, fetch, sleep)
        self.assertIn("x-supra-chain-id", str(raised.exception))

    def test_rejects_wrong_chain_id_header(self):
        fetch, sleep, _, _ = self.fake([registry()], headers={"x-supra-chain-id": "6"})
        with self.assertRaises(generate.RegistryError) as raised:
            generate.read_network("mainnet", None, fetch, sleep)
        self.assertIn("chain ID is 6, expected 8", str(raised.exception))


class CheckHistoryTest(unittest.TestCase):
    def test_new_branch(self):
        self.assertEqual(generate.check_history("mainnet", None, GENESIS, upgrades(1, 1, 1, 1)), "new")

    def test_continues_when_unchanged_or_newer(self):
        for numbers in [(1, 1, 1, 1), (1, 1, 1, 2), (2, 1, 1, 1)]:
            self.assertEqual(generate.check_history("mainnet", record(), GENESIS, upgrades(*numbers)), "continue")

    def test_rejects_an_older_registry(self):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.check_history("devnet", record(upgrades=(1, 1, 1, 5)), GENESIS, upgrades(1, 1, 1, 4))
        self.assertIn("older than the branch head", str(raised.exception))

    def test_rejects_any_lower_upgrade_number(self):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.check_history("mainnet", record(), GENESIS, upgrades(2, 0, 1, 1))
        self.assertIn("AptosStdlib 1 -> 0", str(raised.exception))

    def test_rejects_a_reset_to_a_retired_genesis(self):
        old = "0x" + "cd" * 32
        with self.assertRaises(generate.RegistryError) as raised:
            generate.check_history("devnet", record(retired=[old]), old, upgrades(0, 0, 0, 0))
        self.assertIn("already left", str(raised.exception))

    def test_retired_genesis_hashes(self):
        old, older = "0x" + "cd" * 32, "0x" + "ef" * 32
        self.assertEqual(generate.retired_genesis_hashes(None, "new"), [])
        self.assertEqual(generate.retired_genesis_hashes(record(retired=[older]), "continue"), [older])
        self.assertEqual(
            generate.retired_genesis_hashes(record(genesis_hash=old, retired=[older]), "reset"), [older, old]
        )

    def test_reset_on_a_resettable_network(self):
        older = upgrades(0, 0, 0, 0)
        self.assertEqual(generate.check_history("devnet", record(upgrades=(3, 3, 3, 3)), "0x" + "cd" * 32, older), "reset")

    def test_rejects_a_genesis_change_elsewhere(self):
        for network in ("mainnet", "testnet"):
            with self.assertRaises(generate.RegistryError) as raised:
                generate.check_history(network, record(), "0x" + "cd" * 32, upgrades(1, 1, 1, 1))
            self.assertIn("genesis hash changed", str(raised.exception))



class LoadPreviousTest(unittest.TestCase):
    def load(self, value):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "registry.json")
            with open(path, "w") as file:
                file.write(value if isinstance(value, str) else json.dumps(value))
            return generate.load_previous(path, "devnet")

    def test_missing_file_is_a_new_branch(self):
        self.assertIsNone(generate.load_previous("/nonexistent/registry.json", "devnet"))

    def test_valid_record(self):
        self.assertEqual(self.load(record())["genesis_hash"], GENESIS)

    def test_rejects_malformed_records(self):
        cases = {
            "not readable JSON": "{",
            "it is for network 'mainnet'": dict(record(), network="mainnet", chain_id=8),
            "retired_genesis_hashes": dict(record(), retired=None, retired_genesis_hashes=["0x12"]),
            "not an object": [],
            "genesis_hash is missing": {k: v for k, v in record().items() if k != "genesis_hash"},
            "registry_sha256 is missing": {k: v for k, v in record().items() if k != "registry_sha256"},
            "retired_genesis_hashes is missing": {k: v for k, v in record().items() if k != "retired_genesis_hashes"},
            "packages is missing": dict(record(), packages=[{"name": "MoveStdlib", "upgrade_number": 1}]),
        }
        for message, value in cases.items():
            with self.assertRaises(generate.RegistryError) as raised:
                self.load(value)
            self.assertIn(message, str(raised.exception))


class MainTest(unittest.TestCase):
    def run_main(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = generate.main(list(args))
        return status, stdout.getvalue(), stderr.getvalue()

    def test_unstable_registry_exits_3_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "tree")
            with mock.patch.object(generate, "read_network", side_effect=generate.UnstableRegistry("changed")):
                status, stdout, stderr = self.run_main("--network", "mainnet", "--out", out)
            self.assertEqual(status, generate.EXIT_UNSTABLE)
            self.assertEqual(stdout, "")
            self.assertIn("nothing written", stderr)
            self.assertFalse(os.path.exists(out))

    def test_older_registry_fails_and_keeps_the_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, path, previous = (os.path.join(tmp, name) for name in ("tree", "registry.bcs", "previous.json"))
            with open(path, "wb") as file:
                file.write(registry())
            with open(previous, "w") as file:
                json.dump(dict(record(upgrades=(1, 1, 1, 9)), network="mainnet", chain_id=8), file)
            os.makedirs(out)
            with open(os.path.join(out, "kept"), "w") as file:
                file.write("kept\n")
            status, _, stderr = self.run_main("--network", "mainnet", "--out", out, "--previous", previous,
                                              "--registry", path, "--chain-id", "8", "--genesis-hash", GENESIS)
            self.assertEqual(status, 1)
            self.assertIn("older than the branch head", stderr)
            self.assertTrue(os.path.exists(os.path.join(out, "kept")))

    def test_reset_commit_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, path, previous, message = (
                os.path.join(tmp, name) for name in ("tree", "registry.bcs", "previous.json", "message.txt")
            )
            with open(path, "wb") as file:
                file.write(registry())
            with open(previous, "w") as file:
                json.dump(record(genesis_hash="0x" + "cd" * 32, upgrades=(5, 5, 5, 5)), file)
            status, _, stderr = self.run_main("--network", "devnet", "--out", out, "--previous", previous,
                                              "--registry", path, "--chain-id", "50", "--genesis-hash", GENESIS,
                                              "--message-file", message)
            self.assertEqual(status, 0)
            self.assertIn("devnet was reset", stderr)
            with open(message) as file:
                text = file.read()
            self.assertIn(f"Devnet was reset: genesis hash 0x{'cd' * 32} is now {GENESIS}.", text)
            with open(os.path.join(out, "registry.json")) as file:
                written = json.load(file)
            self.assertEqual(written["genesis_hash"], GENESIS)
            self.assertEqual(written["retired_genesis_hashes"], ["0x" + "cd" * 32])


class SharedSourceTest(unittest.TestCase):
    def test_modules_from_one_file_are_written_once(self):
        shared = "module supra_framework::a {}\nmodule supra_framework::b {}\n"
        framework = package(
            "SupraFramework", {"a": shared, "b": shared, "genesis": "module supra_framework::genesis {}\n"}
        )
        with tempfile.TemporaryDirectory() as out:
            generate.generate("mainnet", registry(packages(SupraFramework=framework)), 8, GENESIS, [], out)
            names = sorted(os.listdir(os.path.join(out, "supra-framework", "sources")))
            self.assertEqual(names, ["a.move", "genesis.move"])

    def test_a_test_only_module_in_a_published_file_is_not_stubbed(self):
        source = (
            "module supra_framework::a {\n    #[test_only]\n    friend supra_framework::a_tests;\n}\n"
            "#[test_only]\nmodule supra_framework::a_tests {}\n"
        )
        framework = package("SupraFramework", {"a": source, "genesis": "module supra_framework::genesis {}\n"})
        with tempfile.TemporaryDirectory() as out:
            generate.generate("mainnet", registry(packages(SupraFramework=framework)), 8, GENESIS, [], out)
            self.assertFalse(os.path.exists(os.path.join(out, "supra-framework", "sources", "a_tests.move")))

    def test_rejects_a_shared_file_that_does_not_declare_every_module(self):
        shared = "module supra_framework::a {}\n"
        framework = package("SupraFramework", {"a": shared, "b": shared})
        with tempfile.TemporaryDirectory() as out:
            with self.assertRaises(generate.RegistryError) as raised:
                generate.generate("mainnet", registry(packages(SupraFramework=framework)), 8, GENESIS, [], out)
        self.assertIn("SupraFramework::b source does not define the module", str(raised.exception))


class ResetMarkerTest(unittest.TestCase):
    def test_marker_is_not_retired(self):
        previous = record(genesis_hash=generate.RESET_MARKER, retired=["0x" + "ef" * 32])
        self.assertEqual(generate.check_history("devnet", previous, GENESIS, upgrades(0, 0, 0, 0)), "reset")
        self.assertEqual(generate.retired_genesis_hashes(previous, "reset"), ["0x" + "ef" * 32])

    def test_marker_commit_message(self):
        with tempfile.TemporaryDirectory() as out:
            tag, written = generate.generate("devnet", registry(), 50, GENESIS, [], out)
        message = generate.commit_message("devnet", tag, "reset", record(genesis_hash=generate.RESET_MARKER), written)
        self.assertIn(f"Devnet was marked for reset in registry.json; genesis hash is now {GENESIS}.", message)
        self.assertNotIn("0x" + "0" * 64 + " is now", message)


class GenesisChangeReadTest(unittest.TestCase):
    def test_changed_genesis_hash_with_an_unchanged_registry_is_read_twice(self):
        data = registry()
        calls, sleeps = [], []
        new_genesis = "0x" + "cd" * 32

        def fetch(url, accept):
            calls.append(url)
            if url.endswith(generate.GENESIS_COMMITTEE_PATH):
                return committee_body(new_genesis, chain_id=50), {}
            return data, {"x-supra-chain-id": "50"}

        previous = record(registry_sha256=hashlib.sha256(data).hexdigest())
        result = generate.read_network("devnet", previous, fetch, sleeps.append)
        self.assertEqual(result[4], "reset")
        self.assertEqual(sleeps, [generate.STABLE_READ_DELAY_SECONDS])
        self.assertEqual(sum(url.endswith(generate.REGISTRY_PATH) for url in calls), 2)


class RegistrySha256Test(unittest.TestCase):
    def run_main(self, path):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = generate.main(["--registry-sha256", path])
        return status, stdout.getvalue(), stderr.getvalue()

    def write(self, tmp, value):
        path = os.path.join(tmp, "registry.json")
        with open(path, "w") as file:
            file.write(value if isinstance(value, str) else json.dumps(value))
        return path

    def test_prints_the_recorded_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_main(self.write(tmp, record(registry_sha256="ab" * 32)))[:2], (0, "ab" * 32 + "\n"))

    def test_reports_a_file_without_it(self):
        for value in ({}, [], "", "{"):
            with tempfile.TemporaryDirectory() as tmp:
                status, stdout, stderr = self.run_main(self.write(tmp, value))
            self.assertEqual((status, stdout), (1, ""))
            self.assertIn("error:", stderr)

    def test_reports_a_missing_file(self):
        status, stdout, _ = self.run_main("/nonexistent/registry.json")
        self.assertEqual((status, stdout), (1, ""))


class FetchRetryTest(unittest.TestCase):
    def attempts_for(self, code):
        attempts = []

        def urlopen(request, timeout):
            attempts.append(request.full_url)
            raise urllib.error.HTTPError(request.full_url, code, "error", {}, None)

        with mock.patch.object(generate.urllib.request, "urlopen", urlopen), mock.patch.object(generate.time, "sleep"):
            with self.assertRaises(generate.RegistryError):
                generate.fetch("https://example.invalid/x", "application/json")
        return len(attempts)

    def test_client_errors_are_not_retried(self):
        for code in (400, 403, 404):
            self.assertEqual(self.attempts_for(code), 1)

    def test_server_errors_are_retried(self):
        self.assertEqual(self.attempts_for(503), 3)


def strip(text):
    return generate.strip_specs(text, generate.code_only(text))


class StripSpecsTest(unittest.TestCase):
    def test_removes_top_level_blocks_with_their_lines(self):
        source = (
            "module std::m {\n"
            "    struct S has drop { x: u64 }\n"
            "    spec S {\n        invariant x > 0;\n    }\n"
            "    public fun f(): u64 { 1 }\n"
            "    spec f {\n        aborts_if false;\n        ensures result == 1;\n    }\n"
            "    spec module {}\n"
            "    spec schema AbortsIf {\n        x: u64;\n        aborts_if x == 0;\n    }\n"
            "    spec fun helper(x: u64): bool { x > 0 }\n"
            "    spec native fun native_helper(): bool;\n"
            "}\n"
        )
        self.assertEqual(
            strip(source),
            "module std::m {\n    struct S has drop { x: u64 }\n    public fun f(): u64 { 1 }\n}\n",
        )

    def test_empties_statements_in_function_bodies(self):
        source = (
            "module std::m {\n"
            "    fun f(n: u64) {\n"
            "        let i = 0;\n"
            "        while ({spec {\n            invariant i <= n;\n        };\n            (i < n)}) {\n"
            "            i = i + 1;\n"
            "        };\n"
            "        spec {\n            assert i == n;\n        };\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(
            strip(source),
            "module std::m {\n"
            "    fun f(n: u64) {\n"
            "        let i = 0;\n"
            "        while ({spec {};\n            (i < n)}) {\n"
            "            i = i + 1;\n"
            "        };\n"
            "        spec {};\n"
            "    }\n"
            "}\n",
        )

    def test_removes_doc_comments_above_a_block_only(self):
        source = (
            "module std::m {\n"
            "    // Kept.\n"
            "    /// Documents the spec.\n"
            "    /// Second line.\n"
            "    spec f {\n        aborts_if false;\n    }\n"
            "    /// Documents g.\n"
            "    fun g() {}\n"
            "}\n"
        )
        self.assertEqual(
            strip(source),
            "module std::m {\n    // Kept.\n    /// Documents g.\n    fun g() {}\n}\n",
        )

    def test_keeps_spec_in_comments_and_strings(self):
        source = (
            "module std::m {\n"
            "    // spec f { aborts_if true; }\n"
            "    /* spec g { } */\n"
            '    const NOTE: vector<u8> = b"spec { }";\n'
            "}\n"
        )
        self.assertEqual(strip(source), source)

    def test_nested_braces(self):
        source = "module std::m {\n    spec f {\n        ensures forall i in 0..1: { true };\n    }\n    fun f() {}\n}\n"
        self.assertEqual(strip(source), "module std::m {\n    fun f() {}\n}\n")

    def test_rejects_an_unterminated_block(self):
        with self.assertRaises(generate.RegistryError) as raised:
            strip("module std::m {\n    spec f {\n        aborts_if false;\n")
        self.assertIn("not terminated", str(raised.exception))

    def test_rejects_a_spec_statement_in_a_public_inline_function(self):
        source = "module std::m {\n    public inline fun f(x: u64): u64 {\n        spec { assume x > 0; };\n        x\n    }\n}\n"
        with tempfile.TemporaryDirectory() as out:
            with self.assertRaises(generate.RegistryError) as raised:
                generate.generate("mainnet", registry(packages(MoveStdlib=package("MoveStdlib", {"m": source}))), 8, GENESIS, [], out)
        self.assertIn("MoveStdlib::m: public inline function f holds a spec statement", str(raised.exception))

    def test_accepts_spec_statements_in_private_inline_functions(self):
        source = "module std::m {\n    inline fun f(x: u64): u64 {\n        spec { assume x > 0; };\n        x\n    }\n    public inline fun g(x: u64): u64 {\n        spec {};\n        x\n    }\n}\n"
        with tempfile.TemporaryDirectory() as out:
            generate.generate("mainnet", registry(packages(MoveStdlib=package("MoveStdlib", {"m": source}))), 8, GENESIS, [], out)
            with open(os.path.join(out, "move-stdlib", "sources", "m.move")) as file:
                self.assertIn("    inline fun f(x: u64): u64 {\n        spec {};\n", file.read())

    def generate_error(self, overrides):
        with tempfile.TemporaryDirectory() as out:
            with self.assertRaises(generate.RegistryError) as raised:
                generate.generate("mainnet", registry(packages(**overrides)), 8, GENESIS, [], out)
        return str(raised.exception)

    def test_rejects_a_public_inline_function_reaching_a_spec_statement_through_inline_calls(self):
        source = (
            "module std::m {\n"
            "    inline fun holder(x: u64): u64 {\n        spec { assume x > 0; };\n        x\n    }\n"
            "    inline fun middle<T>(x: u64): u64 { holder(x) }\n"
            "    public inline fun f(x: u64): u64 { middle<u8>(x) }\n"
            "}\n"
        )
        self.assertIn(
            "MoveStdlib::m: public inline function f calls inline functions that reach a spec statement in MoveStdlib::m::holder",
            self.generate_error({"MoveStdlib": package("MoveStdlib", {"m": source})}),
        )

    def test_rejects_a_public_inline_function_reaching_a_spec_statement_in_another_package(self):
        holder = "module std::m {\n    public(friend) inline fun holder(x: u64): u64 {\n        spec { assume x > 0; };\n        x\n    }\n}\n"
        caller = "module supra_framework::c {\n    public inline fun f(x: u64): u64 { std::m::holder(x) }\n}\n"
        self.assertIn(
            "SupraFramework::c: public inline function f calls inline functions that reach a spec statement in MoveStdlib::m::holder",
            self.generate_error({
                "MoveStdlib": package("MoveStdlib", {"m": holder}),
                "SupraFramework": package("SupraFramework", {"c": caller, "genesis": "module supra_framework::genesis {}\n"}),
            }),
        )

    def test_accepts_a_public_inline_function_calling_a_non_inline_function_with_a_spec_statement(self):
        source = (
            "module std::m {\n"
            "    fun holder(x: u64): u64 {\n        spec { assume x > 0; };\n        x\n    }\n"
            "    public inline fun f(x: u64): u64 { holder(x) }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as out:
            generate.generate("mainnet", registry(packages(MoveStdlib=package("MoveStdlib", {"m": source}))), 8, GENESIS, [], out)

    def test_rejects_an_attribute_on_a_removed_block(self):
        for attribute in ("    #[verify_only]\n", "    #[verify_only] "):
            with self.subTest(attribute=attribute):
                with self.assertRaises(generate.RegistryError) as raised:
                    strip("module std::m {\n" + attribute + "spec f {\n    }\n    fun f() {}\n}\n")
                self.assertIn("a spec block has an attribute", str(raised.exception))

    def test_rejects_a_module_level_invariant(self):
        with self.assertRaises(generate.RegistryError) as raised:
            strip("module std::m {\n    invariant true;\n}\n")
        self.assertIn("an invariant remains", str(raised.exception))

    def test_keeps_a_block_comment_whose_last_line_starts_with_three_slashes(self):
        source = "module std::m {\n    /*\n    /// x */\n    spec f {\n    }\n    fun f() {}\n}\n"
        self.assertEqual(strip(source), "module std::m {\n    /*\n    /// x */\n    fun f() {}\n}\n")

    def test_keeps_indentation_when_code_follows_a_block_on_its_line(self):
        self.assertEqual(
            strip("module std::m {\n    /// Module.\n    spec module {} // comment\n    spec f { } fun f() {}\n}\n"),
            "module std::m {\n    // comment\n    fun f() {}\n}\n",
        )

    def test_rejects_an_unterminated_comment_in_the_result(self):
        source = "module std::m {\n    fun f() {}\n}\n"
        unterminated = [("block", 0, len(source), False)]
        with mock.patch.object(generate, "comments_and_strings", side_effect=[[], [], unterminated]):
            with self.assertRaises(generate.RegistryError) as raised:
                generate.strip_specs(source, source)
        self.assertIn("unterminated", str(raised.exception))

    def test_generated_sources_have_no_spec_blocks(self):
        source = "module std::vector {\n    native public fun empty<T>(): vector<T>;\n    spec empty {\n        pragma intrinsic;\n    }\n}\n"
        with tempfile.TemporaryDirectory() as out:
            generate.generate("mainnet", registry(packages(MoveStdlib=package("MoveStdlib", {"vector": source}))), 8, GENESIS, [], out)
            with open(os.path.join(out, "move-stdlib", "sources", "vector.move")) as file:
                self.assertEqual(file.read(), "module std::vector {\n    native public fun empty<T>(): vector<T>;\n}\n")


if __name__ == "__main__":
    unittest.main()

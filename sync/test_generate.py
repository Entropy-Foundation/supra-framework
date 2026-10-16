import contextlib
import gzip
import hashlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import generate


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
            generate.test_only_friends(STAKE_SOURCE),
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
        generate.generate("mainnet", registry(pkgs), 8, GENESIS, self.out)
        for p in pkgs:
            directory = dict(generate.PACKAGES)[p["name"]]
            self.assertEqual(self.read(directory, "Move.toml"), gzip.decompress(p["manifest"]))
            for module in p["modules"]:
                self.assertEqual(
                    self.read(directory, "sources", module["name"] + ".move"),
                    gzip.decompress(module["source"]),
                )

    def test_writes_only_registry_and_generated_files(self):
        generate.generate("mainnet", registry(), 8, GENESIS, self.out)
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
        generate.generate("mainnet", registry(), 8, GENESIS, self.out)
        stub = self.read("supra-framework", "sources", "stake_tests.move").decode()
        self.assertIn("#[test_only]\nmodule supra_framework::stake_tests {}\n", stub)
        self.assertIn("Generated by sync/generate.py", stub)
        # `genesis` is on chain, so its own source is written and no stub replaces it.
        self.assertEqual(self.read("supra-framework", "sources", "genesis.move"), b"module supra_framework::genesis {}\n")

    def test_unit_test_module_is_the_static_copy(self):
        generate.generate("mainnet", registry(), 8, GENESIS, self.out)
        with open(os.path.join(generate.STATIC_DIR, "move-stdlib", "sources", "unit_test.move"), "rb") as file:
            self.assertEqual(self.read("move-stdlib", "sources", "unit_test.move"), file.read())

    def test_unit_test_module_from_chain_is_not_replaced(self):
        on_chain = "#[test_only]\nmodule std::unit_test {}\n"
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::vector {}\n", "unit_test": on_chain}))
        generate.generate("mainnet", registry(pkgs), 8, GENESIS, self.out)
        self.assertEqual(self.read("move-stdlib", "sources", "unit_test.move"), on_chain.encode())

    def test_registry_json(self):
        data = registry()
        generate.generate("testnet", data, 6, GENESIS, self.out)
        record = json.loads(self.read("registry.json"))
        self.assertEqual(record["network"], "testnet")
        self.assertEqual(record["chain_id"], 6)
        self.assertEqual(record["registry_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual([p["name"] for p in record["packages"]], [name for name, _ in generate.PACKAGES])
        self.assertEqual(record["packages"][3]["upgrade_number"], "1")
        self.assertEqual(record["packages"][3]["source_digest"], digest("SupraFramework"))

    def test_output_is_deterministic(self):
        first = generate.generate("mainnet", registry(), 8, GENESIS, self.out)
        snapshot = {path: self.read(path) for path in self.files()}
        second = generate.generate("mainnet", registry(), 8, GENESIS, self.out)
        self.assertEqual(first, second)
        self.assertEqual({path: self.read(path) for path in self.files()}, snapshot)

    def test_tag_is_the_hash_of_the_registry_bcs(self):
        data = registry()
        tag = generate.generate("devnet", data, 50, GENESIS, self.out)
        self.assertEqual(tag, "devnet-" + hashlib.sha256(data).hexdigest()[:12])

    def test_tag_changes_when_only_an_upgrade_number_changes(self):
        before = generate.generate("mainnet", registry(), 8, GENESIS, self.out)
        redeployed = packages(
            SupraFramework=package(
                "SupraFramework",
                {"stake": STAKE_SOURCE, "genesis": "module supra_framework::genesis {}\n"},
                upgrade_number=2,
            )
        )
        self.assertNotEqual(generate.generate("mainnet", registry(redeployed), 8, GENESIS, self.out), before)

    def test_removes_stale_files_and_keeps_git(self):
        os.makedirs(os.path.join(self.out, ".git"))
        with open(os.path.join(self.out, ".git", "HEAD"), "w") as file:
            file.write("ref: refs/heads/mainnet\n")
        os.makedirs(os.path.join(self.out, "supra-framework", "sources"))
        with open(os.path.join(self.out, "supra-framework", "sources", "removed.move"), "w") as file:
            file.write("module supra_framework::removed {}\n")
        generate.generate("mainnet", registry(), 8, GENESIS, self.out)
        self.assertNotIn("supra-framework/sources/removed.move", self.files())
        self.assertTrue(os.path.exists(os.path.join(self.out, ".git", "HEAD")))

    def assert_rejected(self, data, message, chain_id=8):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.generate("mainnet", data, chain_id, GENESIS, self.out)
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
        tag = generate.generate("mainnet", data, 8, GENESIS, self.out)
        message = generate.commit_message("mainnet", tag, "new", None, self.out)
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


def record(genesis_hash=GENESIS, upgrades=(1, 1, 1, 1), registry_sha256="0" * 64):
    return {
        "network": "devnet",
        "genesis_hash": genesis_hash,
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
            generate.generate("mainnet", registry(packages(SupraStdlib=stdlib)), 8, GENESIS, out)
            self.assertFalse(os.path.exists(os.path.join(out, "supra-stdlib", "sources", "genesis.move")))


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
            generate.test_only_friends(source),
            [("supra_framework", "first"), ("supra_framework", "second")],
        )


class DefinesModuleTest(unittest.TestCase):
    def test_accepted_forms(self):
        self.assertTrue(generate.defines_module("module supra_framework::x {\n}\n", "x"))
        self.assertTrue(generate.defines_module("#[deprecated] module supra_framework::x {}\n", "x"))
        self.assertTrue(generate.defines_module("address 0x1 {\nmodule x {\n}\n}\n", "x"))

    def test_rejected_forms(self):
        self.assertFalse(generate.defines_module("module supra_framework::xy {}\n", "x"))
        self.assertFalse(generate.defines_module("module supra_framework::y { use supra_framework::x; }\n", "x"))
        self.assertFalse(generate.defines_module("/* module supra_framework::x {} */ module a::y {}\n", "x"))


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


class ReadNetworkTest(unittest.TestCase):
    def fake(self, registries, headers=None):
        calls, sleeps = [], []
        registries = list(registries)

        def fetch(url, accept):
            calls.append(url)
            if url.endswith(generate.GENESIS_COMMITTEE_PATH):
                return committee_body(), {}
            return registries.pop(0), headers if headers is not None else {"x-supra-chain-id": "8"}

        return fetch, sleeps.append, calls, sleeps

    def test_new_branch_reads_the_registry_twice(self):
        data = registry()
        fetch, sleep, calls, sleeps = self.fake([data, data])
        self.assertEqual(generate.read_network("mainnet", None, fetch, sleep), (data, 8, GENESIS))
        self.assertEqual(sleeps, [generate.STABLE_READ_DELAY_SECONDS])
        self.assertEqual(sum(url.endswith(generate.REGISTRY_PATH) for url in calls), 2)

    def test_unchanged_registry_is_read_once(self):
        data = registry()
        fetch, sleep, calls, sleeps = self.fake([data])
        previous = record(registry_sha256=hashlib.sha256(data).hexdigest())
        generate.read_network("mainnet", previous, fetch, sleep)
        self.assertEqual(sleeps, [])
        self.assertEqual(sum(url.endswith(generate.REGISTRY_PATH) for url in calls), 1)

    def test_registry_that_changes_between_reads_is_unstable(self):
        changed = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::vector {}\n"}, upgrade_number=2))
        fetch, sleep, _, _ = self.fake([registry(), registry(changed)])
        with self.assertRaises(generate.UnstableRegistry):
            generate.read_network("mainnet", record(), fetch, sleep)

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
        for numbers in [(1, 1, 1, 1), (1, 1, 1, 2), (2, 0, 1, 1)]:
            self.assertEqual(generate.check_history("mainnet", record(), GENESIS, upgrades(*numbers)), "continue")

    def test_rejects_an_older_registry(self):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.check_history("devnet", record(upgrades=(1, 1, 1, 5)), GENESIS, upgrades(1, 1, 1, 4))
        self.assertIn("older than the branch head", str(raised.exception))

    def test_reset_on_a_resettable_network(self):
        older = upgrades(0, 0, 0, 0)
        self.assertEqual(generate.check_history("devnet", record(upgrades=(3, 3, 3, 3)), "0x" + "cd" * 32, older), "reset")

    def test_rejects_a_genesis_change_elsewhere(self):
        for network in ("mainnet", "testnet"):
            with self.assertRaises(generate.RegistryError) as raised:
                generate.check_history(network, record(), "0x" + "cd" * 32, upgrades(1, 1, 1, 1))
            self.assertIn("genesis hash changed", str(raised.exception))

    def test_rejects_previous_without_genesis_hash(self):
        previous = record()
        del previous["genesis_hash"]
        with self.assertRaises(generate.RegistryError) as raised:
            generate.check_history("mainnet", previous, GENESIS, upgrades(1, 1, 1, 1))
        self.assertIn("no genesis_hash", str(raised.exception))


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
                json.dump(record(upgrades=(1, 1, 1, 9)), file)
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
                self.assertEqual(json.load(file)["genesis_hash"], GENESIS)


if __name__ == "__main__":
    unittest.main()

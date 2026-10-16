import contextlib
import gzip
import hashlib
import io
import json
import os
import tempfile
import unittest

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
        generate.generate("mainnet", registry(pkgs), 8, self.out)
        for p in pkgs:
            directory = dict(generate.PACKAGES)[p["name"]]
            self.assertEqual(self.read(directory, "Move.toml"), gzip.decompress(p["manifest"]))
            for module in p["modules"]:
                self.assertEqual(
                    self.read(directory, "sources", module["name"] + ".move"),
                    gzip.decompress(module["source"]),
                )

    def test_writes_only_registry_and_generated_files(self):
        generate.generate("mainnet", registry(), 8, self.out)
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
        generate.generate("mainnet", registry(), 8, self.out)
        stub = self.read("supra-framework", "sources", "stake_tests.move").decode()
        self.assertIn("#[test_only]\nmodule supra_framework::stake_tests {}\n", stub)
        self.assertIn("Generated by sync/generate.py", stub)
        # `genesis` is on chain, so its own source is written and no stub replaces it.
        self.assertEqual(self.read("supra-framework", "sources", "genesis.move"), b"module supra_framework::genesis {}\n")

    def test_unit_test_module_is_the_static_copy(self):
        generate.generate("mainnet", registry(), 8, self.out)
        with open(os.path.join(generate.STATIC_DIR, "move-stdlib", "sources", "unit_test.move"), "rb") as file:
            self.assertEqual(self.read("move-stdlib", "sources", "unit_test.move"), file.read())

    def test_unit_test_module_from_chain_is_not_replaced(self):
        on_chain = "#[test_only]\nmodule std::unit_test {}\n"
        pkgs = packages(MoveStdlib=package("MoveStdlib", {"vector": "module std::vector {}\n", "unit_test": on_chain}))
        generate.generate("mainnet", registry(pkgs), 8, self.out)
        self.assertEqual(self.read("move-stdlib", "sources", "unit_test.move"), on_chain.encode())

    def test_registry_json(self):
        data = registry()
        generate.generate("testnet", data, 6, self.out)
        record = json.loads(self.read("registry.json"))
        self.assertEqual(record["network"], "testnet")
        self.assertEqual(record["chain_id"], 6)
        self.assertEqual(record["registry_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual([p["name"] for p in record["packages"]], [name for name, _ in generate.PACKAGES])
        self.assertEqual(record["packages"][3]["upgrade_number"], "1")
        self.assertEqual(record["packages"][3]["source_digest"], digest("SupraFramework"))

    def test_output_is_deterministic(self):
        first = generate.generate("mainnet", registry(), 8, self.out)
        snapshot = {path: self.read(path) for path in self.files()}
        second = generate.generate("mainnet", registry(), 8, self.out)
        self.assertEqual(first, second)
        self.assertEqual({path: self.read(path) for path in self.files()}, snapshot)

    def test_tag_is_the_hash_of_the_registry_bcs(self):
        data = registry()
        tag = generate.generate("devnet", data, 50, self.out)
        self.assertEqual(tag, "devnet-" + hashlib.sha256(data).hexdigest()[:12])

    def test_tag_changes_when_only_an_upgrade_number_changes(self):
        before = generate.generate("mainnet", registry(), 8, self.out)
        redeployed = packages(
            SupraFramework=package(
                "SupraFramework",
                {"stake": STAKE_SOURCE, "genesis": "module supra_framework::genesis {}\n"},
                upgrade_number=2,
            )
        )
        self.assertNotEqual(generate.generate("mainnet", registry(redeployed), 8, self.out), before)

    def test_removes_stale_files_and_keeps_git(self):
        os.makedirs(os.path.join(self.out, ".git"))
        with open(os.path.join(self.out, ".git", "HEAD"), "w") as file:
            file.write("ref: refs/heads/mainnet\n")
        os.makedirs(os.path.join(self.out, "supra-framework", "sources"))
        with open(os.path.join(self.out, "supra-framework", "sources", "removed.move"), "w") as file:
            file.write("module supra_framework::removed {}\n")
        generate.generate("mainnet", registry(), 8, self.out)
        self.assertNotIn("supra-framework/sources/removed.move", self.files())
        self.assertTrue(os.path.exists(os.path.join(self.out, ".git", "HEAD")))

    def assert_rejected(self, data, message, chain_id=8):
        with self.assertRaises(generate.RegistryError) as raised:
            generate.generate("mainnet", data, chain_id, self.out)
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
        tag = generate.generate("mainnet", data, 8, self.out)
        message = generate.commit_message("mainnet", tag, self.out)
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
                                "--message-file", message])
            mismatch = generate.main(["--network", "mainnet", "--out", self.out, "--registry", path,
                                      "--chain-id", "6"])
        self.assertEqual(ok, 0)
        self.assertEqual(mismatch, 1)
        self.assertTrue(stdout.getvalue().startswith("mainnet-"))
        self.assertTrue(os.path.exists(message))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from missionsready_sbom.core import (
    _RELATIONSHIP_KIND_RULES,
    _RELATIONSHIP_TYPES,
    _validate_relationship_kinds,
    CommittedCleanupError,
    ContractError,
    atomic_write_jsons,
    build_evidence,
    canonical_json_bytes,
    compare_evidence,
    load_json_strict,
    recover_output_transaction,
    validate_evidence,
)
from missionsready_sbom import cli, core

NAME = "ghcr.io/missionsready/example"
DIGEST = "sha256:" + "a" * 64
PLATFORM = "linux/amd64"
VERSION = "1.30.0"


def fixture(name: str):
    return json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))


def source_for(digest: str = DIGEST):
    return {
        "type": "oci-image",
        "name": NAME,
        "reference": f"{NAME}@{digest}",
        "digest": digest,
        "platform": PLATFORM,
    }


def raw_for(digest: str = DIGEST):
    value = fixture("valid/syft-spdx.json")
    value["name"] = f"{NAME}@{digest}"
    return value


class StrictJsonTests(unittest.TestCase):
    def write(self, name: str, data: bytes) -> Path:
        path = ROOT / "tests" / name
        path.write_bytes(data)
        self.addCleanup(path.unlink)
        return path

    def test_rejects_duplicate_object_keys(self):
        path = self.write("duplicate.json", b'{"a":1,"a":2}')
        with self.assertRaisesRegex(ContractError, "duplicate JSON object key"):
            load_json_strict(path)

    def test_rejects_nan_and_infinity(self):
        for index, token in enumerate((b"NaN", b"Infinity", b"-Infinity")):
            path = self.write(f"constant-{index}.json", b'{"value":' + token + b"}")
            with self.assertRaisesRegex(ContractError, "non-finite"):
                load_json_strict(path)

    def test_rejects_invalid_utf8_bom_depth_and_size(self):
        invalid = self.write("invalid-utf8.json", b'{"x":"\xff"}')
        with self.assertRaisesRegex(ContractError, "strict UTF-8"):
            load_json_strict(invalid)
        bom = self.write("bom.json", b"\xef\xbb\xbf{}")
        with self.assertRaisesRegex(ContractError, "BOM"):
            load_json_strict(bom)
        surrogate = self.write("surrogate.json", b'{"value":"\\ud800"}')
        with self.assertRaisesRegex(ContractError, "Unicode surrogate"):
            load_json_strict(surrogate)
        deep = self.write("deep.json", ("[" * 129 + "0" + "]" * 129).encode())
        with self.assertRaisesRegex(ContractError, "depth"):
            load_json_strict(deep)
        large = self.write("large.json", b'{"value":"123456"}')
        with self.assertRaisesRegex(ContractError, "maximum size"):
            load_json_strict(large, max_bytes=5)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is not portable")
    def test_rejects_nonregular_file_without_blocking(self):
        path = ROOT / "tests" / "input.fifo"
        os.mkfifo(path)
        self.addCleanup(path.unlink)
        with self.assertRaisesRegex(ContractError, "not a regular file"):
            load_json_strict(path)

    def test_streaming_read_rejects_simulated_growth_and_oversize(self):
        path = self.write("growing.json", b"{}")
        with mock.patch(
            "missionsready_sbom.core.os.read", side_effect=[b"{}x", b""]
        ) as reader:
            with self.assertRaisesRegex(ContractError, "changed size"):
                load_json_strict(path, max_bytes=10)
            self.assertLessEqual(reader.call_args_list[0].args[1], 11)
        with mock.patch("missionsready_sbom.core.os.read", return_value=b"{}x"):
            with self.assertRaisesRegex(ContractError, "maximum size"):
                load_json_strict(path, max_bytes=2)


class EvidenceTests(unittest.TestCase):
    def build(self, raw=None, digest=DIGEST):
        return build_evidence(
            raw if raw is not None else raw_for(digest),
            NAME,
            digest,
            PLATFORM,
            VERSION,
            source_for(digest),
        )

    def test_normalization_is_deterministic_across_unstable_metadata_and_order(self):
        first = raw_for()
        second = copy.deepcopy(first)
        second["creationInfo"]["created"] = "2030-01-01T00:00:00Z"
        second["creationInfo"]["creators"].reverse()
        second["documentNamespace"] = "https://anchore.example/syft/another-id"
        second["relationships"].reverse()
        self.assertEqual(
            canonical_json_bytes(self.build(first)),
            canonical_json_bytes(self.build(second)),
        )
        evidence = self.build(second)
        self.assertEqual(evidence["creationInfo"]["created"], "1970-01-01T00:00:00Z")
        self.assertEqual(evidence["creationInfo"]["creators"], ["Tool: syft-1.30.0"])
        self.assertEqual(evidence["spdxVersion"], "SPDX-2.3")
        validate_evidence(evidence)
        golden = (ROOT / "fixtures/valid/normalized-spdx.json").read_bytes()
        self.assertEqual(canonical_json_bytes(evidence), golden)

    def test_content_changes_are_not_hidden(self):
        first = self.build()
        changed = raw_for()
        changed["packages"][0]["versionInfo"] = "1.2.4"
        second = self.build(changed)
        self.assertNotEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        report = compare_evidence(first, second)
        self.assertEqual(report["summary"]["packageChanged"], 1)

    def test_delta_reports_components_packages_files_and_relationships(self):
        before = self.build()
        digest = "sha256:" + "d" * 64
        current_raw = raw_for(digest)
        current_raw["packages"].append(
            {
                "name": "new",
                "SPDXID": "SPDXRef-Package-new",
                "downloadLocation": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": "e" * 64}],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:apk/wolfi/new@2.0",
                    }
                ],
            }
        )
        current_raw["files"] = []
        current_raw["relationships"] = [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-new",
            }
        ]
        after = self.build(current_raw, digest)
        report = compare_evidence(before, after)
        self.assertEqual(report["summary"]["componentAdded"], 1)
        self.assertEqual(report["summary"]["packageAdded"], 1)
        self.assertEqual(report["summary"]["fileRemoved"], 1)
        self.assertGreater(report["summary"]["relationshipRemoved"], 0)
        self.assertEqual(report, json.loads(canonical_json_bytes(report)))

    def test_rejects_wrong_binding_or_unpinned_version(self):
        with self.assertRaisesRegex(ContractError, "source metadata"):
            build_evidence(raw_for(), NAME, DIGEST, PLATFORM, VERSION, {**source_for(), "name": "x/y"})
        with self.assertRaisesRegex(ContractError, "exact semantic version"):
            build_evidence(raw_for(), NAME, DIGEST, PLATFORM, "latest", source_for())
        raw = raw_for()
        raw["name"] = NAME + ":latest"
        with self.assertRaisesRegex(ContractError, "document name"):
            self.build(raw)

    def test_rejects_duplicate_ids_broken_relationships_and_missing_checksums(self):
        duplicate = raw_for()
        duplicate["files"][0]["SPDXID"] = duplicate["packages"][0]["SPDXID"]
        with self.assertRaisesRegex(ContractError, "duplicate SPDX identifier"):
            self.build(duplicate)
        broken = raw_for()
        broken["relationships"][0]["relatedSpdxElement"] = "SPDXRef-Missing"
        with self.assertRaisesRegex(ContractError, "unknown related"):
            self.build(broken)
        missing = fixture("invalid/missing-package-checksum.json")
        with self.assertRaisesRegex(ContractError, "required fields: checksums"):
            self.build(missing)

    def test_rejects_unknown_top_level_and_wrong_syft_creator(self):
        unknown = raw_for()
        unknown["unsafeExtension"] = {}
        with self.assertRaisesRegex(ContractError, "unsafe unknown"):
            self.build(unknown)
        creator = raw_for()
        creator["creationInfo"]["creators"].append("Tool: other-1.0.0")
        with self.assertRaisesRegex(ContractError, "unexpected creator"):
            self.build(creator)

    def test_rejects_noncanonical_accepted_evidence(self):
        evidence = self.build()
        evidence["creationInfo"]["created"] = "2026-01-01T00:00:00Z"
        with self.assertRaisesRegex(ContractError, "canonical normalized"):
            validate_evidence(evidence)

    def test_reviewer_nested_type_probes_raise_contract_error(self):
        cases = []

        value = raw_for()
        value["packages"][0]["hasFiles"] = None
        cases.append(("null hasFiles", value))

        value = raw_for()
        value["packages"][0]["externalRefs"] = [None]
        cases.append(("null external reference", value))

        value = raw_for()
        value["files"][0]["checksums"] = None
        cases.append(("null file checksums", value))

        value = raw_for()
        value["relationships"][0]["relationshipType"] = None
        cases.append(("null relationship type", value))

        value = raw_for()
        value["relationships"][0]["comment"] = {}
        cases.append(("object relationship comment", value))

        value = raw_for()
        value["creationInfo"]["creators"] = "Tool: syft-1.30.0"
        cases.append(("scalar creators", value))

        for label, malformed in cases:
            with self.subTest(label=label):
                with self.assertRaises(ContractError):
                    self.build(malformed)

    def test_rejects_required_fields_checksum_and_enum_errors(self):
        missing_package = raw_for()
        del missing_package["packages"][0]["downloadLocation"]
        with self.assertRaisesRegex(ContractError, "downloadLocation"):
            self.build(missing_package)

        missing_file = raw_for()
        del missing_file["files"][0]["fileName"]
        with self.assertRaisesRegex(ContractError, "fileName"):
            self.build(missing_file)

        bad_algorithm = raw_for()
        bad_algorithm["packages"][0]["checksums"][0]["algorithm"] = "CRC32"
        with self.assertRaisesRegex(ContractError, "checksum algorithm"):
            self.build(bad_algorithm)

        bad_value = raw_for()
        bad_value["packages"][0]["checksums"][0]["checksumValue"] = "B" * 64
        with self.assertRaisesRegex(ContractError, "lowercase hexadecimal"):
            self.build(bad_value)

        bad_relation = raw_for()
        bad_relation["relationships"][0]["relationshipType"] = "NOT_A_RELATION"
        with self.assertRaisesRegex(ContractError, "relationshipType"):
            self.build(bad_relation)

        unknown_nested = raw_for()
        unknown_nested["files"][0]["unknown"] = "unsafe"
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            self.build(unknown_nested)

    def test_rejects_wrong_reference_and_relationship_kinds(self):
        has_package = raw_for()
        has_package["packages"][0]["hasFiles"] = ["SPDXRef-Package-libexample"]
        with self.assertRaisesRegex(ContractError, "known file"):
            self.build(has_package)

        dependency = raw_for()
        dependency["files"][0]["fileDependencies"] = ["SPDXRef-Package-libexample"]
        with self.assertRaisesRegex(ContractError, "known file"):
            self.build(dependency)

        wrong_describes = raw_for()
        wrong_describes["relationships"][0] = {
            "spdxElementId": "SPDXRef-Package-libexample",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-File-libexample",
        }
        with self.assertRaisesRegex(ContractError, "source/target kinds"):
            self.build(wrong_describes)

        wrong_contains = raw_for()
        wrong_contains["relationships"][1]["relatedSpdxElement"] = "SPDXRef-DOCUMENT"
        with self.assertRaisesRegex(ContractError, "source/target kinds"):
            self.build(wrong_contains)

        wrong_copy = raw_for()
        wrong_copy["relationships"][1]["relationshipType"] = "COPY_OF"
        with self.assertRaisesRegex(ContractError, "source/target kinds"):
            self.build(wrong_copy)

    def test_validates_snippet_nested_structure_and_dereferences(self):
        snippet = {
            "SPDXID": "SPDXRef-Snippet-example",
            "name": "example snippet",
            "snippetFromFile": "SPDXRef-File-libexample",
            "ranges": [
                {
                    "startPointer": {
                        "reference": "SPDXRef-File-libexample",
                        "offset": 1,
                    },
                    "endPointer": {
                        "reference": "SPDXRef-File-libexample",
                        "offset": 10,
                    },
                },
                {
                    "startPointer": {
                        "reference": "SPDXRef-File-libexample",
                        "lineNumber": 1,
                    },
                    "endPointer": {
                        "reference": "SPDXRef-File-libexample",
                        "lineNumber": 2,
                    },
                }
            ],
        }
        valid = raw_for()
        valid["snippets"] = [snippet]
        self.build(valid)

        malformed = raw_for()
        malformed["snippets"] = [copy.deepcopy(snippet)]
        malformed["snippets"][0]["ranges"][0]["startPointer"]["reference"] = "SPDXRef-Missing"
        with self.assertRaisesRegex(ContractError, "same reference"):
            self.build(malformed)

        malformed = raw_for()
        malformed["snippets"] = [copy.deepcopy(snippet)]
        malformed["snippets"][0]["ranges"][0]["endPointer"]["lineNumber"] = 4
        with self.assertRaisesRegex(ContractError, "exactly one"):
            self.build(malformed)

        reversed_range = raw_for()
        reversed_range["snippets"] = [copy.deepcopy(snippet)]
        reversed_range["snippets"][0]["ranges"][0]["startPointer"]["offset"] = 11
        with self.assertRaisesRegex(ContractError, "must not exceed"):
            self.build(reversed_range)

        mixed_range = raw_for()
        mixed_range["snippets"] = [copy.deepcopy(snippet)]
        end = mixed_range["snippets"][0]["ranges"][0]["endPointer"]
        del end["offset"]
        end["lineNumber"] = 2
        with self.assertRaisesRegex(ContractError, "same reference and pointer type"):
            self.build(mixed_range)

        zero_offset = raw_for()
        zero_offset["snippets"] = [copy.deepcopy(snippet)]
        for pointer in zero_offset["snippets"][0]["ranges"][0].values():
            pointer["offset"] = 0
        with self.assertRaisesRegex(ContractError, "at least 1"):
            self.build(zero_offset)

        missing_byte_range = raw_for()
        missing_byte_range["snippets"] = [copy.deepcopy(snippet)]
        missing_byte_range["snippets"][0]["ranges"] = [
            missing_byte_range["snippets"][0]["ranges"][1]
        ]
        with self.assertRaisesRegex(ContractError, "byte offset range"):
            self.build(missing_byte_range)

    def test_relationship_kind_table_covers_full_spdx_enum(self):
        self.assertEqual(set(_RELATIONSHIP_KIND_RULES), _RELATIONSHIP_TYPES)
        all_kinds = {"document", "external-document", "package", "file", "snippet"}
        all_pairs = {(left, right) for left in all_kinds for right in all_kinds}
        for relation in sorted(_RELATIONSHIP_TYPES):
            allowed = _RELATIONSHIP_KIND_RULES[relation]
            with self.subTest(relation=relation, case="valid"):
                left, right = sorted(allowed)[0]
                _validate_relationship_kinds(relation, left, right, "relationship")
            invalid = sorted(all_pairs - allowed)[0]
            with self.subTest(relation=relation, case="invalid"):
                with self.assertRaises(ContractError):
                    _validate_relationship_kinds(
                        relation, invalid[0], invalid[1], "relationship"
                    )

    def test_spdx_relationship_direction_regressions(self):
        second_file = {
            "SPDXID": "SPDXRef-File-second",
            "fileName": "/usr/lib/second.so",
            "checksums": [{"algorithm": "SHA256", "checksumValue": "d" * 64}],
        }
        valid_relationships = (
            {
                "spdxElementId": "SPDXRef-File-libexample",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": "SPDXRef-File-second",
            },
            {
                "spdxElementId": "SPDXRef-File-libexample",
                "relationshipType": "DYNAMIC_LINK",
                "relatedSpdxElement": "SPDXRef-File-second",
            },
            {
                "spdxElementId": "SPDXRef-File-libexample",
                "relationshipType": "STATIC_LINK",
                "relatedSpdxElement": "SPDXRef-File-second",
            },
            {
                "spdxElementId": "SPDXRef-File-libexample",
                "relationshipType": "FILE_MODIFIED",
                "relatedSpdxElement": "SPDXRef-File-second",
            },
            {
                "spdxElementId": "SPDXRef-File-libexample",
                "relationshipType": "FILE_ADDED",
                "relatedSpdxElement": "SPDXRef-Package-libexample",
            },
            {
                "spdxElementId": "SPDXRef-File-libexample",
                "relationshipType": "FILE_DELETED",
                "relatedSpdxElement": "SPDXRef-Package-libexample",
            },
        )
        for relationship in valid_relationships:
            value = raw_for()
            value["files"].append(copy.deepcopy(second_file))
            value["relationships"].append(relationship)
            with self.subTest(relationship=relationship["relationshipType"]):
                self.build(value)

        for relation in ("FILE_ADDED", "FILE_DELETED"):
            value = raw_for()
            value["relationships"].append(
                {
                    "spdxElementId": "SPDXRef-Package-libexample",
                    "relationshipType": relation,
                    "relatedSpdxElement": "SPDXRef-File-libexample",
                }
            )
            with self.subTest(relationship=relation, case="reverse"):
                with self.assertRaisesRegex(ContractError, "source/target kinds"):
                    self.build(value)

        amended = raw_for()
        amended["externalDocumentRefs"] = [
            {
                "externalDocumentId": "DocumentRef-old",
                "spdxDocument": "https://example.invalid/old.spdx.json",
                "checksum": {"algorithm": "SHA1", "checksumValue": "e" * 40},
            }
        ]
        amended["relationships"].append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "AMENDS",
                "relatedSpdxElement": "DocumentRef-old:SPDXRef-DOCUMENT",
            }
        )
        self.build(amended)

        sentinel = raw_for()
        sentinel["relationships"].append(
            {
                "spdxElementId": "SPDXRef-Package-libexample",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "NONE",
            }
        )
        self.build(sentinel)

    def test_optional_fields_are_restricted_to_spdx_object_types(self):
        package_artifact = raw_for()
        package_artifact["packages"][0]["artifactOfs"] = [{"name": "wrong"}]
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            self.build(package_artifact)

        package_cross_refs = raw_for()
        package_cross_refs["packages"][0]["crossRefs"] = [{"url": "https://example.invalid"}]
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            self.build(package_cross_refs)

        valid_file_artifact = raw_for()
        valid_file_artifact["files"][0]["artifactOfs"] = [
            {"name": "project", "projectUri": "https://example.invalid/project"}
        ]
        self.build(valid_file_artifact)

        bad_file_artifact = raw_for()
        bad_file_artifact["files"][0]["artifactOfs"] = [None]
        with self.assertRaisesRegex(ContractError, "must be an object"):
            self.build(bad_file_artifact)

        bad_cross_ref = raw_for()
        bad_cross_ref["hasExtractedLicensingInfos"] = [
            {
                "licenseId": "LicenseRef-example",
                "extractedText": "example",
                "crossRefs": [
                    {"url": "https://example.invalid/license", "isLive": "yes"}
                ],
            }
        ]
        with self.assertRaisesRegex(ContractError, "must be a boolean"):
            self.build(bad_cross_ref)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.work = ROOT / "tests" / "transaction-work"
        self.work.mkdir(exist_ok=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.work.exists():
            shutil.rmtree(self.work)

    def test_mkdir_failure_is_controlled_and_preserves_outputs(self):
        destination = self.work / "missing" / "output.json"
        with mock.patch.object(Path, "mkdir", side_effect=OSError("mkdir failed")):
            with self.assertRaisesRegex(ContractError, "create output directory"):
                atomic_write_jsons([(destination, {"new": True})])
        self.assertFalse(destination.exists())

    def test_staging_failure_is_controlled_and_preserves_outputs(self):
        destination = self.work / "output.json"
        destination.write_text("old", encoding="utf-8")
        with mock.patch(
            "missionsready_sbom.core.tempfile.mkstemp", side_effect=OSError("stage failed")
        ):
            with self.assertRaisesRegex(ContractError, "stage output"):
                atomic_write_jsons([(destination, {"new": True})])
        self.assertEqual(destination.read_text(encoding="utf-8"), "old")

    def test_write_and_fsync_failures_are_controlled_and_preserve_output(self):
        destination = self.work / "output.json"
        destination.write_text("old", encoding="utf-8")
        original_fdopen = os.fdopen

        class FailingWrite:
            def __init__(self, descriptor, mode):
                self.stream = original_fdopen(descriptor, mode)

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def write(self, data):
                raise OSError("write failed")

        with mock.patch("missionsready_sbom.core.os.fdopen", side_effect=FailingWrite):
            with self.assertRaisesRegex(ContractError, "stage output"):
                atomic_write_jsons([(destination, {"new": True})])
        self.assertEqual(destination.read_text(encoding="utf-8"), "old")

        with mock.patch("missionsready_sbom.core.os.fsync", side_effect=OSError("fsync failed")):
            with self.assertRaisesRegex(ContractError, "stage output"):
                atomic_write_jsons([(destination, {"new": True})])
        self.assertEqual(destination.read_text(encoding="utf-8"), "old")

    def test_post_commit_cleanup_error_is_reported_as_committed(self):
        destination = self.work / "output.json"
        destination.write_text("old", encoding="utf-8")
        original_unlink = os.unlink
        backup_unlinks = 0

        def fail_final_backup_cleanup(path):
            nonlocal backup_unlinks
            if str(path).endswith(".backup"):
                backup_unlinks += 1
                if backup_unlinks == 2:
                    raise OSError("cleanup failed")
            return original_unlink(path)

        with mock.patch(
            "missionsready_sbom.core.os.unlink", side_effect=fail_final_backup_cleanup
        ):
            with self.assertRaisesRegex(CommittedCleanupError, "outputs committed"):
                atomic_write_jsons([(destination, {"new": True})])
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), {"new": True})
        backups = list(self.work.glob(".*.backup"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), "old")

        stderr = io.StringIO()
        with mock.patch.object(
            cli, "_normalize", side_effect=CommittedCleanupError("committed cleanup")
        ):
            with contextlib.redirect_stderr(stderr):
                result = cli.main([
                    "normalize",
                    "--input", "unused",
                    "--output", "unused-output",
                    "--subject-name", NAME,
                    "--subject-digest", DIGEST,
                    "--platform", PLATFORM,
                    "--syft-version", VERSION,
                    "--source-metadata", "unused-source",
                ])
        self.assertEqual(result, 3)
        self.assertIn("committed with cleanup warning", stderr.getvalue())

    def test_cli_second_output_replace_failure_rolls_back_both_outputs(self):
        raw = self.work / "raw.json"
        source = self.work / "source.json"
        previous = self.work / "previous.json"
        output = self.work / "output.json"
        report = self.work / "report.json"
        raw.write_bytes(canonical_json_bytes(raw_for()))
        source.write_bytes(canonical_json_bytes(source_for()))
        previous.write_bytes(canonical_json_bytes(build_evidence(
            raw_for(), NAME, DIGEST, PLATFORM, VERSION, source_for()
        )))
        output.write_text("old-output", encoding="utf-8")
        report.write_text("old-report", encoding="utf-8")

        original_replace = os.replace
        failed = False

        def fail_second_install(source_path, destination_path):
            nonlocal failed
            if (
                not failed
                and Path(destination_path) == report
                and str(source_path).endswith(".stage")
            ):
                failed = True
                raise OSError("injected second replacement failure")
            return original_replace(source_path, destination_path)

        stderr = io.StringIO()
        with mock.patch("missionsready_sbom.core.os.replace", side_effect=fail_second_install):
            with contextlib.redirect_stderr(stderr):
                result = cli.main([
                    "normalize",
                    "--input", str(raw),
                    "--output", str(output),
                    "--subject-name", NAME,
                    "--subject-digest", DIGEST,
                    "--platform", PLATFORM,
                    "--syft-version", VERSION,
                    "--source-metadata", str(source),
                    "--previous", str(previous),
                    "--report", str(report),
                ])
        self.assertEqual(result, 2)
        self.assertIn("rolled back", stderr.getvalue())
        self.assertEqual(output.read_text(encoding="utf-8"), "old-output")
        self.assertEqual(report.read_text(encoding="utf-8"), "old-report")
        self.assertEqual(list(self.work.glob(".*.stage")), [])
        self.assertEqual(list(self.work.glob(".*.backup")), [])

    def test_existing_outputs_remain_present_through_every_replacement(self):
        first = self.work / "first.json"
        second = self.work / "second.json"
        first.write_text("old-first", encoding="utf-8")
        second.write_text("old-second", encoding="utf-8")
        original_replace = os.replace

        def assert_present(source_path, destination_path):
            if str(source_path).endswith(".stage") and Path(destination_path) in {
                first,
                second,
            }:
                self.assertTrue(first.exists())
                self.assertTrue(second.exists())
            return original_replace(source_path, destination_path)

        with mock.patch(
            "missionsready_sbom.core.os.replace", side_effect=assert_present
        ):
            atomic_write_jsons([(first, {"version": 2}), (second, {"version": 2})])
        self.assertEqual(json.loads(first.read_text()), {"version": 2})
        self.assertEqual(json.loads(second.read_text()), {"version": 2})

    def test_directory_fsync_immediately_follows_entry_changes_across_directories(self):
        first_dir = self.work / "first-dir"
        second_dir = self.work / "second-dir"
        first_dir.mkdir()
        second_dir.mkdir()
        first = first_dir / "first.json"
        second = second_dir / "second.json"
        first.write_text("old-first", encoding="utf-8")
        second.write_text("old-second", encoding="utf-8")
        events = []
        original_replace = os.replace
        original_link = os.link
        original_unlink = os.unlink
        original_fsync_directory = core._fsync_directory

        def record_replace(source, destination):
            result = original_replace(source, destination)
            events.append(("entry", "replace", Path(destination).parent))
            return result

        def record_link(source, destination, *args, **kwargs):
            result = original_link(source, destination, *args, **kwargs)
            events.append(("entry", "link", Path(destination).parent))
            return result

        def record_unlink(path, *args, **kwargs):
            result = original_unlink(path, *args, **kwargs)
            events.append(("entry", "unlink", Path(path).parent))
            return result

        def record_directory_fsync(directory):
            events.append(("fsync", "directory", Path(directory)))
            return original_fsync_directory(directory)

        with mock.patch(
            "missionsready_sbom.core.os.replace", side_effect=record_replace
        ), mock.patch(
            "missionsready_sbom.core.os.link", side_effect=record_link
        ), mock.patch(
            "missionsready_sbom.core.os.unlink", side_effect=record_unlink
        ), mock.patch(
            "missionsready_sbom.core._fsync_directory",
            side_effect=record_directory_fsync,
        ):
            atomic_write_jsons([(first, {"version": 2}), (second, {"version": 2})])

        entry_indexes = [
            index for index, event in enumerate(events) if event[0] == "entry"
        ]
        self.assertGreater(len(entry_indexes), 8)
        for index in entry_indexes:
            with self.subTest(event=events[index]):
                self.assertLess(index + 1, len(events))
                self.assertEqual(events[index + 1][0], "fsync")
                self.assertEqual(events[index + 1][2], events[index][2])
        output_replace_parents = {
            event[2]
            for event in events
            if event[:2] == ("entry", "replace") and event[2] in {first_dir, second_dir}
        }
        self.assertEqual(output_replace_parents, {first_dir, second_dir})

    def test_precommit_directory_fsync_failures_restore_original(self):
        for phase in ("prepared-marker", "output", "committed-marker"):
            with self.subTest(phase=phase):
                directory = self.work / phase
                directory.mkdir()
                destination = directory / "output.json"
                destination.write_text("old", encoding="utf-8")
                original_replace = os.replace
                original_fsync_directory = core._fsync_directory
                trigger = False
                failed = False

                def mark_phase(source, target):
                    nonlocal trigger
                    result = original_replace(source, target)
                    target_path = Path(target)
                    if phase == "output" and target_path == destination:
                        trigger = True
                    elif (
                        phase == "prepared-marker"
                        and target_path.name.startswith(".missionsready-sbom-transaction-")
                        and ".committed." not in target_path.name
                    ):
                        trigger = True
                    elif phase == "committed-marker" and ".committed." in target_path.name:
                        trigger = True
                    return result

                def fail_selected_fsync(directory_path):
                    nonlocal trigger, failed
                    if trigger and not failed:
                        trigger = False
                        failed = True
                        raise ContractError(f"injected {phase} directory fsync failure")
                    return original_fsync_directory(directory_path)

                with mock.patch(
                    "missionsready_sbom.core.os.replace", side_effect=mark_phase
                ), mock.patch(
                    "missionsready_sbom.core._fsync_directory",
                    side_effect=fail_selected_fsync,
                ):
                    with self.assertRaises(ContractError):
                        atomic_write_jsons([(destination, {"version": 2})])
                self.assertTrue(failed)
                self.assertTrue(destination.exists())
                self.assertEqual(destination.read_text(), "old")
                self.assertEqual(list(directory.glob(".*.stage")), [])
                self.assertEqual(list(directory.glob(".*.backup")), [])
                self.assertEqual(
                    list(directory.glob(".missionsready-sbom-transaction-*.json")),
                    [],
                )

    def test_parent_stage_and_backup_directory_fsync_failures_are_precommit(self):
        parent_destination = self.work / "new-parent" / "output.json"
        original_fsync_directory = core._fsync_directory
        failed = False

        def fail_parent_fsync(directory):
            nonlocal failed
            if not failed:
                failed = True
                raise ContractError("injected parent directory fsync failure")
            return original_fsync_directory(directory)

        with mock.patch(
            "missionsready_sbom.core._fsync_directory",
            side_effect=fail_parent_fsync,
        ):
            with self.assertRaisesRegex(ContractError, "parent directory fsync"):
                atomic_write_jsons([(parent_destination, {"version": 2})])
        self.assertFalse(parent_destination.exists())

        for phase, failing_call in (("stage", 1), ("backup", 2)):
            with self.subTest(phase=phase):
                directory = self.work / phase
                directory.mkdir()
                destination = directory / "output.json"
                destination.write_text("old", encoding="utf-8")
                calls = 0
                failed = False

                def fail_numbered_fsync(directory_path):
                    nonlocal calls, failed
                    calls += 1
                    if calls == failing_call:
                        failed = True
                        raise ContractError(f"injected {phase} directory fsync failure")
                    return original_fsync_directory(directory_path)

                with mock.patch(
                    "missionsready_sbom.core._fsync_directory",
                    side_effect=fail_numbered_fsync,
                ):
                    with self.assertRaises(ContractError):
                        atomic_write_jsons([(destination, {"version": 2})])
                self.assertTrue(failed)
                self.assertEqual(destination.read_text(), "old")

    def test_second_directory_fsync_failure_rolls_back_cross_directory_outputs(self):
        first_dir = self.work / "first-dir"
        second_dir = self.work / "second-dir"
        first_dir.mkdir()
        second_dir.mkdir()
        first = first_dir / "first.json"
        second = second_dir / "second.json"
        first.write_text("old-first", encoding="utf-8")
        second.write_text("old-second", encoding="utf-8")
        original_replace = os.replace
        original_fsync_directory = core._fsync_directory
        trigger = False
        failed = False

        def mark_second_replace(source, target):
            nonlocal trigger
            result = original_replace(source, target)
            if Path(target) == second and str(source).endswith(".stage"):
                trigger = True
            return result

        def fail_second_directory(directory):
            nonlocal trigger, failed
            if trigger and not failed:
                trigger = False
                failed = True
                raise ContractError("injected second-directory fsync failure")
            return original_fsync_directory(directory)

        with mock.patch(
            "missionsready_sbom.core.os.replace", side_effect=mark_second_replace
        ), mock.patch(
            "missionsready_sbom.core._fsync_directory",
            side_effect=fail_second_directory,
        ):
            with self.assertRaisesRegex(ContractError, "rolled back"):
                atomic_write_jsons([(first, {"version": 2}), (second, {"version": 2})])
        self.assertTrue(failed)
        self.assertEqual(first.read_text(), "old-first")
        self.assertEqual(second.read_text(), "old-second")

    def test_postcommit_cleanup_fsync_failures_are_committed_warnings(self):
        for phase in ("backup-cleanup", "marker-cleanup"):
            with self.subTest(phase=phase):
                directory = self.work / phase
                directory.mkdir()
                destination = directory / "output.json"
                destination.write_text("old", encoding="utf-8")
                original_unlink = os.unlink
                original_fsync_directory = core._fsync_directory
                trigger = False
                backup_unlinks = 0
                failed = False

                def mark_cleanup(path, *args, **kwargs):
                    nonlocal trigger, backup_unlinks
                    result = original_unlink(path, *args, **kwargs)
                    name = Path(path).name
                    if name.endswith(".backup"):
                        backup_unlinks += 1
                        if phase == "backup-cleanup" and backup_unlinks == 2:
                            trigger = True
                    elif (
                        phase == "marker-cleanup"
                        and name.startswith(".missionsready-sbom-transaction-")
                        and ".committed." not in name
                    ):
                        trigger = True
                    return result

                def fail_selected_fsync(directory_path):
                    nonlocal trigger, failed
                    if trigger and not failed:
                        trigger = False
                        failed = True
                        raise ContractError(f"injected {phase} directory fsync failure")
                    return original_fsync_directory(directory_path)

                with mock.patch(
                    "missionsready_sbom.core.os.unlink", side_effect=mark_cleanup
                ), mock.patch(
                    "missionsready_sbom.core._fsync_directory",
                    side_effect=fail_selected_fsync,
                ):
                    with self.assertRaises(CommittedCleanupError):
                        atomic_write_jsons([(destination, {"version": 2})])
                self.assertTrue(failed)
                self.assertEqual(json.loads(destination.read_text()), {"version": 2})
                recover_output_transaction([destination])
                self.assertEqual(json.loads(destination.read_text()), {"version": 2})

    def test_backup_copy_fallback_preserves_continuous_destination(self):
        destination = self.work / "output.json"
        destination.write_text("old", encoding="utf-8")
        with mock.patch(
            "missionsready_sbom.core.os.link",
            side_effect=OSError("hard links unavailable"),
        ):
            atomic_write_jsons([(destination, {"version": 2})])
        self.assertTrue(destination.exists())
        self.assertEqual(json.loads(destination.read_text()), {"version": 2})

    def test_startup_recovery_rolls_back_interrupted_mixed_transaction(self):
        first = self.work / "first.json"
        second = self.work / "second.json"
        first.write_text("old-first", encoding="utf-8")
        second.write_text("old-second", encoding="utf-8")
        original_replace = os.replace

        class SimulatedTermination(BaseException):
            pass

        terminated = False

        def terminate_on_second_install(source_path, destination_path):
            nonlocal terminated
            if (
                not terminated
                and str(source_path).endswith(".stage")
                and Path(destination_path) == second
            ):
                terminated = True
                raise SimulatedTermination()
            return original_replace(source_path, destination_path)

        with mock.patch(
            "missionsready_sbom.core.os.replace",
            side_effect=terminate_on_second_install,
        ):
            with self.assertRaises(SimulatedTermination):
                atomic_write_jsons(
                    [(first, {"version": 2}), (second, {"version": 2})]
                )
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual(json.loads(first.read_text()), {"version": 2})
        self.assertEqual(second.read_text(), "old-second")

        recover_output_transaction([first, second])
        self.assertEqual(first.read_text(), "old-first")
        self.assertEqual(second.read_text(), "old-second")
        self.assertEqual(
            list(self.work.glob(".missionsready-sbom-transaction-*.json")), []
        )

    def test_startup_recovery_preserves_committed_outputs_after_cleanup_interruption(self):
        first = self.work / "first.json"
        second = self.work / "second.json"
        first.write_text("old-first", encoding="utf-8")
        second.write_text("old-second", encoding="utf-8")

        class SimulatedTermination(BaseException):
            pass

        with mock.patch(
            "missionsready_sbom.core._cleanup_paths",
            side_effect=SimulatedTermination(),
        ):
            with self.assertRaises(SimulatedTermination):
                atomic_write_jsons(
                    [(first, {"version": 2}), (second, {"version": 2})]
                )
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual(json.loads(first.read_text()), {"version": 2})
        self.assertEqual(json.loads(second.read_text()), {"version": 2})

        recover_output_transaction([first, second])
        self.assertEqual(json.loads(first.read_text()), {"version": 2})
        self.assertEqual(json.loads(second.read_text()), {"version": 2})
        self.assertEqual(
            list(self.work.glob(".missionsready-sbom-transaction-*.json")), []
        )

    def test_startup_recovery_rolls_back_before_commit_marker(self):
        first = self.work / "first.json"
        second = self.work / "second.json"
        first.write_text("old-first", encoding="utf-8")
        second.write_text("old-second", encoding="utf-8")

        class SimulatedTermination(BaseException):
            pass

        from missionsready_sbom import core

        original_marker_write = core._write_transaction_marker
        marker_writes = 0

        def terminate_before_committed_marker(marker, value):
            nonlocal marker_writes
            marker_writes += 1
            if marker_writes == 2:
                raise SimulatedTermination()
            return original_marker_write(marker, value)

        with mock.patch(
            "missionsready_sbom.core._write_transaction_marker",
            side_effect=terminate_before_committed_marker,
        ):
            with self.assertRaises(SimulatedTermination):
                atomic_write_jsons(
                    [(first, {"version": 2}), (second, {"version": 2})]
                )
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual(json.loads(first.read_text()), {"version": 2})
        self.assertEqual(json.loads(second.read_text()), {"version": 2})

        recover_output_transaction([first, second])
        self.assertEqual(first.read_text(), "old-first")
        self.assertEqual(second.read_text(), "old-second")

    def test_recovery_directory_fsync_failures_remain_retryable(self):
        destination = self.work / "existing.json"
        destination.write_text("old", encoding="utf-8")

        class SimulatedTermination(BaseException):
            pass

        original_marker_write = core._write_transaction_marker
        marker_writes = 0

        def terminate_before_commit(marker, value):
            nonlocal marker_writes
            marker_writes += 1
            if marker_writes == 2:
                raise SimulatedTermination()
            return original_marker_write(marker, value)

        with mock.patch(
            "missionsready_sbom.core._write_transaction_marker",
            side_effect=terminate_before_commit,
        ):
            with self.assertRaises(SimulatedTermination):
                atomic_write_jsons([(destination, {"version": 2})])

        original_fsync_directory = core._fsync_directory
        failed = False

        def fail_restore_fsync(directory):
            nonlocal failed
            if not failed:
                failed = True
                raise ContractError("injected recovery rename fsync failure")
            return original_fsync_directory(directory)

        with mock.patch(
            "missionsready_sbom.core._fsync_directory",
            side_effect=fail_restore_fsync,
        ):
            with self.assertRaisesRegex(ContractError, "recovery rename"):
                recover_output_transaction([destination])
        self.assertTrue(destination.exists())
        self.assertEqual(destination.read_text(), "old")
        recover_output_transaction([destination])
        self.assertEqual(destination.read_text(), "old")

        new_destination = self.work / "new.json"
        marker_writes = 0
        with mock.patch(
            "missionsready_sbom.core._write_transaction_marker",
            side_effect=terminate_before_commit,
        ):
            with self.assertRaises(SimulatedTermination):
                atomic_write_jsons([(new_destination, {"version": 2})])
        self.assertTrue(new_destination.exists())

        original_unlink = os.unlink
        remove_trigger = False
        failed = False

        def mark_recovery_removal(path, *args, **kwargs):
            nonlocal remove_trigger
            result = original_unlink(path, *args, **kwargs)
            if Path(path) == new_destination:
                remove_trigger = True
            return result

        def fail_remove_fsync(directory):
            nonlocal remove_trigger, failed
            if remove_trigger and not failed:
                remove_trigger = False
                failed = True
                raise ContractError("injected recovery removal fsync failure")
            return original_fsync_directory(directory)

        with mock.patch(
            "missionsready_sbom.core.os.unlink", side_effect=mark_recovery_removal
        ), mock.patch(
            "missionsready_sbom.core._fsync_directory",
            side_effect=fail_remove_fsync,
        ):
            with self.assertRaisesRegex(ContractError, "recovery removal"):
                recover_output_transaction([new_destination])
        self.assertFalse(new_destination.exists())
        recover_output_transaction([new_destination])
        self.assertFalse(new_destination.exists())

    def test_recovery_uses_any_representable_old_state_and_rejects_true_corruption(self):
        destination = self.work / "representable.json"
        destination.write_text("old", encoding="utf-8")

        class SimulatedTermination(BaseException):
            pass

        original_replace = os.replace

        def terminate_before_output_replace(source, target):
            if str(source).endswith(".stage") and Path(target) == destination:
                raise SimulatedTermination()
            return original_replace(source, target)

        with mock.patch(
            "missionsready_sbom.core.os.replace",
            side_effect=terminate_before_output_replace,
        ):
            with self.assertRaises(SimulatedTermination):
                atomic_write_jsons([(destination, {"version": 2})])
        backup = list(self.work.glob(f".{destination.name}.*.backup"))[0]
        backup.unlink()
        backup.write_text("corrupt-backup", encoding="utf-8")
        recover_output_transaction([destination])
        self.assertEqual(destination.read_text(), "old")

        corrupted = self.work / "unrecoverable.json"
        corrupted.write_text("old", encoding="utf-8")
        original_marker_write = core._write_transaction_marker
        marker_writes = 0

        def terminate_before_commit_marker(marker, value):
            nonlocal marker_writes
            marker_writes += 1
            if marker_writes == 2:
                raise SimulatedTermination()
            return original_marker_write(marker, value)

        with mock.patch(
            "missionsready_sbom.core._write_transaction_marker",
            side_effect=terminate_before_commit_marker,
        ):
            with self.assertRaises(SimulatedTermination):
                atomic_write_jsons([(corrupted, {"version": 2})])
        backup = list(self.work.glob(f".{corrupted.name}.*.backup"))[0]
        backup.unlink()
        with self.assertRaisesRegex(ContractError, "neither destination nor backup"):
            recover_output_transaction([corrupted])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.work = ROOT / "tests" / "cli-work"
        self.work.mkdir(exist_ok=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for path in self.work.iterdir():
            path.unlink()
        self.work.rmdir()

    def run_cli(self, *args):
        return subprocess.run(
            [str(ROOT / "scripts" / "sbom-tool"), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_normalize_validate_and_compare(self):
        output = self.work / "accepted.json"
        result = self.run_cli(
            "normalize",
            "--input", "fixtures/valid/syft-spdx.json",
            "--output", str(output),
            "--subject-name", NAME,
            "--subject-digest", DIGEST,
            "--platform", PLATFORM,
            "--syft-version", VERSION,
            "--source-metadata", "fixtures/valid/source-metadata.json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("normalized 1 packages", result.stderr)
        self.assertTrue(output.exists())
        validation = self.run_cli("validate", "--input", str(output))
        self.assertEqual(validation.returncode, 0, validation.stderr)
        report = self.work / "report.json"
        comparison = self.run_cli(
            "compare",
            "--previous", str(output),
            "--current", str(output),
            "--report", str(report),
        )
        self.assertEqual(comparison.returncode, 0, comparison.stderr)
        self.assertEqual(json.loads(report.read_text())["summary"]["packageChanged"], 0)

    def test_failure_does_not_replace_existing_output(self):
        output = self.work / "accepted.json"
        output.write_text("keep", encoding="utf-8")
        result = self.run_cli(
            "normalize",
            "--input", "fixtures/invalid/missing-package-checksum.json",
            "--output", str(output),
            "--subject-name", NAME,
            "--subject-digest", DIGEST,
            "--platform", PLATFORM,
            "--syft-version", VERSION,
            "--source-metadata", "fixtures/valid/source-metadata.json",
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_invalid_previous_does_not_replace_existing_output(self):
        output = self.work / "accepted.json"
        previous = self.work / "previous.json"
        report = self.work / "report.json"
        output.write_text("keep", encoding="utf-8")
        previous.write_text("{}", encoding="utf-8")
        result = self.run_cli(
            "normalize",
            "--input", "fixtures/valid/syft-spdx.json",
            "--output", str(output),
            "--subject-name", NAME,
            "--subject-digest", DIGEST,
            "--platform", PLATFORM,
            "--syft-version", VERSION,
            "--source-metadata", "fixtures/valid/source-metadata.json",
            "--previous", str(previous),
            "--report", str(report),
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep")
        self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()

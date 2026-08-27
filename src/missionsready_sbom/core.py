"""Strict validation, canonicalization, and comparison of Syft SPDX JSON."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlsplit

CANONICALIZATION = "missionsready-spdx-json-v1"
BINDING_PREFIX = "MissionsReady-SBOM-Binding: "
FIXED_TIMESTAMP = "1970-01-01T00:00:00Z"
DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 128
MAX_VALUES = 2_000_000
MAX_COLLECTION_ITEMS = 1_000_000
MAX_STRING_CHARS = 8 * 1024 * 1024
MAX_KEY_CHARS = 1024

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUBJECT_RE = re.compile(r"^[a-z0-9.-]+/[a-z0-9._/-]+$")
_PLATFORM_RE = re.compile(r"^linux/(amd64|arm64)$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_SPDX_ID_RE = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

_TOP_LEVEL_FIELDS = {
    "SPDXID",
    "annotations",
    "comment",
    "creationInfo",
    "dataLicense",
    "documentDescribes",
    "documentNamespace",
    "externalDocumentRefs",
    "files",
    "hasExtractedLicensingInfos",
    "name",
    "packages",
    "relationships",
    "revieweds",
    "snippets",
    "spdxVersion",
}

_CHECKSUM_LENGTHS = {
    "ADLER32": 8,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3": 64,
    "MD2": 32,
    "MD4": 32,
    "MD5": 32,
    "MD6": None,
    "SHA1": 40,
    "SHA224": 56,
    "SHA256": 64,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "SHA384": 96,
    "SHA512": 128,
}

_RELATIONSHIP_TYPES = {
    "AMENDS",
    "ANCESTOR_OF",
    "BUILD_DEPENDENCY_OF",
    "BUILD_TOOL_OF",
    "CONTAINED_BY",
    "CONTAINS",
    "COPY_OF",
    "DATA_FILE_OF",
    "DEPENDENCY_MANIFEST_OF",
    "DEPENDENCY_OF",
    "DEPENDS_ON",
    "DESCENDANT_OF",
    "DESCRIBED_BY",
    "DESCRIBES",
    "DEV_DEPENDENCY_OF",
    "DEV_TOOL_OF",
    "DISTRIBUTION_ARTIFACT",
    "DOCUMENTATION_OF",
    "DYNAMIC_LINK",
    "EXAMPLE_OF",
    "EXPANDED_FROM_ARCHIVE",
    "FILE_ADDED",
    "FILE_DELETED",
    "FILE_MODIFIED",
    "GENERATED_FROM",
    "GENERATES",
    "HAS_PREREQUISITE",
    "METAFILE_OF",
    "OPTIONAL_COMPONENT_OF",
    "OPTIONAL_DEPENDENCY_OF",
    "OTHER",
    "PACKAGE_OF",
    "PATCH_APPLIED",
    "PATCH_FOR",
    "PREREQUISITE_FOR",
    "PROVIDED_DEPENDENCY_OF",
    "REQUIREMENT_DESCRIPTION_FOR",
    "RUNTIME_DEPENDENCY_OF",
    "SPECIFICATION_FOR",
    "STATIC_LINK",
    "TEST_CASE_OF",
    "TEST_DEPENDENCY_OF",
    "TEST_OF",
    "TEST_TOOL_OF",
    "VARIANT_OF",
}

_PACKAGE_PURPOSES = {
    "APPLICATION",
    "ARCHIVE",
    "CONTAINER",
    "DEVICE",
    "FILE",
    "FIRMWARE",
    "FRAMEWORK",
    "INSTALL",
    "LIBRARY",
    "OPERATING_SYSTEM",
    "OTHER",
    "SOURCE",
}

_FILE_TYPES = {
    "APPLICATION",
    "ARCHIVE",
    "AUDIO",
    "BINARY",
    "DOCUMENTATION",
    "IMAGE",
    "OTHER",
    "SOURCE",
    "SPDX",
    "TEXT",
    "VIDEO",
}

_DEPENDENCY_RELATIONSHIPS = {
    "BUILD_DEPENDENCY_OF",
    "BUILD_TOOL_OF",
    "DEPENDENCY_OF",
    "DEPENDS_ON",
    "DEV_DEPENDENCY_OF",
    "DEV_TOOL_OF",
    "HAS_PREREQUISITE",
    "OPTIONAL_COMPONENT_OF",
    "OPTIONAL_DEPENDENCY_OF",
    "PREREQUISITE_FOR",
    "PROVIDED_DEPENDENCY_OF",
    "RUNTIME_DEPENDENCY_OF",
    "TEST_DEPENDENCY_OF",
    "TEST_TOOL_OF",
}

_ITEM_KINDS = {"package", "file", "snippet"}
_SOFTWARE_KINDS = {"package", "file"}
_ANY_ITEM_PAIRS = {
    (left, right) for left in _ITEM_KINDS for right in _ITEM_KINDS
}
_SOFTWARE_PAIRS = {
    (left, right) for left in _SOFTWARE_KINDS for right in _SOFTWARE_KINDS
}
_SAME_ITEM_PAIRS = {(kind, kind) for kind in _ITEM_KINDS}

_RELATIONSHIP_KIND_RULES = {
    relationship: set(_ANY_ITEM_PAIRS) for relationship in _RELATIONSHIP_TYPES
}
_RELATIONSHIP_KIND_RULES.update(
    {
        "AMENDS": {("document", "external-document")},
        "DESCRIBES": {("document", kind) for kind in _ITEM_KINDS},
        "DESCRIBED_BY": {(kind, "document") for kind in _ITEM_KINDS},
        "FILE_ADDED": {("file", "package")},
        "FILE_DELETED": {("file", "package")},
        "FILE_MODIFIED": {("file", "file")},
        "DEPENDENCY_MANIFEST_OF": {
            ("file", "file"),
            ("file", "package"),
        },
        "DATA_FILE_OF": {("file", kind) for kind in _SOFTWARE_KINDS},
        "DYNAMIC_LINK": set(_SOFTWARE_PAIRS),
        "STATIC_LINK": set(_SOFTWARE_PAIRS),
        "EXPANDED_FROM_ARCHIVE": {
            (left, right) for left in _ITEM_KINDS for right in _SOFTWARE_KINDS
        },
        "PATCH_FOR": {("file", kind) for kind in _SOFTWARE_KINDS},
        "PATCH_APPLIED": {("file", kind) for kind in _SOFTWARE_KINDS},
        "COPY_OF": set(_SAME_ITEM_PAIRS),
        "ANCESTOR_OF": set(_SAME_ITEM_PAIRS),
        "DESCENDANT_OF": set(_SAME_ITEM_PAIRS),
        "VARIANT_OF": set(_SAME_ITEM_PAIRS),
        "METAFILE_OF": {("file", kind) for kind in _ITEM_KINDS},
        "DOCUMENTATION_OF": {("file", kind) for kind in _ITEM_KINDS},
        "REQUIREMENT_DESCRIPTION_FOR": {
            ("file", kind) for kind in _ITEM_KINDS
        },
        "SPECIFICATION_FOR": {("file", kind) for kind in _ITEM_KINDS},
        "PACKAGE_OF": {("package", "package")},
    }
)
for _relationship in _DEPENDENCY_RELATIONSHIPS:
    _RELATIONSHIP_KIND_RULES[_relationship] = set(_SOFTWARE_PAIRS)


class ContractError(ValueError):
    """Raised when input does not satisfy the evidence contract."""


class CommittedCleanupError(ContractError):
    """Raised when outputs committed but obsolete transaction artifacts remain."""


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number is not allowed: {value}")


def _parse_int(value: str) -> int:
    if len(value.lstrip("-")) > 100:
        raise ContractError("JSON integer is unreasonably large")
    return int(value)


def _parse_float(value: str) -> float:
    if len(value) > 100:
        raise ContractError("JSON number is unreasonably large")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ContractError("non-finite JSON number is not allowed")
    return parsed


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _check_complexity(value: Any) -> None:
    stack = [(value, 1)]
    count = 0
    while stack:
        current, depth = stack.pop()
        count += 1
        if count > MAX_VALUES:
            raise ContractError("JSON input contains too many values")
        if depth > MAX_DEPTH:
            raise ContractError(f"JSON input exceeds maximum depth {MAX_DEPTH}")
        if isinstance(current, str):
            if len(current) > MAX_STRING_CHARS:
                raise ContractError("JSON string is unreasonably large")
            if any(0xD800 <= ord(character) <= 0xDFFF for character in current):
                raise ContractError("JSON string contains an invalid Unicode surrogate")
        elif isinstance(current, dict):
            if len(current) > MAX_COLLECTION_ITEMS:
                raise ContractError("JSON object is unreasonably large")
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("JSON object keys must be strings")
                if len(key) > MAX_KEY_CHARS:
                    raise ContractError("JSON object key is unreasonably large")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            if len(current) > MAX_COLLECTION_ITEMS:
                raise ContractError("JSON array is unreasonably large")
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise ContractError("non-finite JSON number is not allowed")


def load_json_strict(path: str | os.PathLike[str], max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> Any:
    """Read bounded UTF-8 JSON while rejecting duplicate keys and non-finite numbers."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ContractError("maximum input size must be positive")
    try:
        file_path = Path(path)
    except TypeError as exc:
        raise ContractError(f"invalid input path: {exc}") from exc
    descriptor = -1
    raw = bytearray()
    initial_size = -1
    failure: ContractError | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(file_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"input is not a regular file: {file_path}")
        initial_size = metadata.st_size
        if initial_size > max_bytes:
            raise ContractError(f"input exceeds maximum size of {max_bytes} bytes")
        while len(raw) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise ContractError("input read returned non-byte data")
            raw.extend(chunk)
        if len(raw) > max_bytes:
            raise ContractError(f"input exceeds maximum size of {max_bytes} bytes")
        final_size = os.fstat(descriptor).st_size
        if final_size != initial_size or len(raw) != initial_size:
            raise ContractError(f"input changed size while being read: {file_path}")
    except OSError as exc:
        failure = ContractError(f"cannot read {file_path}: {exc}")
    except ContractError as exc:
        failure = exc
    close_failure = None
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError as exc:
            close_failure = ContractError(f"cannot close {file_path}: {exc}")
    if failure is not None:
        if close_failure is not None:
            raise ContractError(f"{failure}; {close_failure}") from failure
        raise failure
    if close_failure is not None:
        raise close_failure
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError("UTF-8 BOM is not allowed")
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractError(f"input is not strict UTF-8: {exc}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ContractError(f"invalid JSON: {exc}") from exc
    _check_complexity(value)
    return value


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ContractError(f"value cannot be encoded as canonical JSON: {exc}") from exc


def _fsync_directory(directory: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        os.fsync(descriptor)
    except OSError as exc:
        raise ContractError(f"cannot fsync directory {directory}: {exc}") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise ContractError(f"cannot close directory {directory}: {exc}") from exc


def _ensure_directory(directory: Path) -> None:
    missing = []
    current = directory
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    if current.exists() and not current.is_dir():
        raise ContractError(f"output parent is not a directory: {current}")
    for path in reversed(missing):
        try:
            path.mkdir()
        except FileExistsError:
            if not path.is_dir():
                raise ContractError(f"output parent is not a directory: {path}")
        except OSError as exc:
            raise ContractError(f"cannot create output directory {path}: {exc}") from exc
        _fsync_directory(path.parent)


def _cleanup_paths(paths: Iterable[str]) -> list[str]:
    errors = []
    for path in paths:
        if not path:
            continue
        try:
            os.unlink(path)
            _fsync_directory(Path(path).parent)
        except FileNotFoundError:
            continue
        except (OSError, ContractError) as exc:
            errors.append(f"{path}: {exc}")
    return errors


def _hash_regular_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"transaction file is not regular: {path}")
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as exc:
        raise ContractError(f"cannot hash transaction file {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise ContractError(f"cannot close transaction file {path}: {exc}") from exc
    return digest.hexdigest()


def _fsync_regular_file(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(f"transaction file is not regular: {path}")
        os.fsync(descriptor)
    except OSError as exc:
        raise ContractError(f"cannot fsync transaction file {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise ContractError(f"cannot close transaction file {path}: {exc}") from exc


def _copy_backup(source: Path, destination: Path, mode: int) -> None:
    source_fd = -1
    destination_fd = -1
    try:
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            stat.S_IMODE(mode),
        )
        while True:
            chunk = os.read(source_fd, 64 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("short backup write")
                view = view[written:]
        os.fsync(destination_fd)
    except OSError as exc:
        _cleanup_paths([str(destination)])
        raise ContractError(f"cannot copy backup for {source}: {exc}") from exc
    finally:
        close_errors = []
        for descriptor in (source_fd, destination_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    close_errors.append(str(exc))
        if close_errors:
            raise ContractError(
                f"cannot close backup files for {source}: {'; '.join(close_errors)}"
            )


def _write_transaction_marker(marker: Path, value: dict[str, Any]) -> None:
    data = canonical_json_bytes(value)
    descriptor = -1
    staged = ""
    try:
        descriptor, staged = tempfile.mkstemp(
            prefix=f".{marker.name}.",
            suffix=".stage",
            dir=marker.parent,
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            written = stream.write(data)
            if written != len(data):
                raise OSError("short marker write")
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(marker.parent)
        os.replace(staged, marker)
        staged = ""
        _fsync_directory(marker.parent)
    except (OSError, ContractError) as exc:
        cleanup_errors = _cleanup_paths([staged])
        suffix = f"; cleanup errors: {'; '.join(cleanup_errors)}" if cleanup_errors else ""
        raise ContractError(f"cannot write transaction marker {marker}: {exc}{suffix}") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise ContractError(f"cannot close transaction marker {marker}: {exc}") from exc


def _marker_path(destinations: list[Path]) -> Path:
    identity = hashlib.sha256(
        canonical_json_bytes([str(path) for path in destinations])
    ).hexdigest()
    return destinations[0].parent / f".missionsready-sbom-transaction-{identity}.json"


def _committed_marker_path(prepared_marker: Path) -> Path:
    return prepared_marker.with_name(
        prepared_marker.name.removesuffix(".json") + ".committed.json"
    )


def _validate_recovery_path(path_value: Any, destination: Path, kind: str) -> Path:
    path = Path(_expect_string(path_value, f"transaction marker {kind}"))
    if path.parent != destination.parent:
        raise ContractError(f"transaction marker {kind} is outside the output directory")
    if kind == "stage" and not (
        path.name.startswith(f".{destination.name}.") and path.name.endswith(".stage")
    ):
        raise ContractError("transaction marker has an invalid stage path")
    if kind == "backup" and not (
        path.name.startswith(f".{destination.name}.") and path.name.endswith(".backup")
    ):
        raise ContractError("transaction marker has an invalid backup path")
    return path


def recover_output_transaction(
    output_paths: Iterable[str | os.PathLike[str]],
) -> None:
    """Recover the deterministic transaction associated with the output path set."""
    try:
        destinations = [Path(path).resolve() for path in output_paths]
    except (OSError, RuntimeError, TypeError) as exc:
        raise ContractError(f"cannot resolve recovery paths: {exc}") from exc
    if not destinations:
        raise ContractError("at least one recovery output path is required")
    prepared_marker = _marker_path(destinations)
    committed_marker = _committed_marker_path(prepared_marker)
    try:
        committed_exists = committed_marker.exists()
        prepared_exists = prepared_marker.exists()
    except OSError as exc:
        raise ContractError(
            f"cannot inspect transaction markers for {prepared_marker}: {exc}"
        ) from exc
    if not committed_exists and not prepared_exists:
        return
    marker = committed_marker if committed_exists else prepared_marker
    value = load_json_strict(marker)
    marker_value = _expect_object(value, "transaction marker")
    _exact_keys(marker_value, {"version", "state", "records"}, "transaction marker")
    expected_state = "committed" if committed_exists else "prepared"
    if marker_value["version"] != 1 or marker_value["state"] != expected_state:
        raise ContractError("transaction marker has an unsupported version or state")
    records = _expect_array(marker_value["records"], "transaction marker.records")
    if len(records) != len(destinations):
        raise ContractError("transaction marker output count does not match recovery request")

    parsed = []
    for index, (record_value, expected_destination) in enumerate(zip(records, destinations)):
        record_path = f"transaction marker.records[{index}]"
        record = _expect_object(record_value, record_path)
        fields = {
            "backup",
            "destination",
            "hadOriginal",
            "newSha256",
            "oldSha256",
            "stage",
        }
        _exact_keys(record, fields, record_path)
        destination = Path(_expect_string(record["destination"], f"{record_path}.destination"))
        if destination != expected_destination:
            raise ContractError("transaction marker destinations do not match recovery request")
        had_original = _expect_bool(record["hadOriginal"], f"{record_path}.hadOriginal")
        new_digest = _expect_string(record["newSha256"], f"{record_path}.newSha256")
        old_digest = record["oldSha256"]
        if had_original:
            old_digest = _expect_string(old_digest, f"{record_path}.oldSha256")
        elif old_digest is not None:
            raise ContractError(f"{record_path}.oldSha256 must be null for a new output")
        if not re.fullmatch(r"[0-9a-f]{64}", new_digest) or (
            old_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", old_digest)
        ):
            raise ContractError(f"{record_path} contains an invalid digest")
        stage = _validate_recovery_path(record["stage"], destination, "stage")
        backup = (
            _validate_recovery_path(record["backup"], destination, "backup")
            if had_original
            else None
        )
        parsed.append((destination, stage, backup, new_digest, old_digest))

    state = marker_value["state"]
    for destination, _, backup, new_digest, old_digest in parsed:
        if state == "prepared":
            if backup is not None:
                destination_is_old = (
                    destination.exists()
                    and _hash_regular_file(destination) == old_digest
                )
                if not destination_is_old:
                    if not backup.exists() or _hash_regular_file(backup) != old_digest:
                        raise ContractError(
                            f"neither destination nor backup represents the old state: {destination}"
                        )
                    try:
                        os.replace(backup, destination)
                        _fsync_directory(destination.parent)
                    except OSError as exc:
                        raise ContractError(f"cannot restore transaction backup {destination}: {exc}") from exc
                    except ContractError:
                        raise
            elif destination.exists():
                if _hash_regular_file(destination) != new_digest:
                    raise ContractError(f"unexpected file blocks transaction recovery: {destination}")
                try:
                    os.unlink(destination)
                    _fsync_directory(destination.parent)
                except OSError as exc:
                    raise ContractError(f"cannot remove interrupted output {destination}: {exc}") from exc
                except ContractError:
                    raise
        else:
            if not destination.exists() or _hash_regular_file(destination) != new_digest:
                raise ContractError(f"committed transaction output is missing or changed: {destination}")

    cleanup_errors = _cleanup_paths(
        [str(stage) for _, stage, _, _, _ in parsed]
        + [str(backup) for _, _, backup, _, _ in parsed if backup is not None]
    )
    if cleanup_errors:
        error_type = CommittedCleanupError if state == "committed" else ContractError
        raise error_type("transaction recovery cleanup failed: " + "; ".join(cleanup_errors))
    markers_to_remove = (
        [str(prepared_marker), str(committed_marker)]
        if state == "committed"
        else [str(prepared_marker)]
    )
    marker_errors = _cleanup_paths(markers_to_remove)
    if marker_errors:
        error_type = CommittedCleanupError if state == "committed" else ContractError
        raise error_type("transaction marker cleanup failed: " + "; ".join(marker_errors))


def atomic_write_jsons(outputs: Iterable[tuple[str | os.PathLike[str], Any]]) -> None:
    """Commit fsynced JSON outputs without removing an existing destination."""
    try:
        prepared = [(Path(path), canonical_json_bytes(value)) for path, value in outputs]
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError(f"invalid output transaction: {exc}") from exc
    if not prepared:
        raise ContractError("at least one output is required")
    try:
        resolved = [path.resolve() for path, _ in prepared]
    except (OSError, RuntimeError) as exc:
        raise ContractError(f"cannot resolve output path: {exc}") from exc
    if len(set(resolved)) != len(resolved):
        raise ContractError("transaction output paths must be distinct")
    marker = _marker_path(resolved)
    committed_marker = _committed_marker_path(marker)
    recover_output_transaction(resolved)

    records: list[dict[str, Any]] = []
    marker_written = False
    committed_durable = False
    try:
        for destination, data in prepared:
            descriptor = -1
            staged = ""
            try:
                _ensure_directory(destination.parent)
                try:
                    destination_metadata = destination.lstat()
                except FileNotFoundError:
                    destination_metadata = None
                if destination_metadata is not None and not stat.S_ISREG(
                    destination_metadata.st_mode
                ):
                    raise ContractError(f"existing output is not a regular file: {destination}")
                descriptor, staged = tempfile.mkstemp(
                    prefix=f".{destination.name}.",
                    suffix=".stage",
                    dir=destination.parent,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = -1
                    written = stream.write(data)
                    if written != len(data):
                        raise ContractError(
                            f"short write while staging output {destination}"
                        )
                    stream.flush()
                    os.fsync(stream.fileno())
                _fsync_directory(destination.parent)
            except ContractError:
                raise
            except OSError as exc:
                raise ContractError(f"cannot stage output {destination}: {exc}") from exc
            finally:
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError as exc:
                        raise ContractError(
                            f"cannot close staged output {destination}: {exc}"
                        ) from exc
            if not staged:
                raise ContractError(f"cannot stage output {destination}")
            records.append(
                {
                    "destination": destination,
                    "stage": staged,
                    "backup": "",
                    "had_original": destination_metadata is not None,
                    "original_identity": (
                        (destination_metadata.st_dev, destination_metadata.st_ino)
                        if destination_metadata is not None
                        else None
                    ),
                    "installed": False,
                    "new_sha256": hashlib.sha256(data).hexdigest(),
                    "old_sha256": None,
                }
            )

        for record in records:
            if record["had_original"]:
                destination = record["destination"]
                backup = ""
                backup_fd = -1
                try:
                    backup_fd, backup = tempfile.mkstemp(
                        prefix=f".{destination.name}.",
                        suffix=".backup",
                        dir=destination.parent,
                    )
                    record["backup"] = backup
                    os.close(backup_fd)
                    backup_fd = -1
                    _fsync_directory(destination.parent)
                    os.unlink(backup)
                    _fsync_directory(destination.parent)
                    try:
                        os.link(destination, backup)
                    except OSError:
                        _copy_backup(
                            destination,
                            Path(backup),
                            destination.lstat().st_mode,
                        )
                    _fsync_regular_file(Path(backup))
                    _fsync_directory(destination.parent)
                    record["old_sha256"] = _hash_regular_file(Path(backup))
                except (OSError, ContractError) as exc:
                    raise ContractError(f"cannot prepare backup for {destination}: {exc}") from exc
                finally:
                    if backup_fd >= 0:
                        try:
                            os.close(backup_fd)
                        except OSError as exc:
                            raise ContractError(
                                f"cannot close backup placeholder for {destination}: {exc}"
                            ) from exc

        for record in records:
            destination = record["destination"]
            try:
                metadata = destination.lstat()
            except FileNotFoundError:
                metadata = None
            except OSError as exc:
                raise ContractError(f"cannot recheck output {destination}: {exc}") from exc
            identity = (metadata.st_dev, metadata.st_ino) if metadata is not None else None
            if identity != record["original_identity"]:
                raise ContractError(f"output changed while transaction was staged: {destination}")

        marker_value = {
            "version": 1,
            "state": "prepared",
            "records": [
                {
                    "destination": str(record["destination"].resolve()),
                    "stage": str(Path(record["stage"]).resolve()),
                    "backup": (
                        str(Path(record["backup"]).resolve())
                        if record["had_original"]
                        else ""
                    ),
                    "hadOriginal": record["had_original"],
                    "newSha256": record["new_sha256"],
                    "oldSha256": record["old_sha256"],
                }
                for record in records
            ],
        }
        marker_written = True
        _write_transaction_marker(marker, marker_value)

        try:
            for record in records:
                destination = record["destination"]
                os.replace(record["stage"], destination)
                record["stage"] = ""
                record["installed"] = True
                _fsync_directory(destination.parent)
            committed_value = {**marker_value, "state": "committed"}
            _write_transaction_marker(committed_marker, committed_value)
            committed_durable = True
        except (OSError, ContractError) as exc:
            rollback_errors = []
            committed_marker_errors = _cleanup_paths([str(committed_marker)])
            for record in reversed(records):
                destination = record["destination"]
                try:
                    if record["installed"] and record["had_original"]:
                        os.replace(record["backup"], destination)
                        record["backup"] = ""
                        _fsync_directory(destination.parent)
                    elif record["installed"]:
                        os.unlink(destination)
                        _fsync_directory(destination.parent)
                except (OSError, ContractError) as rollback_exc:
                    rollback_errors.append(f"{destination}: {rollback_exc}")
            if committed_marker_errors or rollback_errors:
                details = committed_marker_errors + rollback_errors
                raise ContractError(
                    f"output transaction failed; rollback durability incomplete: {exc}; "
                    f"recovery marker retained; errors: {'; '.join(details)}"
                ) from exc
            cleanup_errors = _cleanup_paths(
                [record["stage"] for record in records]
                + [record["backup"] for record in records]
                + ([str(marker)] if marker_written else [])
            )
            if cleanup_errors:
                raise ContractError(
                    f"output transaction failed and prior outputs were restored: {exc}; "
                    f"transaction cleanup errors: {'; '.join(cleanup_errors)}"
                ) from exc
            raise ContractError(f"output transaction failed and was rolled back: {exc}") from exc

        backup_errors = _cleanup_paths(
            [record["backup"] for record in records]
            + [record["stage"] for record in records]
        )
        if backup_errors:
            raise CommittedCleanupError(
                "outputs committed, but backup cleanup failed: " + "; ".join(backup_errors)
            )
        marker_errors = _cleanup_paths([str(marker)])
        if marker_errors:
            raise CommittedCleanupError(
                "outputs committed, but prepared marker cleanup failed: "
                + "; ".join(marker_errors)
            )
        committed_marker_errors = _cleanup_paths([str(committed_marker)])
        if committed_marker_errors:
            raise CommittedCleanupError(
                "outputs committed, but committed marker cleanup failed: "
                + "; ".join(committed_marker_errors)
            )
    except ContractError as exc:
        if not any(record.get("installed") for record in records):
            cleanup_errors = _cleanup_paths(
                [record.get("stage", "") for record in records]
                + [record.get("backup", "") for record in records]
                + ([str(marker)] if marker_written else [])
                + ([str(committed_marker)] if not committed_durable else [])
            )
            if "staged" in locals() and staged:
                cleanup_errors.extend(_cleanup_paths([staged]))
            if cleanup_errors:
                raise ContractError(
                    f"{exc}; transaction cleanup errors: {'; '.join(cleanup_errors)}"
                ) from exc
        raise


def atomic_write_json(path: str | os.PathLike[str], value: Any) -> None:
    atomic_write_jsons([(path, value)])


def _expect_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{path} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ContractError(f"{path} keys must be strings")
    return value


def _expect_array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{path} must be an array")
    return value


def _expect_string(value: Any, path: str, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise ContractError(f"{path} must be a{' non-empty' if nonempty else ''} string")
    return value


def _expect_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{path} must be a boolean")
    return value


def _expect_int(value: Any, path: str, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{path} must be an integer")
    if minimum is not None and value < minimum:
        raise ContractError(f"{path} must be at least {minimum}")
    return value


def _require_keys(value: dict[str, Any], keys: Iterable[str], path: str) -> None:
    missing = sorted(set(keys) - value.keys())
    if missing:
        raise ContractError(f"{path} is missing required fields: {', '.join(missing)}")


def _exact_keys(value: dict[str, Any], keys: Iterable[str], path: str) -> None:
    required = set(keys)
    _require_keys(value, required, path)
    unknown = sorted(value.keys() - required)
    if unknown:
        raise ContractError(f"{path} contains unknown fields: {', '.join(unknown)}")


def _allowed_keys(
    value: dict[str, Any], required: Iterable[str], allowed: Iterable[str], path: str
) -> None:
    _require_keys(value, required, path)
    unknown = sorted(value.keys() - set(allowed))
    if unknown:
        raise ContractError(f"{path} contains unknown fields: {', '.join(unknown)}")


def _validate_string_array(value: Any, path: str, nonempty: bool = False) -> list[str]:
    items = _expect_array(value, path)
    if nonempty and not items:
        raise ContractError(f"{path} must not be empty")
    seen: set[str] = set()
    for index, item in enumerate(items):
        text = _expect_string(item, f"{path}[{index}]")
        if text in seen:
            raise ContractError(f"{path} contains a duplicate value")
        seen.add(text)
    return items


def _optional_strings(value: dict[str, Any], fields: Iterable[str], path: str) -> None:
    for field in fields:
        if field in value:
            _expect_string(value[field], f"{path}.{field}", nonempty=False)


def _validate_annotations(value: Any, path: str) -> None:
    annotations = _expect_array(value, path)
    for index, annotation in enumerate(annotations):
        item_path = f"{path}[{index}]"
        item = _expect_object(annotation, item_path)
        fields = {"annotationDate", "annotationType", "annotator", "comment"}
        _exact_keys(item, fields, item_path)
        _expect_string(item["annotationDate"], f"{item_path}.annotationDate")
        annotation_type = _expect_string(item["annotationType"], f"{item_path}.annotationType")
        if annotation_type not in {"OTHER", "REVIEW"}:
            raise ContractError(f"{item_path}.annotationType is not an SPDX 2.3 value")
        _expect_string(item["annotator"], f"{item_path}.annotator")
        _expect_string(item["comment"], f"{item_path}.comment", nonempty=False)


def _validate_element_common(item: dict[str, Any], path: str) -> None:
    if "annotations" in item:
        _validate_annotations(item["annotations"], f"{path}.annotations")
    if "attributionTexts" in item:
        _validate_string_array(item["attributionTexts"], f"{path}.attributionTexts")
    _optional_strings(item, {"comment"}, path)


def validate_binding(
    subject_name: str,
    subject_digest: str,
    platform: str,
    syft_version: str,
    source: Any,
) -> dict[str, str]:
    subject_name = _expect_string(subject_name, "subject name")
    subject_digest = _expect_string(subject_digest, "subject digest")
    platform = _expect_string(platform, "platform")
    syft_version = _expect_string(syft_version, "Syft version")
    if not _SUBJECT_RE.fullmatch(subject_name):
        raise ContractError("subject name must be a lowercase OCI repository without tag or digest")
    if not _DIGEST_RE.fullmatch(subject_digest):
        raise ContractError("subject digest must be lowercase sha256:<64 hex>")
    if not _PLATFORM_RE.fullmatch(platform):
        raise ContractError("platform must be linux/amd64 or linux/arm64")
    if not _VERSION_RE.fullmatch(syft_version):
        raise ContractError("Syft version must be an exact semantic version")
    source_object = _expect_object(source, "source metadata")
    fields = {"type", "name", "reference", "digest", "platform"}
    _exact_keys(source_object, fields, "source metadata")
    expected = {
        "type": "oci-image",
        "name": subject_name,
        "reference": f"{subject_name}@{subject_digest}",
        "digest": subject_digest,
        "platform": platform,
    }
    if source_object != expected:
        raise ContractError("source metadata does not exactly bind the requested OCI subject")
    return expected


def _validate_checksum(checksum: Any, path: str) -> None:
    item = _expect_object(checksum, path)
    _exact_keys(item, {"algorithm", "checksumValue"}, path)
    algorithm = _expect_string(item["algorithm"], f"{path}.algorithm")
    value = _expect_string(item["checksumValue"], f"{path}.checksumValue")
    if algorithm not in _CHECKSUM_LENGTHS:
        raise ContractError(f"{path}.algorithm is not an accepted SPDX 2.3 checksum algorithm")
    if not _HEX_RE.fullmatch(value) or value != value.lower():
        raise ContractError(f"{path}.checksumValue must be lowercase hexadecimal")
    expected_length = _CHECKSUM_LENGTHS[algorithm]
    if expected_length is not None and len(value) != expected_length:
        raise ContractError(f"{path}.checksumValue has the wrong length for {algorithm}")


def _validate_checksums(value: Any, path: str, required: bool) -> None:
    checksums = _expect_array(value, path)
    if required and not checksums:
        raise ContractError(f"{path} must contain at least one checksum")
    seen: set[tuple[str, str]] = set()
    for index, checksum in enumerate(checksums):
        _validate_checksum(checksum, f"{path}[{index}]")
        key = (checksum["algorithm"], checksum["checksumValue"].lower())
        if key in seen:
            raise ContractError(f"{path} contains a duplicate checksum")
        seen.add(key)


def _record_spdx_id(item: Any, path: str, ids: set[str]) -> str:
    obj = _expect_object(item, path)
    identifier = _expect_string(obj.get("SPDXID"), f"{path}.SPDXID")
    if not _SPDX_ID_RE.fullmatch(identifier):
        raise ContractError(f"{path}.SPDXID is not a valid local SPDX identifier")
    if identifier in ids:
        raise ContractError(f"duplicate SPDX identifier: {identifier}")
    ids.add(identifier)
    return identifier


def _validate_namespace(value: Any) -> str:
    namespace = _expect_string(value, "documentNamespace")
    parts = urlsplit(namespace)
    if parts.scheme != "https" or not parts.netloc or parts.fragment or any(ch.isspace() for ch in namespace):
        raise ContractError("documentNamespace must be an absolute fragment-free HTTPS URI")
    return namespace


def _validate_creation_info(value: Any, path: str, syft_version: str) -> None:
    creation = _expect_object(value, path)
    fields = {"comment", "created", "creators", "licenseListVersion"}
    _allowed_keys(creation, {"created", "creators"}, fields, path)
    _expect_string(creation["created"], f"{path}.created")
    creators = _validate_string_array(creation["creators"], f"{path}.creators", nonempty=True)
    _optional_strings(creation, {"comment", "licenseListVersion"}, path)
    expected_creator = f"Tool: syft-{syft_version}"
    syft_creators = [creator for creator in creators if creator.lower().startswith("tool: syft-")]
    if syft_creators != [expected_creator]:
        raise ContractError(f"{path}.creators must identify exactly {expected_creator}")
    for creator in creators:
        if creator.startswith("Tool:") and creator != expected_creator:
            raise ContractError(f"{path} contains an unexpected creator tool")


def _validate_external_ref(value: Any, path: str) -> None:
    item = _expect_object(value, path)
    fields = {"comment", "referenceCategory", "referenceLocator", "referenceType"}
    _allowed_keys(
        item,
        {"referenceCategory", "referenceLocator", "referenceType"},
        fields,
        path,
    )
    category = _expect_string(item["referenceCategory"], f"{path}.referenceCategory")
    if category not in {"OTHER", "PERSISTENT-ID", "SECURITY", "PACKAGE-MANAGER"}:
        raise ContractError(f"{path}.referenceCategory is not an SPDX 2.3 value")
    _expect_string(item["referenceLocator"], f"{path}.referenceLocator")
    _expect_string(item["referenceType"], f"{path}.referenceType")
    _optional_strings(item, {"comment"}, path)


def _validate_package_verification_code(value: Any, path: str) -> None:
    item = _expect_object(value, path)
    fields = {"packageVerificationCodeExcludedFiles", "packageVerificationCodeValue"}
    _allowed_keys(item, {"packageVerificationCodeValue"}, fields, path)
    code = _expect_string(item["packageVerificationCodeValue"], f"{path}.packageVerificationCodeValue")
    if len(code) != 40 or not _HEX_RE.fullmatch(code) or code != code.lower():
        raise ContractError(f"{path}.packageVerificationCodeValue must be 40 lowercase hex characters")
    if "packageVerificationCodeExcludedFiles" in item:
        _validate_string_array(
            item["packageVerificationCodeExcludedFiles"],
            f"{path}.packageVerificationCodeExcludedFiles",
        )


def _validate_package(value: Any, path: str, ids: set[str]) -> None:
    item = _expect_object(value, path)
    fields = {
        "SPDXID",
        "annotations",
        "attributionTexts",
        "builtDate",
        "checksums",
        "comment",
        "copyrightText",
        "description",
        "downloadLocation",
        "externalRefs",
        "filesAnalyzed",
        "hasFiles",
        "homepage",
        "licenseComments",
        "licenseConcluded",
        "licenseDeclared",
        "licenseInfoFromFiles",
        "name",
        "originator",
        "packageFileName",
        "packageVerificationCode",
        "primaryPackagePurpose",
        "releaseDate",
        "sourceInfo",
        "summary",
        "supplier",
        "validUntilDate",
        "versionInfo",
    }
    _allowed_keys(item, {"SPDXID", "checksums", "downloadLocation", "name"}, fields, path)
    _record_spdx_id(item, path, ids)
    _expect_string(item["name"], f"{path}.name")
    _expect_string(item["downloadLocation"], f"{path}.downloadLocation")
    _validate_checksums(item["checksums"], f"{path}.checksums", required=True)
    _validate_element_common(item, path)
    _optional_strings(
        item,
        {
            "builtDate",
            "copyrightText",
            "description",
            "homepage",
            "licenseComments",
            "licenseConcluded",
            "licenseDeclared",
            "originator",
            "packageFileName",
            "releaseDate",
            "sourceInfo",
            "summary",
            "supplier",
            "validUntilDate",
            "versionInfo",
        },
        path,
    )
    if "filesAnalyzed" in item:
        _expect_bool(item["filesAnalyzed"], f"{path}.filesAnalyzed")
    for field in ("hasFiles", "licenseInfoFromFiles"):
        if field in item:
            _validate_string_array(item[field], f"{path}.{field}")
    if "externalRefs" in item:
        refs = _expect_array(item["externalRefs"], f"{path}.externalRefs")
        for index, reference in enumerate(refs):
            _validate_external_ref(reference, f"{path}.externalRefs[{index}]")
    if "packageVerificationCode" in item:
        _validate_package_verification_code(
            item["packageVerificationCode"], f"{path}.packageVerificationCode"
        )
    if "primaryPackagePurpose" in item:
        purpose = _expect_string(item["primaryPackagePurpose"], f"{path}.primaryPackagePurpose")
        if purpose not in _PACKAGE_PURPOSES:
            raise ContractError(f"{path}.primaryPackagePurpose is not an SPDX 2.3 value")


def _validate_artifact_of(value: Any, path: str) -> None:
    item = _expect_object(value, path)
    fields = {"homepage", "name", "projectUri"}
    _allowed_keys(item, set(), fields, path)
    if not item:
        raise ContractError(f"{path} must not be empty")
    _optional_strings(item, fields, path)


def _validate_file(value: Any, path: str, ids: set[str]) -> None:
    item = _expect_object(value, path)
    fields = {
        "SPDXID",
        "annotations",
        "artifactOfs",
        "attributionTexts",
        "checksums",
        "comment",
        "copyrightText",
        "fileContributors",
        "fileDependencies",
        "fileName",
        "fileTypes",
        "licenseComments",
        "licenseConcluded",
        "licenseInfoInFiles",
        "noticeText",
    }
    _allowed_keys(item, {"SPDXID", "checksums", "fileName"}, fields, path)
    _record_spdx_id(item, path, ids)
    _expect_string(item["fileName"], f"{path}.fileName")
    _validate_checksums(item["checksums"], f"{path}.checksums", required=True)
    _validate_element_common(item, path)
    _optional_strings(
        item,
        {"copyrightText", "licenseComments", "licenseConcluded", "noticeText"},
        path,
    )
    for field in ("fileContributors", "fileDependencies", "licenseInfoInFiles"):
        if field in item:
            _validate_string_array(item[field], f"{path}.{field}")
    if "fileTypes" in item:
        for index, file_type in enumerate(_validate_string_array(item["fileTypes"], f"{path}.fileTypes")):
            if file_type not in _FILE_TYPES:
                raise ContractError(f"{path}.fileTypes[{index}] is not an SPDX 2.3 value")
    if "artifactOfs" in item:
        artifacts = _expect_array(item["artifactOfs"], f"{path}.artifactOfs")
        for index, artifact in enumerate(artifacts):
            _validate_artifact_of(artifact, f"{path}.artifactOfs[{index}]")


def _validate_pointer(value: Any, path: str) -> tuple[str, str, int]:
    item = _expect_object(value, path)
    fields = {"lineNumber", "offset", "reference"}
    _allowed_keys(item, {"reference"}, fields, path)
    reference = _expect_string(item["reference"], f"{path}.reference")
    locations = [field for field in ("lineNumber", "offset") if field in item]
    if len(locations) != 1:
        raise ContractError(f"{path} must contain exactly one of lineNumber or offset")
    position = _expect_int(item[locations[0]], f"{path}.{locations[0]}", minimum=1)
    return reference, locations[0], position


def _validate_snippet(value: Any, path: str, ids: set[str]) -> None:
    item = _expect_object(value, path)
    fields = {
        "SPDXID",
        "annotations",
        "attributionTexts",
        "comment",
        "copyrightText",
        "licenseComments",
        "licenseConcluded",
        "licenseInfoInSnippets",
        "name",
        "ranges",
        "snippetFromFile",
    }
    _allowed_keys(item, {"SPDXID", "name", "ranges", "snippetFromFile"}, fields, path)
    _record_spdx_id(item, path, ids)
    _expect_string(item["name"], f"{path}.name")
    _expect_string(item["snippetFromFile"], f"{path}.snippetFromFile")
    _validate_element_common(item, path)
    _optional_strings(item, {"copyrightText", "licenseComments", "licenseConcluded"}, path)
    if "licenseInfoInSnippets" in item:
        _validate_string_array(item["licenseInfoInSnippets"], f"{path}.licenseInfoInSnippets")
    ranges = _expect_array(item["ranges"], f"{path}.ranges")
    if not ranges:
        raise ContractError(f"{path}.ranges must not be empty")
    pointer_types: set[str] = set()
    for index, range_value in enumerate(ranges):
        range_path = f"{path}.ranges[{index}]"
        range_item = _expect_object(range_value, range_path)
        _exact_keys(range_item, {"startPointer", "endPointer"}, range_path)
        start = _validate_pointer(
            range_item["startPointer"], f"{range_path}.startPointer"
        )
        end = _validate_pointer(range_item["endPointer"], f"{range_path}.endPointer")
        if start[0] != end[0] or start[1] != end[1]:
            raise ContractError(
                f"{range_path} start/end pointers must use the same reference and pointer type"
            )
        if start[2] > end[2]:
            raise ContractError(f"{range_path} start pointer must not exceed end pointer")
        if start[1] in pointer_types:
            raise ContractError(f"{path}.ranges contains a duplicate {start[1]} range")
        pointer_types.add(start[1])
    if "offset" not in pointer_types:
        raise ContractError(f"{path}.ranges must contain one byte offset range")


def _validate_cross_ref(value: Any, path: str) -> None:
    item = _expect_object(value, path)
    fields = {"isLive", "isValid", "isWayBackLink", "match", "order", "timestamp", "url"}
    _allowed_keys(item, {"url"}, fields, path)
    _expect_string(item["url"], f"{path}.url")
    for field in ("isLive", "isValid", "isWayBackLink"):
        if field in item:
            _expect_bool(item[field], f"{path}.{field}")
    if "order" in item:
        _expect_int(item["order"], f"{path}.order", minimum=0)
    _optional_strings(item, {"match", "timestamp"}, path)


def _validate_extracted_license(value: Any, path: str) -> None:
    item = _expect_object(value, path)
    fields = {"comment", "crossRefs", "extractedText", "licenseId", "name", "seeAlsos"}
    _allowed_keys(item, {"extractedText", "licenseId"}, fields, path)
    _expect_string(item["extractedText"], f"{path}.extractedText", nonempty=False)
    _expect_string(item["licenseId"], f"{path}.licenseId")
    _optional_strings(item, {"comment", "name"}, path)
    if "seeAlsos" in item:
        _validate_string_array(item["seeAlsos"], f"{path}.seeAlsos")
    if "crossRefs" in item:
        refs = _expect_array(item["crossRefs"], f"{path}.crossRefs")
        for index, reference in enumerate(refs):
            _validate_cross_ref(reference, f"{path}.crossRefs[{index}]")


def _validate_reviews(value: Any, path: str) -> None:
    reviews = _expect_array(value, path)
    for index, review in enumerate(reviews):
        item_path = f"{path}[{index}]"
        item = _expect_object(review, item_path)
        fields = {"comment", "reviewDate", "reviewer"}
        _allowed_keys(item, {"reviewDate"}, fields, item_path)
        _expect_string(item["reviewDate"], f"{item_path}.reviewDate")
        _optional_strings(item, {"comment", "reviewer"}, item_path)


def _validate_relationship_kinds(
    relation: str, left_kind: str, right_kind: str, path: str
) -> None:
    allowed = _RELATIONSHIP_KIND_RULES.get(relation)
    if allowed is None or (left_kind, right_kind) not in allowed:
        raise ContractError(
            f"{path} has invalid source/target kinds for {relation}: "
            f"{left_kind}->{right_kind}"
        )


def _validate_syft_document(
    document: Any,
    subject_name: str,
    subject_digest: str,
    platform: str,
    syft_version: str,
    source: dict[str, str],
) -> None:
    root = _expect_object(document, "SPDX document")
    unknown = sorted(root.keys() - _TOP_LEVEL_FIELDS)
    if unknown:
        raise ContractError(f"SPDX document contains unsafe unknown top-level fields: {', '.join(unknown)}")
    _require_keys(
        root,
        {
            "SPDXID",
            "creationInfo",
            "dataLicense",
            "documentNamespace",
            "name",
            "packages",
            "relationships",
            "spdxVersion",
        },
        "SPDX document",
    )
    if root["spdxVersion"] != "SPDX-2.3":
        raise ContractError("spdxVersion must be SPDX-2.3")
    if root["dataLicense"] != "CC0-1.0":
        raise ContractError("dataLicense must be CC0-1.0")
    if root["SPDXID"] != "SPDXRef-DOCUMENT":
        raise ContractError("document SPDXID must be SPDXRef-DOCUMENT")
    if root["name"] != source["reference"]:
        raise ContractError("SPDX document name does not exactly match the bound OCI reference")
    _validate_namespace(root["documentNamespace"])

    _validate_creation_info(root["creationInfo"], "creationInfo", syft_version)
    _optional_strings(root, {"comment"}, "SPDX document")
    if "annotations" in root:
        _validate_annotations(root["annotations"], "annotations")
    if "revieweds" in root:
        _validate_reviews(root["revieweds"], "revieweds")

    ids = {"SPDXRef-DOCUMENT"}
    kinds = {"SPDXRef-DOCUMENT": "document"}
    packages = _expect_array(root["packages"], "packages")
    for index, package in enumerate(packages):
        _validate_package(package, f"packages[{index}]", ids)
        kinds[package["SPDXID"]] = "package"

    files = _expect_array(root.get("files", []), "files")
    for index, file_value in enumerate(files):
        _validate_file(file_value, f"files[{index}]", ids)
        kinds[file_value["SPDXID"]] = "file"

    snippets = _expect_array(root.get("snippets", []), "snippets")
    for index, snippet in enumerate(snippets):
        _validate_snippet(snippet, f"snippets[{index}]", ids)
        kinds[snippet["SPDXID"]] = "snippet"

    external_ids: set[str] = set()
    for index, external in enumerate(
        _expect_array(root.get("externalDocumentRefs", []), "externalDocumentRefs")
    ):
        obj = _expect_object(external, f"externalDocumentRefs[{index}]")
        _exact_keys(obj, {"checksum", "externalDocumentId", "spdxDocument"}, f"externalDocumentRefs[{index}]")
        external_id = _expect_string(
            obj.get("externalDocumentId"), f"externalDocumentRefs[{index}].externalDocumentId"
        )
        if not re.fullmatch(r"DocumentRef-[A-Za-z0-9.+-]+", external_id):
            raise ContractError(
                f"externalDocumentRefs[{index}].externalDocumentId is not valid"
            )
        if external_id in external_ids:
            raise ContractError(f"duplicate external document identifier: {external_id}")
        external_ids.add(external_id)
        _expect_string(obj["spdxDocument"], f"externalDocumentRefs[{index}].spdxDocument")
        _validate_checksum(obj["checksum"], f"externalDocumentRefs[{index}].checksum")

    extracted = _expect_array(
        root.get("hasExtractedLicensingInfos", []), "hasExtractedLicensingInfos"
    )
    license_ids: set[str] = set()
    for index, license_value in enumerate(extracted):
        _validate_extracted_license(
            license_value, f"hasExtractedLicensingInfos[{index}]"
        )
        license_id = license_value["licenseId"]
        if license_id in license_ids:
            raise ContractError(f"duplicate extracted license identifier: {license_id}")
        license_ids.add(license_id)

    for index, described in enumerate(
        _expect_array(root.get("documentDescribes", []), "documentDescribes")
    ):
        identifier = _expect_string(described, f"documentDescribes[{index}]")
        if identifier not in kinds or kinds[identifier] == "document":
            raise ContractError(
                f"documentDescribes references an unknown or invalid SPDX element: {identifier}"
            )

    relationship_keys: set[tuple[str, str, str, str]] = set()
    for index, relationship in enumerate(_expect_array(root["relationships"], "relationships")):
        obj = _expect_object(relationship, f"relationships[{index}]")
        relationship_path = f"relationships[{index}]"
        _allowed_keys(
            obj,
            {"spdxElementId", "relationshipType", "relatedSpdxElement"},
            {"comment", "spdxElementId", "relationshipType", "relatedSpdxElement"},
            relationship_path,
        )
        left = _expect_string(obj["spdxElementId"], f"{relationship_path}.spdxElementId")
        right = _expect_string(
            obj["relatedSpdxElement"], f"{relationship_path}.relatedSpdxElement"
        )
        relation = _expect_string(
            obj["relationshipType"], f"{relationship_path}.relationshipType"
        )
        _optional_strings(obj, {"comment"}, relationship_path)
        if relation not in _RELATIONSHIP_TYPES:
            raise ContractError(f"{relationship_path}.relationshipType is not an SPDX 2.3 value")
        if left not in kinds:
            raise ContractError(f"{relationship_path} has an unknown local source SPDX identifier")
        left_kind = kinds[left]
        if right in {"NONE", "NOASSERTION"}:
            if left_kind not in _ITEM_KINDS or relation in {
                "AMENDS",
                "DESCRIBED_BY",
                "DESCRIBES",
            }:
                raise ContractError(
                    f"{relationship_path} cannot use {right} for {relation}"
                )
        else:
            external_match = re.fullmatch(
                r"(DocumentRef-[A-Za-z0-9.+-]+):(SPDXRef-[A-Za-z0-9.-]+)",
                right,
            )
            if external_match:
                external_id, external_element = external_match.groups()
                if external_id not in external_ids:
                    raise ContractError(
                        f"{relationship_path} references an unknown external document"
                    )
                right_kind = (
                    "external-document"
                    if external_element == "SPDXRef-DOCUMENT"
                    else "external-element"
                )
            else:
                if right not in kinds:
                    raise ContractError(
                        f"{relationship_path} has an unknown related SPDX identifier"
                    )
                right_kind = kinds[right]
            _validate_relationship_kinds(
                relation, left_kind, right_kind, relationship_path
            )
        key = (left, relation, right, obj.get("comment", ""))
        if key in relationship_keys:
            raise ContractError(f"duplicate SPDX relationship at {relationship_path}")
        relationship_keys.add(key)

    for index, package in enumerate(packages):
        has_files = _expect_array(package.get("hasFiles", []), f"packages[{index}].hasFiles")
        for file_index, file_id in enumerate(has_files):
            identifier = _expect_string(file_id, f"packages[{index}].hasFiles[{file_index}]")
            if kinds.get(identifier) != "file":
                raise ContractError(
                    f"packages[{index}].hasFiles must reference a known file SPDX identifier"
                )

    for index, file_value in enumerate(files):
        dependencies = _expect_array(
            file_value.get("fileDependencies", []), f"files[{index}].fileDependencies"
        )
        for dependency_index, dependency in enumerate(dependencies):
            identifier = _expect_string(
                dependency, f"files[{index}].fileDependencies[{dependency_index}]"
            )
            if kinds.get(identifier) != "file":
                raise ContractError(
                    f"files[{index}].fileDependencies must reference a known file SPDX identifier"
                )

    for index, snippet in enumerate(snippets):
        source_file = snippet["snippetFromFile"]
        if kinds.get(source_file) != "file":
            raise ContractError(f"snippets[{index}].snippetFromFile must reference a known file")
        for range_index, range_value in enumerate(snippet["ranges"]):
            for pointer_name in ("startPointer", "endPointer"):
                reference = range_value[pointer_name]["reference"]
                if kinds.get(reference) != "file" or reference != source_file:
                    raise ContractError(
                        f"snippets[{index}].ranges[{range_index}].{pointer_name} "
                        "must reference snippetFromFile"
                    )

    # Keep these parameters part of validation, even though their values are represented by source.
    validate_binding(subject_name, subject_digest, platform, syft_version, source)


def _sort_list_of_objects(items: list[Any], key_fields: tuple[str, ...]) -> list[Any]:
    def key(item: Any) -> tuple[str, ...]:
        if not isinstance(item, dict):
            return (canonical_json_bytes(item).decode("utf-8"),)
        return tuple(str(item.get(field, "")) for field in key_fields) + (
            canonical_json_bytes(item).decode("utf-8"),
        )

    return sorted(items, key=key)


def _normalize_annotations(value: Any) -> Any:
    annotations = _expect_array(value, "annotations")
    normalized = []
    for item in annotations:
        copied = _normalize_generic(item)
        if isinstance(copied, dict) and "annotationDate" in copied:
            copied["annotationDate"] = FIXED_TIMESTAMP
        normalized.append(copied)
    return _sort_list_of_objects(
        normalized, ("SPDXID", "annotator", "annotationType", "comment")
    )


def _normalize_generic(value: Any) -> Any:
    if isinstance(value, dict):
        result = {key: _normalize_generic(child) for key, child in value.items()}
        if "annotations" in result:
            result["annotations"] = _normalize_annotations(result["annotations"])
        for field in (
            "checksums",
            "externalRefs",
            "licenseInfoFromFiles",
            "licenseInfoInFiles",
            "licenseInfoInSnippets",
            "fileContributors",
            "fileTypes",
            "attributionTexts",
            "artifactOfs",
            "crossRefs",
            "hasFiles",
            "fileDependencies",
            "packageVerificationCodeExcludedFiles",
            "seeAlsos",
            "ranges",
        ):
            if field in result and isinstance(result[field], list):
                if field == "checksums":
                    result[field] = _sort_list_of_objects(
                        result[field], ("algorithm", "checksumValue")
                    )
                elif field == "externalRefs":
                    result[field] = _sort_list_of_objects(
                        result[field], ("referenceCategory", "referenceType", "referenceLocator")
                    )
                elif field == "ranges":
                    result[field] = sorted(
                        result[field],
                        key=lambda item: canonical_json_bytes(item),
                    )
                else:
                    result[field] = sorted(
                        result[field],
                        key=lambda item: canonical_json_bytes(item).decode("utf-8"),
                    )
        return result
    if isinstance(value, list):
        return [_normalize_generic(child) for child in value]
    return value


def _canonical_namespace(
    subject_digest: str, platform: str, syft_version: str, source: dict[str, str]
) -> str:
    source_hash = hashlib.sha256(canonical_json_bytes(source)).hexdigest()
    version = quote(syft_version, safe=".-")
    platform_part = quote(platform, safe="")
    return (
        "https://sbom.missionsready.org/spdx/2.3/"
        f"{subject_digest.removeprefix('sha256:')}/{platform_part}/{version}/{source_hash}"
    )


def normalize_spdx(
    document: Any,
    subject_name: str,
    subject_digest: str,
    platform: str,
    syft_version: str,
    source: dict[str, str],
) -> dict[str, Any]:
    _validate_syft_document(
        document, subject_name, subject_digest, platform, syft_version, source
    )
    normalized = _normalize_generic(document)
    normalized["documentNamespace"] = _canonical_namespace(
        subject_digest, platform, syft_version, source
    )
    creation = normalized["creationInfo"]
    creation["created"] = FIXED_TIMESTAMP
    creation["creators"] = [f"Tool: syft-{syft_version}"]

    normalized["packages"] = _sort_list_of_objects(normalized["packages"], ("SPDXID",))
    normalized["relationships"] = _sort_list_of_objects(
        normalized["relationships"],
        ("spdxElementId", "relationshipType", "relatedSpdxElement", "comment"),
    )
    for field, keys in (
        ("files", ("SPDXID",)),
        ("snippets", ("SPDXID",)),
        ("externalDocumentRefs", ("externalDocumentId",)),
        ("hasExtractedLicensingInfos", ("licenseId",)),
    ):
        if field in normalized:
            normalized[field] = _sort_list_of_objects(normalized[field], keys)
    if "documentDescribes" in normalized:
        normalized["documentDescribes"] = sorted(normalized["documentDescribes"])
    if "annotations" in normalized:
        normalized["annotations"] = _normalize_annotations(normalized["annotations"])
    if "revieweds" in normalized:
        normalized["revieweds"] = _sort_list_of_objects(
            normalized["revieweds"], ("reviewDate", "reviewer", "comment")
        )
    return normalized


def build_evidence(
    document: Any,
    subject_name: str,
    subject_digest: str,
    platform: str,
    syft_version: str,
    source: Any,
) -> dict[str, Any]:
    source_binding = validate_binding(
        subject_name, subject_digest, platform, syft_version, source
    )
    normalized = normalize_spdx(
        document,
        subject_name,
        subject_digest,
        platform,
        syft_version,
        source_binding,
    )
    binding = {
        "canonicalization": CANONICALIZATION,
        "subject": {
            "name": subject_name,
            "digest": subject_digest,
            "platform": platform,
        },
        "generator": {"name": "syft", "version": syft_version},
        "source": source_binding,
    }
    normalized["creationInfo"]["comment"] = (
        BINDING_PREFIX + canonical_json_bytes(binding).decode("utf-8").rstrip("\n")
    )
    return normalized


def _binding_from_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    creation = _expect_object(evidence.get("creationInfo"), "creationInfo")
    comment = _expect_string(creation.get("comment"), "creationInfo.comment")
    if not comment.startswith(BINDING_PREFIX):
        raise ContractError("creationInfo.comment is missing the MissionsReady evidence binding")
    encoded = comment[len(BINDING_PREFIX) :]
    try:
        binding = json.loads(
            encoded,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ContractError(f"creationInfo.comment has an invalid evidence binding: {exc}") from exc
    _check_complexity(binding)
    binding_object = _expect_object(binding, "evidence binding")
    _exact_keys(
        binding_object,
        {"canonicalization", "subject", "generator", "source"},
        "evidence binding",
    )
    return binding_object


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _expect_object(value, "evidence")
    binding = _binding_from_evidence(evidence)
    if binding["canonicalization"] != CANONICALIZATION:
        raise ContractError("unsupported canonicalization contract")
    subject = _expect_object(binding["subject"], "evidence binding.subject")
    _exact_keys(subject, {"name", "digest", "platform"}, "evidence binding.subject")
    generator = _expect_object(binding["generator"], "evidence binding.generator")
    _exact_keys(generator, {"name", "version"}, "evidence binding.generator")
    if generator["name"] != "syft":
        raise ContractError("evidence generator must be Syft")
    source = validate_binding(
        subject["name"],
        subject["digest"],
        subject["platform"],
        generator["version"],
        binding["source"],
    )
    rebuilt = build_evidence(
        evidence,
        subject["name"],
        subject["digest"],
        subject["platform"],
        generator["version"],
        source,
    )
    if canonical_json_bytes(rebuilt) != canonical_json_bytes(evidence):
        raise ContractError("evidence is not in canonical normalized form")
    return evidence


def _component_key(package: dict[str, Any]) -> str:
    purls = sorted(
        reference.get("referenceLocator", "")
        for reference in package.get("externalRefs", [])
        if isinstance(reference, dict)
        and reference.get("referenceType") == "purl"
        and isinstance(reference.get("referenceLocator"), str)
    )
    if purls:
        return f"purl:{purls[0]}"
    values = [
        str(package.get("name", "")),
        str(package.get("versionInfo", "")),
        str(package.get("primaryPackagePurpose", "")),
        str(package.get("packageFileName", "")),
    ]
    return "package:" + "\x1f".join(values)


def _component_counts(evidence: dict[str, Any]) -> Counter[str]:
    return Counter(_component_key(package) for package in evidence["packages"])


def _index_by_id(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["SPDXID"]: item for item in items}


def _delta_by_id(
    previous: list[dict[str, Any]], current: list[dict[str, Any]]
) -> dict[str, list[Any]]:
    before = _index_by_id(previous)
    after = _index_by_id(current)
    before_ids = set(before)
    after_ids = set(after)
    changed = [
        {
            "id": identifier,
            "previousSha256": hashlib.sha256(canonical_json_bytes(before[identifier])).hexdigest(),
            "currentSha256": hashlib.sha256(canonical_json_bytes(after[identifier])).hexdigest(),
        }
        for identifier in sorted(before_ids & after_ids)
        if canonical_json_bytes(before[identifier]) != canonical_json_bytes(after[identifier])
    ]
    return {
        "added": sorted(after_ids - before_ids),
        "removed": sorted(before_ids - after_ids),
        "changed": changed,
    }


def _relationship_key(item: dict[str, Any]) -> dict[str, str]:
    result = {
        "spdxElementId": item["spdxElementId"],
        "relationshipType": item["relationshipType"],
        "relatedSpdxElement": item["relatedSpdxElement"],
    }
    if "comment" in item:
        result["comment"] = item["comment"]
    return result


def _relationship_token(item: dict[str, Any]) -> bytes:
    return canonical_json_bytes(_relationship_key(item))


def compare_evidence(previous: Any, current: Any) -> dict[str, Any]:
    before = validate_evidence(previous)
    after = validate_evidence(current)
    before_binding = _binding_from_evidence(before)
    after_binding = _binding_from_evidence(after)
    before_subject = before_binding["subject"]
    after_subject = after_binding["subject"]
    if before_subject["name"] != after_subject["name"]:
        raise ContractError("cannot compare evidence for different OCI subject names")
    if before_subject["platform"] != after_subject["platform"]:
        raise ContractError("cannot compare evidence for different platforms")

    before_components = _component_counts(before)
    after_components = _component_counts(after)
    component_keys = sorted(set(before_components) | set(after_components))
    components = {
        "added": [
            {"identity": key, "count": after_components[key] - before_components[key]}
            for key in component_keys
            if after_components[key] > before_components[key]
        ],
        "removed": [
            {"identity": key, "count": before_components[key] - after_components[key]}
            for key in component_keys
            if before_components[key] > after_components[key]
        ],
    }

    before_relationships = {
        _relationship_token(item): _relationship_key(item)
        for item in before["relationships"]
    }
    after_relationships = {
        _relationship_token(item): _relationship_key(item)
        for item in after["relationships"]
    }
    relationship_delta = {
        "added": [
            after_relationships[token]
            for token in sorted(after_relationships.keys() - before_relationships.keys())
        ],
        "removed": [
            before_relationships[token]
            for token in sorted(before_relationships.keys() - after_relationships.keys())
        ],
    }

    report = {
        "apiVersion": "missionsready.org/sbom-delta/v1",
        "kind": "SpdxPlatformDelta",
        "subject": {
            "name": after_subject["name"],
            "platform": after_subject["platform"],
            "previousDigest": before_subject["digest"],
            "currentDigest": after_subject["digest"],
        },
        "components": components,
        "packages": _delta_by_id(
            before["packages"], after["packages"]
        ),
        "files": _delta_by_id(
            before.get("files", []), after.get("files", [])
        ),
        "relationships": relationship_delta,
    }
    report["summary"] = {
        "componentAdded": sum(item["count"] for item in components["added"]),
        "componentRemoved": sum(item["count"] for item in components["removed"]),
        "packageAdded": len(report["packages"]["added"]),
        "packageRemoved": len(report["packages"]["removed"]),
        "packageChanged": len(report["packages"]["changed"]),
        "fileAdded": len(report["files"]["added"]),
        "fileRemoved": len(report["files"]["removed"]),
        "fileChanged": len(report["files"]["changed"]),
        "relationshipAdded": len(relationship_delta["added"]),
        "relationshipRemoved": len(relationship_delta["removed"]),
    }
    return report

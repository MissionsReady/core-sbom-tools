"""Command-line interface for MissionsReady SPDX evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import (
    DEFAULT_MAX_INPUT_BYTES,
    BINDING_PREFIX,
    CommittedCleanupError,
    ContractError,
    atomic_write_json,
    atomic_write_jsons,
    build_evidence,
    compare_evidence,
    load_json_strict,
    recover_output_transaction,
    validate_evidence,
)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-tool",
        description="Validate, normalize, and compare pinned-Syft SPDX 2.3 JSON evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize = subparsers.add_parser("normalize", help="validate and normalize raw Syft SPDX JSON")
    normalize.add_argument("--input", required=True, help="raw SPDX JSON from pinned Syft")
    normalize.add_argument("--output", required=True, help="canonical evidence output path")
    normalize.add_argument("--subject-name", required=True, help="lowercase OCI repository")
    normalize.add_argument("--subject-digest", required=True, help="sha256 OCI manifest digest")
    normalize.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    normalize.add_argument("--syft-version", required=True, help="exact pinned Syft version")
    normalize.add_argument("--source-metadata", required=True, help="strict source metadata JSON")
    normalize.add_argument("--previous", help="previous accepted canonical evidence")
    normalize.add_argument("--report", help="atomic delta report output (requires --previous)")
    normalize.add_argument(
        "--max-input-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_INPUT_BYTES,
        help=f"per-file input limit (default: {DEFAULT_MAX_INPUT_BYTES})",
    )

    compare = subparsers.add_parser("compare", help="compare two accepted canonical evidence files")
    compare.add_argument("--previous", required=True)
    compare.add_argument("--current", required=True)
    compare.add_argument("--report", required=True)
    compare.add_argument(
        "--max-input-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_INPUT_BYTES,
        help=f"per-file input limit (default: {DEFAULT_MAX_INPUT_BYTES})",
    )

    validate = subparsers.add_parser("validate", help="validate accepted canonical evidence")
    validate.add_argument("--input", required=True)
    validate.add_argument(
        "--max-input-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_INPUT_BYTES,
        help=f"input limit (default: {DEFAULT_MAX_INPUT_BYTES})",
    )
    return parser


def _same_path(left: str, right: str) -> bool:
    try:
        return Path(left).resolve() == Path(right).resolve()
    except (OSError, RuntimeError) as exc:
        raise ContractError(f"cannot resolve path: {exc}") from exc


def _summary(report: dict) -> str:
    summary = report["summary"]
    return (
        "delta "
        f"components +{summary['componentAdded']}/-{summary['componentRemoved']}, "
        f"packages +{summary['packageAdded']}/-{summary['packageRemoved']}"
        f"/~{summary['packageChanged']}, "
        f"files +{summary['fileAdded']}/-{summary['fileRemoved']}/~{summary['fileChanged']}, "
        f"relationships +{summary['relationshipAdded']}/-{summary['relationshipRemoved']}"
    )


def _normalize(args: argparse.Namespace) -> None:
    if bool(args.previous) != bool(args.report):
        raise ContractError("--previous and --report must be supplied together")
    for source in (args.input, args.source_metadata, args.previous):
        if source and _same_path(source, args.output):
            raise ContractError("output path must not overwrite an input file")
    if args.report:
        protected = (args.input, args.source_metadata, args.previous, args.output)
        if any(_same_path(args.report, path) for path in protected if path):
            raise ContractError("report path must be distinct from inputs and normalized output")
    transaction_paths = [args.output] + ([args.report] if args.report else [])
    recover_output_transaction(transaction_paths)

    document = load_json_strict(args.input, args.max_input_bytes)
    source = load_json_strict(args.source_metadata, args.max_input_bytes)
    evidence = build_evidence(
        document,
        args.subject_name,
        args.subject_digest,
        args.platform,
        args.syft_version,
        source,
    )
    report = None
    if args.previous:
        previous = load_json_strict(args.previous, args.max_input_bytes)
        report = compare_evidence(previous, evidence)

    outputs = [(args.output, evidence)]
    if report is not None:
        outputs.append((args.report, report))
    atomic_write_jsons(outputs)
    print(
        f"normalized {len(evidence['packages'])} packages for "
        f"{args.subject_name}@{args.subject_digest} ({args.platform})",
        file=sys.stderr,
    )
    if report is not None:
        print(_summary(report), file=sys.stderr)


def _compare(args: argparse.Namespace) -> None:
    if _same_path(args.report, args.previous) or _same_path(args.report, args.current):
        raise ContractError("report path must not overwrite an input file")
    recover_output_transaction([args.report])
    previous = load_json_strict(args.previous, args.max_input_bytes)
    current = load_json_strict(args.current, args.max_input_bytes)
    report = compare_evidence(previous, current)
    atomic_write_json(args.report, report)
    print(_summary(report), file=sys.stderr)


def _validate(args: argparse.Namespace) -> None:
    evidence = load_json_strict(args.input, args.max_input_bytes)
    validate_evidence(evidence)
    binding_text = evidence["creationInfo"]["comment"]
    binding = json.loads(binding_text[len(BINDING_PREFIX) :])
    print(
        f"valid canonical evidence: {binding['subject']['name']}@"
        f"{binding['subject']['digest']} ({binding['subject']['platform']})",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "normalize":
            _normalize(args)
        elif args.command == "compare":
            _compare(args)
        else:
            _validate(args)
    except CommittedCleanupError as exc:
        print(f"sbom-tool: committed with cleanup warning: {exc}", file=sys.stderr)
        return 3
    except ContractError as exc:
        print(f"sbom-tool: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Canonical SPDX platform evidence contract

## Scope and blueprint mapping

Each accepted file represents exactly one OCI platform manifest and is itself
SPDX 2.3 JSON. Its SHA-256 file digest and immutable publication URI populate a
`core-blueprints` `evidence.sboms[]` entry with:

- `subject`: the matching `platform-image` evidence ID;
- `format`: `spdx-json`;
- `mediaType`: `application/spdx+json`;
- `digest`: SHA-256 of the exact canonical file bytes; and
- `uri`: the immutable published evidence location.

Index SBOM policy is separate. This tool's subject platform is limited to the
currently supported blueprint architectures, `linux/amd64` and `linux/arm64`.

## Required caller binding

Normalization requires an OCI repository name without a tag, a lowercase
`sha256:` manifest digest, one supported platform, an exact semantic Syft
version, and source metadata containing only:

```json
{
  "type": "oci-image",
  "name": "<subject name>",
  "reference": "<subject name>@<subject digest>",
  "digest": "<subject digest>",
  "platform": "<platform>"
}
```

The values must match byte-for-byte. The raw SPDX `name` must equal
`source.reference`, and `creationInfo.creators` must contain exactly one
matching `Tool: syft-<version>` entry and no other tool creator.

The accepted SPDX stores the canonical binding as compact JSON after the
`MissionsReady-SBOM-Binding: ` prefix in `creationInfo.comment`. Validation
reconstructs the canonical document from that binding and rejects any drift.
The document namespace is deterministically derived from the subject digest,
platform, Syft version, and source metadata.

## Minimum SPDX and graph checks

Accepted input must have:

- `spdxVersion: SPDX-2.3`, `dataLicense: CC0-1.0`, and
  `SPDXID: SPDXRef-DOCUMENT`;
- an absolute, fragment-free HTTPS document namespace;
- creation information, packages, and relationships;
- a unique valid local SPDX ID for every package, file, and snippet;
- every SPDX-required package, file, snippet, creation, annotation, review,
  external-reference, extracted-license, and relationship field;
- exact nested object/list/scalar types with no unknown nested fields;
- at least one algorithm-correct lowercase hexadecimal checksum on every
  package and file;
- an SPDX 2.3 `relationshipType` and valid source/target element kinds;
- local relationship endpoints that resolve to known IDs;
- no duplicate relationships, external document IDs, or checksums; and
- valid `documentDescribes`, package `hasFiles`, file dependency, snippet
  source, and snippet range-pointer references.

Relationship direction follows SPDX 2.3 Table 68. In particular,
`FILE_ADDED` and `FILE_DELETED` are file-to-package, while `FILE_MODIFIED` is
file-to-file. File-to-file `CONTAINS`, `DYNAMIC_LINK`, and `STATIC_LINK` are
accepted. Every supported relationship enum has an explicit element-kind
rule; `AMENDS` resolves its external document reference, and `NONE` or
`NOASSERTION` is accepted only where an item relationship can use it.

`artifactOfs` is supported only on File objects and `crossRefs` only on
extracted licensing information, with their complete supported nested types.
Snippet pointers must use the same file and pointer kind, positions start at
one, and every start position must be less than or equal to its end. Each
snippet has exactly one byte-offset range and at most one optional line range.

Unknown top-level and nested fields are rejected. Invalid, null, or wrong-type
nested values always fail as contract errors before normalization. Standard
supported SPDX fields are retained so package and file evidence is not
silently discarded.

## Strict JSON limits

Inputs must be regular files and are streamed using reads bounded to at most
`max_bytes + 1`; the implementation never uses an unbounded whole-file read.
Growth, shrinkage, special files, and files already over the limit are
rejected. Inputs are strict UTF-8. UTF-8 BOMs, invalid byte sequences,
duplicate object keys, NaN, infinities, excessive integer/number lengths,
depth over 128, excessive value counts, oversized collections, long keys, and
oversized files or strings are rejected. The default per-file limit is 64 MiB
and may be lowered with `--max-input-bytes`.

## Canonicalization

Canonical output uses UTF-8, sorted object keys, compact separators, one final
newline, and `allow_nan=False`. It normalizes only unstable evidence metadata:

- `creationInfo.created` and annotation dates become
  `1970-01-01T00:00:00Z`;
- creators become the single validated pinned-Syft creator;
- the document namespace and binding comment become deterministic; and
- unordered SPDX collections are sorted by stable identifiers and fields.

Package, file, checksum, license, external reference, relationship, and other
content fields remain present. Thus dependency or content changes alter the
canonical bytes.

## Delta report

Comparison requires the same OCI repository and platform but permits a new
manifest digest or pinned Syft version. The deterministic report includes:

- component count additions/removals, using purl where available;
- package and file ID additions/removals plus content-hash changes; and
- complete relationship additions/removals.

Both a machine-readable report and a concise stderr summary are produced.

## Transactional output

Every output is serialized before filesystem changes. The writer creates
parents, stages every output in its destination directory, writes and fsyncs
every stage, and only then begins replacement. Existing destinations are
preserved as same-directory hard links, falling back to fsynced copies when
hard links are unavailable. Backup file contents and their directory entries
are fsynced before the prepared marker. Each stage is installed directly with
`os.replace`, so an existing destination remains continuously present. If any
replacement fails, all already-replaced destinations are restored in reverse
order and newly created destinations are removed.

Before the first output replacement, a deterministic prepared transaction
marker is written in the first output directory. It records all destinations,
stages, backups, and old/new digests. After every output has been durably
replaced, a separate committed marker containing the same record is published.
Keeping the prepared marker until the committed marker is durable avoids an
ambiguous marker-state replacement window.

Every directory-entry operation is followed by an fsync of that entry's parent
directory: output-parent creation, stage and backup publication/removal,
prepared and committed marker publication, each output replacement, rollback
and recovery replacement/removal, and final cleanup. Outputs in different
directories fsync their own parent independently; the transaction marker lives
in the first output's parent.

CLI startup and the library writer recover matching markers before new work:
a prepared marker without a committed marker rolls back to all prior outputs,
while a committed marker retains and verifies every new output before cleanup.
Recovery fsync failures leave the marker in a retryable state whenever the
recorded backup/digest state is still representable. Only missing or corrupt
data that cannot identify either the recorded old or new state is rejected.
Thus interruption can temporarily expose mixed versions but never requires
removing an existing destination, and the next matching invocation
deterministically resolves the unit.

Validation, parent creation, open, write, file fsync, replacement, rollback,
marker, directory fsync, and pre-commit cleanup failures are controlled
contract errors (CLI exit 2) and preserve prior outputs when rollback
succeeds. Once all output parent directories and the committed marker are
fsynced, later backup or marker cleanup/fsync errors are reported explicitly as
**committed with cleanup warning** (CLI exit 3). Outputs remain committed and
startup recovery completes cleanup; this state is never reported as a failed
transaction.

# Offline split evidence integrity review (#3 / #195, supporting #28)

The existing split-device report validator checks the schema and status
attestations. This separate tool verifies that each observed row refers to
the actual bytes supplied for that case. It does not verify redaction,
signing, build provenance, or the truth of physical observations.

Use a local, owner-controlled directory (including its parent directories)
with one regular nonempty text file per observed case, named exactly
`<case>.txt` using the case identifier in the existing schema. Do not
put raw logs, keys, addresses, identifiers or packet captures here.
First review and redact observations, then calculate the SHA-256 of
those exact bytes and record the digest in the report. Keep the directory
unchanged throughout review. Not-run rows have no digest and are not read;
unrelated directory entries are not read either.

On Linux or macOS, from the repository root:

    python3 scripts/verify-split-evidence-artifacts.py /path/to/report.json /path/to/redacted-artifacts
    python3 scripts/verify-split-evidence-artifacts.py /path/to/report.json /path/to/redacted-artifacts --require-complete

Exit 0 means the required observed artifact digests match (and, with
--require-complete, all cases are operator-marked pass). Exit 1 means
the matching report is incomplete or contains failures when completeness
is requested. Exit 2 indicates invalid input, missing or mismatched
evidence, or unsupported safe local file APIs. The verifier reads at
most 1 MiB per case, rejects symlinks at the directory and file boundary
and nonregular files, and never prints artifact contents or sends them
over a network. It is not a sandbox for hostile parent directories.

An empty observed set can pass a partial integrity check with zero
matching digests; it cannot pass --require-complete. A complete matching
report still requires human examination of the redacted observations,
actual signed build identity and test environment. No automatic closure
of #28, #192 or #3 is authorized by this tool. Do not publish unredacted
artifacts or run the tool against raw evidence. CI uses only synthetic
fixtures.

Component acceptance: #28. Cross-component aggregation and review: #3
under Epic #195. No change to Swift routing or pinned Rust BoringTun.

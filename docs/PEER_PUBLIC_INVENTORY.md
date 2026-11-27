# Public-only daemon inventory boundary (#20)

The independent inventory validator accepts only the public outputs of
`wg show <verified-interface> public-key`, `peers`, and `allowed-ips`,
using the single-interface format (not `all`). The expected server public
key must match; peer keys must be unique and identical across both peer
queries; every managed peer must own exactly its paired /32 and /128 host
routes with a unique slot. Missing, extra, malformed, truncated or noncanonical
rows are rejected. Never use `dump`, `showconf`, private-key or PSK output.
An empty peer list is valid only if both peer queries successfully completed
without truncation. The actual daemon owner must bound capture before parsing,
verify executable/interface/server identity, serialize writes and provide a
terminal fence across the three queries; this parser is not proof of those
properties. It is not invoked by the current UI, does not perform privileged
operations, and cannot enable a second iPhone. Gateway deployment remains #27.

# API Tracing Guarantees and Limitations

This document defines what Mantle can and cannot capture in API tracing.

## Confidence Tiers

- tier1_payload_exact
  - Request/response payload is extractable.
  - Endpoint is matched via exact MITM interval containment.
  - Highest confidence.

- tier2_payload_mapped
  - Request/response payload is extractable.
  - Endpoint is inferred heuristically (nearest interval or fallback mapping).
  - Medium confidence.

- tier3_network_only
  - Only baseline network telemetry is available.
  - Payload-level semantics are unavailable.
  - Lowest confidence.

## Capture Guarantees

- HTTPS API payload capture is available when traffic traverses the configured MITM path and trust setup is valid.
- eBPF capture provides baseline process and network activity telemetry.
- Trace metadata now includes explicit tier/source labels for inferred destinations.

## Deterministic Destination Scope

The current eBPF network path provides deterministic destination ip:port capture for these cases:

- outbound TCP `connect` calls from the traced process tree (root process + descendants)
- IPv4 and IPv6 socket addresses provided by `connect(2)`
- common agent HTTP/HTTPS behaviors that use TCP (for example: `git clone`, `curl`, SDK-based API calls, package/download fetches)

Why this is deterministic in-scope:

- destination endpoint is read directly from the syscall `sockaddr` instead of inferred from later `/proc` socket table races

Domain attribution remains source-dependent:

- deterministic domain when host is explicit in command arguments (for example `https://github.com/...`)
- best-effort domain from DNS/SNI/manual mapping in other cases

## Known Limitations

- Destination inference can degrade when socket resolution fails for short-lived connections.
- Payload extraction depends on successful proxy interception and parseable response bodies.
- Provider parsing quality is strongest for OpenAI-compatible schemas; unknown schemas may need manual mapping.
- Turn correlation is timestamp-based. Response records define turn boundaries, and request context is attached when present.
- Timestamp skew/coarseness or missing proxy timestamps can mis-assign some system events near boundary edges.

Out of deterministic scope (documented for future improvements):

- UDP/QUIC (HTTP/3) endpoint/domain guarantees
- domain recovery when no command host hint and no stable DNS/SNI signal
- certificate-pinned encrypted payload extraction without endpoint cooperation
- namespace/kernel-bypass traffic not observed by current probe set

## Operator Guidance

- Use capture-quality endpoint to inspect trace confidence:
  - GET /api/traces/{trace_id}/capture-quality
- Treat tier2 and tier3 traces as degraded for strict audit scenarios.
- If endpoint attribution quality is critical, prefer runs with stable MITM setup and provider schema coverage.

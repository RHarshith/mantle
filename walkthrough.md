# Walkthrough: Tiered Network Interception

We have successfully overhauled Mantle's network interception architecture, integrating the new tiered observability model seamlessly into the unified Rust proxy.

## Implementation Details

1. **Rust MITM Capabilities Updated**
   - We updated [Cargo.toml](file:///home/harshith/code_projects/nono/Cargo.toml) to bring in `hyper-util`, `tokio-rustls`, `rcgen`, and `rustls-pki-types`.
   - The primary proxy code within [mantle_capture_mitm_proxy.rs](file:///home/harshith/code_projects/mantle/mantle/capture/rust/capture-userspace/src/bin/mantle_capture_mitm_proxy.rs) was completely rewritten to support low-latency proxy tunneling (Tier 1/2 capturing) alongside the existing direct LLM JSON interception (Tier 3).

2. **Connecting the Tiers**
   - **Tier 3 (LLM Fast Path):** All configured LLM requests (OpenAI, Anthropic, Gemini) are routed explicitly via their `BASE_URL` SDK environment variables. Our [run_intercepted_agent.sh](file:///home/harshith/code_projects/mantle/run_intercepted_agent.sh) script dynamically injects these into the agent execution space. This traffic remains unencrypted to the proxy out-of-the-box, allowing transparent payload extraction without any TLS overhead or MITM verification.
   - **Tier 1 & 2 (SNI/CONNECT Port & Domain Capturing):** The agent launcher script handles standard HTTP/HTTPS API traffic via system `$HTTPS_PROXY` overrides, directing it through the Rust API.
   - **Tier 4 (Best Effort TLS Replacement):** We intercept the TCP stream natively during the HTTP `CONNECT` phase and issue our own `Mantle Root CA`-backed certificate generated on the fly. 
     - **Graceful Failure:** If the agent library (such as a strict python `requests` bundle) rejects the MITM self-signed CA, the proxy drops the connection cleanly. Rather than losing the trace context, the system has already successfully logged the `Tier 1/2` details (which includes the remote domain name and the target port). 
     - **Dashboard Continuity:** The dashboard gracefully parses these connections and marks them as masked with missing payloads, preserving the temporal integrity of the execution traces.

## Testing and Verification
- We verified the system's integration with the `cli_agent` runner via [test_agent.py](file:///home/harshith/code_projects/mantle/test_agent.py), simulating a strict SDK executing an off-path network request to Github.
- The logs assert that the [.jsonl](file:///tmp/test_mitm_trace.jsonl) trace captures the explicit endpoint details (e.g `raw.githubusercontent.com:443`) dynamically resolved outside of any hard-coded rulesets, fully solving the API opacity problem with statically compiled `libssl` frameworks.

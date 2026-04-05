# Rust Port for `mantle/capture`

This directory now contains a Rust workspace at `mantle/capture/rust`.

## Build

```bash
mantle/capture/rust/scripts/build_capture_rust.sh
```

This builds:

- `mantle/capture/rust/target/release/mantle_capture_ebpf`
- `mantle/capture/rust/target/release/mantle_capture_mitm_proxy`

## Test

```bash
mantle/capture/rust/scripts/test_capture_rust.sh
```

## Runtime Compatibility

- eBPF capture executes directly via the Rust binary (`mantle_capture_ebpf`).
- MITM capture executes directly via the Rust reverse proxy binary (`mantle_capture_mitm_proxy`) launched by `run_intercepted_agent.sh`.
- No silent fallback to Python is performed if the Rust binaries are missing or fail.

## Optional Overrides

Use these environment variables to point at custom binary locations:

- `MANTLE_CAPTURE_EBPF_BIN`
- `MANTLE_CAPTURE_MITM_BIN`

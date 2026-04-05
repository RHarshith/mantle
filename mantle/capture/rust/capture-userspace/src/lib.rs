//! Interface traits used by capture binaries.

use serde_json::Value;

/// Contract for eBPF capture runners that emit JSONL events.
pub trait EbpfCaptureRunner {
    fn run(&self, output: &std::path::Path, command: &[String]) -> anyhow::Result<i32>;
}

/// Contract for MITM record builders that convert flow payloads into records.
pub trait MitmRecordBuilder {
    fn build_record(&self, payload: &Value) -> anyhow::Result<Option<Value>>;
}

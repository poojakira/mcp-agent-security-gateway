//! Minimal stdin/stdout NDJSON driver for the Rust MCP inspection core.
//!
//! Reads newline-delimited JSON-RPC messages from stdin, inspects each one,
//! and prints the decision as JSON to stdout. This mirrors the read loop of the
//! Python `StdioMCPProxy.run`, minus the downstream subprocess transport (kept
//! out of scope for the port; the security-critical inspection is the point).
//!
//! STATUS: UNVERIFIED locally (no Rust toolchain). Build/verify: rust/README.md.

use std::io::{self, BufRead, Write};

use mcp_stdio_proxy::{inspect_message, Decision, Detector};

/// A tiny built-in denylist detector so the binary is self-contained.
struct DenylistDetector {
    needles: Vec<&'static str>,
}
impl Detector for DenylistDetector {
    fn detect(&self, text: &str) -> Result<Vec<String>, String> {
        let lower = text.to_lowercase();
        Ok(self
            .needles
            .iter()
            .filter(|n| lower.contains(*n))
            .map(|n| (*n).to_string())
            .collect())
    }
}

fn main() -> io::Result<()> {
    let detector = DenylistDetector {
        needles: vec!["ignore previous", "disregard instructions", "system prompt"],
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let result = inspect_message(trimmed, &detector);
        let decision = match result.decision {
            Decision::Allow => "allow",
            Decision::Block => "block",
            Decision::Indeterminate => "indeterminate",
        };
        let json = serde_json::json!({
            "decision": decision,
            "reason": result.reason,
            "matched_patterns": result.matched_patterns,
        });
        writeln!(out, "{json}")?;
        out.flush()?;
    }
    Ok(())
}

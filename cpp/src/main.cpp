// Minimal stdin/stdout NDJSON driver for the C++ MCP inspection core.
// Reads newline-delimited JSON-RPC messages from stdin, inspects each, and
// prints the decision as JSON to stdout. Mirrors the Rust binary in ../rust.

#include "mcp_inspect.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>
#include <vector>

using namespace mcp;

// Consume an oversized record through its newline without retaining its bytes,
// so a subsequent record can still be inspected within the same process.
static bool read_bounded_line(std::istream& input, std::string& line, bool& oversized) {
    line.clear();
    oversized = false;
    bool received = false;
    for (int next; (next = input.get()) != std::char_traits<char>::eof();) {
        received = true;
        if (next == '\n') return true;
        if (line.size() < kMaxMessageBytes) line.push_back(static_cast<char>(next));
        else oversized = true;
    }
    return received;
}

int main() {
    std::vector<std::string> needles = {"ignore previous", "disregard instructions",
                                        "system prompt"};
    Detector detector = [needles](const std::string& text) {
        std::string lower = text;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        std::vector<std::string> hits;
        for (const auto& n : needles) {
            if (lower.find(n) != std::string::npos) hits.push_back(n);
        }
        return hits;
    };

    std::string line;
    bool oversized;
    while (read_bounded_line(std::cin, line, oversized)) {
        // trim
        size_t a = line.find_first_not_of(" \t\r\n");
        if (!oversized && a == std::string::npos) continue;
        InspectionResult r;
        if (oversized) r = block("JSON message exceeds 1 MiB", "malformed_jsonrpc");
        else {
            size_t b = line.find_last_not_of(" \t\r\n");
            r = inspect_message(line.substr(a, b - a + 1), detector);
        }
        const char* d = r.decision == Decision::Allow
                            ? "allow"
                            : (r.decision == Decision::Block ? "block" : "indeterminate");
        std::string patterns = "[";
        for (size_t k = 0; k < r.matched_patterns.size(); ++k) {
            if (k) patterns += ",";
            patterns += quote_json(r.matched_patterns[k]);
        }
        patterns += "]";
        std::cout << "{\"decision\":" << quote_json(d) << ",\"reason\":" << quote_json(r.reason)
                  << ",\"matched_patterns\":" << patterns << "}\n";
    }
    return 0;
}

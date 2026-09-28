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
    while (std::getline(std::cin, line)) {
        // trim
        size_t a = line.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) continue;
        size_t b = line.find_last_not_of(" \t\r\n");
        std::string trimmed = line.substr(a, b - a + 1);

        InspectionResult r = inspect_message(trimmed, detector);
        const char* d = r.decision == Decision::Allow
                            ? "allow"
                            : (r.decision == Decision::Block ? "block" : "indeterminate");
        std::string patterns = "[";
        for (size_t k = 0; k < r.matched_patterns.size(); ++k) {
            if (k) patterns += ",";
            patterns += "\"" + r.matched_patterns[k] + "\"";
        }
        patterns += "]";
        std::cout << "{\"decision\":\"" << d << "\",\"reason\":\"" << r.reason
                  << "\",\"matched_patterns\":" << patterns << "}\n";
    }
    return 0;
}

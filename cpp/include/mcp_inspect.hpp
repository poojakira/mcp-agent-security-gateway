// Fail-closed JSON-RPC inspection core for the MCP stdio proxy — C++ port.
//
// Mirrors the security-critical decision logic of the Python
// `stdio_proxy.py` (`inspect_message`) and the Rust port in ../rust:
// parse a JSON-RPC message, reject malformed/ambiguous input (including
// duplicate object keys), and only forward `tools/call` requests that pass a
// fail-closed inspection.
//
// Parity with the Python/Rust implementations:
//   - Malformed JSON            -> BLOCK (malformed_jsonrpc)
//   - Duplicate object keys     -> BLOCK
//   - Empty batch []            -> BLOCK
//   - Non-object payload (e.g. 42) -> BLOCK
//   - Non-`tools/call` method   -> ALLOW (pass-through)
//   - Benign `tools/call`       -> ALLOW
//   - Injection in arguments    -> BLOCK with matched patterns
//   - Detector throws/fails     -> INDETERMINATE (caller treats as fail-closed)
//   - Batch, one bad member     -> BLOCK all (atomic)
//
// Dependency-light on purpose: a small self-contained JSON parser handles the
// security-relevant subset (objects, arrays, strings, numbers, bool, null) and
// specifically detects duplicate keys, which serde/json libraries silently drop.
//
// STATUS: VERIFIED via a g++ Docker image (see cpp/README.md).

#ifndef MCP_INSPECT_HPP
#define MCP_INSPECT_HPP

#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcp {

enum class Decision { Allow, Block, Indeterminate };

struct InspectionResult {
    Decision decision;
    std::string reason;
    std::vector<std::string> matched_patterns;
};

// A detector maps tool-call argument text to matched pattern names.
// Throwing models a detector failure -> INDETERMINATE (fail closed).
using Detector = std::function<std::vector<std::string>(const std::string&)>;

// ---------------------------------------------------------------------------
// Minimal JSON value + parser (security-subset; detects duplicate keys)
// ---------------------------------------------------------------------------

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object } type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string str;
    std::vector<JsonValue> array;
    // Object stored as ordered pairs so we can detect duplicate keys.
    std::vector<std::pair<std::string, JsonValue>> object;
    bool duplicate_key = false;  // set if any object in the subtree had a dup key

    const JsonValue* find(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        for (const auto& kv : object) {
            if (kv.first == key) return &kv.second;
        }
        return nullptr;
    }
};

class JsonParseError : public std::runtime_error {
public:
    explicit JsonParseError(const std::string& m) : std::runtime_error(m) {}
};

class JsonParser {
public:
    explicit JsonParser(const std::string& s) : s_(s) {}

    JsonValue parse() {
        skip_ws();
        JsonValue v = parse_value();
        skip_ws();
        if (i_ != s_.size()) throw JsonParseError("trailing characters");
        return v;
    }

private:
    const std::string& s_;
    size_t i_ = 0;

    void skip_ws() {
        while (i_ < s_.size()) {
            char c = s_[i_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++i_;
            else break;
        }
    }

    char peek() {
        if (i_ >= s_.size()) throw JsonParseError("unexpected end of input");
        return s_[i_];
    }

    JsonValue parse_value() {
        skip_ws();
        char c = peek();
        switch (c) {
            case '{': return parse_object();
            case '[': return parse_array();
            case '"': {
                JsonValue v; v.type = JsonValue::Type::String; v.str = parse_string();
                return v;
            }
            case 't': case 'f': return parse_bool();
            case 'n': return parse_null();
            default:  return parse_number();
        }
    }

    JsonValue parse_object() {
        JsonValue v; v.type = JsonValue::Type::Object;
        ++i_;  // consume '{'
        skip_ws();
        if (peek() == '}') { ++i_; return v; }
        while (true) {
            skip_ws();
            if (peek() != '"') throw JsonParseError("expected string key");
            std::string key = parse_string();
            skip_ws();
            if (peek() != ':') throw JsonParseError("expected ':'");
            ++i_;
            JsonValue val = parse_value();
            if (val.duplicate_key) v.duplicate_key = true;
            for (const auto& kv : v.object) {
                if (kv.first == key) { v.duplicate_key = true; break; }
            }
            v.object.emplace_back(std::move(key), std::move(val));
            skip_ws();
            char n = peek();
            if (n == ',') { ++i_; continue; }
            if (n == '}') { ++i_; break; }
            throw JsonParseError("expected ',' or '}'");
        }
        return v;
    }

    JsonValue parse_array() {
        JsonValue v; v.type = JsonValue::Type::Array;
        ++i_;  // consume '['
        skip_ws();
        if (peek() == ']') { ++i_; return v; }
        while (true) {
            JsonValue el = parse_value();
            if (el.duplicate_key) v.duplicate_key = true;
            v.array.push_back(std::move(el));
            skip_ws();
            char n = peek();
            if (n == ',') { ++i_; continue; }
            if (n == ']') { ++i_; break; }
            throw JsonParseError("expected ',' or ']'");
        }
        return v;
    }

    std::string parse_string() {
        ++i_;  // consume opening quote
        std::string out;
        while (true) {
            if (i_ >= s_.size()) throw JsonParseError("unterminated string");
            char c = s_[i_++];
            if (c == '"') break;
            if (c == '\\') {
                if (i_ >= s_.size()) throw JsonParseError("bad escape");
                char e = s_[i_++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'n': out.push_back('\n'); break;
                    case 't': out.push_back('\t'); break;
                    case 'r': out.push_back('\r'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'u': {
                        if (i_ + 4 > s_.size()) throw JsonParseError("bad \\u");
                        // Keep the raw escape text; adequate for inspection.
                        out += "\\u";
                        out += s_.substr(i_, 4);
                        i_ += 4;
                        break;
                    }
                    default: throw JsonParseError("invalid escape");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    JsonValue parse_bool() {
        JsonValue v; v.type = JsonValue::Type::Bool;
        if (s_.compare(i_, 4, "true") == 0) { v.boolean = true; i_ += 4; }
        else if (s_.compare(i_, 5, "false") == 0) { v.boolean = false; i_ += 5; }
        else throw JsonParseError("invalid literal");
        return v;
    }

    JsonValue parse_null() {
        if (s_.compare(i_, 4, "null") == 0) { i_ += 4; return JsonValue{}; }
        throw JsonParseError("invalid literal");
    }

    JsonValue parse_number() {
        size_t start = i_;
        if (peek() == '-') ++i_;
        bool any = false;
        while (i_ < s_.size() && ((s_[i_] >= '0' && s_[i_] <= '9') || s_[i_] == '.' ||
                                  s_[i_] == 'e' || s_[i_] == 'E' || s_[i_] == '+' ||
                                  s_[i_] == '-')) {
            ++i_; any = true;
        }
        if (!any) throw JsonParseError("invalid number");
        JsonValue v; v.type = JsonValue::Type::Number;
        v.number = std::stod(s_.substr(start, i_ - start));
        return v;
    }
};

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

inline InspectionResult block(const std::string& reason, const std::string& pattern) {
    return InspectionResult{Decision::Block, reason, {pattern}};
}
inline InspectionResult allow(const std::string& reason) {
    return InspectionResult{Decision::Allow, reason, {}};
}

// Serialize a JSON value back to a compact string (for detector input).
inline std::string dump(const JsonValue& v) {
    switch (v.type) {
        case JsonValue::Type::Null:   return "null";
        case JsonValue::Type::Bool:   return v.boolean ? "true" : "false";
        case JsonValue::Type::Number: {
            std::string s = std::to_string(v.number);
            return s;
        }
        case JsonValue::Type::String: return "\"" + v.str + "\"";
        case JsonValue::Type::Array: {
            std::string s = "[";
            for (size_t k = 0; k < v.array.size(); ++k) {
                if (k) s += ",";
                s += dump(v.array[k]);
            }
            return s + "]";
        }
        case JsonValue::Type::Object: {
            std::string s = "{";
            for (size_t k = 0; k < v.object.size(); ++k) {
                if (k) s += ",";
                s += "\"" + v.object[k].first + "\":" + dump(v.object[k].second);
            }
            return s + "}";
        }
    }
    return "null";
}

inline InspectionResult inspect_value(const JsonValue& v, const Detector& detector) {
    if (v.type == JsonValue::Type::Array) {
        if (v.array.empty()) return block("Empty JSON-RPC batch", "malformed_jsonrpc");
        for (const auto& item : v.array) {
            InspectionResult r = inspect_value(item, detector);
            if (r.decision != Decision::Allow) return r;
        }
        return allow("Batch passed inspection");
    }
    if (v.type != JsonValue::Type::Object) {
        return block("Not a JSON-RPC request object", "malformed_jsonrpc");
    }
    const JsonValue* method = v.find("method");
    std::string method_str =
        (method && method->type == JsonValue::Type::String) ? method->str : "";
    if (method_str != "tools/call") {
        return allow("Non-tool-call method: " + (method_str.empty() ? "<none>" : method_str));
    }
    const JsonValue* params = v.find("params");
    std::string text = params ? dump(*params) : "";
    try {
        std::vector<std::string> patterns = detector(text);
        if (!patterns.empty()) {
            std::string joined;
            for (size_t k = 0; k < patterns.size(); ++k) {
                if (k) joined += ", ";
                joined += patterns[k];
            }
            return InspectionResult{Decision::Block,
                                    "Prompt injection detected: " + joined, patterns};
        }
        return allow("Tool call passed security inspection");
    } catch (const std::exception& e) {
        return InspectionResult{Decision::Indeterminate,
                                std::string("Detector failed: ") + e.what(), {}};
    }
}

// Inspect a raw JSON-RPC message. Fail-closed on every ambiguity.
inline InspectionResult inspect_message(const std::string& raw, const Detector& detector) {
    JsonValue v;
    try {
        JsonParser parser(raw);
        v = parser.parse();
    } catch (const std::exception& e) {
        return block(std::string("Invalid JSON: ") + e.what(), "malformed_jsonrpc");
    }
    if (v.duplicate_key) {
        return block("Invalid JSON: duplicate key", "malformed_jsonrpc");
    }
    return inspect_value(v, detector);
}

}  // namespace mcp

#endif  // MCP_INSPECT_HPP

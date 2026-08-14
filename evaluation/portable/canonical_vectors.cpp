#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

static std::vector<std::uint16_t> utf16_units(const std::string &s) {
    std::vector<std::uint16_t> out;
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        std::uint32_t cp;
        if (c < 0x80) { cp = c; i += 1; }
        else if ((c & 0xE0u) == 0xC0u) { cp = (c & 0x1Fu) << 6; cp |= static_cast<unsigned char>(s[i + 1]) & 0x3Fu; i += 2; }
        else if ((c & 0xF0u) == 0xE0u) { cp = (c & 0x0Fu) << 12; cp |= (static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 6; cp |= static_cast<unsigned char>(s[i + 2]) & 0x3Fu; i += 3; }
        else { cp = (c & 0x07u) << 18; cp |= (static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 12; cp |= (static_cast<unsigned char>(s[i + 2]) & 0x3Fu) << 6; cp |= static_cast<unsigned char>(s[i + 3]) & 0x3Fu; i += 4; }
        if (cp <= 0xFFFFu) out.push_back(static_cast<std::uint16_t>(cp));
        else {
            cp -= 0x10000u;
            out.push_back(static_cast<std::uint16_t>(0xD800u + (cp >> 10)));
            out.push_back(static_cast<std::uint16_t>(0xDC00u + (cp & 0x3FFu)));
        }
    }
    return out;
}

static bool utf16_less(const std::string &a, const std::string &b) {
    const auto au = utf16_units(a), bu = utf16_units(b);
    return std::lexicographical_compare(au.begin(), au.end(), bu.begin(), bu.end());
}

static std::string quoted(const std::string &s) {
    static const char *hex = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\f': out += "\\f"; break;
            case '\r': out += "\\r"; break;
            default:
                if (c <= 0x1F) {
                    out += "\\u00";
                    out += hex[(c >> 4) & 0x0F];
                    out += hex[c & 0x0F];
                } else out += static_cast<char>(c);
        }
    }
    out += '"';
    return out;
}

static void object_line(const std::string &name, std::vector<std::pair<std::string, std::string>> items) {
    std::sort(items.begin(), items.end(), [](const auto &a, const auto &b) { return utf16_less(a.first, b.first); });
    std::cout << name << "\t{";
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << quoted(items[i].first) << ':' << items[i].second;
    }
    std::cout << "}\n";
}

int main() {
    object_line("object_order", {{"b", "2"}, {"a", "1"}});
    std::cout << "string_escape\t" << quoted("line\n\"slash\\ snowman \xE2\x98\x83") << '\n';
    object_line("nested_limits", {{"z", "[true,false,null,-9007199254740991,9007199254740991]"}, {"a", "{\"k\":\"v\"}"}});
    object_line("utf16_order", {{"\xEE\x80\x80", "\"bmp\""}, {"\xF0\x9F\x98\x80", "\"astral\""}});
    object_line("empty", {{"array", "[]"}, {"object", "{}"}, {"null", "null"}});
    return 0;
}

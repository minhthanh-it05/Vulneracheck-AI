// Mẫu code an toàn — strncpy bên trong 1 function dài hơn, có logic parse
// config thật xung quanh, thay vì chỉ gọi rồi return ngay.

#include <cctype>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr size_t kMaxKeyLen = 64;
constexpr size_t kMaxValueLen = 256;

struct ConfigEntry {
    char key[kMaxKeyLen];
    char value[kMaxValueLen];
};

void TrimTrailingWhitespace(char *str) {
    size_t len = std::strlen(str);
    while (len > 0 && std::isspace(static_cast<unsigned char>(str[len - 1]))) {
        str[--len] = '\0';
    }
}

bool ParseConfigLine(const std::string &line, ConfigEntry &out_entry) {
    size_t separator_pos = line.find('=');
    if (separator_pos == std::string::npos) {
        return false;
    }

    size_t key_len = separator_pos;
    if (key_len == 0 || key_len >= kMaxKeyLen) {
        return false;
    }

    // SAFE: strncpy giới hạn theo kích thước buffer đích thật (kMaxKeyLen),
    // luôn null-terminate thủ công.
    strncpy(out_entry.key, line.c_str(), key_len);
    out_entry.key[key_len] = '\0';
    TrimTrailingWhitespace(out_entry.key);

    size_t value_start = separator_pos + 1;
    while (value_start < line.size() && (line[value_start] == ' ' || line[value_start] == '\t')) {
        value_start++;
    }

    strncpy(out_entry.value, line.c_str() + value_start, kMaxValueLen - 1);
    out_entry.value[kMaxValueLen - 1] = '\0';
    TrimTrailingWhitespace(out_entry.value);

    return true;
}

std::vector<ConfigEntry> LoadConfig(const std::vector<std::string> &raw_lines) {
    std::vector<ConfigEntry> entries;

    for (const auto &line : raw_lines) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        ConfigEntry entry;
        if (ParseConfigLine(line, entry)) {
            entries.push_back(entry);
        }
    }

    return entries;
}

}  // namespace

int main() {
    std::vector<std::string> raw_lines = {
        "# sample config file",
        "host = localhost",
        "port = 8080",
        "timeout_seconds = 30",
    };

    for (const auto &entry : LoadConfig(raw_lines)) {
        std::cout << entry.key << " = " << entry.value << std::endl;
    }

    return 0;
}

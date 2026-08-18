// Mẫu code an toàn — snprintf với validate độ dài trước khi ghi, mô phỏng
// gần hơn với code log-formatting thật trong 1 service C++.

#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

namespace {

constexpr size_t kLogLineMax = 256;

struct LogEntry {
    char buffer[kLogLineMax];
    size_t length = 0;
};

bool FormatLogEntry(LogEntry &entry, const std::string &level, const std::string &component,
                     const std::string &message) {
    std::time_t now = std::time(nullptr);
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    // SAFE: snprintf kiểm tra return value để phát hiện truncation thay vì
    // giả định buffer luôn đủ lớn cho message bất kỳ.
    int written = snprintf(entry.buffer, sizeof(entry.buffer), "[%s] %s/%s: %s", timestamp,
                                 level.c_str(), component.c_str(), message.c_str());

    if (written < 0) {
        entry.length = 0;
        return false;
    }

    entry.length = (static_cast<size_t>(written) >= sizeof(entry.buffer))
                       ? sizeof(entry.buffer) - 1
                       : static_cast<size_t>(written);
    return true;
}

void FlushLogEntry(const LogEntry &entry) {
    if (entry.length > 0) {
        std::cout.write(entry.buffer, static_cast<std::streamsize>(entry.length));
        std::cout << std::endl;
    }
}

}  // namespace

int main(int argc, char **argv) {
    LogEntry entry;
    std::string component = (argc > 1) ? argv[1] : "default-component";

    if (!FormatLogEntry(entry, "INFO", component, "service started successfully")) {
        std::cerr << "failed to format log entry" << std::endl;
        return 1;
    }

    FlushLogEntry(entry);
    return 0;
}

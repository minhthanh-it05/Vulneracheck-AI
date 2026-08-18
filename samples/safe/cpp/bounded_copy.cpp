// Mẫu code an toàn tương đương samples/vulnerable/cpp/buffer_overflow.cpp.

#include <cstring>
#include <iostream>
#include <string>

void copy_input(const char *user_input) {
    char buffer[64];
    // SAFE: strncpy giới hạn số byte copy theo kích thước buffer, luôn null-terminate
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    std::cout << buffer << std::endl;
}

void run_backup(const std::string &filename) {
    // SAFE: dùng std::string ghép trực tiếp, không gọi ra shell
    std::string archive_name = "backup_" + filename + ".tar.gz";
    std::cout << "Archiving to " << archive_name << std::endl;
}

int main() {
    char buffer[64] = {0};
    copy_input(buffer);
    return 0;
}

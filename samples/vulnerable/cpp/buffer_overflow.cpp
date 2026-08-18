// Mẫu code có lỗ hổng buffer overflow + command injection (CWE-120, CWE-78) —
// dùng để test phát hiện.

#include <cstring>
#include <cstdlib>
#include <iostream>

void copy_input(const char *user_input) {
    char buffer[64];
    // VULNERABLE: strcpy không kiểm tra độ dài, user_input dài hơn buffer sẽ overflow
    strcpy(buffer, user_input);
    std::cout << buffer << std::endl;
}

void run_backup(const std::string &filename) {
    // VULNERABLE: std::system nối trực tiếp input người dùng vào lệnh shell
    std::system(("tar -czf backup.tar.gz " + filename).c_str());
}

int main() {
    char *buffer = new char[64];
    copy_input(buffer);
    // VULNERABLE: delete không kiểm tra buffer đã bị free trước đó hay chưa
    delete[] buffer;
    return 0;
}

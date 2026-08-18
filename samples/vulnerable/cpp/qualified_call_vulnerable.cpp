// Mẫu code có lỗ hổng buffer overflow (CWE-120, CWE-787, CWE-125) — gọi qua
// namespace-qualified (std::strcpy/std::sprintf), dùng để test rule
// cpp_sinks.scm bắt được cả dạng gọi std:: tường minh, không chỉ dạng gọi
// trực tiếp strcpy(...)/sprintf(...) (rất phổ biến trong code C++ hiện đại
// dùng std:: tường minh thay vì `using namespace std;`).

#include <cstdio>
#include <cstring>
#include <string>

void copy_username(const char *raw_username) {
    char username[32];
    // VULNERABLE: std::strcpy không kiểm tra độ dài, raw_username dài hơn
    // buffer sẽ overflow — giống hệt strcpy(...) không qualify, chỉ khác
    // cách gọi.
    std::strcpy(username, raw_username);
    std::printf("welcome, %s\n", username);
}

void format_greeting(const std::string &name) {
    char greeting[64];
    // VULNERABLE: std::sprintf không giới hạn độ dài output, name dài sẽ
    // overflow greeting.
    std::sprintf(greeting, "hello, %s!", name.c_str());
    std::printf("%s\n", greeting);
}

int main() {
    char input[128];
    if (std::fgets(input, sizeof(input), stdin) != nullptr) {
        copy_username(input);
        format_greeting(input);
    }
    return 0;
}

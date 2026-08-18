/* Mẫu code có lỗ hổng buffer overflow (CWE-120, CWE-787) — dùng để test phát hiện. */

#include <stdio.h>
#include <string.h>

void copy_input(const char *user_input) {
    char buffer[64];
    /* VULNERABLE: strcpy không kiểm tra độ dài, user_input dài hơn buffer sẽ overflow */
    strcpy(buffer, user_input);
    printf("%s\n", buffer);
}

int main(void) {
    char name[32];
    /* VULNERABLE: gets() không giới hạn độ dài input */
    gets(name);
    copy_input(name);
    return 0;
}

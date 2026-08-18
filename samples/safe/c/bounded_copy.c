/* Mẫu code an toàn tương đương samples/vulnerable/c/buffer_overflow.c. */

#include <stdio.h>
#include <string.h>

void copy_input(const char *user_input) {
    char buffer[64];
    /* SAFE: strncpy giới hạn số byte copy theo kích thước buffer, luôn null-terminate */
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("%s\n", buffer);
}

int main(void) {
    char name[32];
    /* SAFE: fgets giới hạn số byte đọc vào, tránh overflow như gets() */
    if (fgets(name, sizeof(name), stdin) != NULL) {
        copy_input(name);
    }
    return 0;
}

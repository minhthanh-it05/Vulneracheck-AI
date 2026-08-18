/*
 * Mẫu code an toàn — strncpy bên trong 1 function dài hơn, có logic xử lý
 * thật xung quanh (parse config line, validate, loop), thay vì chỉ gọi rồi
 * return ngay như sample tối giản ban đầu.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_KEY_LEN 64
#define MAX_VALUE_LEN 256
#define MAX_ENTRIES 32

typedef struct {
    char key[MAX_KEY_LEN];
    char value[MAX_VALUE_LEN];
} config_entry_t;

static void trim_whitespace(char *str) {
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
}

static int parse_config_line(const char *line, config_entry_t *out_entry) {
    const char *separator = strchr(line, '=');
    if (separator == NULL) {
        return -1;
    }

    size_t key_len = (size_t)(separator - line);
    if (key_len == 0 || key_len >= MAX_KEY_LEN) {
        return -1;
    }

    /* SAFE: strncpy giới hạn theo kích thước buffer đích thật (MAX_KEY_LEN),
     * luôn null-terminate thủ công vì strncpy không đảm bảo điều đó khi
     * nguồn dài bằng đúng n. */
    strncpy(out_entry->key, line, key_len);
    out_entry->key[key_len] = '\0';
    trim_whitespace(out_entry->key);

    const char *value_start = separator + 1;
    while (*value_start == ' ' || *value_start == '\t') {
        value_start++;
    }

    strncpy(out_entry->value, value_start, MAX_VALUE_LEN - 1);
    out_entry->value[MAX_VALUE_LEN - 1] = '\0';
    trim_whitespace(out_entry->value);

    return 0;
}

int load_config(const char *raw_lines[], size_t line_count, config_entry_t entries[],
                 size_t max_entries) {
    size_t parsed = 0;

    for (size_t i = 0; i < line_count && parsed < max_entries; i++) {
        if (raw_lines[i] == NULL || raw_lines[i][0] == '#' || raw_lines[i][0] == '\0') {
            continue;
        }
        if (parse_config_line(raw_lines[i], &entries[parsed]) == 0) {
            parsed++;
        }
    }

    return (int)parsed;
}

int main(void) {
    const char *raw_lines[] = {
        "# sample config file",
        "host = localhost",
        "port = 8080",
        "timeout_seconds = 30",
    };
    config_entry_t entries[MAX_ENTRIES];

    int count = load_config(raw_lines, sizeof(raw_lines) / sizeof(raw_lines[0]), entries,
                             MAX_ENTRIES);

    for (int i = 0; i < count; i++) {
        printf("%s = %s\n", entries[i].key, entries[i].value);
    }

    return 0;
}

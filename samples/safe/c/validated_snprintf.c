/*
 * Mẫu code an toàn — snprintf với validate độ dài trước khi ghi, mô phỏng
 * gần hơn với code log-formatting thật trong 1 service (không chỉ gọi rồi
 * return ngay như sample tối giản trước đó).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_LINE_MAX 256

typedef struct {
    char buffer[LOG_LINE_MAX];
    size_t length;
} log_entry_t;

static int format_log_entry(log_entry_t *entry, const char *level, const char *component,
                             const char *message) {
    if (entry == NULL || level == NULL || component == NULL || message == NULL) {
        return -1;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    /* SAFE: snprintf trả về số byte LẼ RA đã ghi (có thể > buffer size),
     * kiểm tra return value để phát hiện truncation thay vì tin tưởng mù
     * quáng vào buffer đủ lớn. */
    int written = snprintf(entry->buffer, sizeof(entry->buffer), "[%s] %s/%s: %s", timestamp,
                            level, component, message);

    if (written < 0) {
        entry->length = 0;
        return -1;
    }

    if ((size_t)written >= sizeof(entry->buffer)) {
        /* Message bị cắt bớt — vẫn an toàn (không overflow), chỉ log ngắn hơn. */
        entry->length = sizeof(entry->buffer) - 1;
    } else {
        entry->length = (size_t)written;
    }

    return 0;
}

static void flush_log_entry(const log_entry_t *entry) {
    if (entry != NULL && entry->length > 0) {
        fwrite(entry->buffer, 1, entry->length, stdout);
        fputc('\n', stdout);
    }
}

int main(int argc, char **argv) {
    log_entry_t entry;
    const char *component = argc > 1 ? argv[1] : "default-component";

    if (format_log_entry(&entry, "INFO", component, "service started successfully") != 0) {
        fprintf(stderr, "failed to format log entry\n");
        return EXIT_FAILURE;
    }

    flush_log_entry(&entry);
    return EXIT_SUCCESS;
}

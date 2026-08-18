; Tree-sitter query: dangerous sinks in C source
; High-recall: chỉ match tên hàm gọi, KHÔNG cố phân tích context/đã sanitize
; hay chưa — việc đó để Layer 3 (verifier) quyết định.

; Buffer overflow / unbounded copy (CWE-120, CWE-787, CWE-125)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "^(strcpy|strcat|sprintf|vsprintf|gets|scanf|stpcpy|wcscpy|wcscat)$"))

; Memory-unsafe operations (CWE-119, CWE-416, CWE-476)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "^(memcpy|memmove|memset|alloca|strncpy|strncat|realloc|free)$"))

; Format string (CWE-134) — không phân biệt format string có phải literal
; hay không ở Layer 2 (quá phức tạp cho query đơn giản), để Layer 3 xử lý.
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "^(printf|fprintf|snprintf|syslog|vfprintf)$"))

; Command/process injection (CWE-78, CWE-88)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "^(system|popen|exec|execl|execlp|execle|execv|execvp|execve|ShellExecute[AW]?|CreateProcess[AW]?)$"))

; malloc/calloc — nguy cơ integer overflow khi cấp phát bộ nhớ (CWE-190 kết
; hợp CWE-789). Match TẤT CẢ lời gọi, không lọc theo dạng tham số (literal,
; biến, hay biểu thức). Đây là quyết định thiết kế có chủ đích, KHÔNG PHẢI
; thiếu sót: lọc theo argument_list là binary_expression trực tiếp sẽ bỏ sót
; đúng case nguy hiểm phổ biến nhất — size đã bị taint từ một lời gọi trước
; đó (vd. `int size = get_user_input(); malloc(size);`), vì đó là một
; identifier chứ không phải binary_expression ngay trong lời gọi. Tree-sitter
; query ở Layer 2 không truy vết được taint qua nhiều dòng, nên match rộng
; theo đúng triết lý high-recall và để Layer 3 quyết định.
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "^(malloc|calloc)$"))

; Tree-sitter query: dangerous sinks in C source
; High-recall: chỉ match tên hàm gọi, KHÔNG cố phân tích context/đã sanitize
; hay chưa — việc đó để Layer 3 (verifier) quyết định.
;
; Mỗi #match? predicate có 2 nhánh nối bằng "|", cùng phục vụ mục tiêu bắt
; wrapper function tự định nghĩa bọc quanh hàm libc gốc (phát hiện qua thực
; nghiệm trên mpack — dùng mpack_memcpy thay vì memcpy trực tiếp, Layer 2 cũ
; bỏ sót hoàn toàn):
;
;   1. "(^|_)(...)($|_)" — dạng snake_case: yêu cầu tên sink là 1 thành phần
;      tách biệt bằng underscore (đầu/cuối chuỗi hoặc liền kề "_"). Bắt
;      mpack_memcpy, safe_strcpy, my_malloc_wrapper.
;   2. "(^|[a-z0-9_])(?=[A-Z])(?i:...)($|[A-Z]|[^a-zA-Z0-9])" — dạng
;      camelCase/PascalCase: biên trái là start-of-string/chữ thường/số/"_"
;      (không phải chữ hoa — tránh dính 2 chữ hoa liền kề kiểu viết tắt, vd.
;      "XStrcpy"), NGAY SAU biên trái phải là 1 chữ hoa (lookahead
;      "(?=[A-Z])" — đúng nghĩa "chữ cái đầu viết hoa ngay sau ranh giới
;      từ"), rồi so khớp tên sink KHÔNG phân biệt hoa/thường qua "(?i:...)"
;      (nên "StrCpy" — viết hoa cả 2 "hump" — vẫn khớp "strcpy", không chỉ
;      riêng dạng "Strcpy" hoa mỗi chữ đầu), biên phải là end-of-string/chữ
;      hoa tiếp theo (hump mới)/ký tự không phải chữ-số. Bắt mpackMemcpy,
;      safeStrCpy, MemcpyWrapper — xem docs/model_card.md mục "False-negative
;      gap ở Layer 2" để biết thực nghiệm và giới hạn còn lại (wrapper không
;      chứa tên sink gốc dưới bất kỳ dạng nào, vd. "safeCopy", vẫn bị bỏ sót
;      — giới hạn cố hữu của cách tiếp cận match-theo-tên).
;
; Regex engine của tree-sitter #match? hỗ trợ lookahead/lookbehind và scoped
; case-insensitive group "(?i:...)" — đã kiểm chứng thực nghiệm bằng chính
; tree_sitter binding của dự án trước khi viết vào đây.
;
; Cả 2 nhánh: KHÔNG match substring dính liền không có ranh giới (vd.
; "mallocator", "freetype_init", "somestrcpycall" — toàn chữ thường, không
; có điểm chuyển hoa nào để nhánh 2 bắt, và không có "_" để nhánh 1 bắt).
; Đánh đổi: bắt rộng hơn = tăng false positive tiềm năng, chấp nhận được
; theo triết lý high-recall của Layer 2 (Layer 3 lọc precision sau).

; Buffer overflow / unbounded copy (CWE-120, CWE-787, CWE-125)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(strcpy|strcat|sprintf|vsprintf|gets|scanf|stpcpy|wcscpy|wcscat)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:strcpy|strcat|sprintf|vsprintf|gets|scanf|stpcpy|wcscpy|wcscat)($|[A-Z]|[^a-zA-Z0-9])"))

; Memory-unsafe operations (CWE-119, CWE-416, CWE-476)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(memcpy|memmove|memset|alloca|strncpy|strncat|realloc|free)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:memcpy|memmove|memset|alloca|strncpy|strncat|realloc|free)($|[A-Z]|[^a-zA-Z0-9])"))

; Format string (CWE-134) — không phân biệt format string có phải literal
; hay không ở Layer 2 (quá phức tạp cho query đơn giản), để Layer 3 xử lý.
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(printf|fprintf|snprintf|syslog|vfprintf)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:printf|fprintf|snprintf|syslog|vfprintf)($|[A-Z]|[^a-zA-Z0-9])"))

; Command/process injection (CWE-78, CWE-88)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(system|popen|exec|execl|execlp|execle|execv|execvp|execve|ShellExecute[AW]?|CreateProcess[AW]?)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:system|popen|exec|execl|execlp|execle|execv|execvp|execve|ShellExecute[AW]?|CreateProcess[AW]?)($|[A-Z]|[^a-zA-Z0-9])"))

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
  (#match? @sink.name "(^|_)(malloc|calloc)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:malloc|calloc)($|[A-Z]|[^a-zA-Z0-9])"))

; Tree-sitter query: dangerous sinks in C++ source
; High-recall: chỉ match tên hàm gọi, KHÔNG cố phân tích context/đã sanitize
; hay chưa — việc đó để Layer 3 (verifier) quyết định.
;
; Tách riêng khỏi rules/c/c_sinks.scm vì grammar C++ có thêm delete/delete[]
; (không tồn tại trong grammar C) và namespace-qualified call (vd. std::system)
; mà grammar C không có.
;
; Mỗi nhóm 1/2/3 có 2 pattern song song: gọi trực tiếp (vd. strcpy(...)) và
; gọi qua namespace-qualified (vd. std::strcpy(...)) — code C++ hiện đại rất
; hay gọi tường minh qua std::, cả 2 dạng đều phải được forward lên Layer 3.
;
; Predicate #match? dùng dạng "(^|_)(...)($|_)" thay vì exact-match "^(...)$":
; bắt được cả wrapper function tự định nghĩa bọc quanh hàm libc gốc (vd.
; mpack_memcpy, safe_strcpy, my_malloc_wrapper) — phát hiện qua thực nghiệm
; trên mpack (dùng mpack_memcpy thay vì memcpy trực tiếp, Layer 2 cũ bỏ sót
; hoàn toàn). Yêu cầu tên sink phải là 1 thành phần tách biệt bằng underscore
; (đầu/cuối chuỗi hoặc liền kề "_"), KHÔNG match substring dính liền (vd.
; "mallocator", "freetype_init" không bị match nhầm). Đánh đổi: bắt rộng hơn
; = tăng false positive tiềm năng, chấp nhận được theo triết lý high-recall
; của Layer 2 (Layer 3 lọc precision sau).

; Buffer overflow / unbounded copy (CWE-120, CWE-787, CWE-125) — gọi trực tiếp
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(strcpy|strcat|sprintf|vsprintf|gets|scanf|stpcpy|wcscpy|wcscat)($|_)"))

; Buffer overflow / unbounded copy (CWE-120, CWE-787, CWE-125) — qua
; namespace-qualified call (vd. std::strcpy(...))
(call_expression
  function: (qualified_identifier
    name: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(strcpy|strcat|sprintf|vsprintf|gets|scanf|stpcpy|wcscpy|wcscat)($|_)"))

; Memory-unsafe operations (CWE-119, CWE-416, CWE-476) — gọi trực tiếp
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(memcpy|memmove|memset|alloca|strncpy|strncat|realloc|free)($|_)"))

; Memory-unsafe operations (CWE-119, CWE-416, CWE-476) — qua
; namespace-qualified call (vd. std::memcpy(...))
(call_expression
  function: (qualified_identifier
    name: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(memcpy|memmove|memset|alloca|strncpy|strncat|realloc|free)($|_)"))

; delete / delete[] (CWE-416, CWE-476) — riêng của C++, không có trong C.
; Không phân biệt object có bị double-free/dangling sau đó hay không.
; Lưu ý: grammar tree-sitter-cpp không đặt field name cho toán hạng của
; delete_expression (chỉ là child vị trí), nên capture cả node làm sink.args
; thay vì trích riêng toán hạng.
(delete_expression "delete" @sink.name) @sink.args

; Format string (CWE-134) — gọi trực tiếp. Không phân biệt format string có
; phải literal hay không ở Layer 2 (quá phức tạp cho query đơn giản), để
; Layer 3 xử lý.
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(printf|fprintf|snprintf|syslog|vfprintf)($|_)"))

; Format string (CWE-134) — qua namespace-qualified call (vd. std::printf(...))
(call_expression
  function: (qualified_identifier
    name: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(printf|fprintf|snprintf|syslog|vfprintf)($|_)"))

; Command/process injection (CWE-78, CWE-88) — gọi trực tiếp (không qua namespace)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(system|popen|exec|execl|execlp|execle|execv|execvp|execve|ShellExecute[AW]?|CreateProcess[AW]?)($|_)"))

; Command/process injection qua namespace-qualified call (CWE-78, CWE-88) —
; vd. std::system(...)
(call_expression
  function: (qualified_identifier
    name: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(system|popen|exec|execl|execlp|execle|execv|execvp|execve)($|_)"))

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
  (#match? @sink.name "(^|_)(malloc|calloc)($|_)"))

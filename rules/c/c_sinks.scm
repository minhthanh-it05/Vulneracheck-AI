; Tree-sitter query: dangerous sinks in C source
; High-recall: only matches the called function's name, does NOT try to
; analyze whether the context is already sanitized — that's Layer 3's
; (verifier) decision.
;
; Each #match? predicate has 2 branches joined by "|", both serving the
; goal of catching self-defined wrapper functions around the original libc
; function (discovered experimentally on mpack — using mpack_memcpy instead
; of memcpy directly, the old Layer 2 missed it completely):
;
;   1. "(^|_)(...)($|_)" — snake_case form: requires the sink name to be a
;      component separated by an underscore (at the start/end of the string
;      or adjacent to "_"). Catches mpack_memcpy, safe_strcpy, my_malloc_wrapper.
;   2. "(^|[a-z0-9_])(?=[A-Z])(?i:...)($|[A-Z]|[^a-zA-Z0-9])" — camelCase/
;      PascalCase form: the left boundary is start-of-string/lowercase
;      letter/digit/"_" (not an uppercase letter — avoids matching 2
;      adjacent uppercase letters like an acronym, e.g. "XStrcpy"),
;      IMMEDIATELY AFTER the left boundary must be an uppercase letter
;      (lookahead "(?=[A-Z])" — precisely meaning "the first letter is
;      uppercase, right after a word boundary"), then case-insensitively
;      matches the sink name via "(?i:...)" (so "StrCpy" — both "humps"
;      capitalized — still matches "strcpy", not just the "Strcpy" form
;      with only the first letter capitalized); the right boundary is
;      end-of-string/next uppercase letter (a new hump)/a non-alphanumeric
;      character. Catches mpackMemcpy, safeStrCpy, MemcpyWrapper — see
;      docs/model_card.md, section "False-negative gap in Layer 2", for the
;      experiment and the remaining limitation (a wrapper that doesn't
;      contain the original sink name in any form at all, e.g. "safeCopy",
;      is still missed — an inherent limitation of the name-matching approach).
;
; Tree-sitter's #match? regex engine supports lookahead/lookbehind and a
; scoped case-insensitive group "(?i:...)" — verified experimentally using
; the project's own tree_sitter binding before being written in here.
;
; Both branches: do NOT match an unrelated adjacent substring with no
; boundary (e.g. "mallocator", "freetype_init", "somestrcpycall" — all
; lowercase, with no case-transition point for branch 2 to catch, and no
; "_" for branch 1 to catch). Trade-off: broader matching = more potential
; false positives, acceptable per Layer 2's high-recall philosophy
; throughout the project (Layer 3 filters for precision afterward).

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

; Format string (CWE-134) — does not distinguish whether the format string
; is a literal or not at Layer 2 (too complex for a simple query), left to Layer 3.
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(printf|fprintf|snprintf|syslog|vfprintf)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:printf|fprintf|snprintf|syslog|vfprintf)($|[A-Z]|[^a-zA-Z0-9])"))

; Command/process injection (CWE-78, CWE-88)
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(system|popen|exec|execl|execlp|execle|execv|execvp|execve|ShellExecute[AW]?|CreateProcess[AW]?)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:system|popen|exec|execl|execlp|execle|execv|execvp|execve|ShellExecute[AW]?|CreateProcess[AW]?)($|[A-Z]|[^a-zA-Z0-9])"))

; malloc/calloc — integer overflow risk when allocating memory (CWE-190
; combined with CWE-789). Matches ALL calls, without filtering by argument
; form (literal, variable, or expression). This is a deliberate design
; decision, NOT an oversight: filtering by whether argument_list is
; directly a binary_expression would miss the most common dangerous case —
; a size already tainted from an earlier call (e.g. `int size =
; get_user_input(); malloc(size);`), since that's an identifier, not a
; binary_expression right in the call. The Tree-sitter query at Layer 2
; cannot trace taint across multiple lines, so it matches broadly per the
; high-recall philosophy and lets Layer 3 decide.
(call_expression
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "(^|_)(malloc|calloc)($|_)|(^|[a-z0-9_])(?=[A-Z])(?i:malloc|calloc)($|[A-Z]|[^a-zA-Z0-9])"))

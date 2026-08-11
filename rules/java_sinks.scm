; Tree-sitter query: dangerous sinks in Java source
; Matches common injection / deserialization / command-execution sinks.

; Runtime.getRuntime().exec(...)
(method_invocation
  object: (method_invocation
    object: (identifier) @_runtime
    name: (identifier) @_getRuntime)
  name: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#eq? @_runtime "Runtime")
  (#eq? @_getRuntime "getRuntime")
  (#eq? @sink.name "exec"))

; ProcessBuilder(...).start()
(method_invocation
  object: (object_creation_expression
    type: (type_identifier) @_type)
  name: (identifier) @sink.name
  (#eq? @_type "ProcessBuilder")
  (#eq? @sink.name "start"))

; Statement.execute*(...) — raw SQL execution
(method_invocation
  name: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "^(execute|executeQuery|executeUpdate)$"))

; ObjectInputStream.readObject() — insecure deserialization
(method_invocation
  object: (identifier) @_stream
  name: (identifier) @sink.name
  (#eq? @sink.name "readObject"))

; XMLDecoder(...) — XXE / deserialization
(object_creation_expression
  type: (type_identifier) @sink.name
  (#eq? @sink.name "XMLDecoder"))

; MessageDigest.getInstance("MD5"/"SHA1") — weak hashing
(method_invocation
  object: (identifier) @_md
  name: (identifier) @sink.name
  arguments: (argument_list (string_literal) @sink.args)
  (#eq? @_md "MessageDigest")
  (#eq? @sink.name "getInstance")
  (#match? @sink.args "\"(MD5|SHA1|SHA-1)\""))

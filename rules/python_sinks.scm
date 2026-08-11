; Tree-sitter query: dangerous sinks in Python source
; Matches common injection / deserialization / command-execution sinks.

; os.system(...) / os.popen(...)
(call
  function: (attribute
    object: (identifier) @_module
    attribute: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#eq? @_module "os")
  (#match? @sink.name "^(system|popen)$"))

; subprocess.* with shell=True
(call
  function: (attribute
    object: (identifier) @_module
    attribute: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#eq? @_module "subprocess")
  (#match? @sink.name "^(call|run|Popen|check_output|check_call)$"))

; eval(...) / exec(...)
(call
  function: (identifier) @sink.name
  arguments: (argument_list) @sink.args
  (#match? @sink.name "^(eval|exec)$"))

; pickle.loads(...) / pickle.load(...)
(call
  function: (attribute
    object: (identifier) @_module
    attribute: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#eq? @_module "pickle")
  (#match? @sink.name "^(loads|load)$"))

; yaml.load(...) without SafeLoader
(call
  function: (attribute
    object: (identifier) @_module
    attribute: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#eq? @_module "yaml")
  (#eq? @sink.name "load"))

; raw SQL string formatting via cursor.execute(...)
(call
  function: (attribute
    object: (identifier) @_cursor
    attribute: (identifier) @sink.name)
  arguments: (argument_list) @sink.args
  (#eq? @sink.name "execute"))

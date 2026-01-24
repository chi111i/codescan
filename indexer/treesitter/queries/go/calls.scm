; Go 函数调用提取查询
; 按功能分类: calls.scm

; ==========================================
; 普通函数调用
; ==========================================

; functionName(args)
(call_expression
  function: (identifier) @call.name
  arguments: (argument_list) @call.args) @call

; ==========================================
; 包/对象方法调用
; ==========================================

; package.Function(args)
(call_expression
  function: (selector_expression
    operand: (identifier) @call.package
    field: (field_identifier) @call.method)
  arguments: (argument_list) @call.args) @call.qualified

; object.Method(args)
(call_expression
  function: (selector_expression
    operand: (_) @call.object
    field: (field_identifier) @call.method)) @call.method_call

; ==========================================
; 链式调用
; ==========================================

; obj.Method1().Method2()
(call_expression
  function: (selector_expression
    operand: (call_expression) @call.chain_object
    field: (field_identifier) @call.chain_method)) @call.chained

; ==========================================
; Goroutine
; ==========================================

; go func()
(go_statement
  (call_expression
    function: (_) @go.func)) @go

; go func() { }()
(go_statement
  (call_expression
    function: (func_literal) @go.closure)) @go.anonymous

; ==========================================
; Defer
; ==========================================

; defer func()
(defer_statement
  (call_expression
    function: (_) @defer.func)) @defer

; ==========================================
; 危险调用模式
; ==========================================

; exec.Command(...)
(call_expression
  function: (selector_expression
    operand: (identifier) @danger.exec
    (#eq? @danger.exec "exec")
    field: (field_identifier) @danger.command
    (#eq? @danger.command "Command"))) @danger.rce

; os.StartProcess(...)
(call_expression
  function: (selector_expression
    operand: (identifier) @danger.os
    (#eq? @danger.os "os")
    field: (field_identifier) @danger.start
    (#eq? @danger.start "StartProcess"))) @danger.process

; db.Query(...) / db.Exec(...)
(call_expression
  function: (selector_expression
    field: (field_identifier) @danger.sql
    (#match? @danger.sql "^(Query|QueryRow|Exec)$"))) @danger.sql_call

; http.Get(...) / http.Post(...)
(call_expression
  function: (selector_expression
    operand: (identifier) @danger.http
    (#eq? @danger.http "http")
    field: (field_identifier) @danger.method
    (#match? @danger.method "^(Get|Post|Do)$"))) @danger.ssrf

; os.Open(...) / os.ReadFile(...)
(call_expression
  function: (selector_expression
    operand: (identifier) @danger.os_file
    (#eq? @danger.os_file "os")
    field: (field_identifier) @danger.file_op
    (#match? @danger.file_op "^(Open|OpenFile|Create|ReadFile|WriteFile)$"))) @danger.file

; json.Unmarshal(...) / xml.Unmarshal(...)
(call_expression
  function: (selector_expression
    operand: (identifier) @danger.marshal
    (#match? @danger.marshal "^(json|xml|gob|yaml)$")
    field: (field_identifier) @danger.unmarshal
    (#eq? @danger.unmarshal "Unmarshal"))) @danger.deserialize

; template.HTML(...) - 潜在 XSS
(call_expression
  function: (selector_expression
    operand: (identifier) @danger.template
    (#eq? @danger.template "template")
    field: (field_identifier) @danger.html
    (#match? @danger.html "^(HTML|JS|URL)$"))) @danger.xss

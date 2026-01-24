; JavaScript 函数调用提取查询
; 按功能分类: calls.scm

; ==========================================
; 简单函数调用
; ==========================================

; func()
(call_expression
  function: (identifier) @call.name
  arguments: (arguments) @call.args) @call

; ==========================================
; 方法调用
; ==========================================

; obj.method()
(call_expression
  function: (member_expression
    object: (identifier) @call.object
    property: (property_identifier) @call.method)
  arguments: (arguments) @call.args) @call.member

; obj.prop.method()
(call_expression
  function: (member_expression
    object: (member_expression) @call.chain
    property: (property_identifier) @call.method)
  arguments: (arguments) @call.args) @call.chained

; this.method()
(call_expression
  function: (member_expression
    object: (this) @call.this
    property: (property_identifier) @call.method)
  arguments: (arguments) @call.args) @call.this_method

; ==========================================
; 可选链调用
; ==========================================

; obj?.method()
(call_expression
  function: (member_expression
    object: (_) @call.object
    "?." @call.optional
    property: (property_identifier) @call.method)) @call.optional_chain

; ==========================================
; 动态调用
; ==========================================

; obj[key]()
(call_expression
  function: (subscript_expression
    object: (_) @call.dynamic_object
    index: (_) @call.dynamic_key)
  arguments: (arguments) @call.args) @call.dynamic

; ==========================================
; 构造函数调用
; ==========================================

; new Class()
(new_expression
  constructor: (identifier) @new.class
  arguments: (arguments)? @new.args) @new

; new module.Class()
(new_expression
  constructor: (member_expression
    object: (_) @new.module
    property: (property_identifier) @new.class)
  arguments: (arguments)? @new.args) @new.member

; ==========================================
; 立即执行函数
; ==========================================

; (function() {})()
(call_expression
  function: (parenthesized_expression
    (function_expression))) @call.iife

; (() => {})()
(call_expression
  function: (parenthesized_expression
    (arrow_function))) @call.iife_arrow

; ==========================================
; 模板字符串标签调用
; ==========================================

; tag`string`
(call_expression
  function: (identifier) @call.tag
  arguments: (template_string)) @call.tagged_template

; ==========================================
; await 调用
; ==========================================

; await func()
(await_expression
  (call_expression
    function: (identifier) @call.await_name)) @call.await

; await obj.method()
(await_expression
  (call_expression
    function: (member_expression
      property: (property_identifier) @call.await_method))) @call.await_member

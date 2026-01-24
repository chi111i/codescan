; PHP 函数调用提取查询
; 按功能分类: calls.scm

; ==========================================
; 普通函数调用
; ==========================================

; func_name($args)
(function_call_expression
  function: (name) @call.name
  arguments: (arguments) @call.args) @call

; ==========================================
; 方法调用
; ==========================================

; $obj->method($args)
(member_call_expression
  object: (_) @call.object
  name: (name) @call.method
  arguments: (arguments) @call.args) @call.member

; $this->method($args)
(member_call_expression
  object: (variable_name) @call.this
  (#eq? @call.this "$this")
  name: (name) @call.method) @call.this_method

; $obj?->method($args) (nullsafe)
(nullsafe_member_call_expression
  object: (_) @call.object
  name: (name) @call.method
  arguments: (arguments) @call.args) @call.nullsafe

; ==========================================
; 静态方法调用
; ==========================================

; ClassName::method($args)
(scoped_call_expression
  scope: (name) @call.class
  name: (name) @call.static_method
  arguments: (arguments) @call.args) @call.static

; self::method($args)
(scoped_call_expression
  scope: (relative_scope) @call.self
  (#eq? @call.self "self")
  name: (name) @call.method) @call.self_method

; parent::method($args)
(scoped_call_expression
  scope: (relative_scope) @call.parent
  (#eq? @call.parent "parent")
  name: (name) @call.method) @call.parent_method

; static::method($args)
(scoped_call_expression
  scope: (relative_scope) @call.static_scope
  (#eq? @call.static_scope "static")
  name: (name) @call.method) @call.late_static

; \Namespace\Class::method($args)
(scoped_call_expression
  scope: (qualified_name) @call.qualified_class
  name: (name) @call.method) @call.qualified_static

; ==========================================
; 对象创建
; ==========================================

; new ClassName($args)
(object_creation_expression
  (name) @new.class
  arguments: (arguments)? @new.args) @new

; new \Namespace\ClassName($args)
(object_creation_expression
  (qualified_name) @new.qualified_class
  arguments: (arguments)? @new.args) @new.qualified

; new $variable($args)
(object_creation_expression
  (variable_name) @new.dynamic_class) @new.dynamic

; ==========================================
; 动态调用
; ==========================================

; $obj->$method($args)
(member_call_expression
  object: (_) @call.object
  name: (variable_name) @call.dynamic_method) @call.dynamic

; ClassName::$method($args)
(scoped_call_expression
  scope: (name) @call.class
  name: (variable_name) @call.dynamic_method) @call.dynamic_static

; $func($args)
(function_call_expression
  function: (variable_name) @call.dynamic_func
  arguments: (arguments) @call.args) @call.dynamic_call

; ==========================================
; 可调用对象
; ==========================================

; $obj($args) - __invoke
(function_call_expression
  function: (variable_name) @call.invokable
  arguments: (arguments) @call.args) @call.invoke

; ==========================================
; 链式调用
; ==========================================

; $obj->method1()->method2()
(member_call_expression
  object: (member_call_expression) @call.chain_object
  name: (name) @call.chain_method) @call.chained

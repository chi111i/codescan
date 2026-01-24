; Java 方法调用提取查询
; 按功能分类: calls.scm

; ==========================================
; 方法调用
; ==========================================

; object.method(args)
(method_invocation
  object: (_) @call.object
  name: (identifier) @call.method
  arguments: (argument_list) @call.args) @call

; method(args) - 无对象的方法调用
(method_invocation
  name: (identifier) @call.method
  arguments: (argument_list) @call.args) @call.simple

; this.method(args)
(method_invocation
  object: (this) @call.this
  name: (identifier) @call.method) @call.this_method

; super.method(args)
(method_invocation
  object: (super) @call.super
  name: (identifier) @call.method) @call.super_method

; ==========================================
; 静态方法调用
; ==========================================

; ClassName.staticMethod(args)
(method_invocation
  object: (identifier) @call.class
  name: (identifier) @call.static_method) @call.static

; package.ClassName.staticMethod(args)
(method_invocation
  object: (field_access
    object: (_) @call.package
    field: (identifier) @call.class)
  name: (identifier) @call.method) @call.qualified

; ==========================================
; 对象创建
; ==========================================

; new ClassName(args)
(object_creation_expression
  type: (type_identifier) @new.class
  arguments: (argument_list) @new.args) @new

; new package.ClassName(args)
(object_creation_expression
  type: (scoped_type_identifier) @new.qualified_class
  arguments: (argument_list) @new.args) @new.qualified

; new ClassName<T>(args) - 泛型
(object_creation_expression
  type: (generic_type
    (type_identifier) @new.generic_class)) @new.generic

; ==========================================
; 链式调用
; ==========================================

; obj.method1().method2()
(method_invocation
  object: (method_invocation) @call.chain_object
  name: (identifier) @call.chain_method) @call.chained

; builder.setX().setY().build()
(method_invocation
  object: (method_invocation
    object: (method_invocation) @call.builder_chain)
  name: (identifier) @call.builder_method) @call.builder

; ==========================================
; 构造函数调用
; ==========================================

; this(args)
(explicit_constructor_invocation
  (this) @ctor.this
  arguments: (argument_list) @ctor.args) @ctor.this_call

; super(args)
(explicit_constructor_invocation
  (super) @ctor.super
  arguments: (argument_list) @ctor.args) @ctor.super_call

; ==========================================
; 危险调用模式
; ==========================================

; Runtime.getRuntime().exec(...)
(method_invocation
  object: (method_invocation
    object: (identifier) @danger.runtime
    (#eq? @danger.runtime "Runtime")
    name: (identifier) @danger.getRuntime
    (#eq? @danger.getRuntime "getRuntime"))
  name: (identifier) @danger.exec
  (#eq? @danger.exec "exec")) @danger.rce

; ProcessBuilder(...).start()
(method_invocation
  object: (object_creation_expression
    type: (type_identifier) @danger.processbuilder
    (#eq? @danger.processbuilder "ProcessBuilder"))
  name: (identifier) @danger.start
  (#eq? @danger.start "start")) @danger.process

; Class.forName(...)
(method_invocation
  object: (identifier) @danger.class
  (#eq? @danger.class "Class")
  name: (identifier) @danger.forName
  (#eq? @danger.forName "forName")) @danger.reflection

; ObjectInputStream.readObject()
(method_invocation
  object: (_) @danger.ois
  name: (identifier) @danger.readObject
  (#eq? @danger.readObject "readObject")) @danger.deserialize

; InitialContext.lookup(...)
(method_invocation
  name: (identifier) @danger.lookup
  (#eq? @danger.lookup "lookup")) @danger.jndi

; Statement.execute...(...)
(method_invocation
  name: (identifier) @danger.sql
  (#match? @danger.sql "^execute")) @danger.sql_exec

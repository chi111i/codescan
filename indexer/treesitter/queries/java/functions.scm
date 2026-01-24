; Java 函数提取查询
; 按功能分类: functions.scm

; ==========================================
; 方法声明
; ==========================================

; public void methodName(params) { body }
(method_declaration
  (modifiers)? @method.modifiers
  type: (_) @method.return_type
  name: (identifier) @method.name
  parameters: (formal_parameters) @method.params
  body: (block)? @method.body) @method

; 抽象方法
(method_declaration
  (modifiers
    "abstract" @method.abstract)
  name: (identifier) @method.name) @method.abstract_def

; 静态方法
(method_declaration
  (modifiers
    "static" @method.static)
  name: (identifier) @method.name) @method.static_def

; ==========================================
; 构造函数
; ==========================================

; public ClassName(params) { body }
(constructor_declaration
  (modifiers)? @constructor.modifiers
  name: (identifier) @constructor.name
  parameters: (formal_parameters) @constructor.params
  body: (constructor_body) @constructor.body) @constructor

; ==========================================
; Lambda 表达式
; ==========================================

; (params) -> expression
(lambda_expression
  parameters: (_) @lambda.params
  body: (_) @lambda.body) @lambda

; ==========================================
; 方法引用
; ==========================================

; ClassName::methodName
(method_reference
  (identifier) @method_ref.class
  (identifier) @method_ref.method) @method_ref

; object::methodName
(method_reference
  (_) @method_ref.object
  (identifier) @method_ref.method) @method_ref.instance

; ==========================================
; 注解方法（用于 @interface）
; ==========================================

(annotation_type_element_declaration
  type: (_) @ann_method.type
  name: (identifier) @ann_method.name) @ann_method

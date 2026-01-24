; PHP 函数提取查询
; 按功能分类: functions.scm

; ==========================================
; 普通函数声明
; ==========================================

; function name($params) { body }
(function_definition
  name: (name) @function.name
  parameters: (formal_parameters) @function.params
  body: (compound_statement) @function.body) @function

; ==========================================
; 方法定义
; ==========================================

; public function name($params) { body }
(method_declaration
  (visibility_modifier)? @method.visibility
  (static_modifier)? @method.static
  name: (name) @method.name
  parameters: (formal_parameters) @method.params
  body: (compound_statement)? @method.body) @method

; abstract public function name($params);
(method_declaration
  (abstract_modifier) @method.abstract
  name: (name) @method.name
  parameters: (formal_parameters) @method.params) @method.abstract_def

; ==========================================
; 构造函数和魔术方法
; ==========================================

; public function __construct($params) { }
(method_declaration
  name: (name) @constructor.name
  (#match? @constructor.name "^__construct$")
  parameters: (formal_parameters) @constructor.params) @constructor

; public function __destruct() { }
(method_declaration
  name: (name) @destructor.name
  (#match? @destructor.name "^__destruct$")) @destructor

; 其他魔术方法
(method_declaration
  name: (name) @magic.name
  (#match? @magic.name "^__")) @magic_method

; ==========================================
; 闭包和箭头函数
; ==========================================

; function($params) use ($vars) { body }
(anonymous_function_creation_expression
  parameters: (formal_parameters) @closure.params
  body: (compound_statement) @closure.body) @closure

; fn($params) => expression
(arrow_function
  parameters: (formal_parameters) @arrow.params
  body: (_) @arrow.body) @arrow

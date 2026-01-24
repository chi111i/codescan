; JavaScript 类提取查询
; 按功能分类: classes.scm

; ==========================================
; 类声明
; ==========================================

; class Name { }
(class_declaration
  name: (identifier) @class.name
  body: (class_body) @class.body) @class

; class Name extends Base { }
(class_declaration
  name: (identifier) @class.name
  (class_heritage
    (extends_clause
      (identifier) @class.base))
  body: (class_body) @class.body) @class.extends

; ==========================================
; 类表达式
; ==========================================

; const Name = class { }
(lexical_declaration
  (variable_declarator
    name: (identifier) @class.name
    value: (class
      body: (class_body) @class.body))) @class.expression

; ==========================================
; 类方法
; ==========================================

; method(params) { body }
(method_definition
  name: (property_identifier) @method.name
  parameters: (formal_parameters) @method.params
  body: (statement_block) @method.body) @method

; async method(params) { body }
(method_definition
  "async" @method.async
  name: (property_identifier) @method.name
  parameters: (formal_parameters) @method.params
  body: (statement_block) @method.body) @method.async

; static method(params) { body }
(method_definition
  "static" @method.static
  name: (property_identifier) @method.name
  parameters: (formal_parameters) @method.params) @method.static_def

; get property() { return value }
(method_definition
  "get" @method.getter
  name: (property_identifier) @method.name) @method.getter_def

; set property(value) { }
(method_definition
  "set" @method.setter
  name: (property_identifier) @method.name) @method.setter_def

; *generatorMethod() { }
(method_definition
  "*" @method.generator
  name: (property_identifier) @method.name) @method.generator_def

; ==========================================
; 构造函数
; ==========================================

; constructor(params) { }
(method_definition
  name: (property_identifier) @constructor.name
  (#eq? @constructor.name "constructor")
  parameters: (formal_parameters) @constructor.params
  body: (statement_block) @constructor.body) @constructor

; ==========================================
; 类字段
; ==========================================

; fieldName = value
(field_definition
  property: (property_identifier) @field.name
  value: (_)? @field.value) @field

; static fieldName = value
(field_definition
  "static" @field.static
  property: (property_identifier) @field.name) @field.static_def

; #privateField = value
(field_definition
  property: (private_property_identifier) @field.private_name) @field.private

; ==========================================
; 导出类
; ==========================================

; export class Name { }
(export_statement
  declaration: (class_declaration
    name: (identifier) @class.name)) @class.exported

; export default class Name { }
(export_statement
  "default" @class.default
  declaration: (class_declaration
    name: (identifier) @class.name)) @class.exported_default

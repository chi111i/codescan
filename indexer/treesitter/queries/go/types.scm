; Go 类型提取查询
; 按功能分类: types.scm

; ==========================================
; 结构体声明
; ==========================================

; type Name struct { }
(type_declaration
  (type_spec
    name: (type_identifier) @struct.name
    type: (struct_type
      (field_declaration_list)? @struct.fields))) @struct

; ==========================================
; 接口声明
; ==========================================

; type Name interface { }
(type_declaration
  (type_spec
    name: (type_identifier) @interface.name
    type: (interface_type) @interface.body)) @interface

; 接口方法
(method_spec
  name: (field_identifier) @interface_method.name
  parameters: (parameter_list) @interface_method.params
  result: (_)? @interface_method.result) @interface_method

; ==========================================
; 类型别名
; ==========================================

; type Name = OtherType
(type_declaration
  (type_alias
    name: (type_identifier) @alias.name
    type: (_) @alias.type)) @alias

; type Name OtherType
(type_declaration
  (type_spec
    name: (type_identifier) @typedef.name
    type: (type_identifier) @typedef.type)) @typedef

; ==========================================
; 字段声明
; ==========================================

; 命名字段
(field_declaration
  name: (field_identifier) @field.name
  type: (_) @field.type) @field

; 嵌入字段
(field_declaration
  type: (type_identifier) @embedded.type) @embedded

; 嵌入指针字段
(field_declaration
  type: (pointer_type
    (type_identifier) @embedded_ptr.type)) @embedded_ptr

; 带标签的字段
(field_declaration
  name: (field_identifier) @tagged_field.name
  type: (_) @tagged_field.type
  tag: (raw_string_literal) @tagged_field.tag) @tagged_field

; ==========================================
; 常量和变量
; ==========================================

; const Name = value
(const_declaration
  (const_spec
    name: (identifier) @const.name
    value: (_) @const.value)) @const

; var Name Type
(var_declaration
  (var_spec
    name: (identifier) @var.name
    type: (_)? @var.type
    value: (_)? @var.value)) @var

; ==========================================
; 泛型 (Go 1.18+)
; ==========================================

; type Name[T any] struct { }
(type_declaration
  (type_spec
    name: (type_identifier) @generic.name
    type_parameters: (type_parameter_list) @generic.params)) @generic

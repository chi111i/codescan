; Java 类提取查询
; 按功能分类: classes.scm

; ==========================================
; 类声明
; ==========================================

; public class Name { }
(class_declaration
  (modifiers)? @class.modifiers
  name: (identifier) @class.name
  body: (class_body) @class.body) @class

; public class Name extends Base { }
(class_declaration
  name: (identifier) @class.name
  (superclass
    (type_identifier) @class.superclass)) @class.extends

; public class Name implements Interface { }
(class_declaration
  name: (identifier) @class.name
  (super_interfaces
    (type_list
      (type_identifier) @class.interface))) @class.implements

; abstract class Name { }
(class_declaration
  (modifiers
    "abstract" @class.abstract)
  name: (identifier) @class.name) @class.abstract_def

; final class Name { }
(class_declaration
  (modifiers
    "final" @class.final)
  name: (identifier) @class.name) @class.final_def

; ==========================================
; 接口声明
; ==========================================

; public interface Name { }
(interface_declaration
  (modifiers)? @interface.modifiers
  name: (identifier) @interface.name
  body: (interface_body) @interface.body) @interface

; public interface Name extends Base { }
(interface_declaration
  name: (identifier) @interface.name
  (extends_interfaces
    (type_list
      (type_identifier) @interface.extends))) @interface.extends_def

; ==========================================
; 枚举声明
; ==========================================

; public enum Name { }
(enum_declaration
  (modifiers)? @enum.modifiers
  name: (identifier) @enum.name
  body: (enum_body) @enum.body) @enum

; 枚举常量
(enum_constant
  name: (identifier) @enum_const.name) @enum_const

; ==========================================
; 记录声明 (Java 14+)
; ==========================================

; public record Name(params) { }
(record_declaration
  (modifiers)? @record.modifiers
  name: (identifier) @record.name
  parameters: (formal_parameters) @record.params
  body: (class_body)? @record.body) @record

; ==========================================
; 注解类型声明
; ==========================================

; public @interface Name { }
(annotation_type_declaration
  (modifiers)? @annotation.modifiers
  name: (identifier) @annotation.name
  body: (annotation_type_body) @annotation.body) @annotation

; ==========================================
; 字段声明
; ==========================================

; private String fieldName;
(field_declaration
  (modifiers)? @field.modifiers
  type: (_) @field.type
  declarator: (variable_declarator
    name: (identifier) @field.name)) @field

; static final String CONSTANT = "value";
(field_declaration
  (modifiers
    "static" @field.static
    "final" @field.final)
  declarator: (variable_declarator
    name: (identifier) @field.name)) @field.constant

; ==========================================
; 内部类
; ==========================================

; 静态内部类
(class_declaration
  (modifiers
    "static" @inner.static)
  name: (identifier) @inner.name) @inner.static_class

; ==========================================
; 泛型类型参数
; ==========================================

(type_parameters
  (type_parameter
    (type_identifier) @type_param.name)) @type_params

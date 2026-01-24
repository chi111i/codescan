; PHP 类提取查询
; 按功能分类: classes.scm

; ==========================================
; 类声明
; ==========================================

; class Name { }
(class_declaration
  name: (name) @class.name
  body: (declaration_list) @class.body) @class

; abstract class Name { }
(class_declaration
  (abstract_modifier) @class.abstract
  name: (name) @class.name
  body: (declaration_list) @class.body) @class.abstract_def

; final class Name { }
(class_declaration
  (final_modifier) @class.final
  name: (name) @class.name) @class.final_def

; class Name extends Base { }
(class_declaration
  name: (name) @class.name
  (base_clause
    (name) @class.base)
  body: (declaration_list) @class.body) @class.extends

; class Name implements Interface { }
(class_declaration
  name: (name) @class.name
  (class_interface_clause
    (name) @class.interface)) @class.implements

; ==========================================
; 接口声明
; ==========================================

; interface Name { }
(interface_declaration
  name: (name) @interface.name
  body: (declaration_list) @interface.body) @interface

; interface Name extends Base { }
(interface_declaration
  name: (name) @interface.name
  (base_clause
    (name) @interface.base)) @interface.extends

; ==========================================
; Trait 声明
; ==========================================

; trait Name { }
(trait_declaration
  name: (name) @trait.name
  body: (declaration_list) @trait.body) @trait

; ==========================================
; 枚举声明 (PHP 8.1+)
; ==========================================

; enum Name { }
(enum_declaration
  name: (name) @enum.name
  body: (enum_declaration_list) @enum.body) @enum

; ==========================================
; 属性定义
; ==========================================

; public $property;
(property_declaration
  (visibility_modifier) @property.visibility
  (property_element
    (variable_name) @property.name)) @property

; public static $property;
(property_declaration
  (static_modifier) @property.static
  (property_element
    (variable_name) @property.name)) @property.static_def

; public readonly string $property;
(property_declaration
  (readonly_modifier) @property.readonly
  (property_element
    (variable_name) @property.name)) @property.readonly_def

; ==========================================
; 常量定义
; ==========================================

; const NAME = value;
(const_declaration
  (const_element
    name: (name) @const.name
    value: (_) @const.value)) @const

; public const NAME = value;
(class_const_declaration
  (visibility_modifier)? @const.visibility
  (const_element
    name: (name) @const.name)) @const.class

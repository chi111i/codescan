; JavaScript 导入提取查询
; 按功能分类: imports.scm

; ==========================================
; ES6 导入
; ==========================================

; import name from 'module'
(import_statement
  (import_clause
    (identifier) @import.default)
  source: (string) @import.source) @import

; import { name } from 'module'
(import_statement
  (import_clause
    (named_imports
      (import_specifier
        name: (identifier) @import.name)))
  source: (string) @import.source) @import.named

; import { name as alias } from 'module'
(import_statement
  (import_clause
    (named_imports
      (import_specifier
        name: (identifier) @import.name
        alias: (identifier) @import.alias)))
  source: (string) @import.source) @import.aliased

; import * as name from 'module'
(import_statement
  (import_clause
    (namespace_import
      (identifier) @import.namespace))
  source: (string) @import.source) @import.namespace

; import 'module' (side effect only)
(import_statement
  source: (string) @import.source) @import.side_effect

; ==========================================
; CommonJS require
; ==========================================

; const name = require('module')
(lexical_declaration
  (variable_declarator
    name: (identifier) @require.name
    value: (call_expression
      function: (identifier) @require.func
      (#eq? @require.func "require")
      arguments: (arguments
        (string) @require.source)))) @require

; const { name } = require('module')
(lexical_declaration
  (variable_declarator
    name: (object_pattern) @require.destructure
    value: (call_expression
      function: (identifier) @require.func
      (#eq? @require.func "require")
      arguments: (arguments
        (string) @require.source)))) @require.destructured

; ==========================================
; 动态导入
; ==========================================

; import('module')
(call_expression
  function: (import) @import.dynamic
  arguments: (arguments
    (string) @import.dynamic_source)) @import.dynamic_call

; await import('module')
(await_expression
  (call_expression
    function: (import)
    arguments: (arguments
      (string) @import.dynamic_source))) @import.dynamic_await

; JavaScript 函数提取查询
; 按功能分类: functions.scm

; ==========================================
; 普通函数声明
; ==========================================

; function name(params) { body }
(function_declaration
  name: (identifier) @function.name
  parameters: (formal_parameters) @function.params
  body: (statement_block) @function.body) @function

; async function name(params) { body }
(function_declaration
  "async" @function.async
  name: (identifier) @function.name
  parameters: (formal_parameters) @function.params
  body: (statement_block) @function.body) @function.async_decl

; function* name(params) { body } (generator)
(generator_function_declaration
  name: (identifier) @function.name
  parameters: (formal_parameters) @function.params
  body: (statement_block) @function.body) @function.generator

; ==========================================
; 箭头函数
; ==========================================

; const name = (params) => { body }
(lexical_declaration
  (variable_declarator
    name: (identifier) @function.name
    value: (arrow_function
      parameters: (formal_parameters) @function.params
      body: (_) @function.body))) @function.arrow

; const name = async (params) => { body }
(lexical_declaration
  (variable_declarator
    name: (identifier) @function.name
    value: (arrow_function
      "async" @function.async
      parameters: (formal_parameters) @function.params
      body: (_) @function.body))) @function.arrow_async

; var/let name = (params) => { body }
(variable_declaration
  (variable_declarator
    name: (identifier) @function.name
    value: (arrow_function
      parameters: (formal_parameters) @function.params
      body: (_) @function.body))) @function.arrow_var

; ==========================================
; 函数表达式
; ==========================================

; const name = function(params) { body }
(lexical_declaration
  (variable_declarator
    name: (identifier) @function.name
    value: (function_expression
      parameters: (formal_parameters) @function.params
      body: (statement_block) @function.body))) @function.expression

; ==========================================
; 导出函数
; ==========================================

; export function name(params) { body }
(export_statement
  declaration: (function_declaration
    name: (identifier) @function.name
    parameters: (formal_parameters) @function.params)) @function.exported

; export default function name(params) { body }
(export_statement
  "default" @function.default
  declaration: (function_declaration
    name: (identifier) @function.name)) @function.exported_default

; export const name = (params) => { body }
(export_statement
  declaration: (lexical_declaration
    (variable_declarator
      name: (identifier) @function.name
      value: (arrow_function)))) @function.exported_arrow

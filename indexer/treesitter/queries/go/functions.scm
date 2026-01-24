; Go 函数提取查询
; 按功能分类: functions.scm

; ==========================================
; 函数声明
; ==========================================

; func name(params) returnType { body }
(function_declaration
  name: (identifier) @function.name
  parameters: (parameter_list) @function.params
  result: (_)? @function.result
  body: (block) @function.body) @function

; main 函数
(function_declaration
  name: (identifier) @main.name
  (#eq? @main.name "main")) @main

; init 函数
(function_declaration
  name: (identifier) @init.name
  (#eq? @init.name "init")) @init

; ==========================================
; 方法声明（带接收者）
; ==========================================

; func (r *Type) name(params) returnType { body }
(method_declaration
  receiver: (parameter_list) @method.receiver
  name: (field_identifier) @method.name
  parameters: (parameter_list) @method.params
  result: (_)? @method.result
  body: (block) @method.body) @method

; 值接收者方法
(method_declaration
  receiver: (parameter_list
    (parameter_declaration
      type: (type_identifier) @method.value_receiver))
  name: (field_identifier) @method.name) @method.value

; 指针接收者方法
(method_declaration
  receiver: (parameter_list
    (parameter_declaration
      type: (pointer_type) @method.pointer_receiver))
  name: (field_identifier) @method.name) @method.pointer

; ==========================================
; 匿名函数 / 闭包
; ==========================================

; func(params) { body }
(func_literal
  parameters: (parameter_list) @closure.params
  result: (_)? @closure.result
  body: (block) @closure.body) @closure

; ==========================================
; HTTP 处理器模式
; ==========================================

; func handler(w http.ResponseWriter, r *http.Request)
(function_declaration
  name: (identifier) @handler.name
  parameters: (parameter_list
    (parameter_declaration
      type: (qualified_type
        package: (package_identifier) @handler.pkg
        (#eq? @handler.pkg "http")
        name: (type_identifier) @handler.type
        (#eq? @handler.type "ResponseWriter"))))) @handler.http

; ServeHTTP 方法
(method_declaration
  name: (field_identifier) @handler.serve
  (#eq? @handler.serve "ServeHTTP")) @handler.serve_http

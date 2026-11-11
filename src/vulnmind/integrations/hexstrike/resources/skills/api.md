---
skill_id: hexstrike-api-1
name: API 与令牌结构调查
version: 1.0.0
target_type: web
vuln_type: hexstrike_api
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.api_fuzzer
- hexstrike.graphql_scanner
- hexstrike.jwt_analyzer
- hexstrike.api_schema_analyzer
- hexstrike.comprehensive_api_audit
---
# API 与令牌结构调查

适用条件：固定 OpenAPI/GraphQL 路径和授权身份。JWT 解析属于结构观察，不证明签名绕过；不得将解码出的秘密写入日志或 RAG。

操作方法：先离线核查 Schema，再对显式操作和字段执行受限请求。修改状态的操作独立审批。双账户越权需要两套明确授权账户及对应资源，不能用匿名状态码代替。

复核与证据：API 错误和 introspection 开放仅为线索。保留字段级预期权限、请求差分和响应摘要，删除令牌及个人信息；需要源码和业务预期支持结论。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

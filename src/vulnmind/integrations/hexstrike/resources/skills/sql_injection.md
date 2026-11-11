---
skill_id: hexstrike-sql_injection-1
name: sqlmap 受控 SQL 注入复核
version: 1.0.0
target_type: web
vuln_type: sql_injection
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.sqlmap_scan
---
# sqlmap 受控 SQL 注入复核

适用条件：仅适用于已授权参数的 SQL 注入调查。必须确定 GET/表单/JSON 编码、参数名、认证和基线；不能把所有 URL 参数都作为已批准目标。

操作方法：优先低风险布尔/错误验证并固定技术、level、risk、参数及会话目录。关闭枚举、数据导出、文件读写、系统命令、tamper 与 OOB。工具每个真实请求都必须经过出口计数；小于工具最低探测成本时应回退内置有界差分。

复核与证据：动态页面、缓存、WAF 和数据库报错可能误导。保存真假条件重复对照与工具版本；时间差须有重复对照而不能单次确认。成功退出与未发现注入分开记录；超时先对账原 execution ID，不能新开 sqlmap 会话。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

---
skill_id: workbench.nosql_injection
name: NoSQL 输入类型检查
version: 6.0.0
target_type: both
vuln_type: nosql_injection
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: [nosql_error]
---
仅针对源码存在 NoSQL 查询信号的只读接口，在两个标量对照之间发送无操作符的普通对象输入。对象独有的数据库类型错误只是输入校验线索，不能证明操作符注入或身份绕过。没有错误不代表安全。确认查询语义控制需要独立证据；不执行写入、无限循环或数据导出。使用 schema 验证输入类型并避免将外部对象直接当查询条件。

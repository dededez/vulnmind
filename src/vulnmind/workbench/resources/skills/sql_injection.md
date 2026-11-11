---
skill_id: workbench.sql_injection
name: SQL 注入
version: 2.0.0
target_type: both
vuln_type: sql_injection
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: ["sql_boolean", "sql_error", "sql_login"]
---
# SQL 注入 / sql_injection

适用条件：请求参数进入拼接 SQL 或出现数据库异常。布尔检查适用于单引号字符串位置，其他语法、必填参数和认证状态可能导致漏报。

检测步骤：比较重复基线、真假条件并反转执行顺序；真条件应匹配基线，假条件重复一致。错误检查仅认挑战独有数据库特征。

误报排查：排除输入反射、WAF 拒绝、动态页面、缓存、分页和网络波动；不以一次错误或延迟确认注入。

证据要求：保存精确请求、状态、完整响应摘要、重复对照、源码位置。只生成候选，不枚举表或提取数据。

修复建议：使用参数化查询，标识符映射到固定允许列表，数据库账户最小权限。

参考：https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：SQL injection boolean differential parameterized queries false positives

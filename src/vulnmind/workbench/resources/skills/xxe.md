---
skill_id: workbench.xxe
name: XML 外部实体
version: 2.0.0
target_type: both
vuln_type: xxe
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: []
---
# XML 外部实体 / xxe

适用条件：不可信 XML 进入支持外部实体的解析器。

检测步骤：检查解析器版本、外部实体和 DTD 配置；本版本不读取文件或发起 XXE 回连。

误报排查：解析 XML 本身不是 XXE；默认配置与库版本可能禁用外部实体。

证据要求：需实际配置和受控夹具证明；只有 parse 调用时保持线索。

修复建议：禁用 DTD 和外部实体，使用安全解析器并限制输入资源消耗。

参考：https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：XML external entity XXE parser external entities

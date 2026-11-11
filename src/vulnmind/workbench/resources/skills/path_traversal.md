---
skill_id: workbench.path_traversal
name: 路径遍历
version: 2.0.0
target_type: both
vuln_type: path_traversal
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: []
---
# 路径遍历 / path_traversal

适用条件：请求输入影响文件路径，open/read/send_file 等调用只形成调查线索。

检测步骤：分析规范化后的路径是否落在允许根目录内；本版本不发送路径穿越或读取敏感文件。

误报排查：注意符号链接、双重解码和不同操作系统分隔符；固定文件读取不构成漏洞。

证据要求：需要输入到文件操作的完整路径和专用无敏感内容夹具；当前标注需补充上下文。

修复建议：固定资源 ID 映射，规范化并检查根目录包含关系，避免直接拼接用户路径。

参考：https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：path traversal file access canonical path validation

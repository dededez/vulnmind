---
skill_id: workbench.open_redirect
name: 不受控跳转
version: 2.0.0
target_type: both
vuln_type: open_redirect
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: [redirect_location]
---
# 不受控跳转 / open_redirect

适用条件：用户可控制跳转目的地址。

检测步骤：审查目的地址规范化和允许列表；使用两个不同的 .invalid 惰性目的地址核对 Location，不跟随跨域跳转。

误报排查：固定跳转、相对站内路径或明确外链提示可能符合预期。

证据要求：需具体可控参数与 Location 证据；静态 redirect 调用不等于漏洞。

修复建议：用固定目的 ID 映射，规范化后精确校验目标来源。

参考：https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：unvalidated redirect destination allowlist

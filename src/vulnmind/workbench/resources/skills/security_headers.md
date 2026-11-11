---
skill_id: workbench.security_headers
name: HTTP 安全响应头
version: 2.0.0
target_type: both
vuln_type: security_headers
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: ["security_headers"]
---
# HTTP 安全响应头 / security_headers

适用条件：HTML 响应适合浏览器防御头检查。

检测步骤：重复检查 Content-Type、Content-Security-Policy、X-Content-Type-Options；缺失只是加固线索。

误报排查：不把 JSON API 缺少 CSP 当作 XSS；策略存在不代表策略有效，重复头也需要人工检查。

证据要求：记录响应类型和缺失项；不要因缺少响应头提升为已确认漏洞。

修复建议：结合业务部署 CSP 与 nosniff，避免破坏合法内容加载。

参考：https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：HTTP security headers content security policy nosniff HTML

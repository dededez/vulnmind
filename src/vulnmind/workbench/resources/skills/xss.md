---
skill_id: workbench.xss
name: XSS 与 HTML 注入
version: 2.0.0
target_type: both
vuln_type: xss
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: ["xss_context", "reflection", "browser_xss"]
---
# XSS 与 HTML 注入 / xss

适用条件：输入进入 HTML 或客户端 DOM；反射本身不是脚本执行。

检测步骤：先用两个不同惰性自定义标签确认 HTML 元素上下文，检查 Content-Type 与编码；纯文本和 JSON 不等于 HTML 执行。

误报排查：排除转义标签、textarea/title/script/style/template 文本上下文、跨响应固定内容及模板示例。解析器只是启发式，不模拟所有浏览器行为。

证据要求：记录输入、响应上下文、响应头和摘要；没有浏览器执行证据时仅报告 HTML 注入候选。

修复建议：按输出位置编码，富文本使用成熟净化库，避免不可信 innerHTML，CSP 为附加防御。

参考：https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：cross site scripting XSS output encoding HTML context reflected input

v7 浏览器复核必须包含无载荷对照、携带本次独有标记的载荷和重复验证。只接受标记完全匹配的 alert；正常页面弹窗、纯 DOM 反射、被阻断或不完整的页面不能确认载荷执行。脚本执行候选仍需评估上下文与影响。

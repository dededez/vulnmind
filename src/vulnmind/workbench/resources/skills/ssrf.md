---
skill_id: workbench.ssrf
name: 服务端请求伪造
version: 2.0.0
target_type: both
vuln_type: ssrf
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: []
---
# 服务端请求伪造 / ssrf

适用条件：用户可控制服务器出站请求目的地；调用 requests/httpx 只是静态线索。

检测步骤：追踪输入到请求 URL、重定向和 DNS 的数据流；本版本无专用主动 SSRF 验证器。

误报排查：固定 URL、允许列表、业务代理及隔离网络需区分；普通外部 HTTP 调用不是漏洞。

证据要求：需要授权回调或可核对的目标侧日志；当前只列需补充上下文。

修复建议：限制协议与目的地址，解析后检查 IP，重定向逐跳检查，阻止内网和元数据目的地。

参考：https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：server side request forgery SSRF outbound URL validation

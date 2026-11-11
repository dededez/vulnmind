---
skill_id: workbench.cors
name: 跨域访问策略
version: 2.0.0
target_type: both
vuln_type: cors
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: ["cors"]
---
# 跨域访问策略 / cors

适用条件：GET 接口需要跨域访问策略检查。

检测步骤：以基线和两个不同的保留 .invalid Origin 请求同一接口；只发送 Origin 头，不访问这些域名。

误报排查：任意源反射且 allow-credentials=true 是候选；公共数据、SameSite、浏览器凭据策略可能阻止实际影响。星号与凭据组合不会直接证明可读。

证据要求：保存响应头及对照，真实跨域敏感数据读取需要额外浏览器与账户证据。

修复建议：精确允许可信 Origin，按需允许凭据，正确设置 Vary: Origin。

参考：https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：CORS origin credentials access control sensitive response

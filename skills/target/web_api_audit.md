---
skill_id: web_api_audit
name: Web/API audit workflow
version: "1"
target_type: web
stage: analysis
risk_level: low
prerequisites: [scope_validation]
tools: [http.request]
---

# Web/API 审计流程

1. 确认 origin、路径前缀与 IP 白名单都在授权范围内；授权过期立即停止。
2. 端点发现优先使用低速率被动与轻量主动探测，避免目录爆破式流量。
3. 检查认证与授权：会话处理、越权（IDOR）、JWT 校验、CORS、CSRF 防护。
4. 检查输入处理：注入、XSS、SSRF、路径遍历、文件上传、反序列化。
5. 记录请求/响应证据的最小片段，并标注工具来源与时间。
6. 主动验证必须经过审批并使用非破坏性载荷；不进行数据导出或状态修改。

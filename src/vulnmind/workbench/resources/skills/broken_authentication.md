---
skill_id: workbench.broken_authentication
name: 认证与口令强度
version: 6.0.0
target_type: both
vuln_type: broken_authentication
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: [weak_password]
---
只对登录端点做有界对照：一次错误口令基线与一次常见弱口令，仅在基线未返回会话且弱口令返回会话时记为候选。不得使用获得的会话继续访问，不得尝试口令喷洒或撞库，不得对除目标账号以外的账号尝试。返回 200、存在 token 或前端跳转都不等于账号可用；判定需要服务端返回的会话与用户标识、且对照请求失败。登录成功证据中不得保存 token 或口令。

同时提醒：登录表单的 SQL 注入是独立根因（`sql_login`），与弱口令不能互相替代；两者都不代表后续接口全部可访问。

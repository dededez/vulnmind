---
skill_id: workbench.broken_access_control
name: 对象级授权与越权
version: 6.0.0
target_type: both
vuln_type: broken_access_control
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval, test_account]
tools: [auth_idor]
---
用唯一授权的测试账号读取"自己的资源"作为基线，再读取相邻 ID 的同类型资源，只有服务端返回了**其他用户的资源**才记为候选。必须同时满足：基线 200 且含本人数据、目标资源 200 且 `UserId`/归属字段不属于本人、请求方法只读。401/403、空数据、返回本人资源都不能算越权。

不得修改、删除或写入他人资源；不得批量枚举 ID（每次最多 2 个相邻值）；不得使用他人凭据。返回 200 或页面可打开不等于越权，判定依赖响应体中的归属证据。

---
skill_id: workbench.broken_access_control
name: 对象级授权与越权
version: 7.0.0
target_type: both
vuln_type: broken_access_control
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval, two_owned_identities_and_resources]
tools: [auth_idor]
---
v7 使用两个不同的受控身份及各自已知归属的资源，接口路径、JSON 身份字段与 owner_only 访问策略由操作者声明。先验证两个本人访问基线，再交换身份读取，最后做两个匿名对照，总计 6 个只读 GET。不猜相邻编号，不使用预设购物篮编号。资源标识不同不能单独证明归属不同。

基线身份不匹配、空数据、401/403 或返回本人资源不算越权。匿名也能读取时单列匿名私有资源读取线索；需独立核实策略与敏感性。即使交叉读取成功仍是候选，不因审计签名有效而提升成漏洞确认。公开资源不适用 owner_only 假设。

v6 历史任务的单账号/种子编号协议仅用于 Juice Shop 兼容，不代表通用权限测试。

---
skill_id: scope_validation
name: Scope validation before any action
version: "1"
target_type: both
stage: recon
risk_level: low
prerequisites: []
tools: []
---

# 授权范围校验

1. 读取任务授权：来源、批准人、生效窗口、允许与拒绝列表。
2. 拒绝优先：目录或 origin 只要命中拒绝项就直接停止，不再继续判断允许项。
3. Web 目标按 origin + 保守路径前缀判断；含百分号、点段、双斜杠的路径一律视为歧义并拒绝。
4. 仓库目标必须位于允许根目录内，且不得与拒绝根目录存在祖先/后代重叠。
5. 每次工具调用前重新校验，不能复用上一次的判定结果。授权过期立即停止。
6. DNS 与重定向检查必须针对实际连接地址，不能用 URL 字符串代替。

当前实现只在预检查层提供这些判断，不构成网络或文件系统沙箱；真实执行前仍需要可强制的隔离。

---
skill_id: hexstrike-authentication-1
name: 认证和哈希审计
version: 1.0.0
target_type: network
vuln_type: hexstrike_authentication
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.hydra_attack
- hexstrike.john_crack
- hexstrike.hashcat_crack
---
# 认证和哈希审计

适用条件：在线认证测试需具体账户、服务、尝试次数和锁定策略；离线哈希审计需样本授权。二者不能共用 Web 请求预算。

操作方法：先辨明哈希格式和测试模式。禁止默认口令喷洒或大字典任务；并发、速率、尝试次数与硬件时间固定，停止条件包含锁定和异常告警。

复核与证据：认证响应差异可能是限速或账户不存在，不能直接判定弱口令。只报告不可逆指纹与是否命中，不保存恢复出的口令到知识库或普通日志。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

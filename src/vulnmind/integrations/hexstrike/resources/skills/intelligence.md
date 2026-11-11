---
skill_id: hexstrike-intelligence-1
name: 漏洞情报关联
version: 1.0.0
target_type: intelligence
vuln_type: hexstrike_intelligence
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.monitor_cve_feeds
- hexstrike.generate_exploit_from_cve
- hexstrike.discover_attack_chains
- hexstrike.research_zero_day_opportunities
- hexstrike.correlate_threat_intelligence
- hexstrike.vulnerability_intelligence_dashboard
- hexstrike.threat_hunting_assistant
---
# 漏洞情报关联

适用条件：公开情报查询与目标测试分离，限制查询域、时间和数据量。产品名称相似不能自动建立 CVE 影响关系。

操作方法：保存一手公告来源、版本范围、发布日期和修订时间，交叉核对目标版本及配置。PoC 和攻击链建议仅作为不可信参考，不直接执行或扩大范围。

复核与证据：CVE 存在、评分或上游硬编码概率不是目标证据。明确区分已证实版本、推断版本、未知配置；没有复核证据只生成调查任务。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

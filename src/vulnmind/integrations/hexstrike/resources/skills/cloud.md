---
skill_id: hexstrike-cloud-1
name: 云账户配置审计
version: 1.0.0
target_type: cloud
vuln_type: hexstrike_cloud
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.prowler_scan
- hexstrike.scout_suite_assessment
- hexstrike.cloudmapper_analysis
- hexstrike.pacu_exploitation
---
# 云账户配置审计

适用条件：必须指定云厂商、账户/订阅 ID、区域、只读角色和时间范围。Web 域名授权不能授权云 API。

操作方法：先核对账户身份和只读权限，按服务枚举配置，再对单项规则复核。计量 API 次数和分页；禁止凭据落盘到报告。Pacu 的状态修改模块必须另有具体变更计划，不能随审计自动运行。

复核与证据：配置发现可能源于继承策略或组织级限制。记录有效策略、资源 ARN、规则版本和采集时间；缺权限应标记未检测而非安全。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

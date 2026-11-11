---
skill_id: hexstrike-discovery-1
name: 资产和历史端点调查
version: 1.0.0
target_type: web
vuln_type: hexstrike_discovery
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.amass_scan
- hexstrike.subfinder_scan
- hexstrike.fierce_scan
- hexstrike.dnsenum_scan
- hexstrike.gau_discovery
- hexstrike.waybackurls_discovery
- hexstrike.paramspider_mining
- hexstrike.paramspider_discovery
---
# 资产和历史端点调查

适用条件：只在授权域名及其明确允许的子域范围调查；第三方历史 URL 是待核对数据，不能自动成为可扫描目标。

操作方法：区分被动数据查询和主动 DNS/HTTP 请求，分别计量。归一化和去重后逐一验证 Origin、路径前缀及解析地址；不沿重定向扩展授权。

复核与证据：历史 URL 可能失效或属于共享租户。缺失历史结果不说明没有资产；保留数据源时间、查询范围、过滤掉的越界数量。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

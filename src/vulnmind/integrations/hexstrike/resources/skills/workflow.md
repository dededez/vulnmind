---
skill_id: hexstrike-workflow-1
name: 组合调查工作流
version: 1.0.0
target_type: web
vuln_type: hexstrike_workflow
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.autorecon_comprehensive
- hexstrike.autorecon_scan
- hexstrike.intelligent_smart_scan
- hexstrike.ai_reconnaissance_workflow
- hexstrike.ai_vulnerability_assessment
- hexstrike.bugbounty_reconnaissance_workflow
- hexstrike.bugbounty_vulnerability_hunting
- hexstrike.bugbounty_business_logic_testing
- hexstrike.bugbounty_osint_gathering
- hexstrike.bugbounty_file_upload_testing
- hexstrike.bugbounty_comprehensive_assessment
- hexstrike.bugbounty_authentication_bypass_testing
---
# 组合调查工作流

适用条件：组合工具必须展开每个子调用、资源、预算与副作用，不能将一次 MCP 调用视为一次网络请求。

操作方法：先把工作流转换为有向任务图，逐项审批和持久化回执；子任务只引用已完成证据，重新规划要产生新摘要。没有可观测子调用的组合工具保持阻塞。

复核与证据：局部成功不能标记整套评估完成。未知子任务先对账，失败与无发现分开；恢复时使用原图和原工具参数，不因目录更新重新排序。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

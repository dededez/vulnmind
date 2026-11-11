---
skill_id: hexstrike-payload-1
name: 测试载荷与框架操作
version: 1.0.0
target_type: workspace
vuln_type: hexstrike_payload
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.generate_payload
- hexstrike.metasploit_run
- hexstrike.msfvenom_generate
- hexstrike.ai_generate_payload
- hexstrike.ai_test_payload
- hexstrike.ai_generate_attack_suite
- hexstrike.advanced_payload_generation
---
# 测试载荷与框架操作

适用条件：生成文件不等于执行授权；Metasploit、脚本和 payload 套件需要单独沙箱、具体目标及逐项子调用计划。

操作方法：仅把可解释、可界定副作用的测试内容提交审批。二进制生成、监听器、回连和后续利用不能隐藏在一个工具调用里。未完成沙箱适配前保持不可调度。

复核与证据：载荷生成成功不是漏洞证据，工具自报成功也不是目标执行证明。保存生成参数、产物哈希和用途，明确标记未执行及未验证。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

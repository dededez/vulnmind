---
skill_id: workbench.command_injection
name: 命令注入
version: 2.0.0
target_type: both
vuln_type: command_injection
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: []
---
# 命令注入 / command_injection

适用条件：用户输入影响进程命令、参数或 shell；subprocess 调用本身不是漏洞。

检测步骤：区分 shell 字符串和参数数组，审查可执行文件与参数允许列表；本版本不执行注入命令。

误报排查：参数注入不同于 shell 注入；固定命令和验证过的参数可能安全。

证据要求：需数据流证据和受控无副作用验证；静态命中保留为线索。

修复建议：使用语言 API 替代命令，固定程序与参数列表，避免 shell=True。

参考：https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：OS command injection argument separation shell execution

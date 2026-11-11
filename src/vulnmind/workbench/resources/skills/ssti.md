---
skill_id: workbench.ssti
name: 服务端模板注入
version: 2.0.0
target_type: both
vuln_type: ssti
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: ["template_expression"]
---
# 服务端模板注入 / ssti

适用条件：请求数据被当作模板源码而非模板变量。

检测步骤：两组不同有界整数表达式与基线比较，预期结果应各自出现且互不交叉。

误报排查：排除原样反射、固定演示结果、客户端计算和正常业务计算接口。

证据要求：双表达式只能确认求值行为；不能推断任意代码执行，需要结合源码与业务意图。

修复建议：固定模板，将输入作为数据传入；避免对不可信模板进行编译。

参考：https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：server side template injection expression evaluation untrusted template

---
skill_id: workbench.deserialization
name: 不安全反序列化
version: 2.0.0
target_type: both
vuln_type: deserialization
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: []
---
# 不安全反序列化 / deserialization

适用条件：不可信数据进入 pickle、非安全 YAML 或对象反序列化。

检测步骤：检查输入信任边界和加载器配置；不运行反序列化利用链。

误报排查：安全 JSON 解析不能等同对象反序列化，可信内部数据也需核查真实性。

证据要求：保存调用点和输入来源，缺少传播路径时标注需补充上下文。

修复建议：使用纯数据格式与模式校验，避免对不可信内容恢复任意对象。

参考：https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

本卡是 VulnMind 项目编写的检测方法摘要，不是 OWASP 原文，也不是目标漏洞证据。

检索词：insecure deserialization untrusted data safe formats

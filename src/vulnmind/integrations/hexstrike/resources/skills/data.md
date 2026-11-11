---
skill_id: hexstrike-data-1
name: URL 和文本预处理
version: 1.0.0
target_type: workspace
vuln_type: hexstrike_data
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.anew_data_processing
- hexstrike.qsreplace_parameter_replacement
- hexstrike.uro_url_filtering
---
# URL 和文本预处理

适用条件：只处理作为数据提供的 URL/文本及本任务输出文件，不自动请求 URL，不继承上游脚本中的任意文件路径。

操作方法：区分语义去重和字节去重；保持参数重复、编码和顺序信息。替换参数后再次检查 Origin 和路径，输出数量与长度有上限。

复核与证据：去重可能合并不同权限或不同编码的端点。保留输入摘要、变换规则、丢弃数量与原始索引，不能把清洗结果当成资产存在证据。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

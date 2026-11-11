---
skill_id: hexstrike-forensics-1
name: 文件与内存取证
version: 1.0.0
target_type: sample
vuln_type: hexstrike_forensics
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.volatility_analyze
- hexstrike.volatility3_analyze
- hexstrike.foremost_carving
- hexstrike.steghide_analysis
- hexstrike.exiftool_extract
- hexstrike.hashpump_attack
---
# 文件与内存取证

适用条件：内存镜像和文件属于专门样本授权，可能含秘密；固定采集时间、哈希与只读副本，输出只在本任务目录。

操作方法：先识别格式与符号表版本；插件名固定允许列表。解压/文件雕刻限制输出文件数量、总大小和层数；不打开或执行提取物。工具版本不匹配时停止而非猜测结构。

复核与证据：时间戳、残留数据、误识别文件头均可能误导。记录提取偏移、插件和符号来源，区分事实、推断与缺失证据，隐去个人信息和密钥。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

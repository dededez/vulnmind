---
skill_id: hexstrike-binary-1
name: 二进制静态分析
version: 1.0.0
target_type: sample
vuln_type: hexstrike_binary
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.gdb_analyze
- hexstrike.radare2_analyze
- hexstrike.binwalk_analyze
- hexstrike.ropgadget_search
- hexstrike.checksec_analyze
- hexstrike.xxd_hexdump
- hexstrike.strings_extract
- hexstrike.objdump_analyze
- hexstrike.ghidra_analysis
- hexstrike.pwntools_exploit
- hexstrike.one_gadget_search
- hexstrike.libc_database_lookup
- hexstrike.gdb_peda_debug
- hexstrike.angr_symbolic_execution
- hexstrike.ropper_gadget_search
- hexstrike.pwninit_setup
---
# 二进制静态分析

适用条件：样本以 SHA-256 绑定并复制到任务独立输入目录；不能读取任意宿主路径、跟随链接或运行样本。调试/符号执行属于另一执行配置。

操作方法：先 strings/xxd 读取固定上限，再看格式、架构和静态保护。strings min_len 限定 4–32；xxd offset/length 为有界整数，输出截断明确标记。工具在无网络的独立环境运行，固定 argv 且拒绝额外参数。

复核与证据：字符串是静态线索；未出现字符串不证明不存在秘密或漏洞。保存样本哈希、偏移、参数、退出状态和截断信息；checksec 缺保护不直接等于存在利用链。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

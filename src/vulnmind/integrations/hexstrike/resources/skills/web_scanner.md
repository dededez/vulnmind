---
skill_id: hexstrike-web_scanner-1
name: Web 扫描与爬取
version: 1.0.0
target_type: web
vuln_type: hexstrike_web_scanner
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.gobuster_scan
- hexstrike.nuclei_scan
- hexstrike.dirb_scan
- hexstrike.nikto_scan
- hexstrike.wpscan_analyze
- hexstrike.ffuf_scan
- hexstrike.feroxbuster_scan
- hexstrike.dotdotpwn_scan
- hexstrike.xsser_scan
- hexstrike.wfuzz_scan
- hexstrike.dirsearch_scan
- hexstrike.katana_crawl
- hexstrike.arjun_parameter_discovery
- hexstrike.x8_parameter_discovery
- hexstrike.jaeles_vulnerability_scan
- hexstrike.dalfox_xss_scan
- hexstrike.httpx_probe
- hexstrike.hakrawler_crawl
- hexstrike.arjun_scan
- hexstrike.wafw00f_scan
---
# Web 扫描与爬取

适用条件：端点、方法、模板、参数和身份必须匹配调查问题。Nuclei 的模板标签不等于检测器能力；先固定具体模板及哈希。

操作方法：经受控出口逐请求校验 Origin、解析 IP、重定向和预算；并发、速率、深度与模板固定。Katana 的浏览器子资源也计量。禁止任意 additional_args、模板下载、自动更新和默认爬全站。

复核与证据：反射不等于 XSS；403、限速和动态内容不等于漏洞。Dalfox 输出没有可复核浏览器证据时保留候选等级。保存模板命中原始请求和匹配器上下文，空结果不触发自动换工具重扫。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

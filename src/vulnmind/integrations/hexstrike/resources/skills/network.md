---
skill_id: hexstrike-network-1
name: 网络服务识别
version: 1.0.0
target_type: network
vuln_type: hexstrike_network
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.nmap_scan
- hexstrike.nmap_advanced_scan
- hexstrike.rustscan_fast_scan
- hexstrike.masscan_high_speed
- hexstrike.enum4linux_scan
- hexstrike.enum4linux_ng_advanced
- hexstrike.netexec_scan
- hexstrike.smbmap_scan
- hexstrike.rpcclient_enumeration
- hexstrike.nbtscan_netbios
- hexstrike.arp_scan_discovery
- hexstrike.responder_credential_harvest
---
# 网络服务识别

适用条件：只对明确授权的 CIDR、端口与协议执行；域名必须先解析并固定地址。广播、二层发现和凭据捕获需要独立网络范围，不能继承 Web Origin。

操作方法：先获取少量端口服务证据，再按服务选择 SMB/RPC 枚举。固定扫描速率、连接数、端口集合和超时；禁止由工具默认扩大端口、网段或执行 NSE 脚本。

复核与证据：开放端口和版本横幅不是漏洞。负载均衡、蜜罐和服务代理会造成版本误判；保存目标 IP、端口、探测选项、工具版本和原始响应。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

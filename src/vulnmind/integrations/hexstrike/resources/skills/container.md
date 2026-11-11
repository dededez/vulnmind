---
skill_id: hexstrike-container-1
name: 容器、集群和 IaC 审计
version: 1.0.0
target_type: cluster
vuln_type: hexstrike_container
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.trivy_scan
- hexstrike.kube_hunter_scan
- hexstrike.kube_bench_cis
- hexstrike.docker_bench_security_scan
- hexstrike.clair_vulnerability_scan
- hexstrike.falco_runtime_monitoring
- hexstrike.checkov_iac_scan
- hexstrike.terrascan_iac_scan
---
# 容器、集群和 IaC 审计

适用条件：镜像摘要、文件快照或集群 UID 必须固定；离线 IaC、镜像扫描和在线集群测试是不同授权类型。

操作方法：镜像/依赖先固定数据库版本；IaC 按解析文件而非执行模板审计。Kube Hunter 等在线探测需网络预算，Falco 监听须限定时间和主机。禁止挂载宿主根目录或默认提升特权。

复核与证据：CVE 包版本命中不等于运行时可利用；厂商回补和不可达代码需复核。保存镜像摘要、漏洞数据库版本、规则、文件位置和豁免理由。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

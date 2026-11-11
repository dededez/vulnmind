---
skill_id: hexstrike-browser-1
name: 浏览器与代理验证
version: 1.0.0
target_type: web
vuln_type: hexstrike_browser
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.burpsuite_scan
- hexstrike.zap_scan
- hexstrike.http_framework_test
- hexstrike.browser_agent_inspect
- hexstrike.http_set_rules
- hexstrike.http_set_scope
- hexstrike.http_repeater
- hexstrike.http_intruder
- hexstrike.burpsuite_alternative_scan
---
# 浏览器与代理验证

适用条件：浏览器会话、登录身份、Origin 和下载目录独立绑定。浏览器启动成功不表示已具备受控网络出口。

操作方法：保持 TLS 验证、同源策略与浏览器沙箱；拦截导航、iframe、脚本、WebSocket 和下载。代理规则和作用域修改需要与精确计划同一摘要。复用登录状态之前检查会话归属。

复核与证据：DOM 变化或弹窗截图不足以证明可利用性。记录事件、对应输入、浏览器版本、响应与执行上下文；区分测试脚本和目标脚本产生的效果。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

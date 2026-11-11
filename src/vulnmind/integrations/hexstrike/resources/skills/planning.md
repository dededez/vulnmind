---
skill_id: hexstrike-planning-1
name: 工具建议与参数规划
version: 1.0.0
target_type: intelligence
vuln_type: hexstrike_planning
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.analyze_target_intelligence
- hexstrike.select_optimal_tools_ai
- hexstrike.optimize_tool_parameters_ai
- hexstrike.create_attack_chain_ai
- hexstrike.detect_technologies_ai
---
# 工具建议与参数规划

适用条件：只对已保存的技术栈证据和能力目录做规则建议；外部推荐不能绕过本机过滤、审批与预算。

操作方法：先做能力等价、输入、范围、依赖和 Skill 检查，再按用户固定选择或 external_preferred 排序。保留被排除工具和理由；参数建议需重新验证 Schema。

复核与证据：上游评分和概率是启发式，不作为证据或验证成功率。计划只提出可审查子任务，Critic 按实际结果决定继续、补充调查或停止。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

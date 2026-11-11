---
skill_id: report_generation
name: Report generation checklist
version: "1"
target_type: both
stage: report
risk_level: low
prerequisites: [finding_triage]
tools: []
---

# 报告生成

1. 报告必须区分工具发现、Agent 推断与人工确认，不能把工具输出写成"已确认漏洞"。
2. 模拟运行必须保留"未执行真实扫描"的显式横幅，不能省略。
3. 没有发现时写明"没有发现不等于不存在漏洞，也不等于扫描已完成"。
4. 每条发现给出位置、来源工具、状态、风险与证据引用；没有证据的写"仅为线索"。
5. 记录限制与假设：未覆盖的目标、未运行的检查、未验证的结论。
6. 报告不包含凭据、令牌与不必要的业务数据。
7. 输出 Markdown 与 JSON 两种格式时，内容与计数必须一致，且可重复生成。

---
skill_id: finding_triage
name: Finding triage and confidence
version: "1"
target_type: both
stage: triage
risk_level: low
prerequisites: [evidence_collection]
tools: []
---

# 发现研判

1. 先按精确身份去重：漏洞类型 + 目标 + 位置；不要用相似度把不同代码路径合并。
2. 保留所有候选及其来源工具，出现结论冲突时保持"未证实"，由人工复核裁决。
3. 严重度取组内最严重的已声明值；没有任何声明时标为 unknown，不猜测。
4. 置信度按状态给基线：confirmed 0.9、not_reproduced 0.8、insufficient_evidence 0.4、unverified 0.3；
   多来源 +0.10、有证据引用 +0.10，冲突封顶 0.50，总上限 0.95。
5. 只有 confirmed 与 not_reproduced 可以不带"待验证"标记；其余必须进入验证队列。
6. 置信度是启发式分数，不是概率，也不能替代验证。

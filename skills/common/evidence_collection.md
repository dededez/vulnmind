---
skill_id: evidence_collection
name: Evidence collection requirements
version: "1"
target_type: both
stage: analysis
risk_level: low
prerequisites: [scope_validation]
tools: []
---

# 证据采集要求

1. 每条发现必须能指向具体位置（文件:行号或请求/响应），只有自然语言结论的不算证据。
2. 证据内容单独存放，数据库只保存引用与哈希；不要把大段源码或响应体塞进状态。
3. 采集最小化：只保留证明问题所需的最小片段，避免无关个人信息与业务数据。
4. 凭据、令牌、密钥不得写入证据、日志或报告；必要时记录哈希或脱敏后的形式。
5. 工具输出本身不等于证据，需要明确标注来源工具与采集时间。
6. 证据缺失时把发现标记为未证实或证据不足，不要补写推测内容。

# VulnMind

可交付版本使用 **v6** 流水线：批次规划（每轮≤24 动作）、全局 300 请求预算账本、TypeScript AST 路由索引、17 类有界检测器、测试账号会话与浏览器 XSS 复核、可恢复审批与证据链。旧任务仍可按 v1–v5 恢复。

面向授权仓库和 Web 目标的本机安全分析工具。当前数据库迁移头为 `0018_workbench_jobs`。

**可视化工作台**：运行 `start-workbench.ps1` 或 `.venv/Scripts/python.exe -m vulnmind ui`，打开 http://127.0.0.1:8765 。支持仓库与部署绑定、接口关联图、模型分轮规划与独立复核、精确请求审批、证据查看、子流程恢复和报告校验。可先点击“本地演示靶场”。v6 的能力、配置、已验证任务与边界见 [WORKBENCH_V6.md](docs/WORKBENCH_V6.md)，历史用法见 [WORKBENCH.md](docs/WORKBENCH.md)。

新建 UI 任务默认 v6：按勾选的检测器执行；每轮知识快照进入规划与复核。检测器与知识说明见 [检测与知识接入](docs/KNOWLEDGE_DETECTION.md)。

- `workflow-run`：11 阶段仓库分析、多 Agent 建议、知识和证据、报告、记忆；支持跨进程恢复。
- `workflow-web`：爬取、分轮规划、等待审批、主动验证、结果证据入库及报告更新。
- `fetch`、`crawl`、`validate-run`：已开放的独立 HTTP 入口。
- `finding-attest`：签名并绑定证据的人工确认；`memory-promote`：明确确认项目长期记忆。
- `report-sign/report-verify`：报告签名；`evidence-gc` 默认预览，Windows `--apply` 使用句柄删除。

使用：[工作流基础与恢复](docs/DURABLE_WORKFLOWS.md)、[本轮新增功能](docs/WORKFLOW_CONTINUATION.md)。

状态与实际测试：[STATUS.md](STATUS.md)、[handoff.md](handoff.md)。生产运行与独立质量验收按用户要求暂缓。未知外部执行不会自动重发；模型建议与探测命中不等于漏洞已确认。

旧 `workflow-scan` 保留兼容。旧说明已移到 [历史 README](docs/README_HISTORY_20261108.md)，其中暂停、迁移版本和未实现说明只描述当时状态。

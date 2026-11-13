# 本机实测与验收


## 2026-11-12 / 重启与真实本机靶场验收完成
用户授权自行重启、配置、验证。确认无运行任务后通过本工作区计划任务隐藏重启；8765现运行修复后代码，目标仅 http://172.19.160.1:3000，允许172.19.160.1/32与127/32。模型规划+独立复核、external_preferred、external_execution=true、300请求/3轮、匿名、allow_post=true；未开启浏览器/双身份/外部爬取/仓库IaC。配置见 evaluation/reliability_live_fixed_job_20261112.json。

第一次任务46e84c89-d343-4d04-b020-51b1d8bfb358暴露MCP重复预留：外层act与内层mcp各计一次SQLMap实耗40，随后Dalfox在真正调用前因第二次预留失败而BudgetExhausted，任务unknown。旧任务、账本未改。诊断证据 evaluation/reliability_budget_diagnosis_20261112.json。
追加修复 engine.execute_external_action：v7传入外层reservation ID，两层幂等预留/结算；未知外部结果仍保留整笔额度。新增成功及未知调用测试。最终回归43 passed、1 skipped（未配置测试PG）；node --check和git diff --check通过。

第二次任务7f7a8b60-68ac-441d-b2c7-4526d27259a6正常finished，280/300请求，3轮，stop_reason=critic_stop，95个动作未测；59观察（6candidate/53inconclusive），6候选根因。登录401/500/401的SQL错误候选保留；搜索q重复布尔差分候选；另4条匿名文件读取候选（audit.json、announcement_encrypted.md、acquisitions.md、docker-compose.yml），敏感性需复核，announcement响应截断。
真实MCP回执：Dalfox27请求，工具结果受限/异常而非XSS阴性；SQLMap40请求，本固定策略未检出注入，不能否定内置差分。账本59条预留，无重复mcp条目、无未结算预留，charged280/available20。未强行花完余额。
报告核验verified，signature_verified=true、audit_valid=true，59条证据、312阶段；这表示完整性而非漏洞已确认。结果 evaluation/reliability_live_fixed_result_20261112.json；核验 evaluation/reliability_live_fixed_verify_20261112.json。

剩余问题：Dalfox受限结果需单独分析；模型要求的独立复测尚未成为完整确认闭环；95动作未测，未实现大部分漏洞覆盖；SQLMap固定策略漏检与有效请求构造需后续改进。停止原因预算耗尽分支本轮通过单测，最终真机没有耗尽预算，不冒称真机验证该分支。未全量回归、提交、推送。工作台保留运行。

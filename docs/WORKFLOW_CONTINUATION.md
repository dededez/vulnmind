# 工作流后续开发（2026-11-08）

本轮按用户要求推进功能与本机交付，暂不做生产运行或独立质量验收。此前 1086 项测试是上一版结果；本轮结果另记。

## Web 发现、审批、验证、证据、报告

```powershell
vulnmind workflow-web --workflow-id <UUID> --project-id <项目UUID> `
  --start <授权URL> --scope-file <授权JSON> --rounds 3 --agent-plan
```

该命令先完成可恢复爬取，保存端点并生成有界探测计划，返回 `waiting_approval`、`approval_id`、计划摘要及具体 probes。使用既有 `approvals decide --id <approval_id> --approver <操作者> --local-owner` 批准这一轮，再运行原命令继续。不会自动批准。

每轮最多 5 项、总共最多 3 轮。`--agent-plan` 让模型根据前轮分类结果选择剩余候选索引；它不能添加 URL/载荷，也不能重复已执行的探测。没有信号或没有剩余探测则结束。有信号且还有候选才进入下一轮审批。未指定该选项时按确定性顺序选择。模型选择属于建议，不是漏洞验证证明。

每轮结果写入 findings 和内容寻址证据，并生成新报告；旧报告保留。所有探测，包括无信号结果，都可追溯。结果证据是分类记录；原始有界 HTTP 响应保存在对应 HTTP operation 的回执中。完成后重放只读取已提交阶段，不重发网络请求。协调器阶段可安全恢复，是因为实际发送仍由独立 HTTP 回执保护，未知请求不会被外层自动重发。

网络子操作 UUID：爬取为父 workflow UUID 的 UUID5(`crawl`)，验证为每轮 approval UUID。父流程的 discover/approval 回执保存关联 ID；用 `workflow-status` 分别查看。需要显式恢复的是发生不确定执行的子 HTTP 阶段。审批到期或拒绝会阻止继续；当前版本不自动换审批绕过原决定。

这是 Web 调查流程；仓库静态分析仍使用 `workflow-run`。没有把源码位置自动映射到线上 URL，也没有自动执行任意利用代码。

## 有证据绑定的人工确认

```powershell
vulnmind finding-attest --attestation-id <稳定UUID> --scan-id <扫描UUID> `
  --fingerprint <发现指纹> --evidence-id <已存证据UUID> `
  --verdict confirmed --actor <操作者> --reason "已在授权环境核对复现，说明确认依据"
```

可重复提供 `--evidence-id`；结论为 confirmed 或 not_reproduced。命令检查所有证据属于该发现，读取并校验实际文件，绑定发现的 observation_revision，以本机签名密钥签名。回执、发现状态与审计同事务提交，再独立生成可恢复的新报告。

报告增加 `attestations` 和 `attested_counts`，与扫描器原始来源声明分开。复用确认时重新校验证据、版本、HMAC 和审计链；改变观察结果、证据或签名后不能沿用旧确认。确认代表持有本机密钥的操作者作出的证据绑定结论，不是自动证明可利用，也不是多用户身份认证。自动探测仍只产生 candidate/inconclusive。

## Skills 与项目记忆

`workflow-run --skills <目录> --use-memory` 在知识阶段保存上下文快照。Skills 按仓库目标与实际漏洞类型过滤，引用含版本和内容摘要；只作为模型的不可信参考，不授予工具执行权限。读取同项目的、已明确确认且有效的长期记忆，最多 8 条。分析与报告 Agent 使用该快照，续跑不受源文件后来变化影响。

```powershell
vulnmind memory-promote --source-id <工作记忆UUID> --actor <确认人> `
  --content "经过核对、可供该项目后续任务使用的经验"
```

晋升显式记录确认人和来源，禁止已失效/过期来源。长期记忆读取沿用既有来源链有效性校验，需要保留时区的 PostgreSQL；SQLite 的此项读取按既有策略失败关闭。模型不会自动把未经确认的建议变成长期事实。

## 报告签名与证据回收

本机报告签名密钥已写入被忽略的 `.env`，不在文档或日志展示。新工作流报告、重建报告自动签名。历史报告可继续用 `report-sign` 显式补签，使用 `report-verify` 检查。密钥应与数据库/文件一起妥善保管；本轮没有轮换或覆盖已有密钥。

`evidence-gc --apply` 在 Windows 上使用专门实现：事务级证据锁保护引用快照，从卷根到证据目录逐级打开禁止删除共享的句柄，拒绝重解析点；文件句柄禁止写入/替换，重新核对修改时间和完整哈希，再通过该句柄删除。仅删除超过宽限期、无数据库引用的内容寻址文件；默认仍为 dry-run。独立 `scan_store` 未协调删除保持拒绝。其他平台没有不安全的路径删除回退。

该能力依赖同一数据库中的协作写者和可信本机操作者；不覆盖绕过协议的任意 SQL/直接写文件。本轮只在临时测试目录执行实际删除，没有清理用户真实证据库。

## 本轮明确未推进

生产部署、多租户身份、全局配额、WAL/PITR、独立标注效果评测和生产规模验收按用户要求暂缓。任务中未知外部执行仍需明确恢复决定。受控多轮调查不等同于无限自主渗透。

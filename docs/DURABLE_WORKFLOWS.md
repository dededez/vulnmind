# 可恢复多 Agent 工作流与 HTTP 权限

后续功能（Web 多轮闭环、证据绑定确认、Skills/记忆、签名和 Windows 回收）见 [续接开发说明](WORKFLOW_CONTINUATION.md)。该说明取代本页末尾关于实际 GC 不在开放范围的历史结论。

本页描述 2026-11-08 验证完成的产品入口。此前交接中“规划之外未拆分”和“fetch/crawl/validate-run 暂停”的结论由本页及 STATUS 最新验证记录取代。旧 `workflow-scan` 保留兼容；新任务使用 `workflow-run`。

## 主流程

`workflow-run` 运行以下 LangGraph 节点，各节点有数据库回执：

```mermaid
flowchart LR
  I[初始化] --> P[规划 Agent]
  P --> A[仓库分析与工具]
  A --> E[证据持久化]
  E --> K[知识检索与快照]
  K --> X[分析 Agent]
  X --> T[研判 Agent]
  T --> W[报告 Agent]
  W --> R[报告落盘]
  R --> M[工作记忆]
  M --> F[完整性检查与完成]
```

工具规划仅选择显式启用的分析器，内置 TLS 检查始终执行。分析 Agent 接收有限发现元数据；`--agent-knowledge` 额外发送已保存的知识快照。研判接收分析意见；报告 Agent 接收研判与分析意见。模型输出是建议，不能修改确定性严重度、验证状态或证据。模型角色均为显式选项；未启用时对应阶段记录停用结果，仍可执行完整的确定性扫描。

```powershell
.\.venv\Scripts\python.exe -m vulnmind workflow-run `
  --workflow-id <新任务UUID> --project-id <项目UUID> `
  --repository <授权仓库绝对路径> --scope-file <授权JSON> `
  --bandit-json <外部Bandit报告> --agent-plan `
  --knowledge-context --agent-knowledge --agent-analysis --agent-review --agent-report

.\.venv\Scripts\python.exe -m vulnmind workflow-status --workflow-id <同一个UUID>
.\.venv\Scripts\python.exe -m vulnmind workflow-context --workflow-id <同一个UUID>
.\.venv\Scripts\python.exe -m vulnmind report --scan-id <输出的scan_id>
```

可用 `--gitleaks-sandbox`、`--trivy-sandbox`、`--semgrep-sarif` 代替或补充 Bandit。外部报告路径与内容摘要绑定任务。知识阶段要求 PostgreSQL、已有知识索引及本地 Qwen encoder；其他阶段支持 PostgreSQL 或文件 SQLite。新入口的知识阶段始终独立，继承的 `--staged-knowledge` 兼容选项不再改变行为。`--agent-knowledge` 在新入口启用分析 Agent 的知识建议，不依赖旧入口的 `--agent-review` 限制。

相同命令和 UUID 可跨进程继续。已提交的模型结果不再调用模型，也不要求重新初始化模型凭据。`--pause-after <阶段>` 在回执提交后正常暂停，用于检查或演练；不改变任务输入绑定。`--reconcile` 在新入口只读取已完成回执，不启动缺失阶段。

## 恢复语义

`durable_steps` 保存阶段、输入摘要、执行次数、结果及结果摘要。业务数据、完成回执和终态审计同事务提交。阶段执行期间不持有业务写事务；工具和模型子事件独立持久化，并关联到阶段 operation ID。恢复会验证结果摘要、终态审计绑定与完整审计链。

PostgreSQL 使用会话级 advisory lock；SQLite 使用数据库旁的 OS 文件锁。锁随进程退出释放。并发执行和人工恢复争用同一把锁，正在运行的任务不能被另一进程重置。SQLite 文件数据库和锁目录必须在同一台主机的本地磁盘；分布式执行使用 PostgreSQL。

仅含数据库事务或内容寻址存储的阶段可安全重新完成；仓库工具、模型或 HTTP 在执行中断且没有完成回执时保持 `unknown`，不会自动重复。确认后可显式决定：

```powershell
vulnmind audit-trace --call-id <workflow-status返回的operation_id>
vulnmind workflow-recover --workflow-id <UUID> --stage <阶段名> `
  --action retry --reason "已核对中断情况，接受该阶段可能再次执行" --acknowledge-possible-repeat
# 再执行原命令继续。也可 --action abort 终止该阶段。
```

`retry` 是明确接受可能重复的人工决定，不是“保证外部操作恰好执行一次”。发送请求与数据库提交之间不存在跨系统原子事务。缺少回执无法证明请求没发送；不要通过更换 UUID 绕过未知状态。当前授权必须仍有效，输入变更会被拒绝。报告与证据文件应与数据库一起备份；文件缺失或被修改会阻止完成核验。

## 已开放的三个命令

`VULNMIND_ENABLED_HTTP_COMMANDS` 为 JSON 列表，当前配置启用 `fetch`、`crawl`、`validate-run`。可设为空列表临时停用。每个请求仍要求有效授权文件及显式 IP 网段；开启能力不赋予任意目标的访问授权。

```powershell
vulnmind fetch --operation-id <UUID> --url <授权URL> --scope-file <授权JSON>
vulnmind crawl --operation-id <另一个UUID> --start <授权URL> --scope-file <授权JSON> `
  --store --project-id <项目UUID>
vulnmind validate-request --scan-id <扫描UUID> --url <带参数的授权URL>
vulnmind approvals list --scan-id <扫描UUID>
vulnmind approvals decide --id <approval_id> --approver <操作者> --local-owner
vulnmind validate-run --scan-id <扫描UUID> --url <同一URL> `
  --scope-file <授权JSON> --approval-token <approval_id>
```

`fetch`/`crawl` 未提供 operation ID 时生成并返回一个；保存它用于续跑。`validate-run` 使用 approval ID 作为稳定 operation ID；计划的单次批准消费与批准阶段回执同事务提交。每个探测分别保存 HTTP 结果，重放直接复用；恢复发送余下探测时仍检查批准期限与当前授权。`--plan-file` 同样受整份计划摘要约束。命中只标为 candidate，无信号只标为 inconclusive。

`--local-owner` 仅适用于持有本机 HMAC 配置的可信 CLI 操作者，对这一个审批决定签名；不会批准其他计划。它不提供登录或多租户身份认证。原 HMAC credential 与 SSH signer 路径继续可用。安装脚本只在未配置任何审批方式时生成本地 HMAC 密钥，存入忽略的 `.env`，不回显密钥。

## 网络出口

产品入口使用 `IsolatedHttpBroker`，运行在 `VulnMindLab` 的 Python 3 中，可由 `VULNMIND_HTTP_BROKER_DISTRO` 指定可信发行版。旧 curl/socat 原型仍停用，不作为回退。

可信 broker 独立复核 origin、端口、路径、授权有效期及所有解析 IP，连接固定数值 IP；之后进入无可用网络接口的新 network namespace、root 所有且不可写的空 chroot（无宿主 UNIX socket、/proc 或可执行文件），降低为 nobody 并设置 no-new-privileges，仅保留这一个已连接 socket。broker 自己构造单个 GET/HEAD，完成上游 TLS 主机名/证书校验并有界读取；模型和分析工具只能收到 JSON，不能取得 socket、CONNECT 隧道或运行任意代码。无代理继承、无自动重定向、无共享 WSL 防火墙/NAT/转发修改。broker、项目代码、发行版和内核属于可信计算边界；不声称能防御已控制这些组件的攻击者。隔离失败前可能已完成 TCP 握手，HTTP 数据仅在隔离成功后发送。

系统 CA 默认启用。专用靶场可设置 `VULNMIND_HTTP_CA_FILE` 为显式可信 CA PEM；没有关闭 TLS 校验的选项。响应体上限 1 MB，单次请求有绝对超时和内存上限；一次爬取最多 50 页、一次验证最多 20 探测。同一任务内请求有节流；这不等同于多任务共享的全局配额。

实现参考 [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) 和 [Python TLS 验证文档](https://docs.python.org/3/library/ssl.html)。本机验证结果见 STATUS；不把本机样例通过等同于通用生产环境安全认证。

## 本机配置与验证

迁移头为 `0017_durable_steps`。本机安装脚本先备份配置中的 loopback PostgreSQL，再迁移并补齐缺失的报告/证据目录和本地审批配置：

```powershell
.\.venv\Scripts\python.exe scripts/setup_durable_runtime.py
.\.venv\Scripts\python.exe -m vulnmind doctor
$env:VULNMIND_RUN_HTTP_LIVE='1'
.\.venv\Scripts\python.exe -m pytest -q tests/integration/test_http_broker_live.py
.\.venv\Scripts\python.exe scripts/pg_durable_restore.py
```

活体测试只启动任务专用临时本机服务，不访问外部目标。工作流与数据完整性测试在临时 SQLite/PostgreSQL 执行。`evidence-gc --apply`、生产部署、多租户权限不在本次开放范围。

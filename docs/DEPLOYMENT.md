# 部署与运维（VulnMind）

> 当前入口：`workflow-run` 提供逐阶段恢复；`fetch`、`crawl`、`validate-run` 已通过可信 broker 开放，依赖 Windows/WSL 的 `VulnMindLab`，需迁移到 0017。配置与恢复见 [DURABLE_WORKFLOWS.md](DURABLE_WORKFLOWS.md)。`evidence-gc --apply` 仍暂停。PostgreSQL 审计在 READ COMMITTED 下使用事务级 advisory lock；普通 Docker 镜像不提供 WSL 网络 broker。

本文件描述一个保守的最小部署路径。VulnMind 仍是原型：所有发现默认 `unverified`，模型复核与主动验证都只是建议性输入，不能当作验收结论。

## 容器镜像

```powershell
docker build -t vulnmind:local .
docker run --rm vulnmind:local --help
```

镜像以非 root 用户（uid 10001）运行，报告与证据默认写入 `/data/reports`、`/data/evidence`。**镜像内没有 WSL 沙箱**：`--gitleaks-sandbox`、`shell-run` 依赖宿主上的 `VulnMindSandbox` 发行版，必须在具备该边界的 Windows 主机上运行，不能在普通容器里提供等价隔离。

本地编排可用 `docker-compose.yml`（PostgreSQL 17 + pgvector 镜像 + CLI）。密码只从环境或未跟踪的 `.env` 读取：

```powershell
$env:POSTGRES_PASSWORD = "<strong-password>"
docker compose up -d postgres
docker compose run --rm cli --help
```

## 配置

| 变量 | 作用 |
|---|---|
| `VULNMIND_DATABASE_URL` | SQLAlchemy URL，例如 `postgresql+psycopg://user:pass@host/db`；仅通过安全渠道提供 |
| `VULNMIND_REPORT_ROOT` | 内容寻址报告目录 |
| `VULNMIND_EVIDENCE_ROOT` | 内容寻址证据目录 |
| `VULNMIND_TEST_DATABASE_URL` | 仅测试用的一次性数据库；不要指向生产库 |
| `DEEPSEEK_API_KEY` / `VULNMIND_DEEPSEEK_API_KEY` | `agent-run` / `scan --agent-review` 的模型密钥；不落盘、不打印 |
| `VULNMIND_APPROVAL_SECRET` 或 `VULNMIND_APPROVAL_ALLOWED_SIGNERS` | 审批凭据，二选一 |

迁移必须人工审阅后对明确指定的数据库执行：

```powershell
.venv/Scripts/python -m alembic upgrade head
.venv/Scripts/python -m alembic downgrade -1   # 仅在明确可回退的测试库使用
```

## 备份与恢复演练

1. 迁移与写入前做一次 `pg_dump -Fc`；报告/证据目录用同版本快照或 `robocopy` 备份，二者要同一时间点。
2. 恢复演练：新建空库 → `pg_restore` → 设置 `VULNMIND_DATABASE_URL` → `vulnmind audit-verify` 必须返回 `valid`（旧版本产生的 NULL 行会计入 `unhashed`，不影响 valid）。
3. 抽查 `vulnmind verify --scan-id <UUID>`：报告与证据哈希一致；`broken` 说明文件缺失或被改。
4. 审计链只证明"从第一个带哈希事件起未发生简单篡改"，不防能重写整表并重算哈希的攻击者；恢复后仍应限制数据库账号权限并保留外部日志。

本机可用一次性演练脚本验证上述流程（不接触现有数据库）：

```powershell
.venv/Scripts/python scripts/pg_backup_restore.py
# 核对输出 status=ok、实际迁移 head、行数、审计链和 pgvector
```

该脚本覆盖逻辑备份/恢复与迁移头、行数、pgvector、审计链核对；不覆盖 WAL 时间点恢复、跨版本升级、主备切换与生产备份窗口。

## 运行时检查

```powershell
vulnmind doctor                         # 只读自检：DB/迁移头/审计链/目录/凭据；0=ok或degraded，1=failed
vulnmind audit-verify --limit 2000     # valid=0，broken=1，缺库=2
vulnmind verify --scan-id <UUID>       # 报告/证据完整性
vulnmind scans --project-id <UUID>     # 扫描列表
vulnmind endpoints --scan-id <UUID>    # 已存爬取端点
```

## 已知边界

- 审批人身份仍是调用方声明的文本；没有 IdP 集成或双人复核。
- 审计链使用应用级数据库锁协调写入，不能防止绕过该协议的写入者或有权重写整表的管理员；生产并发仍需验证。
- 沙箱（Gitleaks/Trivy/Shell/HTTP）依赖 WSL 发行版与宿主内核，镜像不提供。
- 没有高可用、TLS 终止、密钥管理或速率限制网关；不要直接暴露到公网。
- 真实 PostgreSQL 故障切换、资源限制与压力测试尚未执行。

PostgreSQL 审计写入要求当前事务使用 `READ COMMITTED`：`REPEATABLE READ` 和 `SERIALIZABLE` 会失败关闭。事务级 advisory lock 必须与读取链尾时可看到前一个提交的快照配合；无锁写入者、数据库管理员重写链、生产并发负载及非默认设置仍不在本次验证范围内。

> 最新：新任务统一使用通用模式；产品不再提供目标适配器或固定靶场探针。使用说明见 [通用扫描](docs/GENERIC_SCANNING.md)，验证与边界见 [修复交付](docs/GENERIC_REPAIR_DELIVERY_20261111.md)。

# VulnMind

**面向授权仓库与 Web 目标的本机安全分析工作台**：把源码线索、部署声明、受控请求、证据与独立复核串成一条可恢复、可校验的证据链。

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![Version](https://img.shields.io/badge/version-0.2.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17%20%2B%20pgvector-336791)
![Local only](https://img.shields.io/badge/runtime-127.0.0.1-lightgrey)

> 只用于**你自己拥有或已获明确授权**的仓库与 Web 目标。工具默认只监听 `127.0.0.1`，不提供多租户、云托管或生产部署形态。

## 它解决什么问题

手工做一次完整的授权安全评估，往往要在这些事之间来回切换：读源码找入口、确认部署对应关系、构造有限请求、保存证据、复核误报、写报告、失败后重来。

VulnMind 把这些步骤做成一个**有预算、有审批、有证据、可恢复**的工作台：

- 从仓库静态分析出发，建立「源码 → 路由 → 部署 → 证据」的关联
- 每轮调查先给出**逐请求可见的审批计划**，批准后才发送
- 每个动作都有持久阶段回执，进程中断后可恢复，未知调用不会自动重发
- 报告带 HMAC 签名，证据与阶段回执可校验
- 模型只做规划与独立复核，**不能把候选提升为已确认漏洞**

## 核心能力（v6）

| 能力 | 说明 |
|---|---|
| 批次规划 | 每轮最多 24 个有界动作，按漏洞类别轮转、按成本排序；最多 3 轮 |
| 全局预算 | SQLite 预算账本，动作级先预留、执行后按实际结算；耗尽时干净停止并写入 `stop_reason` |
| 路由索引 | 固定 TypeScript 6.0.3（SHA-256 校验）解析 Express/TypeScript 路由与前端 URL；排除构建/测试/示例目录 |
| 检测器 | 17 类：SQL 布尔/错误/登录注入、弱口令、匿名配置、常见暴露端点、目录文件下载、目录列表/堆栈、跳转、NoSQL、HTML 上下文、模板表达式、反射、CORS、安全头、浏览器 XSS、跨账号读取 |
| 浏览器复核 | Playwright + 本机 Edge；越界请求在发出前中止，子资源计入同一预算，只有真实 `alert` 才判脚本执行 |
| 测试账号 | 服务端生成一次性账号，随机口令 DPAPI 加密，token 仅内存 + 加密会话文件，日志与证据自动脱敏 |
| 独立复核 | Critic 读取结构化观察与摘要，对证据不足的结论提出异议 |
| 可恢复 | 阶段 Journal + 审批计划复用；恢复后校验整条证据链 |
| 离线覆盖率 | 用冻结真值评估一次运行覆盖了哪些根因（仅评估，运行时不读取） |

## 快速开始

### 依赖

- Python **3.11+**（开发环境为 3.13）
- PostgreSQL **17 + pgvector**（迁移头 `0019_durable_step_failed`）
- 可选：WSL 发行版（隔离 HTTP 出口与外部工具）、`DEEPSEEK_API_KEY`（模型规划）、Playwright + Edge（浏览器复核）

### 安装

```powershell
git clone https://github.com/dededez/vulnmind.git
cd vulnmind
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
copy .env.example .env    # 填写数据库、审批密钥等
```

需要模型 / 浏览器 / 外部工具时：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test,browser]"
```

### 初始化数据库

```powershell
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe -m vulnmind doctor
```

`doctor` 是只读自检：数据库连接、迁移版本、审计链、报告/证据目录、审批与签名配置、模型密钥是否存在（只报布尔）。期望除可选模型密钥外全部 `ok`。

### 打开工作台

```powershell
# 方式一：后台常驻（推荐；关闭终端后仍运行，页面会在服务重启后自动重连）
.\start-workbench-background.cmd
# 停止后台服务
.\start-workbench-background.cmd -Stop

# 方式二：前台运行（Ctrl+C 停止）
.\start-workbench.cmd
```

浏览器访问 **http://127.0.0.1:8765**，点击「本地演示靶场」可跑一个自带 fixture 的完整流程，无需外部目标。

## 一次调查是怎么走的

```text
源码快照 → 接口关联 → 仓库分析 → 分类 → 工具路由 → 执行路由
   → (每轮) 知识检索 → 规划 → 准备计划 → 人工审批 → 消费审批
   → 执行请求 / MCP / 浏览器 → 结果与证据落库 → 独立复核
   → 报告签名归档 → 完整性校验
```

关键约束：

- **审批绑定具体请求**：计划哈希进入审批，批准后只有该计划可以执行
- **预算先行**：动作执行前按最坏成本预留，执行后按实际结算
- **证据落库**：每次响应计算哈希，证据内容独立存储，报告引用可重算
- **失败关闭**：进程中断留下 `unknown` 阶段，必须显式恢复；不会自动重发未知外部调用

## 常用 CLI

```powershell
# 自检与版本
.\.venv\Scripts\python.exe -m vulnmind --version
.\.venv\Scripts\python.exe -m vulnmind doctor

# 建项目与仓库扫描（scope.json 为授权范围文档）
.\.venv\Scripts\python.exe -m vulnmind project-create --name "本地靶场"
.\.venv\Scripts\python.exe -m vulnmind scan --repository <仓库目录> --project-id <UUID> --scope-file scope.json

# 多 Agent 可恢复工作流
.\.venv\Scripts\python.exe -m vulnmind workflow-run --workflow-id <UUID> --repository <仓库目录> --project-id <UUID> --scope-file scope.json
.\.venv\Scripts\python.exe -m vulnmind workflow-status --workflow-id <UUID>
.\.venv\Scripts\python.exe -m vulnmind workflow-recover --workflow-id <UUID> --stage <阶段> --action retry --reason "<理由>" --acknowledge-possible-repeat

# 校验与审计
.\.venv\Scripts\python.exe -m vulnmind verify --scan-id <UUID>
.\.venv\Scripts\python.exe -m vulnmind audit-verify
```

完整命令列表：`python -m vulnmind --help`。

## 配置

配置来自环境变量或项目根目录 `.env`（模板见 `.env.example`）：

| 变量 | 说明 |
|---|---|
| `VULNMIND_DATABASE_URL` | SQLAlchemy PostgreSQL URL |
| `VULNMIND_REPORT_ROOT` / `VULNMIND_EVIDENCE_ROOT` | 报告与证据目录 |
| `VULNMIND_APPROVAL_SECRET` | 本机审批 HMAC 密钥（≥32 字符） |
| `VULNMIND_REPORT_SIGNING_KEY` | 报告签名密钥（与审批密钥互斥，≥32 字符） |
| `VULNMIND_HTTP_BROKER_DISTRO` | WSL 发行版名称（隔离出口） |
| `VULNMIND_ENABLED_HTTP_COMMANDS` | 已开放的独立 HTTP 入口，如 `["fetch","crawl","validate-run"]` |
| `DEEPSEEK_API_KEY` | 可选；启用模型规划与复核 |
| `VULNMIND_COVERAGE_TRUTH` | 可选；离线覆盖率真值文件路径 |

**不要提交 `.env`**。仓库的 `.gitignore` 已排除它以及数据库、日志、运行时证据目录。

## 测试

```powershell
# 离线全量（无需数据库）
.\.venv\Scripts\python.exe -m pytest -q

# 一次性 PostgreSQL + pgvector 全量（自动创建临时集群）
$env:PYTEST_ADDOPTS="-p no:cacheprovider -rs"
.\.venv\Scripts\python.exe scripts\test_local_postgres.py --require-pgvector
```

- 离线回归当前为 **1239 passed / 75 skipped**；跳过项为 PostgreSQL、真实 WSL、真实模型等显式 opt-in 测试
- Windows 上部分符号链接测试会跳过
- 浏览器复核有独立的 live 测试：`VULNMIND_BROWSER_LIVE=1`

## 仓库结构

```text
src/vulnmind/
  workbench/          # 调查引擎、检测器、预算账本、浏览器、账号、覆盖率
  analysis/           # 爬取、验证、HTTP 隔离出口、持久化
  agents/             # 模型运行时、提示词、独立复核
  graph/              # 可恢复工作流与仓库分析图
  knowledge/          # 技能加载、检索、嵌入
  persistence/        # ORM、审计链、阶段 Journal
  reports/            # 报告生成、签名、校验
  security/           # 授权范围、审批、限速
  tools/              # 受控工具注册表
  integrations/       # MCP 客户端与 HexStrike 适配
tests/                # 单元与集成测试（含 PostgreSQL/SQLite 双跑）
migrations/           # Alembic 0001–0018
docs/                 # 使用、部署、工作流与设计文档
knowledge/corpora/    # 公开语料（含来源与许可证）
skills/               # 方法技能卡
scripts/              # 运维、验收、评估脚本
```

## 安全边界

- 仅用于授权目标；启动页要求显式确认仓库与部署绑定关系
- 不执行 DoS/RCE、内存炸弹、XXE 读取系统文件、上传可执行内容
- 需要登录、注册、浏览器或外部情报的检查，只有在显式勾选后才可能执行
- 候选（`candidate`）≠ 已确认漏洞；行为确认也不等于可利用性证明
- 生产部署、多租户认证、跨系统 exactly-once 不在当前范围

## 文档

- [v6 交付说明](docs/WORKBENCH_V6.md)：能力、配置、验证记录、已知边界
- [工作台使用](docs/WORKBENCH.md)：界面与流程
- [可恢复工作流](docs/DURABLE_WORKFLOWS.md)：阶段、审批、恢复
- [部署](docs/DEPLOYMENT.md)：容器、数据库、备份与校验
- [知识检索](docs/KNOWLEDGE_DETECTION.md)
- [变更记录](CHANGELOG.md)

## 许可证

[MIT](LICENSE) © 2026 dededez

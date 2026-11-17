# VulnMind

**面向授权仓库与 Web 目标的漏洞挖掘智能体平台**：将源码静态分析、知识检索、智能体协同规划、逐请求人工审批、受控探测与浏览器复核、独立 Critic 审查以及签名证据链整合为一套本机运行、可中断恢复的自动化安全评估工作台。

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![Version](https://img.shields.io/badge/version-0.2.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17%20%2B%20pgvector-336791)
![Local only](https://img.shields.io/badge/runtime-127.0.0.1-lightgrey)

> 仅用于**你自己拥有或已获明确授权**的仓库与 Web 目标。平台默认仅监听 `127.0.0.1`，不提供多租户、云托管或生产部署形态。

## 为什么做 VulnMind

在一次完整的授权漏洞挖掘中，安全研究人员通常需要在多个环节之间反复切换：通读源码梳理攻击面、核对代码路由与线上部署的映射、构造受控验证请求、保留原始响应证据、剔除误报、编写报告并在意外中断后重头再来。

VulnMind 将这套人工挖洞流程抽象为**有边界、可审批、可审计、可恢复**的智能体协作流水线：

- **白盒与黑盒联动**：从仓库静态分析出发，建立「源码线索 → 接口路由 → 部署目标 → 验证证据」的完整关联
- **智能体规划 + 人工闸门**：每轮由智能体生成**逐请求可见的探测计划**，经本地 HMAC 审批签发后才允许执行
- **预算与边界硬约束**：所有探测动作在执行前预留预算、按实际消耗结算，越界请求直接拦截
- **断点可恢复**：每个阶段落库持久回执（Journal），进程中断后可安全恢复，未知状态的外部调用绝不盲目重发
- **模型与定性解耦**：智能体仅负责线索规划与独立复核，**不能在缺乏真实证据的情况下将候选直接定性为已确认漏洞**

## 平台核心能力

| 模块 | 能力说明 |
|---|---|
| 智能体工作流编排 | 基于 LangGraph 构建多阶段可恢复工作流，支持中断恢复、状态追踪与失败显式处置 |
| 知识增强与路由索引 | 结合安全方法技能卡与本地语料检索；内置 TypeScript AST 路由索引（固定编译器版本与 SHA-256 校验），提取接口、参数位置、sink 信号与前端 URL 线索 |
| 有界批次规划 | 每轮最多规划 24 个有界探测动作，按漏洞类别轮转并按成本排序，最多执行 3 轮 |
| 全局预算账本 | SQLite 预算账本实现动作级预留与实际结算，额度耗尽时干净收口并记录 `stop_reason` |
| 多维度检测矩阵 | 覆盖 17 类常见 Web 与接口风险：SQL 布尔/错误/登录注入、NoSQL 类型差分、弱口令、匿名配置、常见暴露端点、目录文件下载、目录列表/堆栈泄露、开放跳转、HTML 上下文、模板表达式、反射、CORS、安全头、浏览器 XSS 与跨账号读取 |
| 浏览器真实复核 | 基于 Playwright + 本机 Edge 执行动态验证，越界请求在发出前中止，子资源纳入统一预算，仅真实脚本执行（如 `alert`）才判定命中 |
| 隔离出口与工具集成 | 支持通过受控工具注册表、MCP 客户端及 WSL 隔离出口执行 HTTP 探测与外部工具调用 |
| 独立复核（Critic） | 独立的复核智能体读取结构化观察与摘要，对证据链不充分的候选结论提出质疑与驳回 |
| 测试账号与脱敏 | 服务端按需生成一次性测试账号，随机口令采用 DPAPI 加密，令牌仅驻留内存与加密会话文件，日志与证据自动脱敏 |
| 签名报告与离线评估 | 证据独立落库并计算响应哈希，报告支持 HMAC 签名与全量完整性校验；支持基于离线真值评估根因覆盖率（运行时不读取真值） |

## 挖洞工作流全貌

```text
源码快照 → 接口关联 → 仓库分析 → 分类与工具路由
   → (每轮循环) 知识检索 → 智能体规划 → 准备探测计划 → 人工审批 → 消费审批
   → 受控请求 / MCP 工具 / 浏览器复核 → 观察与证据落库 → Critic 独立复核
   → 报告签名归档 → 证据链完整性校验
```

关键安全机制：

- **审批绑定具体请求**：探测计划摘要（Hash）进入审批凭证，批准后仅允许执行该确定计划
- **预算先行**：动作执行前按最坏成本预留额度，完成后按实际开销结算
- **证据可重算**：每次请求响应计算哈希并独立存档，报告引用与审计链可独立复核
- **失败关闭（Fail-Closed）**：进程异常中断留下 `unknown` 阶段时必须显式恢复，系统不会自动重发状态未知的外部请求

## 快速开始

### 环境依赖

- Python **3.11+**（推荐 3.13）
- PostgreSQL **17 + pgvector**（迁移头 `0019_durable_step_failed`）
- 可选组件：WSL 发行版（用于隔离 HTTP 出口与外部工具）、`DEEPSEEK_API_KEY`（启用智能体规划与复核）、Playwright + Edge（启用浏览器复核）

### 安装

```powershell
git clone https://github.com/dededez/vulnmind.git
cd vulnmind
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
copy .env.example .env    # 填写数据库连接、审批密钥与报告签名密钥等
```

如需启用模型规划、浏览器复核或外部工具集成：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test,browser]"
```

### 初始化数据库与自检

```powershell
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe -m vulnmind doctor
```

`doctor` 为只读自检命令，用于核查数据库连接、Alembic 迁移版本、审计链、报告/证据目录、审批与签名密钥配置以及模型密钥可用性（仅输出布尔状态）。除可选的模型密钥外，其余检查项均应返回 `ok`。

### 启动智能体工作台

```powershell
# 方式一：后台常驻（推荐；关闭终端后仍保持运行，前端支持断线自动重连）
.\start-workbench-background.cmd
# 停止后台服务
.\start-workbench-background.cmd -Stop

# 方式二：前台运行（Ctrl+C 停止）
.\start-workbench.cmd
```

启动后在浏览器访问 **http://127.0.0.1:8765**。平台内置「本地演示靶场」入口，可直接跑通完整智能体挖洞流程，无需外部目标。通用任务使用方式详见 [通用扫描指南](docs/GENERIC_SCANNING.md)。

## 常用 CLI

```powershell
# 自检与版本
.\.venv\Scripts\python.exe -m vulnmind --version
.\.venv\Scripts\python.exe -m vulnmind doctor

# 创建项目与执行仓库扫描（scope.json 为授权范围声明）
.\.venv\Scripts\python.exe -m vulnmind project-create --name "本地靶场"
.\.venv\Scripts\python.exe -m vulnmind scan --repository <仓库目录> --project-id <UUID> --scope-file scope.json

# 多智能体可恢复工作流
.\.venv\Scripts\python.exe -m vulnmind workflow-run --workflow-id <UUID> --repository <仓库目录> --project-id <UUID> --scope-file scope.json
.\.venv\Scripts\python.exe -m vulnmind workflow-status --workflow-id <UUID>
.\.venv\Scripts\python.exe -m vulnmind workflow-recover --workflow-id <UUID> --stage <阶段> --action retry --reason "<理由>" --acknowledge-possible-repeat

# 报告与审计链校验
.\.venv\Scripts\python.exe -m vulnmind verify --scan-id <UUID>
.\.venv\Scripts\python.exe -m vulnmind audit-verify
```

完整子命令说明可通过 `python -m vulnmind --help` 查看。

## 配置说明

配置从环境变量或项目根目录 `.env` 读取（模板见 `.env.example`）：

| 变量 | 说明 |
|---|---|
| `VULNMIND_DATABASE_URL` | SQLAlchemy PostgreSQL 连接串 |
| `VULNMIND_REPORT_ROOT` / `VULNMIND_EVIDENCE_ROOT` | 报告与证据存储目录 |
| `VULNMIND_APPROVAL_SECRET` | 本机审批 HMAC 密钥（≥32 字符） |
| `VULNMIND_REPORT_SIGNING_KEY` | 报告签名密钥（须与审批密钥不同，≥32 字符） |
| `VULNMIND_HTTP_BROKER_DISTRO` | WSL 发行版名称（用于隔离 HTTP 出口） |
| `VULNMIND_ENABLED_HTTP_COMMANDS` | 已开放的独立 HTTP 入口，如 `["fetch","crawl","validate-run"]` |
| `DEEPSEEK_API_KEY` | 可选；启用智能体规划与 Critic 复核 |
| `VULNMIND_COVERAGE_TRUTH` | 可选；离线覆盖率真值文件路径 |

**切勿提交 `.env` 文件**。`.gitignore` 已默认排除 `.env`、本地数据库、日志及运行时证据目录。

## 测试

```powershell
# 离线全量测试（无需 PostgreSQL）
.\.venv\Scripts\python.exe -m pytest -q

# 一次性 PostgreSQL + pgvector 全量测试（自动拉起临时实例）
$env:PYTEST_ADDOPTS="-p no:cacheprovider -rs"
.\.venv\Scripts\python.exe scripts\test_local_postgres.py --require-pgvector
```

- 离线测试套件中，依赖 PostgreSQL、真实 WSL、真实大模型 API 的用例为显式 opt-in 跳过项
- Windows 环境下部分符号链接相关测试会自动跳过
- 浏览器复核实时测试可通过 `VULNMIND_BROWSER_LIVE=1` 触发

## 仓库结构

```text
src/vulnmind/
  workbench/          # 调查引擎、检测器、预算账本、浏览器复核、账号与覆盖率
  analysis/           # 爬取、验证、HTTP 隔离出口、持久化分析
  agents/             # 智能体运行时、提示词、独立 Critic 复核
  graph/              # 可恢复工作流与仓库分析图
  knowledge/          # 技能卡加载、检索与向量嵌入
  persistence/        # ORM 模型、审计链、阶段 Journal
  reports/            # 报告生成、HMAC 签名与校验
  security/           # 授权范围校验、审批签名、限速
  tools/              # 受控工具注册表
  integrations/       # MCP 客户端与外部工具适配
tests/                # 单元与集成测试（支持 PostgreSQL / SQLite）
migrations/           # Alembic 数据库迁移脚本
docs/                 # 使用、部署、工作流与架构文档
knowledge/corpora/    # 公开安全语料（含来源与许可证）
skills/               # 安全分析方法技能卡
scripts/              # 运维、验收与评估脚本
```

## 安全边界

- 仅面向已授权目标；启动扫描前要求显式确认仓库与部署目标的绑定关系
- 严禁执行 DoS/RCE、内存炸弹、XXE 读取系统文件或上传可执行载荷
- 需要登录态、账号注册、浏览器交互或外部情报的探测，仅在显式授权勾选后才可能执行
- 候选发现（`candidate`）不等同于已确认漏洞；行为层面的差分确认也不等同于可利用性证明
- 多租户认证、生产级托管部署及跨系统 exactly-once 语义不在当前平台范围内

## 相关文档

- [通用扫描说明](docs/GENERIC_SCANNING.md)：通用任务接入与使用方式
- [工作台使用](docs/WORKBENCH.md)：界面操作与分析流程
- [可恢复工作流](docs/DURABLE_WORKFLOWS.md)：阶段状态、审批机制与故障恢复
- [部署指南](docs/DEPLOYMENT.md)：容器化、数据库配置、备份与校验
- [知识检索与检测](docs/KNOWLEDGE_DETECTION.md)：技能卡与语料检索机制
- [变更记录](CHANGELOG.md)

## 许可证

[MIT](LICENSE) © 2026 dededez

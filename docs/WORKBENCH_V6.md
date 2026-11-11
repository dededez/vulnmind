# VulnMind 工作台 v6 交付说明

版本 **0.2.0**。本文件描述当前可交付版本的能力、启动方式、配置项、验证证据与边界。它取代 v4 时代的"每轮最多两项、SQLMap 固定预留 300"表述；旧行为仍可在 UI 选择 v4/v5 复现。

## 1. 启动与验证

```powershell
.\.venv\Scripts\python.exe -m vulnmind --version      # VulnMind 0.2.0 (workbench v6)
.\.venv\Scripts\python.exe -m vulnmind doctor         # 期望 schema=head 0018，审计链 valid
.\start-workbench.ps1                                 # 或 python -m vulnmind ui --port 8765
```

浏览器打开 `http://127.0.0.1:8765`。首次使用可点"本地演示靶场"跑一个自有 fixture；真实目标需要填写本机仓库、部署 Origin、部署版本、授权依据与允许网段，并确认绑定。

模型模式需要 `DEEPSEEK_API_KEY`（用户级环境变量即可）。未配置时保持"规则模式"，不要勾选"启用模型规划"。

浏览器复核需要 `browser` 可选依赖与本机 Edge：

```powershell
.\.venv\Scripts\python.exe -m pip install "playwright>=1.40,<2"
```

## 2. 本版新增（v6 流水线）

- **批次规划**：每轮最多 24 个有界动作，按类别轮转、按成本排序；不再固定"每轮两项"。
- **全局预算账本**：SQLite 原子预留/结算，按动作最坏成本先预留、执行后按实际结算；预算耗尽时任务 `finished` 且写入 `stop_reason=budget_exhausted`，不会越界。
- **轮次额度**：60 / 150 / 90 累计额度（可由规划器在剩余额度内重分配），执行仍逐请求审批。
- **AST 路由索引**：固定 TypeScript 6.0.3（SHA-256 校验），排除 `data/static`、构建目录与测试夹具，按 `(method,path)` 合并重复，提取查询/JSON 参数位置与关键 sink 信号；前端 `hostServer + '/rest/…'` 与模板字面量的 URL 也会提取为线索（不是证据）。
- **检测器（17 类，按需勾选）**：SQL 布尔/错误/登录注入、弱口令、匿名配置、常见暴露端点、目录中的文件下载、目录列表/堆栈、跳转差分、NoSQL 类型差分、HTML 上下文、模板表达式、反射、CORS、安全头、**浏览器 XSS 复核**、**跨账号购物篮读取**。
- **账号与会话**：可勾选"注册一个本机测试账号"，服务端生成随机口令、DPAPI 加密保存，登录 token 只存在内存与 DPAPI 会话文件中；计划与证据中的 token 自动脱敏。
- **证据边界**：候选（candidate）与行为确认（verified_behavior）分开；浏览器只有真实 `alert` 才算脚本执行；跨账号读取只做 GET、只探测种子 1–3 号购物篮。
- **可恢复**：每阶段 Journal 回执、审批计划持久化并在恢复时复用（不会因账本余额变化重算计划），恢复后可校验整条证据链。审计链改为"首次全量 + 之后仅校验新增事件"（热路径约 0.05s，替代约 1.5s 的全量扫描；最终 `verify` 仍是全量）。
- **离线覆盖率评估**：任务完成后可在概览页点击"离线覆盖率"，由 `POST`/`GET /api/jobs/<id>/coverage` 用冻结真值（`VULNMIND_COVERAGE_TRUTH`，默认 `evaluation/juice_shop_coverage_ground_truth_20261111.json`）生成总体/配置内覆盖率与已覆盖根因。该数据只用于评估，引擎运行时不读取。

## 3. 新建任务的主要配置

| 字段 | 说明 |
|---|---|
| 流水线版本 | 默认 **v6**；v5 上下文管理、v4 兼容旧任务仍可选 |
| 轮数 / 预算 | 默认 3 轮 / 120 次；单任务所有执行器合计，外部 MCP 与浏览器子资源都计入 |
| 工具策略 | 外部优先（需要已验证的 HexStrike 回执）或仅内置 |
| 认证 | 可选 Bearer/Cookie（DPAPI 加密，仅发送到绑定 Origin） |
| 登录探针 | 允许对登录端点做有界 SQL 注入/弱口令对照；不会使用获得的会话 |
| 测试账号 | 注册一次性账号并对自己的资源做跨账号读取检查（仅本机） |
| 模型规划 | 需要模型密钥；启用后 Planner 与独立 Critic 都会读取结构化上下文 |

## 4. 已验证（真实运行，可复核）

| 任务 | 配置 | 结果 |
|---|---|---|
| `6122e4bc…` | v6 规则/内置 60 预算 1 轮 | finished、48 请求、20 观察、verify=verified |
| `47e07f31…` | v6 规则 120 预算 2 轮 | finished、117 请求、30 观察、verify=verified |
| `124fe7de…` | 带测试账号 40 预算 | finished、33 请求、会话建立、`/api/Cards` 由 401 变 200 |
| `67afb3ba…` | 带账号 + 浏览器 200 预算 2 轮 | finished、110 请求、27 观察、DOM XSS=`script_execution` |
| `b597fe25…` | 带账号 60 预算 | finished、52 请求、购物篮 IDOR=`cross_account_read` |
| `621035f8…` | 带账号 120 预算 3 轮 | finished、104 请求、`stop_reason=budget_exhausted`、`/ftp/acquisitions.md` 候选 |
| `61302aa9…` | **模型规划 + 独立复核**、固定配置 120 预算 2 轮 | finished、120 请求、32 观察、9 根因、verify=verified（182 阶段）；覆盖率 8.8% / 33.3% |

所有上述任务均通过 `verify`：报告签名、证据哈希、阶段回执与审计链一致。离线回归 **1230 passed、75 skipped**。

覆盖率与缺口见 覆盖率缺口（离线评估产物，未随仓库发布） 与 `scripts/juice_shop_coverage_report.py`（离线，不参与运行）。

## 5. 已知边界

- 不执行 DoS、RCE、内存炸弹、XXE 读取系统文件、上传可执行内容；不修改靶场源码。
- 需要登录态/注册/浏览器的挑战只有在显式勾选相应选项后才可能覆盖；未勾选时报告"未测试"，不显示为安全。
- 覆盖率不是产品功能：真值是离线评估文件，运行时不读取挑战答案。
- 恢复时审计链采用"全量一次 + 增量校验"（进程内缓存，120 秒后重新全量）；最终 `verify` 与 CLI 始终全量校验。增量模式对"尾部删除"有计数检测，但对**中间行被改写**只在全量校验时发现——需要更强的完整性保证时运行 `verify`。
- 外部 MCP 的 23 项回执绑定环境指纹；修改 worker/ops 源码后需要重新跑 `scripts/hexstrike_smoke.py` 覆盖 `validation.json`。
- 报告签名、审批密钥、数据库密码不得写入文档或提交；当前工作树全部改动未提交。

## 6. 故障排查

| 现象 | 处理 |
|---|---|
| 打开页面 403 | 用 `127.0.0.1` 而不是 `localhost`；服务重启后刷新一次页面会重建会话 |
| 任务 unknown，阶段停在 running | 用"阶段与恢复"里的 retry（未知外部调用先对账），不要重复发送 |
| 模型任务失败 | 检查 `DEEPSEEK_API_KEY` 是否在启动服务的用户环境中；必要时先用规则模式 |
| 浏览器复核 unavailable | 安装 `playwright` 且确认本机 Edge 存在；浏览器失败只记为未测试 |
| 预算不足提前结束 | 看报告的 `stop_reason` 与 `budget_skipped_actions`；调大预算或减少昂贵检测器 |

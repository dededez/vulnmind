# 为什么一直“检测不到漏洞”：2026-11-12 实测诊断

目标：本机授权靶场 `http://172.19.160.1:3000`（juice-shop-master），仓库 `<本机仓库>`。
方式：经本机工作台 API（127.0.0.1:8765）创建任务、逐轮审批，规则模式（未用模型）、仅内置检测器。三次运行全部 `finished`，未调真实模型、未用外部工具。测试脚本位于 `.devtools/`（drive_scan.py、simulate_schedule.py、analyse_report.py），结果见 `evaluation/diagnosis_{a,b,c}_20261112.json`。

## 三次实测结果

| 配置 | 预算 / 轮数 | 允许 POST | 检测器数 | 实际请求 | 观察 | 候选 | 未测动作 |
|---|---|---|---|---|---|---|---|
| A 诊断 | 300 / 3 | 是 | 11 | 296 | 68 | **7** | 177 |
| B 诊断 | 300 / 3 | 否 | 11 | 299 | 64 | **8** | 98 |
| C 界面默认 | 120 / 3 | 否 | 4 | 117 | 30 | **6** | 6 |

三次都是 `0 项具体行为已确认`。但候选不是空话，具体如下（A 配置）：

| 类型 | 位置 | 证据 |
|---|---|---|
| SQL 错误差分 | `POST /rest/user/login`（email） | 401 / 500 / 401，测试输入独有 `SQLITE_ERROR: unrecognized token` |
| SQL 错误差分 | `GET /rest/products/search?q=` | 200 / 500 / 200，`SQLITE_ERROR: near "'%'": syntax error` |
| SQL 布尔差分 | `GET /rest/products/search?q=` | 6 次重复差分稳定：真条件一致、假条件一致且不同、未反射 |
| 匿名文件读取 | `/ftp/acquisitions.md` | 200，908 字符 |
| 匿名文件读取 | `/ftp/announcement_encrypted.md` | 200，200000 字符（截断） |
| 匿名文件读取 | `/infrastructure/docker-compose.yml` | 200，1766 字符 |
| 匿名文件读取 | `/support/logs/audit.json` | 200，790 字符 |

这 7 条对应的都是该靶场的真实考点（搜索/登录注入、可下载内部文档与部署/日志文件）。B 配置关掉 POST 后，登录注入那条消失，多出 `GET /rest/user/whoami?callback=` 的反射与布尔差分两条；C 用界面默认值仍然拿到 6 条。

## 根因（按影响排序）

### 1. 产品按设计不产出“已确认漏洞”

- 自动判定只有三种结论：`verified_behavior`（行为已确认）、`candidate`（待核实线索）、`inconclusive`（证据不足）。
- 当前只有 `template_expression` 的算术求值会给出 `verified_behavior`；SQL、文件、CORS、安全头等最多到 `candidate`，且 `counts_as_confirmed_vulnerability=false`。
- 界面摘要原文：`0 项具体行为已确认 · N 条候选线索 · M 个动作未测试`，面板标题是“候选分组与预算（非漏洞确认）”，并注明“当前自动流程尚未完成独立漏洞确认；零确认不代表没有漏洞”。
- 因此在这个靶场（Express/Node，无模板注入）上，**“已确认”永远是 0**，与你的配置无关。截图：`evaluation/diagnosis_a_overview_20261112.png`。

### 2. 预算与调度：240 个动作、1097 请求成本，300 预算只够跑 63 个

源码索引：119 条路由（78 条可执行）；11 个通用检测器展开为 240 个动作，全跑需 1097 次请求。
300 / 3 轮的实际排程（`.devtools/simulate_schedule.py`）：

- 第 0 轮：上限 60 请求，只放成本 ≤12 的动作（SQL 布尔差分成本 18，被排除）；
- 第 1 轮：上限 150；第 2 轮：到 300 为止。
- 结果：执行 63 / 240 个动作，剩 177 个未测（与 A 的 `untested_action_count=177` 一致）。

界面默认 120 预算时只能跑约 25 个动作，覆盖更窄；这就是“配置越小心，越像没结果”的原因。

### 3. 认证面：近一半动作在认证/跳转上失败，直接判证据不足

A 的 61 条 inconclusive 按首个状态码分布：401 共 31 条、400 共 5 条、301 共 5 条、403 共 1 条、406 共 1 条，另有 18 条 200 但未通过判定（JSON 目录、CORS/安全头不满足等）。401 主要集中在 `/api/*`：通用模式不猜账号、不自动注册；没有配置凭据档案时，这些接口不可能出结论。

### 4. 默认关闭 POST，直接漏掉登录注入

界面 `allow_post` 默认不勾选。登录 SQL 注入只能经 POST 触发；A 开了 POST 就拿到该候选，B、C 关掉就没有。这是三组结果差异的主要来源。

### 5. 检测器的已知盲区（实测证据）

- `/ftp` 在扫描器发送 `Accept: application/json, text/html` 时返回 **JSON 数组**而不是 HTML 目录页，`response_disclosure` 只认 HTML 列表 → 判 inconclusive；真正救回来的是后续 `exposed_file` 跟进（文件命中仍成立）。
- `/redirect?to=` 对三个测试值都返回 406（仅白名单域），无法构造差分。
- `/rest/chat` 返回 `LLM error: TypeError: messages.some is not a function`，NoSQL 差分无信号。
- `cors` / `security_headers` 需要“两个无关 Origin 都被反射且允许凭据”或“HTML 响应缺 CSP/XCTO”，该靶场不满足，12 条全部 inconclusive。

### 6. 会整轮报废的运行失败（历史记录）

数据库中 `unknown` 任务：`BudgetExhausted`（MCP 重复预留，已修复）、`HttpDenied: isolated broker failed: TimeoutError`、旧版 `workflow input changed`。这类任务观察数为 0，看起来就是“什么都没检测到”。另外未审批的任务会停在 `waiting_approval`，同样没有结果。

## 想最大化“找到东西”，建议这样配

1. 预算 **300、3 轮**，勾满 11 个通用检测器（不要只留 4 个）；POST **开**。
2. 需要登录面的结论时，先在“认证方式”里保存凭据档案（Cookie/Bearer），否则 `/api/*` 全是 401。
3. 要 XSS 结论需勾“浏览器复核”（本机 Edge，成本高）；要越权结论需配置双身份 A/B 资源与归属策略。
4. 关注“候选”表与证据链，不要看“已确认覆盖率”（没有真值文件时该按钮会报错，有真值时确认数也是 0）。
5. 需要更强的注入结论可启用外部 MCP（SQLMap/Dalfox），但本轮实测显示 Dalfox 结果受限、不能当阴性。

## 边界

- 本轮未用模型、未用外部工具、未配置凭据/浏览器/双身份，因此不代表这些路径的效果。
- 未做全量回归；未提交、未推送。三次任务和证据保留在工作台数据库中。
- 结论仍是“候选”，不应对外表述为已确认漏洞；确认闭环（独立复测、因果与影响证明）尚未实现，这是下一步开发项。

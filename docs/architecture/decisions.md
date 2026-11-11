# 设计基线和当前决定

原始文档 V1.0 是权威设计依据；其架构与检索图以文本形式存在，正文、全部表格、附录均已读取，文档内无嵌入媒体。已确认：Python + LangGraph、Repo 和 Web/API、多 Agent、受治理 Shell、Skills + Dense/Sparse + RRF + Rerank、动态上下文与三级记忆。PostgreSQL + pgvector 是项目指令指定的主要方案，文档中数据库部署形态仍待确认。

尚待确认：三级记忆正式命名与晋升规则；扫描器组合；数据库部署形态；模型、embedding 与 reranker；审批细则；Web 检测强度。原文的候选扫描器不是已选定依赖。暂用短期/工作/长期作为工作术语，不视为最终命名。

依赖顺序：Schema/配置/Scope/持久化基础 → Tool Registry/策略/审计与隔离 → Planner 和 Repo/Web 编排及恢复 → 扫描器适配 → RAG/Skills → 上下文/记忆 → 验证与报告。工具调用前再次检查范围；网络检查须覆盖 DNS 解析、连接地址与每次重定向，避免只检查 URL 字符串。Shell 的网络禁用不能靠声明实现，必须由可验证的系统隔离或其他可靠执行环境强制约束，未具备前默认拒绝执行。

初始化时选择最小规划图以验证 LangGraph 与失败关闭；它不模拟扫描发现。当时 Web allowlist 仅支持严格 origin，后续已增加保守路径前缀；实际 HTTP 工具不得使用此预检查替代完整 Scope Guard。初始迁移覆盖 projects、targets、scopes、scans，后续已增加执行记录表；字段、索引和外键仍须 Schema 评审。当时业务数据库和持久 checkpoint 均未连接。

## 2026-11-03：数据库与工具原型

四表 ORM 与迁移对应，新增离线一致性测试；真实 PostgreSQL upgrade/downgrade 测试需要显式设置专用测试数据库，目前未运行。参考 [Alembic 官方 GitHub 项目](https://github.com/sqlalchemy/alembic) 的迁移与模型比较说明和 [SQLAlchemy 官方映射文档](https://docs.sqlalchemy.org/en/20/orm/declarative_tables.html)，仅参考设计方式，未复制第三方代码。自动生成迁移仍必须人工审核。

Registry 现仅接受可信开发者定义的纯计算异步函数，安全属性不是由进程或网络沙箱强制实现。它仅为接口原型，不能用于真实扫描器、文件、Shell 或 HTTP；纯工具可以超时取消但无法保证不合作协程或有副作用操作被终止。数据库审计、审批和权限控制仍未实现。

## 2026-11-03：执行记录与模拟流程

新增 0002 迁移，覆盖任务、运行、调用、Finding、Evidence、Report、Approval 和审计事件；其字段仍是设计基线的工作映射，尚未通过真实 PostgreSQL 评审和迁移测试，暂不视为最终 schema。审计事件 sink 通过独立事务写入，字段有 allowlist；目前没有追加专用数据库权限、防篡改或 PostgreSQL 可用性验证。

Registry 的 permission/risk/approval 声明实现默认拒绝：当前只执行声明为低风险、不需审批的纯计算工具；声明不是隔离或安全证明。仅显式声明幂等的纯工具的 `TransientToolError` 可有限重试，每次重新检查授权；超时和其他错误不重试。模拟图不读取仓库或访问网络，使用 fake 工具并显式标识未扫描。

## 2026-11-03：Web 路径预检查

`allowed_web_paths` 和 `denied_web_paths` 按 origin 配置允许/拒绝路径前缀，拒绝优先，按路径段匹配；允许映射非空时未配置的 origin 不允许。仅接受保守 ASCII 路径语法，拒绝百分号、点段、双斜杠及分号等含糊形式，避免对服务端解码/归一化做未经验证的假设。允许映射为空时，为兼容原有 origin 语义暂放行该 origin 下符合语法的路径；是否改成必须显式路径的生产默认值待评审。后续 HTTP 层仍需对实际连接和每个跳转重新检查。

## 2026-11-03：Checkpoint 接口

PostgreSQL 保持主要持久化方案；为不依赖外部服务验证规划状态跨进程读取，增加仅供本地模拟的可选 SQLite Saver。生产目标 PostgreSQL Saver 单独提供可选同步接口，setup 显式 opt-in；使用受限 msgpack 反序列化且禁用 pickle。参考 [LangGraph PostgreSQL checkpointer 官方仓库说明](https://github.com/langchain-ai/langgraph/blob/main/libs/checkpoint-postgres/README.md)，未复制项目代码。数据库包含明文状态，禁止凭据进入状态；数据库加密、访问控制和非幂等操作恢复仍未实现或验证。

## 2026-11-03：本地 PostgreSQL 17.11 实测

原先"真实 PostgreSQL upgrade/downgrade 未运行"的状态已改变：用一次性本机集群（`scripts/test_local_postgres.py` + `.devtools` 中的 17.11 二进制，随机端口、仅 127.0.0.1、scram 密码、用完即删）跑完整套件得到 92 passed，两项 live 测试真实执行——迁移升降级 12 表、ORM 写入、审计 sink 插入、授权快照往返、checkpoint 跨连接重开。结论不变：PostgreSQL 仍是主要方案，但这是一次性本地实例；pgvector 扩展、远程/生产库、并发、故障切换与非幂等恢复仍未验证，schema 仍待人工评审。`.devtools/` 不进入版本库。

## 2026-11-03：知识与记忆表，pgvector 暂时推迟

迁移 0003 建立 `knowledge_documents`、`knowledge_chunks`、`skills`、`memory_records`、`context_manifests`（合计 17 表）。选择：`knowledge_chunks` 先只存正文 + PostgreSQL `tsvector`（GIN 索引），`memory_records` 以 level CHECK 约束三级取值并外键到 projects/scan_tasks；写入与读取都经仓储，读取复用 Pydantic 校验，时区缺失即失败关闭。

`embedding` 列与 ivfflat 索引**没有**写进 0003：本机与测试用 PostgreSQL 17.11 二进制不含 `vector` 服务端扩展（`share/extension` 无 vector.control），若强行写入会导致 `upgrade head` 在无扩展环境直接失败，且无法在真实数据库验证。按项目"不把未验证能力标记为完成"的规则，稠密向量推迟到具备 pgvector 的部署再补（`CREATE EXTENSION vector` + `embedding vector(N)` + ivfflat），届时再接入 dense 检索。当前混合检索只有稀疏一路有真实存储与验证；RRF/Reranker 仍是注入式接口。

## 2026-11-03：审批有效期与网络工具默认拒绝

迁移 0004 给 `approvals` 增加 `expires_at`（默认 24 小时），过期后 `is_approved` 返回 False；审批人仍是自由文本，没有身份认证，也没有单次使用防护，因此审批只能作为流程记录，不能当作强授权。SQLite 丢失时区时按 UTC 解释审批时间戳（仅审批内部时间，不是用户授权窗口）。

HTTP 工具选择"默认无 transport 即拒绝"：设计与项目规则都要求网络约束由可验证的出口策略强制（DNS 固定、每跳检查、隔离），在当前环境无法实现，因此仅提供策略层与假传输测试，不启用真实网络。接入 httpx 前必须先解决 DNS 重绑定、重定向逐跳强制、并发与速率上限。

## 2026-11-03：pgvector、扫描器与审批身份落地

**pgvector**：维度定为 1536（常见 embedding 输出；改动需新迁移）。索引选 HNSW + `vector_cosine_ops` 而非 ivfflat：HNSW 不需要训练数据，行为更稳定；代价是建索引更慢、内存占用更高。迁移 0009 先 `CREATE EXTENSION IF NOT EXISTS vector` 再建列，扩展缺失时迁移应直接失败——不允许"迁移成功但列不存在"的假象。测试 schema 的 `search_path` 为 `<schema>,public`，扩展装在 public，避免每个测试 schema 重复安装扩展（PostgreSQL 不允许同库重复安装同一扩展）。

**扫描器**：Gitleaks 以独立二进制放在 `.devtools/scanners`，不进项目依赖；`GitleaksAnalyzer` 要求可执行文件位于可信根、argv 由代码构造、带超时/报告上限/`--redact`。这是"可信工具 + 参数不可注入"的治理，不是进程隔离；真实扫描器仍以调用者身份运行。

**审批身份**：除 HMAC 共享密钥外，新增 OpenSSH 签名（`ssh-keygen -Y sign/verify` + `allowed_signers`）。签名载荷绑定 approval_id、scan_id、action、target、expires_at 与 operation_hash，因此同一签名不能挪用到另一条审批。OpenSSH 签名证明私钥持有者，但仍依赖 `allowed_signers` 的完整性与吊销流程；企业 IdP 仍是更完整的方向。

**隔离（未落地）**：当前会话非管理员，WSL 发行版与 Docker 均无法安装，因此真实 HTTP transport 与隔离扫描器继续关闭。这一状态是环境限制，不是设计取舍。

## 2026-11-04：WSL 沙箱选型与网络允许列表

**发行版选型**：Store 安装失败（`WININET_E_INVALID_SERVER_RESPONSE`），改用 Alpine minirootfs（3.20.3，约 3MB）经 `wsl --import` 导入为 `VulnMindSandbox`。理由：无需 Store、体积小、启动快；代价是需要 `apk` 手工装工具（已装 util-linux/curl/nftables，并从 GitHub 安装 Linux 版 Gitleaks）。Ubuntu 可作为将来替换项，`WslSandbox` 只依赖 distro 名与 POSIX 工具。

**扫描器隔离**：命令前固定加 `unshare -n`，argv 由代码构造（不拼 shell），cwd 用 `--cd` 映射到宿主仓库；Gitleaks 以 `--source .` 产生相对路径，报告经 `/tmp` 读回后删除。它隔离的是网络与工具目标，不隔离文件系统读取权限（仓库挂载为 /mnt/<drive>）。

**HTTP 允许列表**：每次请求在沙箱内建 `inet vulnmind_egress` 表，policy drop，仅放行 loopback、established/related 与已解析并校验的 IP:port，随后 `curl --resolve` 直连该 IP（不再解析 DNS），结束后删表。因为 nft 规则作用于整个发行版命名空间，调用必须串行；这是本项目接受的取舍，若需并发应改为每调用一个 network namespace 或独立容器。


## 2026-11-04：HTTP 出口改为逐调用 network namespace

此前方案在共享 netns 上安装全局 nftables 规则，需要 `ip_forward=1` 与全局 NAT，会影响同发行版内其他进程，因而被禁用。新方案为每次请求创建独立 network namespace + veth 对，出口只有一个 `socat` 代理，代理仅连预先校验的目标地址；`curl --connect-to` 保持 Host/SNI 并禁止跳转，输出按预算截断。代价是每次请求的 netns/veth 创建开销与 flock 串行；换取的是不触碰任何全局网络配置，也不依赖 `ip_forward`。仅支持 IPv4 单地址，多地址取第一个（需多地址时可扩展为逐个尝试）。


## 2026-11-04：人工判定与报告重建

**决定**：误报/确认等结论写入 append-only 的 `finding_feedback`，以 `(finding_id, revision)` 唯一约束防止并发覆盖，最新 revision 胜出；判定不修改 finding 的状态、严重度或证据。报告 schema v7 以 `feedback` 字段和独立小节呈现，并标注 `operator_recorded_decision_not_verification`。

**理由**：把“操作者处理结论”和“系统验证结果”分开，避免误报标注被误读为证据或验证；保留历史便于审计。重建报告时从 observations 重算分组并要求观察历史完整，缺少历史就失败关闭，而不是生成一份看似完整的报告。

## 2026-11-04：报告签名使用 HMAC-SHA256 sidecar

**决定**：`report-sign` 对“用途前缀 + 内容 SHA-256 + 长度”做 HMAC-SHA256，签名写成与报告同目录的 `<digest>.sig`；密钥只来自环境变量或密钥文件，签名记录只含 key_id（密钥摘要前 16 位）。`verify` 在存在签名但本进程无密钥时判为 `not_configured` 并让整体 incomplete。

**理由**：项目没有公钥基础设施，HMAC 只需运维共享一个密钥即可检测报告被替换或篡改；sidecar 不改变报告内容寻址格式，旧报告不受影响。代价是签名可被任何密钥持有者伪造、验证方必须持有密钥、没有密钥轮换或多信任列表；这意味着它不能作为对外可验证的第三方签名，文档与输出都已注明。

## 2026-11-04：离线 Web 快照分析替代实时抓取

**决定**：在真实 HTTP 执行仍暂停的前提下，新增 `web-analyze` 消费外部采集的快照，不恢复任何网络请求。快照是不可信输入：严格限制大小/页数/HTML/headers，逐页重新执行 scope 检查，超范围页面只计数不分析；证据只保存响应元数据的规范化 JSON。

**理由**：可以在不触碰真实目标的情况下补齐 Web 分析入库/报告链路，并让检测逻辑与网络执行解耦。代价是快照来源与完整性不受本系统认证，分析结果不包含采集时间线、认证态或动态内容；真实抓取恢复后仍需独立验收。

## 2026-11-05：embedding 维度改为 1024（Qwen3-Embedding-0.6B）

**决定**：选用本地 `Qwen/Qwen3-Embedding-0.6B`（Apache-2.0，1024 维，32k 上下文，100+ 语言，sentence-transformers 原生支持，不需要 `trust_remote_code`），迁移 0014 把 `knowledge_chunks.embedding` 从 1536 改为 1024 并重建 HNSW 索引。迁移在检测到已存向量时拒绝 upgrade，避免静默降维丢数据；downgrade 会丢弃向量（1024 无法放入 1536），与 0009 downgrade 直接删列同属破坏性操作。0009 冻结 1536 作为历史事实，不再 import 可变常量。文档编码不加指令前缀，查询编码必须使用模型的 `prompt_name="query"`。

**理由**：原 1536 只是占位；0.6B 模型在质量/体积（约 1.2GB）/供应安全之间折中，本地运行不向外部 API 发送知识正文。代价是引入一次 schema 变更，且换模型必须再迁移并全量重算向量；尚未注入分析模型上下文，因此不构成 RAG 闭环。
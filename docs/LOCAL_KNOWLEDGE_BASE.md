# 本地开发数据库与 RAG 知识库

2026-11-05 本轮补充：追加 MITRE CWE 官方 CSV 快照的 12 条描述（15 片段），开发库目前 60 篇文档、812 片段、812 向量。来源快照、许可和哈希见 `knowledge/corpora/cwe_699_20261105/`。16 条 AI 笔记已由原作者对照 CWE 定义，发现并修正 CWE-862 标题范围过窄；这不构成独立专家审核。问答现在可返回文档标题、受限公开来源、版本和经文本匹配的摘录，并提供证据不足状态；摘录存在不代表语义支持已验证。后文较早的数字保留为历史记录。

2026-11-06 补充：812 个向量已通过本地模型重新编码核对并记录来源标记。后续使用 `python scripts/backfill_embeddings_optimistic.py --apply --device cpu --batch-size 8`，计算期间不持有表锁，写入前重新核对数据；重复运行实测复用了全部 812 项。原回填脚本和普通仓储写入会拒绝修改已标记向量。混合查询会核对模型指纹及向量来源；旧格式库需先验证并登记，直接操作底层数据库或仓储查询仍不受该适配器全部约束。模型文件摘要不是发行方签名。实测、局限和恢复门槛见 `docs/RETRIEVAL_AND_RELEASE_GATES.md`。

2026-11-05 新增语料批次：在此前 8 条演示资料和 6 篇 OWASP 文档的基础上，追加 18 篇 OWASP 固定版本原文和 16 条 AI 自写中文笔记。开发库实查共 48 篇文档、797 个片段和 797 个向量。AI 笔记未经人工审核，CWE 链接仅供核验，不代表 MITRE 背书；知识问答引用会标识 `unreviewed_ai`。来源清单和许可见 `knowledge/corpora/README.md`。18 个手工拟定问题的 top-5 命中：全文 1/18、向量 18/18、混合 18/18；见 `evaluation/owasp_full_results_20261105.json`。这是有针对性的冒烟检查，不能代表生产准确率，全文检索表现尤其需要改进。本条为最新批次说明，以下旧数字保留作为历史记录。

2026-11-05 由 DeepSeek 建立并验证。本文只描述本机（DESKTOP-DB0QVT6）上的开发环境；它不是生产部署说明，也不代表项目已完成。

## 1. 一句话结论

VulnMind 的可检索知识库存放在 PostgreSQL 的 `knowledge_documents` / `knowledge_chunks` 表里；固定版本的公开语料同时保存在项目目录中。本机持久开发库已迁移到 head `0014_embedding_dimension`，包含示例与 OWASP 语料；全文检索和本地 Qwen3 1024 维向量检索均已实测。仓库扫描的知识辅助需要显式启用，尚未完成生产验收。

2026-11-05 补充：现有开发库包含原 8 条示例和 6 篇固定版本 OWASP 官方 Cheat Sheet，共 14 篇文档、215 个片段及 215 个向量。OWASP 原文、许可、版本和来源见 `knowledge/corpora/owasp_cheatsheets_757270a/`；原本的两类“知识”文件如下：

这 6 篇来自 OWASP Cheat Sheet Series，许可为 CC BY-SA 4.0；每篇保留原仓库固定提交、来源 URL、许可及正文 SHA-256。`evaluation/owasp_retrieval_cases.json` 有 6 个人工拟定的冒烟问题，可用 `python scripts/evaluate_owasp_retrieval.py` 进行只读复测。此样本太小，且问题与语料主题对应，不能作为生产准确率。

- `evaluation/corpus.json`：8 条手写 CWE 片段，原本只用于 `python -m vulnmind.knowledge.benchmark` 的检索指标自测，本次被灌入开发库作为演示数据；
- `skills/*.md`：Skill 文件，正文留在磁盘、元数据进 `skills` 表，属于另一个机制，不是 RAG 语料。

## 2. 连接信息

| 项 | 值 |
|---|---|
| 主机 / 端口 | `127.0.0.1:5432`（只监听回环地址） |
| 数据库 | `vulnmind` |
| 用户 | `vulnmind`（scram-sha-256 认证） |
| 连接串 | `postgresql+psycopg://vulnmind:<密码>@127.0.0.1:5432/vulnmind` |
| 密码位置 | 项目根 `projects/vulnmind/.env` 的 `VULNMIND_DATABASE_URL`（已被 `.gitignore` 忽略，`git check-ignore` 已验证） |
| 向量模型 | `Qwen/Qwen3-Embedding-0.6B`（本地运行，Apache-2.0，1024 维），权重缓存在 `%USERPROFILE%\.cache\huggingface\hub` |

- 在项目根目录运行 CLI / 脚本时，`vulnmind.config.Settings` 会自动读取同目录 `.env`，无需手工导出变量；从其他目录运行时需要自己设置 `VULNMIND_DATABASE_URL`。
- **Alembic 例外**：`migrations/env.py` 只读进程环境变量（`os.environ`），不会读 `.env`。执行迁移前先导出：

```powershell
$env:VULNMIND_DATABASE_URL = ((Get-Content .env -Raw).Trim() -replace '^VULNMIND_DATABASE_URL=', '')
.\.venv\Scripts\python.exe -m alembic upgrade head
```

- 不要把密码复制进 README、STATUS、handoff、日志或提交；需要密码时读 `.env`。
- psql 示例：

```powershell
$env:PGPASSWORD = '<从 .env 读取>'
& '<用户目录>\vulnmind-pg\pgsql\bin\psql.exe' -h 127.0.0.1 -p 5432 -U vulnmind -d vulnmind
```

## 3. 启动 / 停止 / 状态

安装位置：`<用户目录>\vulnmind-pg`

```
pgsql\    PostgreSQL 17.11 二进制副本（含 pgvector 0.8.0），来源 .devtools\pgsql
data\     集群数据目录（initdb 生成）
server.log 服务器日志
```

### 启动（必须用 Start-Process）

```powershell
Start-Process -FilePath '<用户目录>\vulnmind-pg\pgsql\bin\pg_ctl.exe' `
  -ArgumentList '-D','<用户目录>\vulnmind-pg\data','-l','<用户目录>\vulnmind-pg\server.log','start' `
  -WindowStyle Hidden
```

**不要**直接执行 `& pg_ctl.exe ... start`：服务器进程会成为当前 shell 的子进程，DSH/Codex 这类工具会一直等待它退出（实测命令挂起超过 120 秒），结束会话/任务时还会连带杀掉数据库。`Start-Process` 启动的是独立进程，会话结束不影响数据库。

### 状态 / 停止

```powershell
& '<用户目录>\vulnmind-pg\pgsql\bin\pg_ctl.exe' -D '<用户目录>\vulnmind-pg\data' status
& '<用户目录>\vulnmind-pg\pgsql\bin\pg_ctl.exe' -D '<用户目录>\vulnmind-pg\data' -m fast -w stop
```

- **登录自启已配置**：`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\vulnmind-postgres.vbs` 在用户登录时静默检查并启动集群（状态检查失败才启动）。删除该文件即关闭自启；本机拒绝 `schtasks` 注册（Access denied，需要管理员），所以没有用计划任务。
- 没有注册 Windows 服务（`pg_ctl register` 需要管理员）：**用户未登录时数据库不会运行**；需要无人值守请先解决管理员权限。
- 判断是否在跑：`Get-NetTCPConnection -LocalPort 5432 -State Listen`。

### 为什么集群在 <用户目录> 而不是工作区

`initdb` 在包含中文的路径（`D:\新建文件夹\...`）上执行 post-bootstrap 时会报
`invalid byte sequence for encoding "UTF8": 0xd0 0xc2` 并删除数据目录：Windows 控制台代码页把中文路径按 GBK 传给以 UTF-8 初始化的服务器。仓库测试脚本 `scripts/test_local_postgres.py` 早已因同一原因把一次性集群放到 `%PUBLIC%`。请不要把 `data\` 挪回中文路径。

同样原因，`.devtools\pgsql` 里自编的 PostgreSQL/pgvector 被复制到 ASCII 路径后再使用；如果以后重新编译 pgvector，需要重新复制 `pgsql\`（并重启）。

## 4. 入库

批量（推荐，可重复执行）：

```powershell
.\.venv\Scripts\python.exe scripts\ingest_corpus.py evaluation\corpus.json
# {"ingested": 8, "skipped": 0, "chunks": 8}
```

- 语料是 UTF-8 JSON 数组；每项必须有 `content` 和 `source_type`，可选 `title`、`source`、`source_url`、`version`、`trust_level`、`id`（`id` 写入 chunk 的 `corpus_id` 元数据）。
- `title` 缺省为 `"<source_type> <source>"`；只有同标题且内容、切分及来源元数据一致时才跳过，若同名内容不一致或数据库存在多个同名文档则拒绝整批入库，避免静默忽略更新。并发入库尚无数据库唯一约束。
- 脚本拒绝 SQLite 连接：稀疏索引、元数据过滤和 pgvector 都只在 PostgreSQL 上工作。

单篇（CLI，读取本地 UTF-8 文本，上限 10MB）：

```powershell
.\.venv\Scripts\python.exe -m vulnmind knowledge ingest --file <path> --title <t> --source-type CWE `
  --source-url <url> --version <v> --trust-level <level> --size 1000 --overlap 100
```

## 5. 检索

- 稀疏（全文）检索：`KnowledgeRepository.search_chunks(query)`，走 `knowledge_chunks.tsvector` 的 GIN 索引，使用 `pg_catalog.simple` 配置 + `plainto_tsquery`。**所有词都必须命中（AND）**，没有词干还原、同义词或中文分词。
  - 实测：`SQL injection parameterized statements` → 命中 CWE-89；`TLS certificate verification` → 命中 CWE-295；`SSRF allowlist redirect` → 0 条，因为 CWE-918 正文写的是 “Server side request forgery”（缩写不参与匹配）。
- 稠密（向量）检索：`dense_search(values)` 使用 pgvector 余弦距离，向量由本地 `Qwen/Qwen3-Embedding-0.6B` 生成（1024 维；表结构由迁移 0014 从占位的 1536 改为 1024）。文档入库时**不加指令前缀**，查询时必须用 `prompt_name="query"` 编码，两边不一致会明显降低效果。
  - 实测（8 条语料）：`cross site scripting output encoding` → FTS 0 条、dense 命中 CWE-79；`SQL 注入 参数化查询` → FTS 0 条、dense 命中 CWE-89（跨语言）；`hardcoded credentials in source code` → 命中 CWE-798；`server side request forgery allowlist redirect` → 命中 CWE-918。
- 扫描侧 `vulnmind scan --knowledge-context` 只使用上面的 PostgreSQL FTS，把选中的文档/片段 ID 写入 Context Manifest，不调用 dense、重排器或模型。

验证命令（任意 Python 片段）：

```python
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from vulnmind.config import Settings
from vulnmind.persistence.models import KnowledgeChunk, KnowledgeDocument

engine = create_engine(Settings().database_url)
with Session(engine) as session:
    print(session.scalar(select(func.count()).select_from(KnowledgeDocument)))  # 8
    print(session.scalar(select(func.count()).select_from(KnowledgeChunk)))     # 8
    print(session.scalar(select(func.count()).select_from(KnowledgeChunk)
                         .where(KnowledgeChunk.embedding.is_not(None))))        # 8
```

## 6. 向量模型与回填

选型：`Qwen/Qwen3-Embedding-0.6B`（Apache-2.0，1024 维，32k 上下文，100+ 语言，sentence-transformers 原生支持，不需要 `trust_remote_code`）。对本项目的中英混合、短安全文本足够强，权重约 1.2GB、查询延迟低、数据不出本机。代价是把占位的 1536 维改成 1024 维，需要迁移 0014（迁移时无任何向量，安全）。

- 迁移 0014 的 upgrade 和 downgrade 均在检测到已有向量时拒绝执行；执行前持表锁以阻止并发写入，避免静默丢失向量。降级前须先备份并单独处理向量数据。0009 保留 1536 作为历史事实，不再跟随代码常量。
- 回填：`.\.venv\Scripts\python.exe scripts\backfill_embeddings.py`。每次先在事务锁内重新编码并比对所有已有向量，一致后才原子写入缺失向量；`--all` 显式请求在同一事务中重算全部向量。每次最多 5000 个片段、1000 万字符，过程可能阻塞知识库写入，超限或模型不匹配会失败。数值比对不能证明模型文件来源；历史模型版本仍未记录。
- 暂时只允许使用固定的 Qwen 模型；同维度也不代表模型向量可比较。目前没有逐片段模型版本/来源记录，切换模型需先设计可验证的来源记录与安全重算流程。
- 查询编码：`SentenceTransformer(...).encode([query], prompt_name="query", normalize_embeddings=True)`；文档侧不加前缀，两边不要混用。

## 7. 备份与恢复（开发库）

```powershell
# 备份
& '<用户目录>\vulnmind-pg\pgsql\bin\pg_dump.exe' -h 127.0.0.1 -U vulnmind -Fc -f vulnmind-dev.dump vulnmind
# 恢复到新库（先 createdb 目标库）
& '<用户目录>\vulnmind-pg\pgsql\bin\pg_restore.exe' -h 127.0.0.1 -U vulnmind -d <新库> vulnmind-dev.dump
```

开发库没有自动备份策略；重要演示数据请先 dump。

## 8. 从零重建

1. 复制二进制到 ASCII 路径（若 `.devtools\pgsql` 更新过）：`robocopy .devtools\pgsql <用户目录>\vulnmind-pg\pgsql /E`。
2. `initdb -D <用户目录>\vulnmind-pg\data -U vulnmind --pwfile <ASCII 密码文件> --auth=scram-sha-256 --encoding=UTF8 --locale=C`，随后删除密码文件。
3. `postgresql.conf` 追加 `listen_addresses = '127.0.0.1'`、`port = 5432`、`password_encryption = 'scram-sha-256'`。
4. 按 §3 启动；`createdb -h 127.0.0.1 -U vulnmind vulnmind`；`psql ... -c "CREATE EXTENSION IF NOT EXISTS vector"`。
5. 在项目根写 `.env`（连接串），按 §2 把同一 URL 导出为 `VULNMIND_DATABASE_URL`（Alembic 不读 `.env`），执行 `.\.venv\Scripts\python.exe -m alembic upgrade head`。
6. `.\.venv\Scripts\python.exe scripts\ingest_corpus.py evaluation\corpus.json`。
7. `.\.venv\Scripts\python.exe scripts\backfill_embeddings.py`（首次运行会下载模型，之后走本地缓存）。

## 9. 边界与安全

- 库只监听 `127.0.0.1`，使用 scram-sha-256；没有开放到局域网。
- 已入库的 8 条 CWE 片段是演示语料（手写、极短），**不是**完整 CWE/OWASP 知识库，也不可信；知识正文始终是数据，不能当指令执行。
- 向量由本地模型生成，没有数据外发；但检索结果**仍未注入分析模型上下文**、未做重排，不能声称 RAG 模型闭环或生产可用。模型输出可能有偏差，向量检索结果同样属于不可信数据。
- 知识表可能包含来源 URL；不要把密钥、令牌或内部地址写进语料。
- 该环境是开发便利设施，不属于项目验收证据；项目仍未完成。

## 10. 下一位 Agent 的快速上手

1. 读本文件、`handoff.md` 最新一节、`STATUS.md` 最新一节。
2. 确认数据库在跑：`pg_ctl ... status`；不在跑就按 §3 用 `Start-Process` 启动。
3. 在项目根执行任意 CLI（自动读 `.env`），或用 §5 的片段验证 8 条文档；需要更多语料按 §4 入库。

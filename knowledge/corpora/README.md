# 知识语料目录

本目录按来源分组保存供开发库导入的材料。`corpus.json` 中的来源、版本、许可和正文哈希可用于追溯；检索到材料不代表内容已验证，也不能作为漏洞成立的证据。

| 目录 | 内容 | 来源与状态 |
| --- | --- | --- |
| `owasp_cheatsheets_757270a/` | 6 篇 OWASP Cheat Sheet | 固定提交 757270a26306e5edda9957bb7f86cfcde03c30f9；CC BY-SA 4.0；原文和许可文件同目录保存。 |
| `owasp_expansion_757270a/` | 18 篇 OWASP Cheat Sheet，涵盖授权、上传、反序列化、日志、TLS 等 | 同一固定提交和许可；`SOURCE.md`、原文及 `LICENSE.md` 保留作者信息。 |
| `ai_guidance_20261105/` | 16 条中文安全审查辅助笔记 | AI 编写，未经人工审核；CWE 链接仅供核对，不代表 MITRE 撰写或背书。 |
| `cwe_699_20261105/` | MITRE CWE 软件开发视图的 12 条描述摘录 | 原始 CSV 压缩包、SHA-256 和 MITRE 许可同目录保存；版本字段表示快照哈希，不宣称具体 CWE 发布版本。 |

另有 `evaluation/corpus.json` 的 8 条手写演示资料。固定提交的资料是历史快照，不能保证反映最新安全建议。所有资料均按不可信内容处理，使用前需核对权威原始资料；引用 OWASP 内容时应保留原作者、来源及 CC BY-SA 4.0 许可要求。

导入命令在项目根目录运行：`python scripts/ingest_corpus.py knowledge/corpora/<目录>/corpus.json`。新增内容后需执行本地 `scripts/backfill_embeddings.py` 才能参与向量检索；导入和回填是分开的操作，期间新内容可能只有全文检索。导入前确认目标数据库并备份。

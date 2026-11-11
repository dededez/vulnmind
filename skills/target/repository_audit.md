---
skill_id: repository_audit
name: Repository audit workflow
version: "1"
target_type: repository
stage: analysis
risk_level: low
prerequisites: [scope_validation]
tools: [repo.list_directory, repo.read_file]
---

# 仓库审计流程

1. 确认仓库位于授权根目录内，且没有与被拒绝路径重叠。
2. 识别语言与框架：按扩展名与依赖清单（package.json、pyproject.toml、go.mod、pom.xml）判断。
3. 优先关注：认证授权逻辑、输入解析、数据库访问、文件操作、反序列化、模板渲染、加密与随机数。
4. 依赖与秘密检查交给成熟工具（Gitleaks、Trivy、Semgrep 等），本流程只做编排与结果归一。
5. 每处线索记录文件与行号，并保留工具来源；不要把工具结果直接写成已确认漏洞。
6. 跳过 `.git`、`node_modules`、`.venv` 等目录，避免噪声与越界读取。

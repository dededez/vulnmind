# 通用应用扫描

新建调查统一使用通用流程，不再选择目标适配器或旧流水线。从源码和导入接口生成探测，认证使用已有 Cookie/Bearer，双身份验证使用用户指定的资源归属。固定注册、固定登录口令、种子编号和特定应用路径不再作为产品功能。

历史任务与签名报告保留；旧专用流程不再通过工作台新建或续跑。历史实现及离线基准文件仅用于兼容验证和旧结果追溯，不属于新扫描能力。

## 双身份访问检查

在 UI 勾选“双身份资源读取”，展开“通用测试身份与资源权限检查”，分别填写身份 A、B 的 Cookie/Bearer Token、各自资源 URL、归属值及类型。填写响应归属字段路径（例如 `payload.owner`）及访问规则说明，确认只允许本人读取。页面自动创建加密凭据档案并组装检查配置，无需手写 JSON；也可选择已有凭据档案 ID。界面不提供隐含注册流程。

以下 JSON 仅供 API 调用参考（`POST /api/credentials` 保存凭据后，将档案 ID 放入任务的 `access_checks`）：

```json
[
  {
    "credential_a": "账号 A 的凭据档案 ID",
    "credential_b": "账号 B 的凭据档案 ID",
    "resource_a": "http://127.0.0.1:3000/documents/red",
    "resource_b": "http://127.0.0.1:3000/documents/blue",
    "identity_path": ["payload", "owner"],
    "identity_a": "alice",
    "identity_b": "bob",
    "expected_policy": "owner_only",
    "ownership_basis": "两个受控测试账号分别创建、且按业务规则只允许所有者读取的文档"
  }
]
```

每项 6 个 GET：A→A、B→B、A→B、B→A、匿名→A、匿名→B。审批页展示完整矩阵与凭据 ID。身份和资源必须不同，本人基线必须匹配声明的身份字段。发现交叉读取仍保留为候选，因为资源归属和私有策略来自操作者声明；匿名也能读取时单列匿名私有资源读取，不能当作已证明的跨账号权限绕过。公开资源不要填写 owner_only。

通用模式不会推测注册/登录协议。CSRF、刷新令牌、自动资源创建、复杂业务权限图尚未实现；过期身份或不匹配基线会得到证据不足。没有这项配置时不会猜资源编号。

## 浏览器与文件

v7 浏览器检查由已发现的 GET 路由及查询参数生成，使用标记载荷、无载荷对照和两次标记复测；三次导航合计最多 120 个子资源请求，每次最多 40。只有本次标记弹窗重复出现、对照不出现且无请求被阻断，才形成脚本执行候选。普通页面弹窗不算命中。浏览器需要 Playwright、本机 Edge 和支持 WebSocket 拦截的版本。

浏览器目标 HTTP 请求通过已有隔离 HTTP broker 转发，不由浏览器直接连接目标；每跳检查当前 scope 与解析 IP，拒绝跨域、写入方法、Service Worker 和 WebSocket。禁用后台网络与非代理 WebRTC UDP；这仍不等于对整个浏览器进程建立了操作系统级网络沙箱。未知失败保留整笔预留额，恢复重试另行预留，不把失败计作零请求。暂不提供浏览器认证态注入，也不声称覆盖 SPA 的全部客户端路由。

文件跟进以实际发现的目录为基址，最多 3 个链接；不会把其他目录拼到 `/ftp/`。匿名信息检查明确不携带默认会话。文件可下载只表示可读取，不自动证明敏感信息泄露。

## 评估口径

审计/签名 `verified` 只表示记录链有效。候选、具体行为、漏洞确认分别展示；现有自动检测器没有独立漏洞确认流程，因此不能把它们计入已确认漏洞覆盖率。原有 Juice Shop 覆盖百分比属于旧候选统计口径。

离线覆盖率没有默认靶场清单。需显式设置 `VULNMIND_COVERAGE_TRUTH`，文件使用 `coverage-truth-2`，绑定当前 origin、repository 和 source_snapshot；不匹配则拒绝计算。每项根因通过实际路径、方法、参数、检测类型及可选行为规则匹配，候选仍不算已确认漏洞。例如：

```json
{
  "schema_version": "coverage-truth-2",
  "target": {
    "origin": "http://127.0.0.1:3000",
    "repository": "C:/your-application",
    "source_snapshot": "从当前报告复制的64位SHA256"
  },
  "roots": [{
    "id": "search-query-injection",
    "eligible": true,
    "method": "GET",
    "path": "/catalog/find",
    "parameter": "term",
    "kinds": ["sql_error", "sql_boolean"],
    "behaviors": []
  }]
}
```

此文件应来自独立人工标注，不能按扫描结果增删分母。没有基准时正常输出观察和证据，但不虚构覆盖率。

## 安装与验证边界

沿用项目 `.venv`、PostgreSQL 与受控 WSL broker。AST 需要 Node 和工作区固定版本 TypeScript 编译器，安装及哈希见 `src/vulnmind/workbench/resources/ast_parser.json`。未安装时会停止索引，不会执行目标代码。

本轮泛化验证使用不同 URL/JSON 结构的受控 HTTP 应用与修复版阴性样本；它证明这条访问控制链不依赖购物篮协议，不代表在未知大型应用上已有稳定召回率。新浏览器与外部工具的生产覆盖率需单独验收。

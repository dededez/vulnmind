---
skill_id: workbench.information_disclosure
name: 匿名响应信息暴露
version: 6.0.0
target_type: both
vuln_type: information_disclosure
stage: investigation
risk_level: low
prerequisites: [authorized_target, exact_request_approval]
tools: [response_disclosure, config_exposure, well_known_exposure, exposed_file]
---
重复请求已映射的只读端点，核对目录列表、文件链接、服务端堆栈是否可匿名取得。不自动下载列表文件。目录索引和堆栈是待核实线索；公开文档、静态资源目录和业务有意展示的数据可能是误报。不能仅凭 URL 中含 admin、backup 或缺少认证就确认敏感信息泄露。确认需要数据敏感性、访问策略和可重复的未授权读取证据。

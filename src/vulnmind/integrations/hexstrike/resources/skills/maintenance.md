---
skill_id: hexstrike-maintenance-1
name: 任务运行环境维护
version: 1.0.0
target_type: execution
vuln_type: hexstrike_maintenance
stage: external_tool
risk_level: high
prerequisites:
- 精确资源授权
- 已验证执行适配器
- 固定参数与真实预算
- 持久执行回执
tools:
- hexstrike.create_file
- hexstrike.modify_file
- hexstrike.delete_file
- hexstrike.list_files
- hexstrike.install_python_package
- hexstrike.execute_python_script
- hexstrike.server_health
- hexstrike.get_cache_stats
- hexstrike.clear_cache
- hexstrike.get_telemetry
- hexstrike.list_active_processes
- hexstrike.get_process_status
- hexstrike.terminate_process
- hexstrike.pause_process
- hexstrike.resume_process
- hexstrike.get_process_dashboard
- hexstrike.execute_command
- hexstrike.display_system_metrics
- hexstrike.error_handling_statistics
- hexstrike.test_error_recovery
---
# 任务运行环境维护

适用条件：文件操作只在当前任务目录；进程操作只能引用执行账本记录的本任务进程。全局 execute_command 和包安装不是一般规划工具。

操作方法：健康检查只证明桥和依赖状态，不证明扫描能力。删除、暂停、恢复必须校验资源归属及当前状态；包安装走锁定构建流程，不能接受模型给出的任意命令。

复核与证据：区分进程退出、工具业务失败和未知状态。重启后先核对 execution ID；缓存命中不能冒充本次执行，未知执行不自动降级重试。

失败处理：先区分协议错误、执行失败、解析失败、无发现和未知。未知必须对账，不自动重放或回退。新增参数或工具需新计划摘要。

来源：https://github.com/0x4m4/hexstrike-ai/tree/d689933ff579d839c676c82b231f8e98326c5f04

这是 VulnMind 编写的接入方法，不是上游文档指令，也不代表对应工具已安装或已通过验证。

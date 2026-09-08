# 三端联调记录

更新时间：2026-09-06

## 已打通链路

```text
Web :4173
  -> /api/v1 同源代理
  -> FastAPI :8000
  -> tea121 CLI + Clang/LLVM 15 + tea121-extract
  -> analyzer-result 1.0.0 校验与导入
  -> Run / Alarm / Diagnostic / CFG / State / IR / Trace / SSE 查询
  -> Web adapter 与工作台
```

`docker compose up --build backend web` 现在启动真实 API 模式的 Web 和内置完整
LLVM 工具链的 backend。Web 不再依赖跨域配置，REST 和 SSE 都通过 `/api` 代理。

自动验收命令：

```bash
scripts/three-tier-smoke.sh
```

该脚本上传 `analyzer/tests/fixtures/c/simple_oob.c`，创建 trace Run，并断言：

- Run 终态为 `succeeded`；
- CWE-121 definite 告警为 1 条，偏移 `[8,8]`；
- 告警关联上传的源码快照；
- CFG block state 和 trace 可查询；
- source 与 normalized IR artifact 均可查询；
- 请求从 Web 入口经过代理到达 backend，而 backend 调用真实 analyzer。

## 本轮修复的契约差异

- backend 将 analyzer 的进程内 `run_id` 绑定到 API 创建的 Run UUID 后再导入。
- analyzer 的 C/LLVM 路径输出 normalized IR artifact 及 SHA-256。
- Web 创建 Run 时携带上传文件 ID，并跳转到服务端返回的真实 Run ID。
- Web 告警/诊断查询传递筛选与分页参数。
- Web 监听全部契约定义的具名 SSE，queued 与 running 状态都启用轮询恢复。
- Evaluation 不再固定请求 `proj-001`，真实项目无评估时显示空状态。

## 尚未纳入本轮联调

- 多 C 文件编译、链接和头文件编排；当前真实 smoke 是单文件。
- 从 Web 创建 Juliet Evaluation；已有 Evaluation 读取和后端执行接口。
- 浏览器级 Playwright 交互与多尺寸截图；当前为 Web 构建、adapter 测试和 HTTP
  三端 smoke。
- backend 进程重启后的 queued/running 任务恢复。

## 浏览器启动注意事项

开发服务器默认使用真实 API；不要只依赖容器环境变量判断浏览器模式，Vite
需要通过 `.env.docker`/`--mode docker` 或显式 `VITE_USE_MOCK=true` 注入前端
构建。真实页面顶部应显示“真实 API”。

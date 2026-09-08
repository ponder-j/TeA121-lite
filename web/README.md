# TeA121 Lite Web

三端真实联调：

```bash
docker compose up --build backend web
```

打开 `http://localhost:4173/`。容器内 Web 使用真实 API，并将 `/api` 代理到
backend；本地独立开发仍默认使用 Mock。

独立启动：

```bash
npm install
npm run dev
```

开发服务器默认连接 `/api/v1` 的真实 REST/SSE 服务。需要脱离后端演示时，设置
`VITE_USE_MOCK=true`；测试模式会自动使用契约形状的本地 Mock 数据。

OpenAPI 类型生成：

```bash
npm run generate:types
```

生成结果写入 `src/types/openapi.generated.ts`。`src/types/generated.ts` 是工作台使用的归一化视图模型，API 客户端负责把服务端 DTO 映射到这些模型。

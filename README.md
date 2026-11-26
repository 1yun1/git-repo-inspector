# Git仓库接入体检工具
## 项目简介
输入公开 Git 仓库链接，自动完成仓库接入前体检，检测仓库完备度、硬编码路径、敏感密钥、Windows高危脚本，可视化输出接入就绪度评分与风险清单，用于评估仓库是否可以安全接入。

## 功能清单
### 必做功能
- 支持输入公开 GitHub 仓库链接发起体检
- 仓库完备度检测
  - README 文件存在校验
  - 多语言依赖清单识别（pyproject.toml、package.json、pom.xml、go.mod、Cargo.toml 等）
  - Windows 高危脚本识别：`.bat` `.cmd` `.ps1` `.vbs`
- 内容风险扫描
  - 硬编码绝对路径：`C:\`、`/Users/` 等路径
  - 敏感信息检测：`sk-`、`AKID`、Bearer token、私钥、`.env` 明文配置
- 可视化报告
  - 接入就绪度仪表盘评分，分级：优秀 80–100｜合格 60–79｜需改进 40–59｜危险 0–39
  - 风险清单表格，支持风险等级筛选，hover 悬浮查看完整命中内容
  - 扫描统计、扣分明细、完备度检测卡片展示
- 异步任务架构
  - 异步任务 + 前端轮询，解决 GitHub 接口慢、大仓库扫描超时问题
  - 扫描进度条 + 阶段文字提示，失败/超时友好提示

### 加分项
AI 智能接入整改建议：扫描完成后调用 DeepSeek 大模型，基于本次扫描结果自动生成项目接入整改建议；未配置 `DEEPSEEK_API_KEY` 时该模块自动禁用，不影响基础扫描功能。

### 增量更新跟踪方案
1. 每次扫描记录仓库 commit sha，报告标注本次体检基于的 commit；
2. 再次扫描时优先拉取两次 commit 的 diff，只扫描变更文件，避免全量重扫；
3. 限流/网络失败兜底：指数退避重试；多次失败降级为全量扫描，并在报告备注可信度风险。

## 技术栈
- 后端：Python / FastAPI，内存任务管理，GitHub REST API
- 前端：Vue3 + Element Plus + ECharts
- 开发方式：Vibe Coding 辅助开发

## 快速启动
### 后端
```bash
cd backend
pip install fastapi uvicorn pydantic requests
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
```

后端服务：`http://127.0.0.1:8001`

### 前端

```
cd frontend
npm install
npm run serve
```

前端页面：`http://localhost:5175`

## 使用方式

1. 打开前端页面，粘贴公开 GitHub / Gitee 仓库链接
2. 点击【开始扫描】，观察实时扫描进度
3. 扫描完成查看就绪度评分、完备项、扣分明细、风险清单、AI 接入建议（已配置密钥才显示）
4. 风险表格支持筛选等级，鼠标悬浮查看完整命中内容

## 目录结构

```
├── backend/
│   └── main.py         # 后端服务、扫描规则、异步任务、接口
├── frontend/
│   ├── src/
│   │   ├── App.vue     # 主页面、可视化、轮询逻辑
│   │   └── api.js      # 请求封装
├── .env.example        # 环境变量模板(GITHUB_TOKEN/GITEE_TOKEN/DEEPSEEK_API_KEY)
├── AI_USAGE.md         # AI使用记录文档（单独提交）
└── README.md           # 项目说明
```

## 评分规则

- 正向加分：存在 README、合法依赖清单、无高危脚本
- 风险扣分：命中硬编码路径、敏感密钥等风险项，扣分设置上限
- 最终得分区间：0 ~ 100，分为四个评级档位

## 注意事项

1. GitHub、Gitee 公开 API 均存在访问频率限流；可配置对应 Token 提升请求额度。Gitee 匿名访问容易触发 403 限流，建议配置`GITEE_TOKEN`。
2. 当前仅支持公开仓库，私有仓库暂不支持。
3. 任务存储在内存，服务重启后历史任务丢失，生产可替换 Redis 持久化。
4. AI 接入建议依赖 DeepSeek API，未配置密钥将关闭该功能；接口调用失败不会阻断基础扫描结果展示。
5. 本工具仅用于代码接入前风险筛查，不替代专业安全审计。
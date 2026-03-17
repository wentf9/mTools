# AI 助手开发协作指南 (AGENTS.md)

本文件定义了 **xops-cli** 项目的开发流程、质量标准和协作规范。所有 AI 助手（包括当前及未来的会话）在执行任务前必须仔细阅读并严格遵守。

---

## 🚀 1. 开发工作流 (Workflow)

项目采用 **"研究 -> 思考 -> 拆解 -> 执行 -> 验证"** 的闭环开发流程。AI 在执行任何代码修改前，必须展现清晰的逻辑链条。

### 阶段一：研究与分析 (Research)

- **环境探索**：必须首先确认当前环境状态。
- **上下文检索**：使用 `grep` 或其他工具深度分析受影响的代码上下文。

### 阶段二：深度思考 (Think & Strategy)

- **禁止无脑输出**：在写代码之前，必须先输出具体的修改策略。
- **全局评估**：方案必须说明对项目依赖、架构设计的兼容性与潜在影响。

### 阶段三：任务拆分 (Task Breakdown)

- **原子化执行**：将复杂需求拆解为多个独立、可验证的子任务（例如：1. 定义接口 -> 2. 实现逻辑 -> 3. 编写测试）。
- **逐步推进**：一次只专注于一个子任务，完成并验证后再进行下一步。

### 阶段四：执行与验证 (Execution & Validation) - 🔴 核心红线

- **强制要求测试**：**必须**为所有新增功能、核心逻辑或修复的 Bug 编写对应的测试用例（Unit Test 或 Integration Test）。拒绝任何无测试覆盖的代码修改。
- **强制校验规范**：在任何 `git push` 或提交 PR 之前，必须在本地终端执行并成功通过以下命令：
  1. `go build ./...` (确保编译通过)
  2. `go test ./...` (确保逻辑正确且测试通过)
  3. `golangci-lint run ./...` (确保代码质量 0 Issues)
- **配置校验**：修改 `.golangci.yml` 后，必须运行 `golangci-lint config verify` 进行格式检查。

### 阶段五：文档同步 (Documentation Sync) - 🔴 核心红线

- **代码即文档**：更新代码的同时，**必须**同步更新相关的文档。这包括但不限于：`README.md`、CLI 命令的帮助信息 (`help text`)、关键函数的代码注释等。
- 未更新文档的任务将被视为未完成。

---

## 🛠️ 2. 技术栈与环境 (Tech Stack)

- **语言**：Go 1.26+ (严禁降级)
- **Linter**：golangci-lint v2.x (遵循版本字符串格式 `version: "2"`)
- **配置管理**：`.golangci.yml`
- **自动化**：GitHub Actions (CI/CD), GitHub Dependabot

---

## 🎨 3. 代码规范 (Coding Standards)

### 3.1 命名规范 (Naming)

- 遵循 Go 社区的缩写命名惯例：**ID, URL, SSH, CLI, SFTP, TCP** 必须全大写。
- **禁止使用**：`nodeId`, `hostId`, `identityId`。
- **必须使用**：`nodeID`, `hostID`, `identityID`。

### 3.2 错误处理 (Error Handling)

- **不准静默失败**：所有返回 `error` 的函数必须被检查。
- **显式忽略**：若确定无需检查（如 CLI 的 `Flush` 或 `Close`），必须使用 `_ =` 或 `_, _ =` 显式标记，禁止直接留空。
- **错误字符串**：不应以标点符号（如 `!` 或 `.`）或换行符结尾。

### 3.3 变量赋值

- 避免 **Ineffectual Assignment**：若变量赋值后不再使用，必须删除或使用下划线忽略。

---

## 📦 4. 依赖与仓库管理

- **Dependabot**：本项目启用了每周一次的依赖自动更新。AI 助手在处理 Dependabot PR 时应优先进行本地 `go build` 验证。
- **Commit 规范**：
  - `feat: ...` (新功能)
  - `fix: ...` (修复)
  - `chore: ...` (配置/维护)
  - `ci: ...` (流水线修改)
  - `docs: ...` (文档更新)
  - `test: ...` (测试用例)
- **Bypass 权限**：仓库设置了强制 PR 规则，但在紧急修复 Lint 或 CI 配置文件时，可利用管理员 Bypass 权限直接推送到 `master`。

---

## 🔧 5. 常用命令清单 (Commands)

| 命令 | 用途 |
| --- | --- |
| make build | 本地编译二进制文件 |
| make test | 运行 pkg 目录下所有测试 |
| golangci-lint run ./... | 运行全量代码扫描 |
| golangci-lint run --fix ./... | 自动修复可修正的 Lint 问题 |
| gh pr list --author "app/dependabot" | 查看当前的依赖更新 PR |

---
**提示**：在任何时候，代码的“干净程度”优于实现的“速度”。

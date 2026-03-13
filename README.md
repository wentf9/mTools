# XOps (XOps) 运维工具箱

xops (XOps) 是一个基于 Go 语言开发的命令行运维工具集，旨在简化日常的服务器管理工作。它集成了 SSH 连接管理、远程命令批量执行、文件传输、防火墙配置及网络工具等功能，并提供了基于标签的主机分组管理能力。

## 🚀 核心功能

- **主机管理 (Inventory)**: 支持对主机进行增删改查，提供别名和标签 (Tags) 分组功能。支持从 CSV 文件批量导入主机及其凭据。
- **SSH 增强**: 快速连接远程主机，支持跳板机 (JumpHost)、Sudo 模式以及连接信息的自动保存。
- **批量执行 (Exec)**: 支持在单台或多台主机（或按标签分组）上并行执行命令或本地脚本。
- **文件传输 (SCP)**: 支持本地与远程、远程与远程之间的数据传输，支持按分组批量分发文件。
- **防火墙管理 (Firewall)**: 自动识别并管理多种防火墙后端（firewalld, ufw, iptables, nftables）。
- **实用工具**: 集成 DNS 查询、网络探测 (Ping/NC)、编码转换等常用运维工具。
- **安全保障**: 配置文件中的敏感信息（如密码）采用对称加密存储。
- **🤖 MCP 协议支持 (AI 增强)**: 内置 Model Context Protocol 服务端，让 AI Agent 可以原生调用本工具链的能力执行运维操作。

## 🛠️ 安装

### 环境要求
- Go 1.25 或更高版本

### 编译
```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
go build -o xops ./cmd/cli/main.go
```

## 📖 快速上手

### 1. 管理主机信息
```bash
# 批量从 CSV 文件导入主机 (支持识别表头: 主机, 端口, 别名, 用户, 密码, 私钥, 私钥密码)
# 导入的同时可以将所有主机加入指定标签组
xops inventory load hosts.csv -t web
# 或者使用快捷入口
xops loadHost hosts.csv -t web

# 导出 CSV 导入模板
xops inventory load -T template.csv

# 手动添加一台主机并打上 web 标签
xops host add --name web-01 --address 192.168.1.10 --user root --tag web

# 查看主机列表
xops host list

# 查看所有标签分组
xops host tags
```

### 2. SSH 连接
```bash
# 通过名称直接连接（会自动保存连接信息）
xops ssh web-01

# 连接的同时指定分组
xops ssh root@192.168.1.11 -t db
```

### 3. 批量命令执行
```bash
# 对 web 分组的所有主机执行 uptime
xops exec -t web -c "uptime"

# 并行数设置为 5，执行本地脚本
xops exec -t web --shell ./setup.sh --task 5
```

### 4. 文件传输
```bash
# 将本地文件上传到指定分组的远程目录
xops scp ./config.conf -t web --dest /etc/app/
```

### 5. 防火墙操作
```bash
# 查看远程主机的防火墙规则
xops firewall list -H web-01

# 在远程主机上开放 80 端口
xops firewall port 80 --proto tcp
```

### 6. AI Agent 集成 (MCP Server)
使用支持 Model Context Protocol 的 AI Agent (如 Claude Desktop, Cursor, Cline 等) 可以直接调用本机配置的 `xops` 能力。
只需在您的 MCP 客户端配置信息中加入以下内容：
```json
{
  "mcpServers": {
    "xopss": {
      "command": "/这里填入绝对路径/xops",
      "args": ["mcp"]
    }
  }
}
```
配置完成后，您的 AI Agent 即可直接查询您的主机节点并自动帮您执行管理指令。

## 📂 配置文件

工具默认将配置存储在用户家目录下的 `.xops` 文件夹中：
- `~/.xops/xops_config.yaml`: 存储节点、主机及身份认证信息（敏感字段已加密）。
- `~/.xops/secret.key`: 用于加解密的密钥文件，请务必妥善保管，首次运行时自动生成。
- `~/.xops/audit.log`: MCP 护栏审计日志（JSON Lines 格式，记录 Agent 的所有工具调用）。

完整的配置项说明及示例请参考 [xops_config.example.yaml](xops_config.example.yaml)。

## 📅 规划与进度 (Roadmap)
当前项目核心运维能力已实现闭环，并正向着 AI Agent 原生运维工具箱的方向演进：
- [x] **引入 MCP (Model Context Protocol) 核心支持** (`xops mcp`)
  - [x] 工具：`xops_list_nodes` (查询本地节点)
  - [x] 工具：`xops_ssh_run` (远程 SSH 命令执行)
  - [x] 工具：`xops_read_file` / `xops_write_file` (SFTP 远程读写文件)
  - [x] 工具：`xops_upload` / `xops_download` (SFTP 文件传输)
  - [x] 工具：`xops_fs_ls` / `xops_fs_mkdir` / `xops_fs_touch` / `xops_fs_mv` / `xops_fs_rm` / `xops_fs_cp` (远程文件系统操作)
- [x] **MCP 安全护栏** (`guardrail`)
  - [x] 三级风险分类：Safe / Moderate / Dangerous
  - [x] 命令黑名单（`rm -rf /`、`mkfs`、`dd`、fork bomb 等硬拦截）
  - [x] 用户审批机制（MCP Elicitation 协议）
  - [x] 客户端不支持 Elicitation 时的回退策略（兼容 Gemini CLI 等）
  - [x] 节点级别策略覆盖（glob 模式，`prod-*` 更严格）
  - [x] JSON Lines 审计日志
  - [ ] 工具：接入网络探测能力 (Ping/DNS)
  - [ ] 工具：接入防火墙规则管理能力

## 📜 开源协议

本项目采用 [LICENSE](LICENSE) 中所述的开源协议。

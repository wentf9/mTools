# mTools (Miku Tools) 运维工具箱

mtool (Miku Tools) 是一个基于 Go 语言开发的命令行运维工具集，旨在简化日常的服务器管理工作。它集成了 SSH 连接管理、远程命令批量执行、文件传输、防火墙配置及网络工具等功能，并提供了基于标签的主机分组管理能力。

## 🚀 核心功能

- **主机管理 (Inventory)**: 支持对主机进行增删改查，提供别名和标签 (Tags) 分组功能。
- **SSH 增强**: 快速连接远程主机，支持跳板机 (JumpHost)、Sudo 模式以及连接信息的自动保存。
- **批量执行 (Exec)**: 支持在单台或多台主机（或按标签分组）上并行执行命令或本地脚本。
- **文件传输 (SCP)**: 支持本地与远程、远程与远程之间的数据传输，支持按分组批量分发文件。
- **防火墙管理 (Firewall)**: 自动识别并管理多种防火墙后端（firewalld, ufw, iptables, nftables）。
- **实用工具**: 集成 DNS 查询、网络探测 (Ping/NC)、编码转换等常用运维工具。
- **安全保障**: 配置文件中的敏感信息（如密码）采用对称加密存储。

## 🛠️ 安装

### 环境要求
- Go 1.25 或更高版本

### 编译
```bash
git clone <repository-url>
cd mTools
go build -o mtool ./cmd/cli/main.go
```

## 📖 快速上手

### 1. 管理主机信息
```bash
# 添加一台主机并打上 web 标签
mtool host add --name web-01 --address 192.168.1.10 --user root --tag web

# 查看主机列表
mtool host list

# 查看所有标签分组
mtool host tags
```

### 2. SSH 连接
```bash
# 通过名称直接连接（会自动保存连接信息）
mtool ssh web-01

# 连接的同时指定分组
mtool ssh root@192.168.1.11 -t db
```

### 3. 批量命令执行
```bash
# 对 web 分组的所有主机执行 uptime
mtool exec -t web -c "uptime"

# 并行数设置为 5，执行本地脚本
mtool exec -t web --shell ./setup.sh --task 5
```

### 4. 文件传输
```bash
# 将本地文件上传到指定分组的远程目录
mtool scp ./config.conf -t web --dest /etc/app/
```

### 5. 防火墙操作
```bash
# 查看远程主机的防火墙规则
mtool firewall list -H web-01

# 在远程主机上开放 80 端口
mtool firewall port 80 --proto tcp
```

## 📂 配置文件

工具默认将配置存储在用户家目录下的 `.mtools` 文件夹中：
- `~/.mtools/config.yaml`: 存储节点、主机及身份认证信息（敏感字段已加密）。
- `~/.mtools/config.key`: 用于加解密的密钥文件，请务必妥善保管。

## 📜 开源协议

本项目采用 [LICENSE](LICENSE) 中所述的开源协议。

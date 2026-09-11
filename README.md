# VPS Security Hardening v2.1.1

一个面向 **Debian 12 / Debian 13** 的交互式 VPS 基础安全加固脚本，适合新 VPS 初始化后执行，也可用于已经存在基础环境的 VPS。

v2.1 的核心目标是：

> **最小侵入、防失联、可验证、可回滚、可重复执行，并兼容“密码登录”和“厂商强制 SSH 密钥登录”两类 VPS。**

> **v2.1.1 修复：**解决项目版本变量 `VERSION` 与 Debian `/etc/os-release` 中同名 `VERSION` 字段冲突、导致脚本在系统预检阶段报 `readonly variable` 的问题。

---

## v2.1 最重要的新功能：SSH 认证方式可选

安装过程中会询问：

```text
3. 请选择 root SSH 登录认证方式 [默认: 1]
   1) root + 密码登录（默认）
   2) root + SSH 公钥登录（适合厂商强制密钥登录）
```

### 方式 1：root + 密码登录（默认）

保持原来的使用习惯：

- 使用 `root` 管理 VPS；
- 手动设置新的 root 密码；
- 开启 SSH 密码认证；
- 不创建额外管理员；
- 不主动写入、删除或禁用服务器已有 SSH 公钥；
- 如果厂商原本已经配置了可用 Key，它仍可继续作为额外救援登录方式。

核心 SSH 策略：

```text
PermitRootLogin yes
PasswordAuthentication yes
AuthenticationMethods any
```

### 方式 2：root + SSH 公钥登录

适合以下 VPS：

- 厂商禁止密码 SSH；
- 厂商要求创建实例时绑定 SSH Key；
- 必须使用厂商平台生成或导入的 Key；
- 用户希望关闭公网 SSH 密码认证。

脚本会要求手动粘贴一整行 OpenSSH 公钥，例如：

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... my-key
```

然后会：

1. 使用 `ssh-keygen` 检查公钥格式；
2. 计算并显示公钥指纹；
3. 备份现有 `/root/.ssh/authorized_keys`；
4. 保留厂商已经写入的所有 Key；
5. 按公钥**指纹**判断是否已存在；
6. 已存在则跳过重复写入；
7. 不存在则追加到 `authorized_keys`；
8. 设置 `/root/.ssh` 为 `700`、`authorized_keys` 为 `600`；
9. SSH 改成 **publickey only**；
10. 第二终端真实密钥登录成功后才继续收紧 UFW。

核心 SSH 策略：

```text
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
```

> 公钥不是私钥。脚本要求输入的是可以公开的 `.pub` 内容，绝对不要粘贴私钥内容。

---

# 支持系统

正式支持：

- Debian 12 Bookworm
- Debian 13 Trixie

不支持 Debian 11。

Debian 11 已结束 Debian 官方 LTS，因此脚本会拒绝在 Debian 11 上继续执行。

---

# 仓库文件

```text
vps-security-hardening/
├── install-vps-hardening.sh   # 一键交互式安装 / 加固
├── rollback.sh                # 历史备份选择 / 回滚
├── CHANGELOG.md               # 版本变化
└── README.md                  # 使用说明
```

---

# 一键执行

假设 GitHub 仓库为：

```text
https://github.com/shaolonger/vps-security-hardening
```

直接执行：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh)"
```

必须以 `root` 身份执行。

查看版本：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh)" -- --version
```

对于会修改 SSH 和防火墙的脚本，更稳妥的方式仍是先下载查看：

```bash
curl -fsSLO https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh
less install-vps-hardening.sh
bash install-vps-hardening.sh
```

---

# 完整交互流程

大致顺序：

```text
系统预检
↓
选择时区
↓
选择 SSH 端口
↓
选择 SSH 认证方式
  ├─ root + password（默认）
  └─ root + publickey
       └─ 粘贴并校验公钥
↓
选择是否执行 apt-get upgrade
↓
显示最终修改计划
↓
输入 YES
↓
创建完整备份
↓
APT / 时间同步处理
↓
准备认证材料
  ├─ password → passwd root
  └─ publickey → 保留并追加 authorized_keys
↓
如果 UFW 原本 active，临时允许新 SSH 端口
↓
写入 managed SSH 配置
↓
sshd -t / sshd -T
↓
切换并启动 SSH listener
↓
确认新端口实际 LISTEN
↓
第二终端真实登录
↓
输入 VERIFIED
↓
最终重置/收紧 UFW
↓
配置 Fail2ban
↓
配置自动安全更新
↓
最终健康检查
```

---

# 系统预检

脚本修改系统前会检查：

- 必须以 root 执行；
- 必须有交互式 TTY；
- Debian 版本；
- OpenSSH Server 是否存在；
- `ssh.service` / `sshd.service`；
- `ssh.socket`；
- 当前 SSH 端口；
- apt/dpkg 是否已有其他任务；
- `dpkg --audit` 是否异常；
- 根分区剩余空间；
- 是否存在全局 IPv6；
- 新 SSH 端口是否已经被其他程序监听；
- `443` / `19175` 当前是否已有监听。

不会粗暴删除 APT lock，也不会强制杀死 apt/dpkg。

---

# SSH 端口

默认：

```text
22222
```

允许范围：

```text
10000-65535
```

禁止选择：

```text
443
19175
```

因为这两个端口保留给 sing-box。

如果所选端口已被其他程序监听，会要求重新输入。

---

# SSH 配置方式

项目使用：

```text
/etc/ssh/sshd_config.d/00-vps-hardening.conf
```

并把精确 `Include` 放到主：

```text
/etc/ssh/sshd_config
```

前部，使项目关键策略优先生效，而不是整份覆盖厂商原 SSH 配置。

同时保留：

```text
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding yes
PermitTunnel no
PermitUserEnvironment no
LogLevel VERBOSE
```

不会硬编码固定的 KEX / Cipher / MAC 白名单，让 Debian/OpenSSH 自身安全更新负责算法生命周期。

---

# 公钥模式的详细行为

## 不覆盖厂商已有 Key

脚本不会这样做：

```bash
echo "$KEY" > /root/.ssh/authorized_keys
```

而是先保留原文件，再追加。

例如原来厂商已经写入：

```text
ssh-ed25519 AAAA... provider-key
```

你输入：

```text
ssh-ed25519 BBBB... my-key
```

最终会是：

```text
ssh-ed25519 AAAA... provider-key
ssh-ed25519 BBBB... my-key
```

如果你输入的其实就是平台已经写入的同一个 Key，即使注释不同，只要指纹相同，脚本也会跳过重复添加。

## 支持的常见公钥类型

包括：

```text
ssh-ed25519
ssh-rsa
ecdsa-sha2-nistp256
ecdsa-sha2-nistp384
ecdsa-sha2-nistp521
sk-ssh-ed25519@openssh.com
sk-ecdsa-sha2-nistp256@openssh.com
```

推荐新建 Key 时优先使用 Ed25519。

## 厂商只给了私钥怎么办？

如果你手中只有私钥文件，例如：

```text
provider-key
```

可以在自己的电脑上生成对应公钥：

```bash
ssh-keygen -y -f provider-key
```

将输出的：

```text
ssh-ed25519 AAAA...
```

粘贴给安装脚本。

**不要把私钥文件本身粘贴进脚本。**

## `.ssh` / `authorized_keys` 是符号链接时

如果检测到：

```text
/root/.ssh
```

或：

```text
/root/.ssh/authorized_keys
```

是符号链接，脚本会停止公钥模式，不会贸然向链接目标写入内容。

这是为了避免误改厂商通过特殊机制管理的密钥文件。此时应先通过厂商控制台确认该 VPS 的 SSH Key 管理方式。

---

# 密码模式

密码模式是默认值。

脚本调用：

```bash
passwd root
```

因此密码：

- 不回显；
- 不进入脚本变量；
- 不写日志；
- 不写 backup manifest。

完成后使用：

```bash
passwd -S root
```

确认 root 账户密码状态有效。

需要注意：

> `rollback.sh` 无法恢复旧 root 密码，因为脚本从不保存旧密码。

---

# 事务式 SSH 迁移

SSH 和防火墙采用两阶段方式。

如果原 UFW 已经 active：

```text
先临时允许新 SSH 端口
↓
写 SSH 配置
↓
sshd -t
↓
sshd -T
↓
重启 SSH
↓
检查新端口 LISTEN
↓
第二终端真实登录
↓
VERIFIED
↓
最终 ufw reset
```

在 `VERIFIED` 之前，如果 SSH 迁移失败，脚本会尽力恢复：

- 原 `sshd_config`；
- 原 managed SSH 配置；
- 原 Banner；
- 原 SSH service/socket listener 模式；
- 原 UFW；
- v2.1 中记录的原 `authorized_keys`。

密码模式下，已经修改的新 root 密码无法恢复。

---

# 必须进行第二终端登录验证

新的 SSH listener 启动后，脚本会停在：

```text
请输入 VERIFIED / STATUS / ROLLBACK:
```

## 密码模式

在第二个终端：

```bash
ssh -p 22222 root@你的VPS_IP
```

输入新的 root 密码。

## 公钥模式

在第二个终端：

```bash
ssh -i /path/to/private-key -p 22222 root@你的VPS_IP
```

如果对应私钥已经加载进 `ssh-agent`，也可以：

```bash
ssh -p 22222 root@你的VPS_IP
```

只有真正登录成功后才回到原窗口输入：

```text
VERIFIED
```

如果失败：

```text
STATUS
```

查看 SSH 服务和监听状态。

或输入：

```text
ROLLBACK
```

恢复本次执行前的 SSH / UFW / `authorized_keys` 状态。

> 不要在没有实际成功登录第二终端的情况下直接输入 `VERIFIED`。

---

# ssh.socket 兼容

部分 Debian 环境使用：

```text
ssh.socket
```

systemd socket activation。

v2.1 会检测其 active/enabled 状态；需要时会安全切换到：

```text
ssh.service
```

或：

```text
sshd.service
```

使选择的 SSH 端口真正由 `sshd_config` 控制。

执行前状态会写入 backup manifest，rollback 会尽力恢复原 listener 模式。

---

# UFW

最终：

```text
Default incoming: deny
Default outgoing: allow
```

只保留：

| 端口 | 协议 | 用途 |
|---|---|---|
| 自定义 SSH 端口 | TCP | root SSH 管理，`ufw limit` |
| `443` | TCP | sing-box VLESS / Reality |
| `19175` | TCP | sing-box Shadowsocks |
| `19175` | UDP | sing-box Shadowsocks UDP |

例如：

```text
22222/tcp     LIMIT
443/tcp       ALLOW
19175/tcp     ALLOW
19175/udp     ALLOW
```

无论选择密码还是公钥，SSH 防火墙规则都一样。

## 注意：最终会重置现有 UFW

在第二终端 SSH 验证成功后会执行：

```bash
ufw --force reset
```

如果服务器还运行：

- Nginx `80/TCP`
- 管理面板
- Docker 映射端口
- Komari
- 数据库
- 其他代理/游戏服务

这些端口不会自动保留。

---

# IPv6

检测：

```bash
ip -6 addr show scope global
```

如果有全局 IPv6，会确保：

```text
/etc/default/ufw
IPV6=yes
```

并在最终健康检查中确认 UFW 存在 `(v6)` 规则。

---

# Fail2ban

使用独立文件：

```text
/etc/fail2ban/jail.d/99-vps-hardening.local
```

不会覆盖：

```text
/etc/fail2ban/jail.local
```

默认 sshd jail：

```ini
[sshd]
enabled = true
backend = systemd
port = <SSH端口>
filter = sshd
banaction = ufw
findtime = 10m
maxretry = 3
bantime = 24h
```

无论密码还是公钥模式，都保留 Fail2ban 作为公网 SSH 的额外保护层。

---

# 自动安全更新

创建：

```text
/etc/apt/apt.conf.d/99-vps-hardening-periodic
```

不会覆盖 Debian 自带的：

```text
/etc/apt/apt.conf.d/50unattended-upgrades
```

开启：

```text
apt-daily.timer
apt-daily-upgrade.timer
```

---

# apt upgrade 可选择

安装时会询问：

```text
执行 apt-get upgrade？[Y/n]:
```

默认 `Y`。

脚本不会自动：

```bash
apt autoremove
```

避免安全初始化脚本擅自删除其他服务依赖。

---

# 时间同步

不会无条件替换为 Chrony。

优先保留当前已经 active 的：

- Chrony；
- systemd-timesyncd；
- ntpsec；
- ntp。

只有没有活动时间同步服务时，才会启用已有 `systemd-timesyncd`，或安装 Chrony。

---

# 备份

每次运行前创建：

```text
/root/vps-hardening-backups/YYYYMMDD_HHMMSS_XXXXXX/
```

其中可能包括：

```text
manifest.env
sshd_config
00-vps-hardening.conf
banner.vps-hardening
root-authorized_keys   # 仅公钥模式且执行前文件存在时
ufw/
default-ufw
99-vps-hardening.local
99-vps-hardening-periodic
```

`manifest.env` 会记录：

- 脚本版本；
- 新旧 SSH 端口；
- 本次认证方式；
- SSH service/socket 原状态；
- UFW 原状态；
- Fail2ban 原状态；
- 自动更新 timers；
- 时区；
- 时间同步服务；
- IPv6；
- 公钥模式下 `/root/.ssh` 是否存在及目录元数据；
- 公钥模式下 `authorized_keys` 是否存在。

密码模式不会管理或回滚 `authorized_keys`。公钥本身不会写进 manifest；只有公钥模式才会把执行前已有的 `authorized_keys` 作为 root-only 备份文件保存。

---

# 回滚

交互选择历史备份：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/rollback.sh)"
```

只列出：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/rollback.sh)" -- --list
```

恢复最新 v2 格式备份：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/rollback.sh)" -- --latest
```

v2.1 rollback 会恢复：

- SSH 配置；
- SSH listener service/socket；
- UFW；
- Fail2ban drop-in；
- 自动更新配置和 timer 状态；
- 时区；
- 时间同步状态；
- **如果备份来自 v2.1：恢复执行前的 `authorized_keys` 状态。**

为了兼容 v2.0：

> 如果旧备份没有 `ROOT_AUTH_KEYS_TRACKED=1`，rollback 会完全不碰 `authorized_keys`，避免把 v2.0 从未管理过的密钥误删。

不会恢复：

- 密码模式下执行前的旧 root 密码；
- 已安装的软件包；
- 已经完成升级的软件包版本。

---

# 最终健康检查

结束前会检查：

- SSH service active；
- 新 SSH TCP 端口正在监听；
- 当前认证方式对应的 OpenSSH 配置；
- 密码模式下 root 密码状态；
- 公钥模式下 `authorized_keys`；
- 公钥模式下本次输入的 Key 指纹确实存在；
- UFW active；
- SSH / 443 / 19175 UFW 规则；
- IPv6 UFW；
- Fail2ban；
- sshd jail；
- apt timers；
- 时间同步服务。

`443` / `19175` 没有程序监听不会判为失败，因为本项目不负责安装 sing-box，只负责为它们准备防火墙。

---

# 常用检查命令

查看版本：

```bash
bash install-vps-hardening.sh --version
```

查看 SSH 实际配置：

```bash
sshd -T -C user=root,host=localhost,addr=127.0.0.1 | \
grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|authorizedkeysfile) '
```

查看 SSH：

```bash
systemctl status ssh --no-pager
ss -lntp
```

查看 root 公钥：

```bash
cat /root/.ssh/authorized_keys
ssh-keygen -lf /root/.ssh/authorized_keys
```

查看 UFW：

```bash
ufw status verbose
```

查看 Fail2ban：

```bash
fail2ban-client status
fail2ban-client status sshd
```

查看自动更新：

```bash
systemctl status apt-daily.timer --no-pager
systemctl status apt-daily-upgrade.timer --no-pager
```

---

# 云厂商 Security Group / Firewall / ACL

本机 UFW 并不能替代云厂商上游防火墙。

请确保控制台允许：

```text
你的 SSH 管理端口 / TCP
443 / TCP
19175 / TCP
19175 / UDP（如使用）
```

对于强制密钥的厂商：

- 优先使用厂商要求的 Key；
- 如果平台已经把 Key 写入实例，可以把同一 `.pub` 内容粘贴给本脚本，脚本会按指纹识别并避免重复；
- 如果平台通过特殊的 `AuthorizedKeysCommand`、符号链接或其他动态机制管理 Key，请不要盲目覆盖平台机制；
- 脚本的第二终端真实登录验证是最终安全网。

---

# 安全说明

## 密码模式

公网 root 密码登录的安全性通常低于密钥认证，因此建议：

- 使用长、唯一、随机的 root 密码；
- SSH 使用非 22 端口；
- 保持 Fail2ban 与 UFW；
- 不复用其他服务密码。

## 公钥模式

更推荐使用：

```text
Ed25519
```

并注意：

- 私钥只保存在自己的可信设备；
- 不要把私钥上传到 VPS 或 GitHub；
- 私钥可以设置本地 passphrase；
- 保留厂商 Web Console / Serial Console 等救援入口；
- 删除不再需要的旧 Key 前先确认至少还有一个可用登录方式。

---

# 项目明确不会做什么

不会：

- 修改 hostname；
- 创建非 root 管理员；
- 写 sysctl / BBR；
- 修改或锁死 `/etc/resolv.conf`；
- 强制 IPv4 优先；
- 固定 SSH KEX/Cipher/MAC 白名单；
- 自动安装 sing-box；
- 自动执行 `apt autoremove`；
- 绕过厂商本身的 SSH Key / Security Group 安全策略。

---

# 版本

当前：

```text
v2.1.1
```

版本变化见：

```text
CHANGELOG.md
```

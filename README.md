# VPS Security Hardening v2.2.3

一个面向 **Debian 12 / Debian 13** 的交互式 VPS 基础安全初始化与加固脚本。

v2.2.3 延续 v2.2 的核心目标，并继续增强对厂商定制 Debian 镜像的兼容性：除 v2.2.2 的 OpenSSH Include 修复外，本版还会自动检测并修复“已安装 UFW、但 `/etc/ufw/ufw.conf` 缺失”的残缺 UFW 环境：

> **最小侵入、防失联、可验证、可回滚、可重复执行，并兼容普通公网 VPS、厂商自定义 SSH 端口、NAT/端口映射 VPS、密码登录与强制 SSH Key 登录。**

---

## v2.2.3：UFW 残缺安装自动修复

部分 VPS 厂商镜像可能已经把 `ufw` 标记为已安装，但运行时文件并不完整，例如缺少：

```text
/etc/ufw/ufw.conf
```

这种情况下，仅执行 `apt-get install ufw` 可能不会重新生成缺失文件，随后执行 `ufw reset` 会出现：

```text
ERROR: Couldn't stat '/etc/ufw/ufw.conf'
```

v2.2.3 会在组件安装后以及最终写入 UFW 规则前再次检查 UFW：

- 缺少 `/etc/ufw/ufw.conf` 时，从软件包自带模板 `/usr/share/ufw/ufw.conf` 安全补齐；
- 缺少 `/etc/default/ufw` 时，尝试重新安装 UFW 并恢复缺失配置；
- 不覆盖已经存在的用户 UFW 配置；
- 修复后执行 `ufw status` 验证运行时完整性；
- 验证失败则停止，而不是冒险继续启用防火墙。

---

## v2.2.0 重点：SSH 内部端口与公网端口分离

很多 VPS 厂商面板显示的“SSH 端口”并不一定等于 VPS 内部 `sshd` 真正监听的端口。

例如 NAT VPS 可能是：

```text
公网 1.2.3.4:35678
        ↓
厂商 NAT / Port Forward
        ↓
VPS 内部 10.x.x.x:22
```

这种情况下：

- 登录命令使用公网端口 `35678`；
- `sshd` 使用内部端口 `22`；
- UFW 放行内部端口 `22`；
- Fail2ban 监控内部端口 `22`；
- **绝不能把内部 sshd 端口改成 35678，除非厂商同步修改 NAT 映射。**

因此 v2.2.0 不再只有一个 `SSH_PORT`，而是明确区分：

```text
SSH_INTERNAL_PORT  VPS 内部 sshd / UFW / Fail2ban 使用
SSH_EXTERNAL_PORT  用户从公网连接时使用
```

---

## SSH 端口策略

脚本会先自动检测当前 SSH 会话实际到达 VPS 的内部端口，然后询问：

```text
2. 请选择 SSH 端口策略 [默认: 1]
   当前 SSH 会话实际到达 VPS 的内部端口：22

   1) 保持当前 VPS 内部 SSH 端口（推荐，默认）
   2) 修改 VPS 内部 SSH 端口
   3) 厂商 NAT / 公网端口映射（公网端口与 VPS 内部端口不同）
```

### 1）保持当前内部端口（默认、推荐）

适合绝大多数 VPS，包括厂商已经把系统 SSH 改成自定义端口的情况。

例如当前 SSH 实际进入 VPS 的端口为 `35678`：

```text
内部 SSH：35678
公网 SSH：35678
```

直接回车即可，脚本不会主动把它换成 `22222`。

这是 v2.2.0 与旧版最重要的行为变化之一：**默认不再修改 SSH 端口。**

### 2）主动修改 VPS 内部 SSH 端口

只有明确希望修改内部 `sshd` 端口时才选择此项。

例如：

```text
当前内部端口：22
新的内部端口：22222
```

脚本会：

1. 检查目标端口是否合法、是否被其他服务占用；
2. 如果 UFW 已启用，先临时放行目标内部端口；
3. 写入新的 SSH 配置；
4. `sshd -t` / `sshd -T` 校验；
5. 重启 SSH；
6. 确认真正监听新端口；
7. 要求第二终端真实登录；
8. 直接按 **回车**确认后才最终收紧 UFW。

内部端口允许 `1-65535`，但 `443` 和 `19175` 被本项目预留给 sing-box，因此主动修改模式不允许选择这两个端口。

### 3）厂商 NAT / 公网端口映射

适用于 NAT VPS，例如厂商面板写：

```text
公网 SSH 端口：35678
```

但 VPS 内部当前实际 SSH 是：

```text
22
```

选择 `3` 后输入：

```text
公网端口：35678
```

脚本会记录：

```text
公网 35678 -> VPS 内部 22
```

最终：

```text
sshd     : 22
UFW      : 22/tcp
Fail2ban : 22
登录命令 : ssh -p 35678 root@公网IP
```

公网映射端口不会错误写入 VPS 内部 UFW 或 Fail2ban。

---


### Debian 12 / OpenSSH 兼容说明

从 v2.2.2 起，本项目的 SSH managed config 改为：

```text
/etc/ssh/sshd_config.vps-hardening.conf
```

脚本会把它作为 `/etc/ssh/sshd_config` 的第一条精确 `Include`，并确保旧版：

```text
/etc/ssh/sshd_config.d/00-vps-hardening.conf
```

不再同时被加载。原因是 Debian 默认通常已经存在 `Include /etc/ssh/sshd_config.d/*.conf`；旧版同时再插入一次精确 Include 时，同一个文件可能被解析两次。对于密码模式里的 `AuthenticationMethods any`，OpenSSH 8.7+ 的解析行为可能因此报：

```text
"any" must appear alone in AuthenticationMethods
```

v2.2.2 通过“managed config 放到 `sshd_config.d` 目录之外 + 只精确 Include 一次”彻底避免重复解析，同时仍保持本项目 SSH 配置优先于厂商后续配置。

## SSH 认证方式

端口策略之后会询问：

```text
3. 请选择 root SSH 登录认证方式 [默认: 1]
   1) root + 密码登录（默认）
   2) root + SSH 公钥登录（适合厂商强制密钥登录）
```

### root + 密码（默认）

- 使用 `root`；
- 手动执行 `passwd root` 设置新密码；
- `PasswordAuthentication yes`；
- 不创建额外管理员；
- 不主动删除或禁用厂商已有 SSH Key。

核心策略：

```text
PermitRootLogin yes
PasswordAuthentication yes
AuthenticationMethods any
```

### root + SSH 公钥

适合厂商强制 SSH Key 的 VPS。

脚本会要求粘贴一整行 OpenSSH 公钥，例如：

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@example
```

随后：

- 使用 `ssh-keygen` 验证公钥；
- 显示 SHA256 指纹；
- 保留厂商已有 `/root/.ssh/authorized_keys`；
- 按指纹去重后追加新 Key；
- 修正 `.ssh` / `authorized_keys` 权限；
- 公钥模式纳入 SSH 事务和回滚；
- SSH 密码认证关闭。

核心策略：

```text
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
```

> 输入的是 `.pub` 公钥，不是私钥。绝不要粘贴 `-----BEGIN OPENSSH PRIVATE KEY-----` 内容。

---

## 支持系统

正式支持：

- Debian 12 Bookworm
- Debian 13 Trixie

Debian 11 已结束 Debian 官方 LTS，脚本会拒绝继续执行。

---

## 仓库结构

```text
vps-security-hardening/
├── install-vps-hardening.sh
├── rollback.sh
├── CHANGELOG.md
└── README.md
```

---

## 一键执行

仓库示例：

```text
https://github.com/shaolonger/vps-security-hardening
```

直接执行：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh)"
```

建议先确认版本：

```bash
curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh \
  | grep HARDENING_VERSION
```

应看到：

```text
readonly HARDENING_VERSION="2.2.3"
```

---

## 完整交互流程

大致顺序：

```text
系统预检
  ↓
检测 Debian / SSH / apt-dpkg / 磁盘 / IPv6
  ↓
选择时区
  ↓
选择 SSH 端口策略
  ├─ 保持当前内部端口（默认）
  ├─ 修改内部端口
  └─ NAT：记录公网端口 -> 内部端口
  ↓
选择 root 密码 / SSH 公钥
  ↓
选择是否 apt-get upgrade
  ↓
最终摘要确认 [Y/n]
  ↓
创建备份
  ↓
安装必要组件 / 时间同步
  ↓
准备密码或 authorized_keys
  ↓
事务式配置 SSH
  ↓
第二终端实际登录
  ↓
VERIFIED
  ↓
最终 UFW
  ↓
Fail2ban
  ↓
自动安全更新
  ↓
健康检查
```

所有 `[Y/n]` 提示均支持：

- 直接回车 = `Y`
- `y / Y / yes / YES` = 继续
- `n / N / no / NO` = 否
- 其他输入 = 重新询问

---

## UFW 最终规则

UFW 永远使用 **VPS 内部端口**，不是 NAT 的公网映射端口。

| 端口 | 协议 | 用途 |
|---|---|---|
| SSH 内部端口 | TCP | root SSH，使用 `ufw limit` |
| `443` | TCP | sing-box VLESS / Reality |
| `19175` | TCP | sing-box Shadowsocks |
| `19175` | UDP | sing-box Shadowsocks UDP |

其他入站默认拒绝。

例如 NAT：

```text
公网 35678 -> 内部 22
```

UFW 应显示的是：

```text
22/tcp       LIMIT
443/tcp      ALLOW
19175/tcp    ALLOW
19175/udp    ALLOW
```

而不是 `35678/tcp`。

如果 VPS 有全局 IPv6，脚本还会确保 UFW IPv6 防护处于开启状态并进行最终检查。

---

## Security Group / ACL 与 NAT 的区别

### Security Group / Firewall / ACL

如果是普通公网 VPS：

```text
公网端口 == VPS 内部端口
```

厂商安全组必须允许该端口。

例如内部 SSH 为 `22222`：

```text
Security Group: allow 22222/TCP
UFW:            allow/limit 22222/TCP
sshd:           listen 22222
```

### NAT / Port Forward

如果是：

```text
公网 35678 -> 内部 22
```

则：

```text
厂商面板 NAT : 35678 -> 22
VPS sshd      : 22
VPS UFW       : 22
VPS Fail2ban  : 22
客户端        : ssh -p 35678 ...
```

不要把这两种情况混淆。

---

## 第二终端验证

SSH 配置生效后，脚本不会直接继续重置最终 UFW，而是暂停：

```text
请输入 回车确认 / STATUS / ROLLBACK:
```

### VERIFIED

确认第二终端已经真实登录成功后输入：

```text
VERIFIED
```

脚本才继续最终 UFW。

### STATUS

显示当前 SSH 服务和内部监听端口。

### ROLLBACK

在当前 SSH 事务中立即恢复执行前的 SSH/UFW；公钥模式还会恢复 `authorized_keys`。

密码模式下新 root 密码无法恢复为旧密码，因为脚本不会保存旧密码。

---

## APT / DPKG 安全预检

脚本会识别真正运行中的：

- `apt`
- `apt-get`
- `dpkg`
- `unattended-upgrade`
- `apt.systemd.daily`
- `apt-daily.service`
- `apt-daily-upgrade.service`

并明确忽略长期存在的：

```text
unattended-upgrade-shutdown --wait-for-signal
```

发现真实软件包管理任务时，默认可以安全等待最多 15 分钟。

脚本不会：

- `kill -9 apt/dpkg`
- 删除 `/var/lib/dpkg/lock*`
- 强行破坏软件包数据库锁

同时会执行 `dpkg --audit` 检查。

---

## Fail2ban

使用独立配置：

```text
/etc/fail2ban/jail.d/99-vps-hardening.local
```

不会覆盖已有 `/etc/fail2ban/jail.local`。

默认只管理 `sshd` jail：

```text
findtime = 10m
maxretry = 3
bantime  = 24h
```

Fail2ban 使用 **SSH 内部端口**。

---

## 自动安全更新

创建：

```text
/etc/apt/apt.conf.d/99-vps-hardening-periodic
```

并确保：

```text
apt-daily.timer
apt-daily-upgrade.timer
```

处于可用状态。

不会覆盖 Debian 自带的 `50unattended-upgrades` 软件包选择策略。

---

## 时间同步

脚本优先保留系统已经正常工作的时间同步服务，包括：

- Chrony
- systemd-timesyncd
- ntpsec
- ntp

只有当前没有有效同步服务时才启用可用服务或安装 Chrony。

---

## 备份

每次执行前创建唯一目录：

```text
/root/vps-hardening-backups/YYYYMMDD_HHMMSS_XXXXXX/
```

主要保存：

- `/etc/ssh/sshd_config`
- 本项目独立 SSH managed config `/etc/ssh/sshd_config.vps-hardening.conf`
- SSH Banner
- UFW 配置
- Fail2ban drop-in
- 自动更新配置
- 公钥模式下的 `/root/.ssh/authorized_keys`
- 服务状态与端口信息 manifest

v2.2 manifest 额外记录：

```text
SSH_PORT_MODE_NEW
SSH_INTERNAL_PORT_NEW
SSH_EXTERNAL_PORT_NEW
```

同时继续写入旧字段 `SSH_PORT_OLD` / `SSH_PORT_NEW`，便于兼容 v2 系列回滚逻辑。

---

## 回滚

交互选择历史备份：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/rollback.sh)"
```

列出备份：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/rollback.sh)" -- --list
```

自动选择最新 v2 备份：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/rollback.sh)" -- --latest
```

回滚会尽量恢复：

- SSH 配置
- SSH service/socket 状态
- UFW 配置和 active 状态
- Fail2ban 配置和服务状态
- 自动更新配置/timers
- 时区
- 时间同步服务状态
- 公钥模式下原 `authorized_keys`

不会恢复：

- 旧 root 密码
- 已安装的软件包
- 已经升级的软件包版本

---

## 常用检查命令

查看 SSH 有效配置：

```bash
sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods) '
```

查看真实监听端口：

```bash
ss -lntp | grep ssh
```

查看 SSH 服务：

```bash
systemctl status ssh --no-pager
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
systemctl status apt-daily.timer apt-daily-upgrade.timer --no-pager
```

---

## 不会做的事情

本项目不会：

- 修改主机名；
- 创建非 root 管理员；
- 写入 sysctl/BBR 等内核调优；
- 强制修改或锁死 `/etc/resolv.conf`；
- 强制 IPv4 优先；
- 强杀 apt/dpkg；
- 自动删除厂商已有 SSH Key；
- 自动修改厂商控制台上的 Security Group / NAT / ACL。

厂商控制台属于 VPS 外部控制面，脚本只能根据用户输入正确配置 VPS 内部系统。

---

## 安全说明

`root + password` 虽然方便，但通常弱于 `root/admin + SSH public key`。如果使用密码模式，至少建议：

- 使用长、随机且唯一的密码；
- 保持 UFW 与 Fail2ban 正常；
- 不开放不需要的端口；
- 有条件时保留厂商 Web Console / VNC / Serial Console；
- 执行脚本时始终保留当前 SSH 会话，直到第二终端验证完成。

对于 NAT VPS，请把厂商面板提供的“公网 SSH 端口”和 VPS 内部 sshd 端口分别记录，不要混为一个端口。

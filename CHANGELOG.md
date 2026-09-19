# Changelog

## v2.2.2 - 2026-09-18

### Debian 12 / OpenSSH AuthenticationMethods compatibility

- 修复 Debian 12 / OpenSSH 9.2 上密码模式可能出现：
  - `/etc/ssh/sshd_config.d/00-vps-hardening.conf line ...: "any" must appear alone in AuthenticationMethods`
- 根因不是 Debian 12 不支持 `AuthenticationMethods any`；Debian 12 的 OpenSSH 文档支持该值。问题来自旧版把 managed config 放在 `/etc/ssh/sshd_config.d/`，同时又在主配置第一行精确 Include；而 Debian 默认通常还会通过 `Include /etc/ssh/sshd_config.d/*.conf` 再加载一次，造成同一 `AuthenticationMethods any` 被解析两次。
- SSH managed config 改为 `/etc/ssh/sshd_config.vps-hardening.conf`，位于 `sshd_config.d` 目录之外。
- 主配置只保留一条精确 Include，并在应用新配置前清理旧版 exact Include 与旧 drop-in。
- 事务回滚现在同时备份/恢复新旧两种 managed config 布局。
- `rollback.sh` 继续兼容 v2.0-v2.2.1 的旧备份：旧备份中的 `00-vps-hardening.conf` 会恢复到旧 drop-in 路径，新备份则恢复到新的独立 managed config 路径。

---

## v2.2.1 - 2026-09-11

### Fail2ban startup verification

- 修复 `systemctl restart fail2ban` 后立即执行 `fail2ban-client status sshd` 可能产生的启动时序误判。
- 新增最多 20 秒的就绪等待，同时确认：
  - `fail2ban.service` active；
  - `fail2ban-client ping` 成功；
  - `fail2ban-client status sshd` 成功。
- 超时后不再只给一句错误，而会输出 `fail2ban-client status`、`systemctl status fail2ban` 和最近 50 行 journal，便于判断真正的 jail 配置问题。

### SSH second-terminal confirmation

- 第二终端实际 SSH 登录成功后，现在**直接按回车即可继续**。
- `VERIFIED` 仍作为向后兼容输入保留，但不再要求用户输入。
- `STATUS` 与 `ROLLBACK` 继续保留用于排查和回滚。

---
## v2.2.0 - 2026-09-11

v2.2.0 重构 SSH 端口模型，正式兼容厂商自定义 SSH 端口与 NAT / 公网端口映射 VPS。

### SSH port model

- 默认行为改为**保持当前检测到的 VPS 内部 SSH 端口不变**，不再默认改成 `22222`。
- 新增三种端口策略：
  - 保持当前内部端口（默认、推荐）；
  - 主动修改 VPS 内部 SSH 端口；
  - 厂商 NAT / 公网端口映射。
- 引入独立变量：
  - `SSH_INTERNAL_PORT`：供 sshd、UFW、Fail2ban 使用；
  - `SSH_EXTERNAL_PORT`：供用户公网 SSH 登录命令使用；
  - `SSH_PORT_MODE`：记录 `keep / change / nat`。
- NAT 模式下明确记录 `公网端口 -> VPS 内部端口`，不会把公网映射端口错误写入 UFW、Fail2ban 或 sshd。
- 主动修改内部端口时支持 `1-65535`，不再强制 `10000-65535`；仍禁止把内部 SSH 改到本项目预留的 `443` / `19175`。
- 若选择低于 1024 的非 22 端口，会显示特权端口提示。
- 第二终端验证命令使用公网端口；SSH 服务监听检查使用内部端口。
- Security Group / ACL 提示与 NAT 映射提示分开处理。

### Firewall / Fail2ban

- UFW 的 SSH 规则始终使用 `SSH_INTERNAL_PORT`。
- Fail2ban `sshd` jail 始终使用 `SSH_INTERNAL_PORT`。
- NAT 外部端口只存在于登录提示和 manifest，不会错误开放在 VPS 内部 UFW。

### Backup / compatibility

- manifest 新增：`SSH_PORT_MODE_NEW`、`SSH_INTERNAL_PORT_NEW`、`SSH_EXTERNAL_PORT_NEW`。
- 继续保留 `SSH_PORT_OLD` 与 `SSH_PORT_NEW` 字段，维持 v2 系列回滚兼容性。
- installer / rollback 版本同步更新为 `2.2.0`。

---

## v2.1.3 - 2026-09-11

修复最终执行确认必须精确输入 `YES`、直接回车会被误判为取消的问题，并统一 `[Y/n]` 交互行为。

### Fixed

- 最终确认从 `确认继续？请输入 YES:` 改为 `确认继续？[Y/n]:`。
- 最终确认直接回车时按默认 `Y` 继续执行。
- 支持 `y`、`Y`、`yes`、`YES` 确认；支持 `n`、`N`、`no`、`NO` 取消。
- 对无法识别的输入不再直接取消，而是提示重新输入。
- 将 APT 等待、完整升级选择、root 密码重试等 `[Y/n]` 交互统一到同一确认函数，保持行为一致。
- installer / rollback 版本同步更新为 `2.1.3`。

---

## v2.1.2 - 2026-09-10

修复 APT/DPKG 系统预检把 `unattended-upgrade-shutdown --wait-for-signal` 常驻辅助进程误判为正在执行系统升级的问题。

### Fixed

- 不再使用容易截断进程名的 `ps -eo comm=` 来识别 `unattended-upgrades`。
- 改为结合 `apt-daily.service`、`apt-daily-upgrade.service` 状态与完整进程命令行识别真实软件包管理任务。
- 明确排除 `unattended-upgrade-shutdown`，该关机辅助进程即使长期存在也不会阻止脚本运行。
- 继续识别真正的 `apt`、`apt-get`、`dpkg`、`unattended-upgrade` 与 `apt.systemd.daily`。
- 检测到真实软件包管理任务时，默认允许安全等待最多 15 分钟；任务结束后自动继续。
- 等待期间每 30 秒输出一次状态；15 分钟仍未结束则安全退出。
- 脚本始终不会强制 kill APT/DPKG，也不会删除 dpkg/apt lock 文件。
- installer / rollback 版本同步更新为 `2.1.2`。

---

## v2.1.1 - 2026-09-10

修复 v2.1.0 在 Debian 12/13 上读取 `/etc/os-release` 时可能立即退出的问题。

### Fixed

- 将项目自身的只读版本变量从通用名称 `VERSION` 改为 `HARDENING_VERSION`，避免与 `/etc/os-release` 的标准 `VERSION` 字段冲突。
- `check_os()` 不再把 `/etc/os-release` 直接 source 到主脚本环境；改为在隔离的子 shell 中读取，仅提取 `ID`、`VERSION_ID`、`PRETTY_NAME`。
- 避免系统信息字段污染或覆盖项目变量。
- 同步更新 installer / rollback 的版本显示为 `2.1.1`。
- 增加针对该问题的实际回归验证：在 Debian 13 环境中 `check_os()` 可正常完成。

---

## v2.1.0 - 2026-09-10

v2.1 增加可选择的 SSH 认证模式，兼容强制 SSH Key 的 VPS 厂商，同时保持密码模式为默认。

### SSH authentication

- 安装时新增认证方式选择：
  - `root + password`（默认）
  - `root + publickey`
- 公钥模式要求用户手动粘贴一整行 OpenSSH 公钥。
- 使用 `ssh-keygen` 校验输入公钥并显示 SHA256 指纹。
- 支持常见 Ed25519、RSA、ECDSA 和 FIDO/SK 公钥类型。
- 公钥模式使用：
  - `PermitRootLogin prohibit-password`
  - `PasswordAuthentication no`
  - `PubkeyAuthentication yes`
  - `AuthenticationMethods publickey`
  - `AuthorizedKeysFile .ssh/authorized_keys`
- 密码模式继续使用：
  - `PermitRootLogin yes`
  - `PasswordAuthentication yes`
  - `AuthenticationMethods any`
- 密码模式不会主动修改、删除或禁用系统已有 SSH Key。

### authorized_keys safety

- 公钥模式不会覆盖 `/root/.ssh/authorized_keys`。
- 保留厂商已经注入的 Key，并追加用户输入 Key。
- 按公钥指纹去重，而不是只比较整行文本，因此同一个 Key 即使注释不同也不会重复写入。
- 自动修正 `/root/.ssh` 与 `authorized_keys` 的安全权限。
- 如果 `/root/.ssh` 或 `authorized_keys` 是符号链接，脚本会停止公钥模式，避免误改厂商动态管理的目标路径。
- 本次输入的公钥本身不会写入 backup manifest。

### Transaction and rollback

- 公钥模式下 `authorized_keys` 纳入 v2.1 SSH 事务；密码模式不管理或回滚该文件。
- 公钥模式下，在第二终端输入 `VERIFIED` 前发生失败，会尽力恢复执行前的 `authorized_keys`。
- v2.1 backup manifest 新增：
  - `AUTH_MODE_NEW`
  - `ROOT_AUTH_KEYS_TRACKED`
  - `ROOT_SSH_DIR_EXISTED`
  - `ROOT_AUTH_KEYS_EXISTED`
  - `/root/.ssh` 原目录权限和 UID/GID
- standalone `rollback.sh` 可以恢复 v2.1 执行前的 `authorized_keys`。
- 对 v2.0 旧备份保持兼容：缺少 `ROOT_AUTH_KEYS_TRACKED=1` 时，rollback 完全不碰 `authorized_keys`，避免误删旧版本从未管理过的密钥。

### Verification

- 第二终端提示会根据认证模式给出不同登录命令。
- 公钥模式要求使用与输入公钥匹配的私钥真实登录。
- 最终健康检查会验证：
  - `PubkeyAuthentication yes`
  - `PasswordAuthentication no`
  - `AuthenticationMethods publickey`
  - `authorized_keys` 存在
  - 本次输入公钥的指纹确实存在
- UFW SSH 规则注释改为通用 `SSH root management`，同时适用于密码和公钥模式。

---

## v2.0.0 - 2026-09-10

v2 以“最小侵入、防失联、可验证、可回滚、可重复执行”为核心重新设计。

### Breaking changes

- 正式支持系统从 Debian 11/12/13 改为 Debian 12/13；Debian 11 已结束 Debian 官方 LTS，脚本会拒绝执行。
- SSH managed config 改为 `/etc/ssh/sshd_config.d/00-vps-hardening.conf`。
- Fail2ban 不再覆盖 `/etc/fail2ban/jail.local`，改为 `/etc/fail2ban/jail.d/99-vps-hardening.local`。
- 自动更新配置改为 `/etc/apt/apt.conf.d/99-vps-hardening-periodic`。
- v2 rollback 只自动恢复 `BACKUP_FORMAT_VERSION=2` 的备份。

### SSH

- 保留 `root + password`。
- 不再设置 `PubkeyAuthentication no`。
- 不写入、删除或管理 `authorized_keys`。
- 增加 `AuthenticationMethods any`，避免旧配置要求组合认证。
- 增加 SSH 端口占用检查。
- SSH 端口禁止使用 sing-box 预留的 443 / 19175。
- 增加 `ssh.socket` 检测，并在需要时切换为 ssh service listener 模式。
- 新配置先通过 `sshd -t` 与 `sshd -T`。
- SSH 迁移改为事务式；验证完成前出错会尽力自动恢复 SSH/UFW。
- 强制第二终端实测；支持 `VERIFIED`、`STATUS`、`ROLLBACK`。

### UFW

- 如果原 UFW 已 active，会先临时放行新的 SSH 端口。
- 只有第二终端 SSH 验证成功后才执行最终 `ufw reset`。
- 最终规则只开放 SSH、443/TCP、19175/TCP、19175/UDP。
- 检测全局 IPv6；存在 IPv6 时确保 UFW IPv6 防护开启并进行最终验证。
- 最终 UFW 配置失败时优先避免 SSH 被错误锁死。

### Fail2ban

- 使用独立 `jail.d` drop-in。
- 仅管理 `sshd` jail。
- 删除默认 `recidive`，避免依赖 Fail2ban 文件日志配置。
- 配置后执行 `fail2ban-client -t` 与 sshd jail 检查。

### APT / system updates

- `apt-get upgrade` 改为交互式可选，默认执行。
- 删除自动 `apt autoremove`。
- 增加 apt/dpkg 正在运行检测。
- 增加 `dpkg --audit` 检测。
- 增加根分区可用空间检查。

### Time sync

- 不再无条件替换为 Chrony。
- 优先保留已有 active 的 Chrony、systemd-timesyncd、ntpsec 或 ntp。
- 只有不存在活动时间同步服务时才启用已有 timesyncd 或安装 Chrony。

### Backups and rollback

- 备份目录改用 `mktemp -d`，避免同一秒运行造成冲突。
- backup manifest 增加 `BACKUP_FORMAT_VERSION=2`。
- 记录 SSH service/socket、UFW、Fail2ban、APT timers、时区、时间同步和 IPv6 状态。
- rollback 支持列出并选择历史备份。
- 增加 `--latest`、`--list`、`--help`。
- 回滚可恢复时区及更多 service enable/active 状态。

### Removed / intentionally not managed

- 不修改 hostname。
- 不创建非 root 管理员。
- 不管理 SSH public key。
- 不配置固定 SSH cipher/KEX/MAC 算法白名单。
- 不写 sysctl/BBR。
- 不修改或锁定 `/etc/resolv.conf`。
- 不强制设置 IPv4 优先。


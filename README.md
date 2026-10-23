# VPS Security Hardening v2.3.0

面向 **Debian 12 / Debian 13（systemd + OpenSSH Server）** 的 VPS 交互式基础加固脚本。

> **运行前提醒**：这是一份可直接替换仓库文件的完整候选版本，已经执行 Bash 语法检查及本地逻辑检查，**尚未在你的实际 VPS 上完成端到端实机验证**。建议先在带厂商控制台和快照的测试 VPS 上验证。请始终保留原有 SSH 会话。

## 仓库文件

- `install-vps-hardening.sh`：**唯一主安装/修复入口**，完整独立运行，不依赖其他脚本。
- `rollback.sh`：手动回滚，兼容 `BACKUP_FORMAT_VERSION=2`（既有 v2.2.x 备份和 v2.3.0 新备份）。
- `README.md`：使用、限制及故障排查。
- `tests/smoke-test.sh`：不依赖真实 systemd 的 APT 定时器场景冒烟测试（使用函数模拟）。

## v2.3.0 更新摘要

1. **修复厂商镜像屏蔽 APT 单元导致的中断**：启动之前同时检查 `apt-daily.service`、`apt-daily-upgrade.service`、`apt-daily.timer`、`apt-daily-upgrade.timer`。对 `masked` 状态明确提示并询问是否解除，绝不悄悄 unmask。
2. **不再吞掉 systemd 错误**：失败时输出单元加载状态、`UnitFileState`、`FragmentPath`、`LoadError` 与相关 journal 日志。
3. **可单独修复 APT**：`--repair-apt-timers` 只处理 APT 的自动更新配置与四个单元，不触碰 SSH/UFW/Fail2ban；写入前会备份已有 APT 专属配置。
4. **支持安全检查点恢复**：`--resume` 只对达到**第 5 步（UFW 完成）之后**且尚未完成的 v2.3.0 运行起效。先核实 SSH 端口与 UFW 状态，再继续 Fail2ban / APT / 最终检查，绝不自动重复改 SSH 端口和 root 密码。
5. **更严格的 SSH 双终端验证**：管理员必须在第二个终端实际成功登录，再输入 `VERIFIED`；空回车不会通过。
6. **保留兼容性**：root 密码登录（默认）或公钥模式，保持当前内部端口（默认）/ 修改端口 / NAT 公网端口映射，Fail2ban 仅 sshd jail，UFW 仅保留 SSH + 443/tcp + 19175/tcp+udp。
7. **可回滚厂商单元策略**：新备份额外记录上述四个 APT systemd 单元原有状态，回滚时可恢复初始 `masked` 状态。
8. 禁用 unattended-upgrades 意外自动重启：使用 `Unattended-Upgrade::Automatic-Reboot "false";`。

## 安装方式

通过 **GitHub raw** 运行主脚本（请先审核代码）：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh)"
```

如系统还没有 `curl`，可先安装，或将脚本上传到 VPS 再执行：

```bash
chmod 700 install-vps-hardening.sh
bash ./install-vps-hardening.sh
```

> 运行远程下载脚本前，推荐锁定可信 commit 的 URL 或先下载检查 SHA256。**不要直接信任任意他人提供的 raw 链接**。

## 可用参数

| 参数 | 用途 | 是否修改 SSH/UFW |
|---|---|---|
| 无参数 | 完整交互式加固 | **是**，必须双终端验证 |
| `--repair-apt-timers` | 单独修复自动更新的服务和计时器 | **否** |
| `--resume` | 从上一次第 5 步及以后恢复 | **否**，会检查 SSH/UFW 是否仍正常 |
| `--check` | 只读输出状态 | **否** |
| `--version` | 显示版本 | 否 |
| `--help` | 显示帮助 | 否 |

例如，仅修复你遇到过的四个 APT 单元屏蔽问题：

```bash
bash ./install-vps-hardening.sh --repair-apt-timers
```

如果已将最新版部署到 GitHub，可用：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh)" -- --repair-apt-timers
```

这里 `--` 后的参数会传给 `bash -c` 脚本：第一个 `--` 是脚本位置参数 `$0`，后面的 `--repair-apt-timers` 成为 `$1`。建议**优先采用先下载再执行**的写法，便于审计。

```bash
curl -fsSL https://raw.githubusercontent.com/shaolonger/vps-security-hardening/main/install-vps-hardening.sh -o install-vps-hardening.sh
bash ./install-vps-hardening.sh --repair-apt-timers
```

## 默认交互设计

**SSH 登录**：root + 密码（默认），会调用系统 `passwd root` 直接输入；也可以选公钥模式，粘贴有效 SSH 公钥并保留已有 `authorized_keys`。密码不会存储到脚本变量或备份文件，但**root 密码无法自动回滚**。

**SSH 端口**：默认保持当前内部端口，避免厂商自定义端口被覆盖。NAT VPS 要区分：

```text
公网 1.2.3.4:35678 -> 厂商 NAT ->  VPS 内部 :22
                          sshd、UFW、Fail2ban 使用内部 22
                          SSH 客户端使用公网 35678
```

**UFW 入站**：最终清除此前 UFW 规则，仅保留下列端口（其他入站默认拒绝；出站默认允许）：

- VPS 内部 SSH 端口：TCP limit
- 443/tcp：sing-box VLESS
- 19175/tcp 与 19175/udp：sing-box Shadowsocks

如果主机还需要网站、面板、WireGuard、额外 SSH、Komari 面板等入站端口，请**不要直接套用本脚本的最终 UFW**，必须先修改端口政策。云平台安全组/NAT 映射不由 UFW 管理。

**Fail2ban**：在 `/etc/fail2ban/jail.d/99-vps-hardening.local` 中只为 `[sshd]` 添加管理配置。`backend=systemd`，`banaction=ufw`，10 分钟内 3 次失败则封禁 24 小时。由于存在 SSH 锁定风险，请确认管理出口 IP 稳定，必要时手动配置 `ignoreip`。

**自动更新**：`/etc/apt/apt.conf.d/99-vps-hardening-periodic` 会开启 APT 索引更新、无人值守安全更新和每 7 天自动清理缓存。允许更新的来源由 Debian 的 `50unattended-upgrades` 控制；不会强制自动重启。**timer active 只证明已调度，并不保证后续执行成功**。

## 执行阶段

1. 检测 Debian、SSH 与软件包状态；更新 APT；安装必需包，必要时补齐 UFW 缺失的运行时文件。
2. 设置时区及时间同步服务（尽量保留系统已有服务）。
3. 当需要切换 SSH 端口且 UFW 已启用时，先临时放行新的 VPS 内部 SSH 端口。
4. 事务式配置 OpenSSH，第二终端实际登录后**手动输入 `VERIFIED`**；失败可输入 `ROLLBACK`。
5. 重设最终 UFW 入站规则，完成后写入恢复检查点。
6. 配置 Fail2ban 的 sshd jail。
7. 配置 Debian APT 自动更新四个 systemd 单元并处理 masked 状态。
8. 核实 SSH、UFW、Fail2ban、APT 定时器运行状态。

## 检查与回滚

检查状态：

```bash
bash install-vps-hardening.sh --check
ufw status verbose
fail2ban-client status sshd
systemctl list-timers --all apt-daily.timer apt-daily-upgrade.timer
```

手动回滚：

```bash
bash rollback.sh --list
bash rollback.sh                # 交互选择
bash rollback.sh --latest       # 最近的 format=2 备份
```

**回滚不可恢复** root 旧密码、升级前的软件包版本、整个系统的历史状态、云平台安全组及 NAT 映射。回滚变更防火墙/SSH，强烈建议厂商控制台操作且保留旧会话。

## 典型 APT 故障

### `apt-daily.timer 未处于 active 状态`

```bash
systemctl is-enabled apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer
systemctl status apt-daily.timer apt-daily-upgrade.timer --no-pager -l
```

如果出现 `masked`，可运行：

```bash
bash install-vps-hardening.sh --repair-apt-timers
```

脚本会识别**被屏蔽的 `.service` 和 `.timer`**，并在得到确认后解除屏蔽。若厂商明确要求保持屏蔽，请选择 `N`，不要擅自覆盖厂商政策。

### 计时器已启动，但自动更新未执行

```bash
apt-config dump | grep -E 'APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)'
systemctl list-timers --all apt-daily.timer apt-daily-upgrade.timer
journalctl -u apt-daily-upgrade.service -u apt-daily.service --since yesterday --no-pager
```

### 第 7 步失败后恢复

- 如果失败来自 v2.3.0 且已经完成第 5 步，运行 `bash install-vps-hardening.sh --resume`。
- 如果此前运行的是 v2.2.4，**没有安全检查点**，请使用 `--repair-apt-timers`，再运行 `--check`，不要重新执行全套 SSH 修改。

## 环境及安全界限

- 只支持 Debian 12/13 + systemd + OpenSSH Server；不支持 Alpine、OpenWrt、Docker 容器镜像的特殊 init 环境。
- 不修改主机名、DNS、内核参数；不自动卸载任何软件包，不执行 `apt autoremove`。
- 对厂商系统服务遮蔽（`masked`）的处理必须由管理员确认。
- 不尝试绕过 VPS 厂商的防火墙、云安全组和公网端口映射限制。
- 任何脚本均不能在所有厂商自定义 Debian 模板上保证零风险；本项目强调可见诊断、保守配置、二次连接验证与可回滚。

## 本地冒烟测试

```bash
bash -n install-vps-hardening.sh
bash -n rollback.sh
bash tests/smoke-test.sh
```

测试覆盖：参数帮助与版本输出、APT service 被 `masked` 且管理员允许解除、管理员拒绝解除。**这不替代生产环境或隔离 VPS 的实机验证。**

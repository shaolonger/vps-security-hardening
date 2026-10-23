#!/usr/bin/env bash
# VPS Security Hardening v2.3.0 — Debian 12/13
# Interactive and conservative hardening for root-managed VPS, including NAT port mappings.
set -Eeuo pipefail
umask 077

VERSION='2.3.0'
BACKUP_ROOT='/root/vps-hardening-backups'
SSH_CONFIG='/etc/ssh/sshd_config'
SSH_MANAGED='/etc/ssh/sshd_config.vps-hardening.conf'
SSH_LEGACY='/etc/ssh/sshd_config.d/00-vps-hardening.conf'
SSH_BANNER='/etc/ssh/banner.vps-hardening'
KEYS='/root/.ssh/authorized_keys'
F2B_CONFIG='/etc/fail2ban/jail.d/99-vps-hardening.local'
APT_CONFIG='/etc/apt/apt.conf.d/99-vps-hardening-periodic'
UFW_DEFAULTS='/etc/default/ufw'
APT_UNITS=(apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer)

BACKUP_DIR='' STAGE='预检' TRANSACTION=0 ERRORS=0
SSH_SERVICE='' SSH_INTERNAL_PORT='' SSH_EXTERNAL_PORT='' SSH_PORT_MODE='keep'
CURRENT_PORT='' AUTH_MODE='password' SSH_PUBLIC_KEY='' KEY_FP=''
FULL_UPGRADE=1 TIMEZONE='UTC' TIME_SERVICE='' GLOBAL_IPV6=0
OS_VERSION='' OS_NAME='' ROOT_FREE='' VERIFIED=0

say()  { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
ask_yes() {
    local answer
    while :; do
        IFS= read -r -p "$1 [Y/n]: " answer || return 1
        case "${answer,,}" in ''|y|yes) return 0;; n|no) return 1;; *) warn '请输入 Y 或 N。';; esac
    done
}
ask_exact() { local answer; IFS= read -r -p "$1: " answer || return 1; [[ "$answer" == "$2" ]]; }
require_root() { (( EUID == 0 )) || fail '请使用 root 执行。'; }
require_tty() { [[ -t 0 ]] || fail '需要交互式终端（不能将 stdin 重定向给脚本）。'; }
valid_port() { [[ "${1:-}" =~ ^[0-9]{1,5}$ ]] && ((10#$1>=1 && 10#$1<=65535)); }
unit_state() { systemctl is-enabled "$1" 2>/dev/null || true; }
unit_load() { systemctl show "$1" -p LoadState --value 2>/dev/null || true; }
unit_active() { systemctl is-active --quiet "$1"; }
unit_present() { local v; v=$(unit_load "$1"); [[ -n "$v" && "$v" != not-found && "$v" != error ]]; }
unit_active_flag() { if unit_active "$1"; then printf 1; else printf 0; fi; }
installed_flag() { if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -qx 'install ok installed'; then printf 1; else printf 0; fi; }
manifest() { printf '%s=%q\n' "$1" "${2-}" >> "$BACKUP_DIR/manifest.env"; }
backup_file() { local src=$1 name=$2; [[ ! -e "$src" ]] || cp -a -- "$src" "$BACKUP_DIR/$name"; }
restore_file() {
    local present=$1 name=$2 dest=$3
    if [[ "$present" == 1 && -e "$BACKUP_DIR/$name" ]]; then
        mkdir -p -- "$(dirname "$dest")"
        cp -a -- "$BACKUP_DIR/$name" "$dest"
    else
        rm -f -- "$dest"
    fi
}

restore_ssh_ufw_best_effort() {
    (( TRANSACTION == 1 )) || return 0
    TRANSACTION=0
    warn "SSH 验证前失败：尝试回滚 SSH/UFW。备份：$BACKUP_DIR"
    if [[ -f "$BACKUP_DIR/manifest.env" ]]; then
        # manifest is created by this root-run program inside a root-only directory.
        # shellcheck disable=SC1090
        source "$BACKUP_DIR/manifest.env"
        restore_file "${SSH_CONFIG_EXISTED:-0}" sshd_config "$SSH_CONFIG"
        restore_file "${SSH_MANAGED_CONFIG_EXISTED:-0}" sshd_config.vps-hardening.conf "$SSH_MANAGED"
        restore_file "${SSH_LEGACY_MANAGED_CONFIG_EXISTED:-0}" 00-vps-hardening.conf "$SSH_LEGACY"
        restore_file "${SSH_BANNER_EXISTED:-0}" banner.vps-hardening "$SSH_BANNER"
        if [[ "${ROOT_AUTH_KEYS_TRACKED:-0}" == 1 ]]; then
            restore_file "${ROOT_AUTH_KEYS_EXISTED:-0}" root-authorized_keys "$KEYS"
        fi
        if [[ "${UFW_DIR_EXISTED:-0}" == 1 && -d "$BACKUP_DIR/ufw" ]]; then
            rm -rf /etc/ufw
            cp -a "$BACKUP_DIR/ufw" /etc/ufw
        fi
        if [[ "${UFW_DEFAULTS_EXISTED:-0}" == 1 ]]; then
            restore_file 1 default-ufw "$UFW_DEFAULTS"
        fi
        if /usr/sbin/sshd -t >/dev/null 2>&1; then
            systemctl daemon-reload || true
            if [[ "${SSH_SOCKET_WAS_ACTIVE:-0}" == 1 ]] && unit_present ssh.socket; then
                systemctl stop "${SSH_SERVICE_UNIT_OLD:-ssh.service}" || true
                systemctl enable --now ssh.socket || true
            else
                systemctl disable --now ssh.socket >/dev/null 2>&1 || true
                systemctl restart "${SSH_SERVICE_UNIT_OLD:-ssh.service}" || true
            fi
        else
            warn '回滚后 sshd -t 失败，请在当前会话中人工处理。'
        fi
        if command -v ufw >/dev/null 2>&1; then
            if [[ "${UFW_WAS_ACTIVE:-0}" == 1 ]]; then
                ufw --force enable || true
                ufw reload || true
            else
                ufw --force disable || true
            fi
        fi
    fi
    warn '请保持当前 SSH 会话并确认第二终端可登录；root 密码不会回滚。'
}
on_exit() {
    local rc=$1
    trap - EXIT
    if (( rc != 0 )); then
        warn "失败阶段：${STAGE}，退出状态：${rc}"
        restore_ssh_ufw_best_effort
        [[ -z "$BACKUP_DIR" ]] || warn "备份位置：$BACKUP_DIR"
    fi
}
trap 'on_exit $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'warn "错误所在行: $LINENO"' ERR

usage() {
    cat <<EOF
VPS Security Hardening v${VERSION} — Debian 12/13

用法：
  bash install-vps-hardening.sh                  # 完整交互式加固
  bash install-vps-hardening.sh --repair-apt-timers  # 只修复 APT 自动更新（不动 SSH/UFW）
  bash install-vps-hardening.sh --resume         # 从最后一次安全检查点（第5步以后）继续
  bash install-vps-hardening.sh --check          # 只读检查服务状态
  bash install-vps-hardening.sh --help | --version

使用 root 在 VPS 终端直接运行；首次运行请同时保留一个救援控制台。
EOF
}

check_debian() {
    [[ -r /etc/os-release ]] || fail '无法读取 /etc/os-release。'
    local -a info=()
    mapfile -t info < <(set +u; source /etc/os-release; printf '%s\n%s\n%s\n' "${ID:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-}")
    [[ "${info[0]}" == debian && ( "${info[1]}" == 12 || "${info[1]}" == 13 ) ]] || fail '仅支持 Debian 12/13。'
    OS_VERSION=${info[1]}; OS_NAME=${info[2]}
    command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || fail '需要由 systemd 管理的 Debian VPS。'
}

check_apt_busy() {
    local waited=0 info
    while :; do
        info=$(ps -eo comm=,args= | awk '
            /unattended-upgrade-shutdown/ {next}
            $1=="apt-get" || $1=="apt" || $1=="dpkg" || /\/unattended-upgrade([[:space:]]|$)/ || /\/apt.systemd.daily([[:space:]]|$)/ {print}' || true)
        if [[ -z "$info" ]] && ! unit_active apt-daily.service && ! unit_active apt-daily-upgrade.service; then break; fi
        (( waited != 0 )) || { warn "APT 正在执行其他任务：\n$info"; ask_yes '最多等待 15 分钟使 APT 完成？' || fail 'APT 忙碌，已停止。'; }
        (( waited < 900 )) || fail '等待 APT 超时，请自行检查运行中的 apt/dpkg。'
        sleep 5; waited=$((waited+5))
    done
    local audit
    audit=$(dpkg --audit 2>&1 || true)
    [[ -z "$audit" ]] || fail "dpkg 状态异常：$audit"
}

preflight() {
    STAGE='环境预检'; check_debian
    [[ -x /usr/sbin/sshd && -f "$SSH_CONFIG" ]] || fail '未找到 OpenSSH Server /etc/ssh/sshd_config。'
    if unit_present ssh.service; then SSH_SERVICE=ssh.service
    elif unit_present sshd.service; then SSH_SERVICE=sshd.service
    else fail '没有找到 SSH 服务单元。'; fi
    CURRENT_PORT=''
    [[ -z "${SSH_CONNECTION:-}" ]] || CURRENT_PORT=$(awk '{print $4}' <<< "$SSH_CONNECTION")
    if ! valid_port "$CURRENT_PORT"; then
        CURRENT_PORT=$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port"{print $2;exit}' || true)
    fi
    ROOT_FREE=$(df -Pm / | awk 'NR==2{print $4}')
    [[ "$ROOT_FREE" =~ ^[0-9]+$ ]] && (( ROOT_FREE >= 512 )) || fail '根分区剩余空间不足 512MiB。'
    if command -v ip >/dev/null && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then GLOBAL_IPV6=1; fi
    check_apt_busy
    say "系统：$OS_NAME；SSH 服务：$SSH_SERVICE；内部端口：${CURRENT_PORT:-未知}；剩余磁盘：${ROOT_FREE}MiB。"
}

choose_options() {
    say '1. 选择时区（默认：America/Los_Angeles）'
    printf '%s\n' '  1) America/Los_Angeles  2) Asia/Shanghai  3) Asia/Hong_Kong' \
        '  4) Asia/Tokyo          5) Asia/Singapore 6) Europe/London 7) UTC'
    local ans port info
    IFS= read -r -p '时区 [1-7，默认1]: ' ans || fail '读取输入失败。'
    case "${ans:-1}" in 1) TIMEZONE=America/Los_Angeles;; 2) TIMEZONE=Asia/Shanghai;;
        3) TIMEZONE=Asia/Hong_Kong;; 4) TIMEZONE=Asia/Tokyo;; 5) TIMEZONE=Asia/Singapore;;
        6) TIMEZONE=Europe/London;; 7) TIMEZONE=UTC;; *) fail '时区选项无效。';; esac

    say '2. SSH 端口：1) 保持内部端口（推荐） 2) 修改内部端口 3) NAT 映射（公网与内部不同）'
    IFS= read -r -p '选择 [1-3，默认1]: ' ans || fail '读取输入失败。'
    case "${ans:-1}" in
        1) SSH_PORT_MODE=keep; SSH_INTERNAL_PORT=$CURRENT_PORT; SSH_EXTERNAL_PORT=$CURRENT_PORT ;;
        2)
            SSH_PORT_MODE=change
            while :; do
                IFS= read -r -p '新的内部 SSH 端口 [22222]: ' port || fail '读取输入失败。'
                port=${port:-22222}
                valid_port "$port" || { warn '端口超出 1-65535。'; continue; }
                [[ "$port" != 443 && "$port" != 19175 ]] || { warn '443/19175 预留给 sing-box。'; continue; }
                info=$(ss -H -ltnp "sport = :$port" 2>/dev/null || true)
                if [[ -n "$info" && "$port" != "$CURRENT_PORT" ]]; then warn "端口被占用：$info"; continue; fi
                break
            done
            SSH_INTERNAL_PORT=$port; SSH_EXTERNAL_PORT=$port ;;
        3)
            SSH_PORT_MODE=nat; SSH_INTERNAL_PORT=$CURRENT_PORT
            while :; do
                IFS= read -r -p '厂商 NAT 公网 SSH 端口: ' port || fail '读取输入失败。'
                valid_port "$port" && break
                warn '端口超出 1-65535。'
            done
            SSH_EXTERNAL_PORT=$port ;;
        *) fail 'SSH 端口策略无效。';;
    esac
    valid_port "$SSH_INTERNAL_PORT" || fail '无法确定 VPS 内部 SSH 端口，请从 SSH 终端重新执行。'

    say '3. root 认证：1) 密码（默认） 2) 公钥'
    IFS= read -r -p '选择 [1-2，默认1]: ' ans || fail '读取输入失败。'
    case "${ans:-1}" in 1) AUTH_MODE=password;; 2) AUTH_MODE=publickey;; *) fail '认证模式无效。';; esac
    if [[ "$AUTH_MODE" == publickey ]]; then
        [[ ! -L /root/.ssh && ! -L "$KEYS" ]] || fail 'root SSH 路径是符号链接，请检查厂商动态管理方式。'
        [[ ! -e "$KEYS" || -f "$KEYS" ]] || fail 'authorized_keys 不是普通文件。'
        while :; do
            IFS= read -r -p '粘贴完整 SSH 公钥: ' SSH_PUBLIC_KEY || fail '读取输入失败。'
            [[ "$SSH_PUBLIC_KEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]] || { warn '公钥格式不正确。'; continue; }
            local keytmp; keytmp=$(mktemp)
            printf '%s\n' "$SSH_PUBLIC_KEY" > "$keytmp"
            KEY_FP=$(ssh-keygen -lf "$keytmp" 2>/dev/null | awk '{print $2}' || true)
            rm -f "$keytmp"
            [[ -n "$KEY_FP" ]] && break
            warn 'ssh-keygen 校验失败。'
        done
        ok "公钥指纹：$KEY_FP"
    fi

    say '4. 是否执行完整 apt-get upgrade（默认是）'
    if ask_yes '执行完整升级？'; then FULL_UPGRADE=1; else FULL_UPGRADE=0; fi
    printf '\n--- 确认操作 ---\n系统时区: %s\nSSH: 内部 %s / 公网 %s / 策略 %s\n认证: %s\n完整升级: %s\n' \
        "$TIMEZONE" "$SSH_INTERNAL_PORT" "$SSH_EXTERNAL_PORT" "$SSH_PORT_MODE" "$AUTH_MODE" "$FULL_UPGRADE"
    printf '%s\n' '最终 UFW 规则：内部 SSH/tcp (limit)、443/tcp、19175/tcp、19175/udp。'
    warn 'UFW 会清空此前的 UFW 入站规则。网站、面板及其他自定义端口可能因此不可访问。'
    warn 'SSH 修改及防火墙规则收紧前必须从第二终端测试登录；root 密码变更无法回滚。'
    if [[ "$SSH_PORT_MODE" == nat ]]; then
        warn "请确认厂商 NAT 映射仍为：公网 ${SSH_EXTERNAL_PORT} -> 内部 ${SSH_INTERNAL_PORT}。"
    fi
    ask_exact '输入 APPLY 才开始修改' APPLY || fail '用户取消。'
}

snapshot() {
    STAGE='备份'; mkdir -p "$BACKUP_ROOT"
    BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/$(date +%Y%m%d_%H%M%S)_XXXXXX")
    backup_file "$SSH_CONFIG" sshd_config
    backup_file "$SSH_MANAGED" sshd_config.vps-hardening.conf
    backup_file "$SSH_LEGACY" 00-vps-hardening.conf
    backup_file "$SSH_BANNER" banner.vps-hardening
    [[ ! -d /etc/ufw ]] || cp -a /etc/ufw "$BACKUP_DIR/ufw"
    backup_file "$UFW_DEFAULTS" default-ufw
    backup_file "$F2B_CONFIG" 99-vps-hardening.local
    backup_file "$APT_CONFIG" 99-vps-hardening-periodic
    [[ "$AUTH_MODE" != publickey ]] || backup_file "$KEYS" root-authorized_keys
    local oldtz
    oldtz=$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)
    : > "$BACKUP_DIR/manifest.env"
    manifest BACKUP_FORMAT_VERSION 2
    manifest SCRIPT_VERSION "$VERSION"
    manifest BACKUP_CREATED "$(date -Is)"
    manifest OS_VERSION_ID "$OS_VERSION"
    manifest TIMEZONE_OLD "$oldtz"
    manifest TIMEZONE_NEW "$TIMEZONE"
    manifest SSH_PORT_OLD "$CURRENT_PORT"
    manifest SSH_PORT_NEW "$SSH_INTERNAL_PORT"
    manifest SSH_PORT_MODE_NEW "$SSH_PORT_MODE"
    manifest SSH_INTERNAL_PORT_NEW "$SSH_INTERNAL_PORT"
    manifest SSH_EXTERNAL_PORT_NEW "$SSH_EXTERNAL_PORT"
    manifest AUTH_MODE_NEW "$AUTH_MODE"
    manifest SSH_SERVICE_UNIT_OLD "$SSH_SERVICE"
    manifest SSH_SOCKET_UNIT_OLD ssh.socket
    manifest SSH_SERVICE_WAS_ACTIVE "$(unit_active_flag "$SSH_SERVICE")"
    manifest SSH_SERVICE_WAS_ENABLED_STATE "$(unit_state "$SSH_SERVICE")"
    manifest SSH_SOCKET_WAS_ACTIVE "$(unit_active_flag ssh.socket)"
    manifest SSH_SOCKET_WAS_ENABLED_STATE "$(unit_state ssh.socket)"
    local f var name
    for var in SSH_CONFIG SSH_MANAGED SSH_LEGACY SSH_BANNER; do
        f=${!var}
        case "$var" in SSH_CONFIG) name=SSH_CONFIG_EXISTED;; SSH_MANAGED) name=SSH_MANAGED_CONFIG_EXISTED;; SSH_LEGACY) name=SSH_LEGACY_MANAGED_CONFIG_EXISTED;; SSH_BANNER) name=SSH_BANNER_EXISTED;; esac
        manifest "$name" "$([[ -e "$f" ]] && echo 1 || echo 0)"
    done
    manifest ROOT_AUTH_KEYS_TRACKED "$([[ "$AUTH_MODE" == publickey ]] && echo 1 || echo 0)"
    manifest ROOT_AUTH_KEYS_EXISTED "$([[ -e "$KEYS" ]] && echo 1 || echo 0)"
    manifest ROOT_SSH_DIR_EXISTED "$([[ -d /root/.ssh ]] && echo 1 || echo 0)"
    manifest ROOT_SSH_DIR_MODE "$(stat -c %a /root/.ssh 2>/dev/null || true)"
    manifest ROOT_SSH_DIR_UID "$(stat -c %u /root/.ssh 2>/dev/null || true)"
    manifest ROOT_SSH_DIR_GID "$(stat -c %g /root/.ssh 2>/dev/null || true)"
    manifest UFW_DIR_EXISTED "$([[ -d /etc/ufw ]] && echo 1 || echo 0)"
    manifest UFW_DEFAULTS_EXISTED "$([[ -e "$UFW_DEFAULTS" ]] && echo 1 || echo 0)"
    manifest UFW_WAS_INSTALLED "$(installed_flag ufw)"
    manifest UFW_WAS_ACTIVE "$(LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active' && echo 1 || echo 0)"
    manifest FAIL2BAN_WAS_INSTALLED "$(installed_flag fail2ban)"
    manifest FAIL2BAN_WAS_ACTIVE "$(unit_active_flag fail2ban.service)"
    manifest FAIL2BAN_WAS_ENABLED_STATE "$(unit_state fail2ban.service)"
    manifest FAIL2BAN_CONFIG_EXISTED "$([[ -e "$F2B_CONFIG" ]] && echo 1 || echo 0)"
    manifest UNATTENDED_WAS_INSTALLED "$(installed_flag unattended-upgrades)"
    manifest AUTO_UPGRADES_CONFIG_EXISTED "$([[ -e "$APT_CONFIG" ]] && echo 1 || echo 0)"
    manifest APT_DAILY_TIMER_ACTIVE "$(unit_active_flag apt-daily.timer)"
    manifest APT_DAILY_TIMER_ENABLED_STATE "$(unit_state apt-daily.timer)"
    manifest APT_UPGRADE_TIMER_ACTIVE "$(unit_active_flag apt-daily-upgrade.timer)"
    manifest APT_UPGRADE_TIMER_ENABLED_STATE "$(unit_state apt-daily-upgrade.timer)"
    for f in "${APT_UNITS[@]}"; do manifest "APT_UNIT_STATE_${f//[-.]/_}" "$(unit_state "$f")"; done
    manifest CHRONY_WAS_INSTALLED "$(installed_flag chrony)"
    for f in chrony.service systemd-timesyncd.service ntpsec.service ntp.service; do
        local prefix
        case "$f" in chrony.service) prefix=CHRONY;; systemd-timesyncd.service) prefix=TIMESYNCD;; ntpsec.service) prefix=NTPSEC;; ntp.service) prefix=NTP;; esac
        manifest "${prefix}_WAS_ACTIVE" "$(unit_active_flag "$f")"
        manifest "${prefix}_WAS_ENABLED_STATE" "$(unit_state "$f")"
    done
    manifest HAS_GLOBAL_IPV6 "$GLOBAL_IPV6"
    manifest FULL_UPGRADE "$FULL_UPGRADE"
    manifest SSH_PUBLIC_KEY_FINGERPRINT "$KEY_FP"
    checkpoint 0
    ok "已备份：$BACKUP_DIR"
}

checkpoint() { [[ -z "$BACKUP_DIR" ]] || printf '%s\n' "$1" > "$BACKUP_DIR/completed.stage"; }

packages() {
    STAGE='APT 安装'; say '[1/8] 更新索引、升级（可选）并安装组件'
    export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none
    apt-get update
    if (( FULL_UPGRADE == 1 )); then
        apt-get upgrade -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'
    fi
    apt-get install -y ca-certificates curl iproute2 ufw fail2ban python3-systemd unattended-upgrades apt-listchanges
    ensure_ufw_runtime
    checkpoint 1
}

ensure_ufw_runtime() {
    local needed=0 repaired=0 f template mode missing=0
    command -v ufw >/dev/null || fail 'UFW 安装异常。'
    mkdir -p /etc/ufw
    if [[ ! -f /etc/default/ufw || ! -f /etc/ufw/sysctl.conf ]]; then
        warn 'UFW 基础配置缺失，尝试恢复缺失的 Debian conffiles。'
        apt-get install --reinstall -y -o Dpkg::Options::='--force-confmiss' ufw
    fi
    for f in ufw.conf user.rules user6.rules before.rules before6.rules after.rules after6.rules; do
        [[ ! -f "/etc/ufw/$f" ]] || continue
        template="/usr/share/ufw/$f"
        [[ -f "$template" ]] || { warn "UFW 模板缺失：$template"; missing=1; continue; }
        case "$f" in ufw.conf) mode=0644;; *) mode=0640;; esac
        install -m "$mode" "$template" "/etc/ufw/$f"
        repaired=1
    done
    for f in /etc/default/ufw /etc/ufw/sysctl.conf /etc/ufw/{ufw.conf,user.rules,user6.rules,before.rules,before6.rules,after.rules,after6.rules}; do
        [[ -f "$f" ]] || { warn "仍缺文件：$f"; missing=1; }
    done
    (( missing == 0 )) || fail 'UFW 缺少必需文件；未修改防火墙规则。'
    if ! LC_ALL=C ufw status >/dev/null 2>&1; then
        warn 'UFW 首次状态检查失败，尝试通过重新安装软件包恢复（保留原配置）。'
        apt-get install --reinstall -y -o Dpkg::Options::='--force-confmiss' ufw
        LC_ALL=C ufw status || { dpkg -V ufw || true; fail 'UFW 仍无法正常运行。'; }
    fi
    (( repaired == 0 )) || ok 'UFW 缺失规则文件已修复。'
}

time_sync() {
    STAGE='时区和时间同步'; say '[2/8] 配置时区、时间同步'
    timedatectl set-timezone "$TIMEZONE"
    local f
    for f in chrony.service systemd-timesyncd.service ntpsec.service ntp.service; do
        if unit_active "$f"; then TIME_SERVICE=$f; checkpoint 2; return; fi
    done
    if unit_present systemd-timesyncd.service; then
        systemctl enable --now systemd-timesyncd.service
        TIME_SERVICE=systemd-timesyncd.service
    else
        apt-get install -y chrony
        systemctl enable --now chrony.service
        TIME_SERVICE=chrony.service
    fi
    checkpoint 2
}

install_auth() {
    if [[ "$AUTH_MODE" == password ]]; then
        STAGE='重设 root 密码'; say '直接调用 passwd root；密码不会由脚本保存。'
        passwd root || fail 'passwd root 失败。'
        [[ "$(passwd -S root | awk '{print $2}')" == P ]] || fail 'root 密码状态不是 P。'
    else
        STAGE='写入 root 公钥'; mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        touch "$KEYS"; chmod 600 "$KEYS"; chown root:root /root/.ssh "$KEYS"
        if [[ -n "$KEY_FP" ]] && ssh-keygen -lf "$KEYS" 2>/dev/null | awk '{print $2}' | grep -Fqx "$KEY_FP"; then
            ok '相同指纹公钥已存在。'
        else
            [[ ! -s "$KEYS" ]] || { [[ "$(tail -c1 "$KEYS" | od -An -tx1 | tr -d '[:space:]')" == 0a ]] || printf '\n' >> "$KEYS"; }
            printf '%s\n' "$SSH_PUBLIC_KEY" >> "$KEYS"
        fi
    fi
}

new_ssh_config() {
    STAGE='SSH 配置'; say '[3/8] SSH 变更准备及临时防火墙放行'
    if LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active' && [[ "$SSH_INTERNAL_PORT" != "$CURRENT_PORT" ]]; then
        ufw allow "${SSH_INTERNAL_PORT}/tcp" comment 'TEMP vps-hardening SSH migration'
    fi
    say '[4/8] 事务式写入 OpenSSH 配置'
    cat > "$SSH_MANAGED" <<EOF
# Managed by VPS Security Hardening ${VERSION}
Port ${SSH_INTERNAL_PORT}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
HostbasedAuthentication no
UsePAM yes
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
Banner ${SSH_BANNER}
EOF
    if [[ "$AUTH_MODE" == password ]]; then
        cat >> "$SSH_MANAGED" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
AuthenticationMethods any
EOF
    else
        cat >> "$SSH_MANAGED" <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
EOF
    fi
    cat > "$SSH_BANNER" <<'EOF'
*******************************************************************
*  WARNING: Unauthorized access to this system is prohibited.     *
*  All connections may be monitored and recorded.                 *
*******************************************************************
EOF
    # Put the managed include at the top: OpenSSH first-value-wins semantics.
    sed -i '\|^[[:space:]]*Include[[:space:]]\+/etc/ssh/sshd_config\.vps-hardening\.conf[[:space:]]*$|d' "$SSH_CONFIG"
    sed -i '\|^[[:space:]]*Include[[:space:]]\+/etc/ssh/sshd_config\.d/00-vps-hardening\.conf[[:space:]]*$|d' "$SSH_CONFIG"
    rm -f "$SSH_LEGACY"
    sed -i "1iInclude ${SSH_MANAGED}" "$SSH_CONFIG"

    /usr/sbin/sshd -t || fail 'sshd -t 未通过；将回滚。'
    local effective
    effective=$(/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1)
    grep -qFx "port $SSH_INTERNAL_PORT" <<< "$effective" || fail 'sshd 有效端口与预期不一致。'
    if [[ "$AUTH_MODE" == password ]]; then
        grep -qFx 'permitrootlogin yes' <<< "$effective" || fail '未正确开启 root 登录。'
        grep -qFx 'passwordauthentication yes' <<< "$effective" || fail '未正确开启 SSH 密码登录。'
        grep -qFx 'authenticationmethods any' <<< "$effective" || fail 'SSH 认证方式受其他配置限制。'
    else
        grep -qFx 'passwordauthentication no' <<< "$effective" || fail '公钥模式未关闭 SSH 密码认证。'
        grep -qFx 'pubkeyauthentication yes' <<< "$effective" || fail '未允许 SSH 公钥认证。'
        grep -qFx 'authenticationmethods publickey' <<< "$effective" || fail '未要求 SSH 公钥认证。'
    fi
    if unit_present ssh.socket && { unit_active ssh.socket || [[ "$(unit_state ssh.socket)" == enabled ]]; }; then
        warn '检测到 ssh.socket；切换到 ssh.service 监听，以保证 sshd_config 端口生效。'
        systemctl disable --now ssh.socket
    fi
    systemctl enable "$SSH_SERVICE" || fail "无法将 $SSH_SERVICE 设置为开机启动。"
    systemctl restart "$SSH_SERVICE"
    unit_active "$SSH_SERVICE" || fail 'SSH 服务未启动。'
    [[ -n "$(ss -H -ltn "sport = :${SSH_INTERNAL_PORT}")" ]] || fail 'SSH 目标端口没有监听。'
}

verify_ssh() {
    STAGE='第二终端 SSH 验证'
    printf '\n==== 必须在另一终端实际登录成功 ====\n'
    if [[ "$AUTH_MODE" == password ]]; then
        printf 'ssh -p %s root@<公网IP>\n' "$SSH_EXTERNAL_PORT"
    else
        printf 'ssh -i <私钥> -p %s root@<公网IP>\n' "$SSH_EXTERNAL_PORT"
    fi
    if [[ "$SSH_PORT_MODE" == nat ]]; then
        printf 'NAT: 公网 %s/tcp -> 内部 %s/tcp\n' "$SSH_EXTERNAL_PORT" "$SSH_INTERNAL_PORT"
    fi
    printf '请保持本窗口连接。只有第二终端真实登录成功才能输入 VERIFIED。\n'
    local reply
    while :; do
        IFS= read -r -p '输入 VERIFIED / STATUS / ROLLBACK: ' reply || fail '无法读取验证结果。'
        case "${reply^^}" in
            VERIFIED) VERIFIED=1; TRANSACTION=0; checkpoint 4; ok 'SSH 已由管理员确认第二终端登录成功。'; return;;
            STATUS) systemctl status "$SSH_SERVICE" --no-pager -l || true; ss -H -ltnp "sport = :${SSH_INTERNAL_PORT}" || true;;
            ROLLBACK) restore_ssh_ufw_best_effort; fail '已回滚 SSH/UFW。';;
            *) warn '请先在另一个终端实测登录成功。不能直接回车跳过。';;
        esac
    done
}

ufw_fail_safe() {
    warn '最终 UFW 配置失败。为了防止 SSH 失联，将尝试禁用 UFW。'
    ufw --force disable || true
    fail 'UFW 配置失败，请保持现有 SSH 会话。'
}

final_ufw() {
    STAGE='UFW 最终规则'; say '[5/8] 配置最终 UFW 规则'
    ensure_ufw_runtime
    if (( GLOBAL_IPV6 == 1 )); then
        if grep -q '^IPV6=' "$UFW_DEFAULTS"; then sed -i 's/^IPV6=.*/IPV6=yes/' "$UFW_DEFAULTS"
        else printf '\nIPV6=yes\n' >> "$UFW_DEFAULTS"; fi
    fi
    ufw --force reset || ufw_fail_safe
    ufw default deny incoming || ufw_fail_safe
    ufw default allow outgoing || ufw_fail_safe
    ufw limit "${SSH_INTERNAL_PORT}/tcp" comment 'SSH root management' || ufw_fail_safe
    ufw allow 443/tcp comment 'sing-box VLESS' || ufw_fail_safe
    ufw allow 19175/tcp comment 'sing-box Shadowsocks TCP' || ufw_fail_safe
    ufw allow 19175/udp comment 'sing-box Shadowsocks UDP' || ufw_fail_safe
    ufw --force enable || ufw_fail_safe
    LC_ALL=C ufw status | grep -q '^Status: active' || ufw_fail_safe
    if (( GLOBAL_IPV6 == 1 )); then
        LC_ALL=C ufw status | grep -q '(v6)' || ufw_fail_safe
    fi
    checkpoint 5
}

fail2ban_setup() {
    STAGE='Fail2ban'; say '[6/8] 配置 Fail2ban sshd jail'
    mkdir -p /etc/fail2ban/jail.d
    cat > "$F2B_CONFIG" <<EOF
# Managed by VPS Security Hardening ${VERSION}
[sshd]
enabled = true
backend = systemd
port = ${SSH_INTERNAL_PORT}
filter = sshd
banaction = ufw
findtime = 10m
maxretry = 3
bantime = 24h
EOF
    fail2ban-client -t || fail 'Fail2ban 配置测试失败。'
    systemctl enable fail2ban.service
    systemctl restart fail2ban.service
    local i
    for ((i=0;i<25;i++)); do
        if unit_active fail2ban.service && fail2ban-client ping >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1; then
            checkpoint 6; ok 'Fail2ban sshd jail 正常。'; return
        fi
        sleep 1
    done
    systemctl status fail2ban.service -l --no-pager || true
    journalctl -u fail2ban.service -n 50 --no-pager || true
    fail 'Fail2ban sshd jail 没有在 25 秒内正常启动。'
}

apt_diagnostics() {
    local f
    warn 'APT systemd 单元诊断：'
    for f in "${APT_UNITS[@]}"; do
        printf '%-28s LoadState=%-12s UnitFileState=%s\n' "$f" "$(unit_load "$f")" "$(unit_state "$f")" >&2
        systemctl show "$f" -p FragmentPath -p LoadError --no-pager >&2 || true
    done
    journalctl -b -u apt-daily.service -u apt-daily-upgrade.service -u apt-daily.timer -u apt-daily-upgrade.timer -n 50 --no-pager >&2 || true
}

apt_unmask_units_if_approved() {
    local -a masked=()
    local f state load
    for f in "${APT_UNITS[@]}"; do
        state=$(unit_state "$f"); load=$(unit_load "$f")
        if [[ "$state" == masked || "$state" == masked-runtime || "$load" == masked ]]; then masked+=("$f"); fi
    done
    if (( ${#masked[@]} > 0 )); then
        warn "检测到厂商镜像屏蔽了 APT 单元：${masked[*]}"
        warn '解除屏蔽可能改变厂商预设的更新策略。仅会修改 APT 单元状态，不直接执行升级。'
        ask_yes '是否解除以上单元的屏蔽，允许自动更新？' || fail '用户拒绝解除 APT 单元屏蔽；APT 阶段未完成。可之后使用 --repair-apt-timers。'
        systemctl unmask "${masked[@]}" || fail '解除 APT 单元屏蔽失败。'
        systemctl daemon-reload
    fi
}

apt_setup() {
    STAGE='自动安全更新'; say '[7/8] 配置 APT 自动安全更新'
    if [[ "$(installed_flag apt)" != 1 || "$(installed_flag unattended-upgrades)" != 1 ]]; then
        fail 'apt 或 unattended-upgrades 未安装。请先安装软件包。'
    fi
    apt_unmask_units_if_approved
    local f
    for f in "${APT_UNITS[@]}"; do
        case "$(unit_load "$f")" in
            loaded) : ;;
            *) apt_diagnostics; fail "APT 单元 $f 未加载。请先检查是否缺失 APT 软件包文件。";;
        esac
    done
    mkdir -p /etc/apt/apt.conf.d
    cat > "$APT_CONFIG" <<'EOF'
// Managed by VPS Security Hardening.
// Upgrade origins are defined by Debian's 50unattended-upgrades; no dist-upgrade here.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
// Avoid surprise reboots on headless VPS nodes.
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    for f in apt-daily.timer apt-daily-upgrade.timer; do
        if ! systemctl enable --now "$f"; then
            systemctl status "$f" --no-pager -l || true
            apt_diagnostics
            fail "无法启动 $f。"
        fi
        if ! unit_active "$f"; then apt_diagnostics; fail "$f 没有进入 active 状态。"; fi
        [[ "$(unit_state "$f")" == enabled ]] || warn "$f 未显示 enabled，请检查系统默认设置。"
    done
    local settings
    settings=$(apt-config dump)
    grep -Eq '^APT::Periodic::Update-Package-Lists "1";' <<< "$settings" || fail 'APT 自动更新索引设置不正确。'
    grep -Eq '^APT::Periodic::Unattended-Upgrade "1";' <<< "$settings" || fail 'APT 自动安全更新设置不正确。'
    checkpoint 7
    ok 'APT 两个 timer 已启用（执行结果需在首次计划任务后检查）。'
}

checkitem() {
    local label=$1; shift
    if "$@"; then printf '[OK] %s\n' "$label"; else printf '[FAIL] %s\n' "$label"; ERRORS=$((ERRORS+1)); fi
}
check_ssh_port() { [[ -n "$(ss -H -ltn "sport = :${SSH_INTERNAL_PORT}" 2>/dev/null)" ]]; }
check_ufw_port() { local text=$1 port=$2; grep -Eq "(^|[[:space:]])${port}[[:space:]]" <<< "$text"; }
check_fp() { ssh-keygen -lf "$KEYS" 2>/dev/null | awk '{print $2}' | grep -Fqx "$KEY_FP"; }
final_check() {
    STAGE='健康检查'; say '[8/8] 健康检查'
    ERRORS=0
    local effective status opts
    effective=$(/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1)
    status=$(LC_ALL=C ufw status)
    checkitem 'sshd -t' /usr/sbin/sshd -t
    checkitem 'SSH service active' unit_active "$SSH_SERVICE"
    checkitem "SSH 内部 $SSH_INTERNAL_PORT 端口监听" check_ssh_port
    checkitem 'SSH 实际端口设置' grep -qFx "port ${SSH_INTERNAL_PORT}" <<< "$effective"
    if [[ "$AUTH_MODE" == password ]]; then
        checkitem 'root 密码状态' test "$(passwd -S root | awk '{print $2}')" = P
        checkitem 'SSH root 密码登录允许' grep -qFx 'permitrootlogin yes' <<< "$effective"
        checkitem 'SSH PasswordAuthentication yes' grep -qFx 'passwordauthentication yes' <<< "$effective"
    else
        checkitem 'authorized_keys 非空' test -s "$KEYS"
        [[ -z "$KEY_FP" ]] || checkitem '公钥指纹已写入' check_fp
        checkitem 'SSH PasswordAuthentication no' grep -qFx 'passwordauthentication no' <<< "$effective"
        checkitem 'SSH PubkeyAuthentication yes' grep -qFx 'pubkeyauthentication yes' <<< "$effective"
    fi
    checkitem 'UFW active' grep -q '^Status: active' <<< "$status"
    for opts in "${SSH_INTERNAL_PORT}/tcp" 443/tcp 19175/tcp 19175/udp; do
        checkitem "UFW 允许 $opts" check_ufw_port "$status" "$opts"
    done
    if (( GLOBAL_IPV6 == 1 )); then checkitem 'UFW IPv6 规则' grep -q '(v6)' <<< "$status"; fi
    checkitem 'Fail2ban active' unit_active fail2ban.service
    checkitem 'Fail2ban sshd jail' fail2ban-client status sshd
    for opts in apt-daily.timer apt-daily-upgrade.timer; do
        checkitem "$opts active" unit_active "$opts"
        checkitem "$opts enabled" test "$(unit_state "$opts")" = enabled
    done
    if [[ -n "$TIME_SERVICE" ]]; then checkitem "时间同步服务 $TIME_SERVICE" unit_active "$TIME_SERVICE"; fi
    if [[ -f /var/run/reboot-required ]]; then warn '检测到 reboot-required，确认业务后安排重启。'; fi
    (( ERRORS == 0 )) || fail "共有 ${ERRORS} 项健康检查不通过，请勿关闭当前 SSH 会话。"
    checkpoint 8
    ok '关键安全检查全部通过。'
}

summary() {
    printf '\n========== VPS Security Hardening %s ==========\n' "$VERSION"
    printf 'Debian：%s\nSSH 内部端口：%s\nSSH 公网端口：%s\n认证模式：%s\n' "$OS_NAME" "$SSH_INTERNAL_PORT" "$SSH_EXTERNAL_PORT" "$AUTH_MODE"
    printf 'UFW 允许：%s/tcp、443/tcp、19175/tcp、19175/udp\n' "$SSH_INTERNAL_PORT"
    printf 'Fail2ban：sshd jail active\nAPT timers：active + enabled\n备份目录：%s\n' "$BACKUP_DIR"
    warn '请保留当前 SSH 会话，确认第二终端登录和 sing-box 等业务运行正常。'
    warn 'rollback.sh 可回滚配置，不会恢复原 root 密码和已升级软件包。'
}

repair_apt_only() {
    STAGE='APT 专项修复'; check_debian; require_tty
    warn '专项模式仅修改 /etc/apt/apt.conf.d/99-vps-hardening-periodic 及四个 APT systemd 单元状态。'
    local original_copy=''
    if [[ -e "$APT_CONFIG" ]]; then
        original_copy="${APT_CONFIG}.backup-$(date +%Y%m%d_%H%M%S)"
        cp -a "$APT_CONFIG" "$original_copy"
        ok "已备份现有 APT 配置至：$original_copy"
    fi
    check_apt_busy
    apt_setup
    systemctl list-timers --all apt-daily.timer apt-daily-upgrade.timer
    ok '专项修复完成；SSH、UFW、Fail2ban 均未修改。'
}

readonly_health() {
    check_debian
    printf '系统: %s\n' "$OS_NAME"
    for x in ssh.service sshd.service ssh.socket ufw.service fail2ban.service "${APT_UNITS[@]}"; do
        printf '%-28s %-12s %-18s %s\n' "$x" "$(unit_load "$x")" "$(unit_state "$x")" "$(systemctl is-active "$x" 2>/dev/null || true)"
    done
    printf '\nUFW：\n'; if command -v ufw >/dev/null; then ufw status verbose || true; fi
    printf '\nFail2ban：\n'; if command -v fail2ban-client >/dev/null; then fail2ban-client status sshd || true; fi
    printf '\nAPT timers：\n'; systemctl list-timers --all apt-daily.timer apt-daily-upgrade.timer || true
}

resume() {
    STAGE='恢复安全检查点'; check_debian; require_tty
    [[ -d "$BACKUP_ROOT" ]] || fail '没有备份记录，不能恢复。'
    local dir saved_stage
    while IFS= read -r dir; do
        [[ -f "$dir/completed.stage" ]] || continue
        saved_stage=$(cat "$dir/completed.stage")
        if [[ "$saved_stage" =~ ^[0-9]+$ ]] && (( saved_stage >= 5 && saved_stage < 8 )); then
            BACKUP_DIR=$dir; break
        fi
    done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print | sort -r)
    [[ -n "$BACKUP_DIR" ]] || fail '没有第 5 步之后未完成的安全检查点；拒绝自动重新修改 SSH/UFW。'
    [[ -f "$BACKUP_DIR/manifest.env" ]] || fail '备份清单缺失，不能继续。'
    # shellcheck disable=SC1090
    source "$BACKUP_DIR/manifest.env"
    [[ "${BACKUP_FORMAT_VERSION:-}" == 2 ]] || fail '备份格式不兼容。'
    SSH_INTERNAL_PORT=${SSH_INTERNAL_PORT_NEW:-}
    SSH_EXTERNAL_PORT=${SSH_EXTERNAL_PORT_NEW:-}
    SSH_PORT_MODE=${SSH_PORT_MODE_NEW:-keep}
    SSH_SERVICE=${SSH_SERVICE_UNIT_OLD:-ssh.service}
    AUTH_MODE=${AUTH_MODE_NEW:-password}
    TIMEZONE=${TIMEZONE_NEW:-UTC}
    FULL_UPGRADE=${FULL_UPGRADE:-0}
    KEY_FP=${SSH_PUBLIC_KEY_FINGERPRINT:-}
    GLOBAL_IPV6=${HAS_GLOBAL_IPV6:-0}
    valid_port "$SSH_INTERNAL_PORT" || fail '记录的内部 SSH 端口无效。'
    [[ -d "$BACKUP_DIR" && "$(stat -c %u "$BACKUP_DIR")" == 0 ]] || fail '备份目录权限/归属异常。'
    /usr/sbin/sshd -t || fail 'sshd 配置检查失败，拒绝自动恢复。'
    unit_active "$SSH_SERVICE" && check_ssh_port || fail 'SSH 服务或记录的内部端口不匹配，拒绝自动恢复。'
    local resume_ufw
    resume_ufw=$(LC_ALL=C ufw status) || fail '无法读取 UFW 状态。'
    grep -q '^Status: active' <<< "$resume_ufw" || fail 'UFW 已非 active，拒绝自动恢复。'
    check_ufw_port "$resume_ufw" "${SSH_INTERNAL_PORT}/tcp" || fail 'UFW 中的内部 SSH 端口规则缺失，拒绝自动恢复。' 
    printf '恢复目录：%s\n已完成步骤：%s/8\n' "$BACKUP_DIR" "$saved_stage"
    ask_exact '输入 RESUME 以确认只继续后续步骤' RESUME || fail '取消恢复。'
    if (( saved_stage < 6 )); then fail2ban_setup; fi
    if (( saved_stage < 7 )); then apt_setup; fi
    final_check; summary
}

main() {
    require_root
    case "${1:-}" in
        --help|-h) usage;;
        --version|-V) printf '%s\n' "$VERSION";;
        --repair-apt-timers) repair_apt_only;;
        --resume) resume;;
        --check) readonly_health;;
        '')
            require_tty; preflight; choose_options; snapshot
            packages; time_sync
            TRANSACTION=1; install_auth; new_ssh_config; verify_ssh
            final_ufw; fail2ban_setup; apt_setup; final_check; summary
            ;;
        *) usage; fail "未知参数：$1";;
    esac
}
main "$@"

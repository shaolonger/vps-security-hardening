#!/usr/bin/env bash
set -Eeuo pipefail

# VPS Security Hardening v2
# Target: Debian 12 / 13
# Authentication model: selectable root + password (default) or root + SSH public key

readonly HARDENING_VERSION="2.1.1"
readonly SCRIPT_NAME="VPS Security Hardening"
readonly BACKUP_ROOT="/root/vps-hardening-backups"
readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly SSH_MANAGED_CONFIG="/etc/ssh/sshd_config.d/00-vps-hardening.conf"
readonly SSH_BANNER="/etc/ssh/banner.vps-hardening"
readonly UFW_DEFAULTS="/etc/default/ufw"
readonly FAIL2BAN_CONFIG="/etc/fail2ban/jail.d/99-vps-hardening.local"
readonly AUTO_UPGRADES_CONFIG="/etc/apt/apt.conf.d/99-vps-hardening-periodic"
readonly ROOT_SSH_DIR="/root/.ssh"
readonly ROOT_AUTH_KEYS="/root/.ssh/authorized_keys"

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

CURRENT_STAGE="初始化"
BACKUP_DIR=""
SSH_TRANSACTION_ACTIVE=0
TEMP_UFW_CHANGED=0
ERROR_HANDLER_RUNNING=0
SSH_SERVICE_UNIT=""
SSH_SOCKET_UNIT="ssh.socket"
CURRENT_SSH_PORT=""
HAS_GLOBAL_IPV6=0
FULL_UPGRADE=1
TIME_SYNC_SELECTED=""
AUTH_MODE="password"
SSH_PUBLIC_KEY=""
SSH_PUBLIC_KEY_FINGERPRINT=""

log()  { printf '%b\n' "${CYAN}$*${RESET}"; }
ok()   { printf '%b\n' "${GREEN}$*${RESET}"; }
warn() { printf '%b\n' "${YELLOW}$*${RESET}"; }
err()  { printf '%b\n' "${RED}$*${RESET}" >&2; }

unit_exists() {
    systemctl cat "$1" >/dev/null 2>&1
}

unit_active_flag() {
    systemctl is-active --quiet "$1" 2>/dev/null && printf '1' || printf '0'
}

unit_enabled_state() {
    systemctl is-enabled "$1" 2>/dev/null || true
}

pkg_installed_flag() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed' && printf '1' || printf '0'
}

manifest_set() {
    local key=$1 value=${2-}
    printf '%s=%q\n' "$key" "$value" >> "$BACKUP_DIR/manifest.env"
}

restore_file_from_backup() {
    local existed=$1 backup_path=$2 target_path=$3
    if [[ "$existed" == "1" && -e "$backup_path" ]]; then
        mkdir -p "$(dirname "$target_path")"
        cp -a "$backup_path" "$target_path"
    else
        rm -f "$target_path"
    fi
}

restore_ufw_snapshot_best_effort() {
    [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/manifest.env" ]] || return 0
    # shellcheck disable=SC1090
    . "$BACKUP_DIR/manifest.env"

    if [[ "${UFW_DIR_EXISTED:-0}" == "1" && -d "$BACKUP_DIR/ufw" ]]; then
        rm -rf /etc/ufw
        cp -a "$BACKUP_DIR/ufw" /etc/ufw
    fi

    if [[ "${UFW_DEFAULTS_EXISTED:-0}" == "1" && -e "$BACKUP_DIR/default-ufw" ]]; then
        cp -a "$BACKUP_DIR/default-ufw" "$UFW_DEFAULTS"
    fi

    if command -v ufw >/dev/null 2>&1; then
        if [[ "${UFW_WAS_ACTIVE:-0}" == "1" ]]; then
            ufw --force enable >/dev/null 2>&1 || true
            ufw reload >/dev/null 2>&1 || true
        else
            ufw --force disable >/dev/null 2>&1 || true
        fi
    fi
}

restore_ssh_listener_mode_best_effort() {
    [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/manifest.env" ]] || return 0
    # shellcheck disable=SC1090
    . "$BACKUP_DIR/manifest.env"

    local service_unit=${SSH_SERVICE_UNIT_OLD:-ssh.service}
    local socket_unit=${SSH_SOCKET_UNIT_OLD:-ssh.socket}

    systemctl daemon-reload >/dev/null 2>&1 || true

    if unit_exists "$socket_unit"; then
        if [[ "${SSH_SOCKET_WAS_ENABLED_STATE:-}" == "enabled" || "${SSH_SOCKET_WAS_ENABLED_STATE:-}" == "enabled-runtime" ]]; then
            systemctl enable "$socket_unit" >/dev/null 2>&1 || true
        else
            systemctl disable "$socket_unit" >/dev/null 2>&1 || true
        fi
    fi

    if unit_exists "$service_unit"; then
        if [[ "${SSH_SERVICE_WAS_ENABLED_STATE:-}" == "enabled" || "${SSH_SERVICE_WAS_ENABLED_STATE:-}" == "enabled-runtime" ]]; then
            systemctl enable "$service_unit" >/dev/null 2>&1 || true
        else
            systemctl disable "$service_unit" >/dev/null 2>&1 || true
        fi
    fi

    # 优先恢复执行前实际工作的监听模式。
    if [[ "${SSH_SOCKET_WAS_ACTIVE:-0}" == "1" ]] && unit_exists "$socket_unit"; then
        systemctl stop "$service_unit" >/dev/null 2>&1 || true
        systemctl restart "$socket_unit" >/dev/null 2>&1 || systemctl start "$socket_unit" >/dev/null 2>&1 || true
    elif [[ "${SSH_SERVICE_WAS_ACTIVE:-0}" == "1" ]] && unit_exists "$service_unit"; then
        systemctl stop "$socket_unit" >/dev/null 2>&1 || true
        systemctl restart "$service_unit" >/dev/null 2>&1 || systemctl start "$service_unit" >/dev/null 2>&1 || true
    fi
}

rollback_ssh_transaction_best_effort() {
    [[ "$SSH_TRANSACTION_ACTIVE" == "1" ]] || return 0
    SSH_TRANSACTION_ACTIVE=0
    warn "SSH 迁移阶段失败，正在自动恢复执行前的 SSH/UFW 配置……"

    if [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/manifest.env" ]]; then
        # shellcheck disable=SC1090
        . "$BACKUP_DIR/manifest.env"

        restore_file_from_backup "${SSH_CONFIG_EXISTED:-0}" \
            "$BACKUP_DIR/sshd_config" "$SSH_CONFIG"
        restore_file_from_backup "${SSH_MANAGED_CONFIG_EXISTED:-0}" \
            "$BACKUP_DIR/00-vps-hardening.conf" "$SSH_MANAGED_CONFIG"
        restore_file_from_backup "${SSH_BANNER_EXISTED:-0}" \
            "$BACKUP_DIR/banner.vps-hardening" "$SSH_BANNER"
        if [[ "${ROOT_AUTH_KEYS_TRACKED:-0}" == "1" ]]; then
            restore_file_from_backup "${ROOT_AUTH_KEYS_EXISTED:-0}" \
                "$BACKUP_DIR/root-authorized_keys" "$ROOT_AUTH_KEYS"
            if [[ "${ROOT_SSH_DIR_EXISTED:-0}" == "1" ]]; then
                [[ -d "$ROOT_SSH_DIR" ]] || mkdir -p "$ROOT_SSH_DIR"
                [[ -n "${ROOT_SSH_DIR_MODE:-}" ]] && chmod "$ROOT_SSH_DIR_MODE" "$ROOT_SSH_DIR" 2>/dev/null || true
                if [[ -n "${ROOT_SSH_DIR_UID:-}" && -n "${ROOT_SSH_DIR_GID:-}" ]]; then
                    chown "${ROOT_SSH_DIR_UID}:${ROOT_SSH_DIR_GID}" "$ROOT_SSH_DIR" 2>/dev/null || true
                fi
            elif [[ -d "$ROOT_SSH_DIR" ]] && \
                 [[ -z "$(find "$ROOT_SSH_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
                rmdir "$ROOT_SSH_DIR" 2>/dev/null || true
            fi
        fi

        if [[ -x /usr/sbin/sshd ]] && /usr/sbin/sshd -t >/dev/null 2>&1; then
            restore_ssh_listener_mode_best_effort
        else
            err "自动恢复后的 SSH 配置未通过 sshd -t；请保持当前会话并使用备份目录人工检查：$BACKUP_DIR"
        fi
        restore_ufw_snapshot_best_effort
    fi

    if [[ "${AUTH_MODE:-password}" == "password" ]]; then
        warn "自动恢复已执行。root 密码无法回滚，仍是本次刚设置的新密码。"
    else
        warn "自动恢复已执行。root authorized_keys 已按备份恢复。"
    fi
}

die() {
    err "错误: $*"
    if [[ "$SSH_TRANSACTION_ACTIVE" == "1" && "$ERROR_HANDLER_RUNNING" == "0" ]]; then
        ERROR_HANDLER_RUNNING=1
        rollback_ssh_transaction_best_effort || true
        ERROR_HANDLER_RUNNING=0
    fi
    exit 1
}

on_error() {
    local exit_code=$?
    local line_no=${1:-unknown}
    trap - ERR
    err "脚本在阶段“${CURRENT_STAGE}”的第 ${line_no} 行执行失败，退出码: ${exit_code}"
    if [[ "$SSH_TRANSACTION_ACTIVE" == "1" && "$ERROR_HANDLER_RUNNING" == "0" ]]; then
        ERROR_HANDLER_RUNNING=1
        rollback_ssh_transaction_best_effort || true
        ERROR_HANDLER_RUNNING=0
    fi
    [[ -n "$BACKUP_DIR" ]] && warn "本次备份目录: $BACKUP_DIR"
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR

print_help() {
    cat <<EOF_HELP
${SCRIPT_NAME} v${HARDENING_VERSION}

用法：
  bash install-vps-hardening.sh
  bash install-vps-hardening.sh --version
  bash install-vps-hardening.sh --help

该脚本必须由 root 在 Debian 12/13 的交互式终端中执行。
EOF_HELP
}

parse_args() {
    case "${1:-}" in
        --help|-h) print_help; exit 0 ;;
        --version|-V) printf '%s v%s\n' "$SCRIPT_NAME" "$HARDENING_VERSION"; exit 0 ;;
        "") ;;
        *) die "未知参数: $1" ;;
    esac
}

require_root_and_tty() {
    [[ $(id -u) -eq 0 ]] || die "必须使用 root 用户执行此脚本。"
    [[ -t 0 ]] || die "需要交互式终端。请直接在 VPS SSH/Console 中执行，不要把 stdin 重定向到文件。"
}

check_os() {
    [[ -r /etc/os-release ]] || die "无法识别操作系统。"

    # 在子 shell 中读取 os-release，只提取本脚本需要的字段。
    # 这样既不会污染当前 shell，也不会与项目自身变量发生命名冲突。
    local -a os_info=()
    mapfile -t os_info < <(
        set +u
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s\n%s\n%s\n' "${ID:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-}"
    )

    local os_id=${os_info[0]:-}
    local os_version_id=${os_info[1]:-}
    local os_pretty_name=${os_info[2]:-unknown}

    [[ "$os_id" == "debian" ]] || die "当前仅支持 Debian 12/13。检测到: ${os_pretty_name}"
    case "$os_version_id" in
        12|13) ;;
        11) die "Debian 11 已结束 Debian 官方 LTS，本 v2 不再支持。请先升级到 Debian 12/13。" ;;
        *) die "当前仅支持 Debian 12/13。检测到 Debian ${os_version_id:-unknown}" ;;
    esac

    OS_VERSION_ID=$os_version_id
    OS_PRETTY_NAME=$os_pretty_name
}

detect_ssh_environment() {
    [[ -x /usr/sbin/sshd ]] || die "未找到 /usr/sbin/sshd。本脚本只支持使用 OpenSSH Server 的 VPS。"
    [[ -f "$SSH_CONFIG" ]] || die "未找到 $SSH_CONFIG。"

    if unit_exists ssh.service; then
        SSH_SERVICE_UNIT="ssh.service"
    elif unit_exists sshd.service; then
        SSH_SERVICE_UNIT="sshd.service"
    else
        die "未找到 ssh.service 或 sshd.service。"
    fi

    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        CURRENT_SSH_PORT=$(awk '{print $4}' <<< "$SSH_CONNECTION" 2>/dev/null || true)
    fi
    if [[ -z "$CURRENT_SSH_PORT" || ! "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]]; then
        CURRENT_SSH_PORT=$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}')
    fi
    CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-unknown}
}

check_apt_and_dpkg_state() {
    local busy=""
    if command -v ps >/dev/null 2>&1; then
        busy=$(ps -eo comm= 2>/dev/null | grep -E '^(apt|apt-get|dpkg|unattended-upgr)$' | sort -u | tr '\n' ' ' || true)
    fi
    [[ -z "$busy" ]] || die "检测到其他软件包管理进程正在运行：$busy。请等待其结束后重新执行。"

    local audit
    audit=$(dpkg --audit 2>/dev/null || true)
    [[ -z "$audit" ]] || die "dpkg 检测到未完成/异常的软件包状态，请先修复后再执行：\n$audit"
}

check_disk_space() {
    local avail_mb
    avail_mb=$(df -Pm / | awk 'NR==2 {print $4}')
    [[ "$avail_mb" =~ ^[0-9]+$ ]] || die "无法检测根分区剩余空间。"
    (( avail_mb >= 512 )) || die "根分区仅剩 ${avail_mb} MiB，低于安全执行下限 512 MiB。"
    if (( avail_mb < 2048 )); then
        warn "根分区剩余空间约 ${avail_mb} MiB；如果选择完整系统升级，建议先确认空间是否充足。"
    fi
    ROOT_FREE_MB=$avail_mb
}

detect_ipv6() {
    if command -v ip >/dev/null 2>&1 && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
        HAS_GLOBAL_IPV6=1
    else
        HAS_GLOBAL_IPV6=0
    fi
}

print_header() {
    clear 2>/dev/null || true
    printf '%b\n' "${GREEN}=================================================================${RESET}"
    printf '%b\n' "${GREEN}       VPS 代理服务器安全加固一键脚本 v${HARDENING_VERSION}（Debian 12/13）${RESET}"
    printf '%b\n' "${GREEN}=================================================================${RESET}"
    printf '%s\n' "设计原则：最小侵入、防失联、可验证、可回滚、可重复执行"
    printf '%s\n' "SSH 登录方式：root + 密码（默认）或 root + SSH 公钥（可选）"
    printf '%s\n' "不会修改：主机名、内核/sysctl、系统 DNS；公钥模式会保留并追加 authorized_keys"
    printf '\n'
}

print_preflight_summary() {
    local socket_state="不存在/未启用"
    if unit_exists "$SSH_SOCKET_UNIT"; then
        if systemctl is-active --quiet "$SSH_SOCKET_UNIT" 2>/dev/null; then
            socket_state="active（v2 将安全切换为 ${SSH_SERVICE_UNIT}）"
        elif [[ "$(unit_enabled_state "$SSH_SOCKET_UNIT")" == "enabled" ]]; then
            socket_state="enabled（v2 将切换为 ${SSH_SERVICE_UNIT}）"
        else
            socket_state="存在但未启用"
        fi
    fi

    printf '%b\n' "${BOLD}预检结果${RESET}"
    printf '  系统               : %s\n' "$OS_PRETTY_NAME"
    printf '  当前 SSH 服务      : %s\n' "$SSH_SERVICE_UNIT"
    printf '  当前 SSH 连接端口  : %s\n' "$CURRENT_SSH_PORT"
    printf '  ssh.socket         : %s\n' "$socket_state"
    printf '  根分区剩余         : %s MiB\n' "$ROOT_FREE_MB"
    printf '  公网/全局 IPv6     : %s\n' "$([[ "$HAS_GLOBAL_IPV6" == "1" ]] && echo '检测到' || echo '未检测到')"
    printf '\n'
}

choose_timezone() {
    printf '%b\n' "${BOLD}1. 请选择系统时区 [默认: 1]${RESET}"
    printf '%s\n' \
        "   1) America/Los_Angeles (美西/洛杉矶 - 默认)" \
        "   2) Asia/Shanghai       (中国/上海)" \
        "   3) Asia/Hong_Kong      (中国/香港)" \
        "   4) Asia/Tokyo          (日本/东京)" \
        "   5) Asia/Singapore      (新加坡)" \
        "   6) Europe/London       (英国/伦敦)" \
        "   7) UTC                 (协调世界时)"

    local choice
    read -r -p "请输入序号 [1-7]: " choice
    case "${choice:-1}" in
        1) TIMEZONE="America/Los_Angeles" ;;
        2) TIMEZONE="Asia/Shanghai" ;;
        3) TIMEZONE="Asia/Hong_Kong" ;;
        4) TIMEZONE="Asia/Tokyo" ;;
        5) TIMEZONE="Asia/Singapore" ;;
        6) TIMEZONE="Europe/London" ;;
        7) TIMEZONE="UTC" ;;
        *) warn "输入无效，使用默认时区 America/Los_Angeles。"; TIMEZONE="America/Los_Angeles" ;;
    esac
}

port_listener_info() {
    local port=$1
    ss -H -ltnp "sport = :${port}" 2>/dev/null || true
}

port_is_current_openssh() {
    local port=$1
    [[ "$CURRENT_SSH_PORT" == "$port" ]] && return 0
    /usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" {print $2}' | grep -qx "$port"
}

choose_ssh_port() {
    printf '\n%b\n' "${BOLD}2. 设置 SSH 管理端口${RESET}"
    printf '%s\n' "建议使用 10000-65535 范围内的非冲突端口。默认: 22222"

    while true; do
        read -r -p "请输入 SSH 端口 [22222]: " SSH_PORT
        SSH_PORT=${SSH_PORT:-22222}

        if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 10000 && SSH_PORT <= 65535 )); then
            if [[ "$SSH_PORT" == "443" || "$SSH_PORT" == "19175" ]]; then
                warn "443 与 19175 已保留给 sing-box，请选择其他 SSH 端口。"
                continue
            fi

            local listener
            listener=$(port_listener_info "$SSH_PORT")
            if [[ -n "$listener" ]] && ! port_is_current_openssh "$SSH_PORT"; then
                warn "端口 ${SSH_PORT} 已被其他监听占用："
                printf '%s\n' "$listener"
                continue
            fi
            break
        fi
        warn "请输入 10000-65535 之间的有效端口。"
    done
}

validate_public_key_line() {
    local key=$1 tmp
    [[ -n "$key" ]] || return 1
    [[ "$key" != *$'\n'* && "$key" != *$'\r'* ]] || return 1
    [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]] || return 1

    command -v ssh-keygen >/dev/null 2>&1 || return 1
    tmp=$(mktemp)
    chmod 600 "$tmp"
    printf '%s\n' "$key" > "$tmp"
    if ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

choose_auth_mode() {
    printf '\n%b\n' "${BOLD}3. 请选择 root SSH 登录认证方式 [默认: 1]${RESET}"
    printf '%s\n' \
        "   1) root + 密码登录（默认）" \
        "   2) root + SSH 公钥登录（适合厂商强制密钥登录）"

    local choice
    while true; do
        read -r -p "请输入序号 [1-2]: " choice
        case "${choice:-1}" in
            1)
                AUTH_MODE="password"
                SSH_PUBLIC_KEY=""
                return 0
                ;;
            2)
                AUTH_MODE="publickey"
                command -v ssh-keygen >/dev/null 2>&1 || die "系统缺少 ssh-keygen，无法安全校验输入的 SSH 公钥。"
                if [[ -L "$ROOT_SSH_DIR" || -L "$ROOT_AUTH_KEYS" ]]; then
                    die "$ROOT_SSH_DIR 或 $ROOT_AUTH_KEYS 当前是符号链接。为避免误改厂商动态管理的密钥路径，v2.1 不会自动写入；请先使用厂商控制台确认其管理方式。"
                fi
                if [[ -e "$ROOT_AUTH_KEYS" && ! -f "$ROOT_AUTH_KEYS" ]]; then
                    die "$ROOT_AUTH_KEYS 存在但不是普通文件，无法安全追加 SSH 公钥。"
                fi
                printf '\n%s\n' "请粘贴完整 SSH 公钥（一整行，例如 ssh-ed25519 AAAA... comment）。"
                printf '%s\n' "脚本会保留 /root/.ssh/authorized_keys 中已有厂商 Key，仅在不存在时追加你输入的 Key。"
                while true; do
                    read -r -p "SSH 公钥: " SSH_PUBLIC_KEY
                    if validate_public_key_line "$SSH_PUBLIC_KEY"; then
                        local tmp fp
                        tmp=$(mktemp)
                        printf '%s\n' "$SSH_PUBLIC_KEY" > "$tmp"
                        fp=$(ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}' || true)
                        rm -f "$tmp"
                        SSH_PUBLIC_KEY_FINGERPRINT="$fp"
                        [[ -n "$fp" ]] && ok "公钥格式有效，指纹：$fp" || ok "公钥格式有效。"
                        return 0
                    fi
                    warn "公钥格式或内容无效。请粘贴 OpenSSH 单行公钥，例如 ssh-ed25519 / ssh-rsa / ecdsa-sha2-*。"
                done
                ;;
            *) warn "请输入 1 或 2。" ;;
        esac
    done
}

choose_upgrade_policy() {
    printf '\n%b\n' "${BOLD}4. 是否执行完整的软件包升级？${RESET}"
    printf '%s\n' "新 VPS 推荐执行；已有生产业务时可选择跳过，只安装本脚本必需组件。"
    local answer
    read -r -p "执行 apt-get upgrade？[Y/n]: " answer
    case "${answer:-Y}" in
        n|N|no|NO) FULL_UPGRADE=0 ;;
        *) FULL_UPGRADE=1 ;;
    esac
}

warn_reserved_port_usage() {
    local p info
    for p in 443 19175; do
        info=$(port_listener_info "$p")
        if [[ -n "$info" ]]; then
            warn "检测到 ${p}/TCP 当前已有监听。脚本只会开放防火墙，不会停止该服务："
            printf '%s\n' "$info"
        fi
    done
}

confirm_changes() {
    printf '\n%b\n' "${YELLOW}即将执行以下操作：${RESET}"
    printf '  时区               : %s\n' "$TIMEZONE"
    printf '  完整 apt upgrade   : %s\n' "$([[ "$FULL_UPGRADE" == "1" ]] && echo '是' || echo '否')"
    printf '  SSH 用户           : root\n'
    printf '  SSH 端口           : %s/tcp\n' "$SSH_PORT"
    if [[ "$AUTH_MODE" == "password" ]]; then
        printf '  SSH 认证方式       : root + 密码（默认模式）\n'
        printf '  root 密码          : 手动重新设置\n'
        printf '  SSH 公钥           : 不写入、不删除、不强制禁用（保留现有能力）\n'
    else
        printf '  SSH 认证方式       : root + SSH 公钥（仅公钥）\n'
        printf '  root 密码          : 不修改，SSH 密码认证关闭\n'
        printf '  authorized_keys    : 保留已有 Key，并追加用户输入 Key（若不存在）\n'
    fi
    printf '  UFW 最终入站       : %s/tcp (SSH limit)\n' "$SSH_PORT"
    printf '                       443/tcp (sing-box VLESS)\n'
    printf '                       19175/tcp + 19175/udp (sing-box Shadowsocks)\n'
    printf '  其他 UFW 入站      : 最终默认拒绝\n'
    printf '  Fail2ban           : 独立 jail.d 配置，仅管理 sshd jail\n'
    printf '  自动安全更新       : 开启 apt-daily / apt-daily-upgrade timers\n'
    printf '  主机名/sysctl/DNS  : 不修改\n'
    printf '\n'
    warn "最终 UFW 会重置现有 UFW 规则。如果服务器还运行网站、面板等其他公网服务，它们会被关闭端口。"
    warn "SSH 会采用“两阶段迁移”：先临时放行新端口，重启并验证新登录成功后，才收紧最终 UFW。"
    warn "如果云厂商有 Security Group / ACL，请确保新 SSH 端口也允许公网访问。"
    if [[ "$AUTH_MODE" == "password" ]]; then
        warn "root 密码修改不可由回滚脚本恢复。"
    else
        warn "公钥模式不会修改 root 密码；authorized_keys 会纳入备份并可回滚。请确保你持有对应私钥。"
    fi

    local answer
    read -r -p "确认继续？请输入 YES: " answer
    [[ "$answer" == "YES" ]] || die "用户取消执行。"
}

capture_state_and_backup() {
    CURRENT_STAGE="创建备份"
    umask 077
    mkdir -p "$BACKUP_ROOT"
    BACKUP_DIR=$(mktemp -d "${BACKUP_ROOT}/$(date '+%Y%m%d_%H%M%S')_XXXXXX")

    local old_timezone
    old_timezone=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)

    [[ -e "$SSH_CONFIG" ]] && cp -a "$SSH_CONFIG" "$BACKUP_DIR/sshd_config"
    [[ -e "$SSH_MANAGED_CONFIG" ]] && cp -a "$SSH_MANAGED_CONFIG" "$BACKUP_DIR/00-vps-hardening.conf"
    [[ -e "$SSH_BANNER" ]] && cp -a "$SSH_BANNER" "$BACKUP_DIR/banner.vps-hardening"
    [[ -d /etc/ufw ]] && cp -a /etc/ufw "$BACKUP_DIR/ufw"
    [[ -e "$UFW_DEFAULTS" ]] && cp -a "$UFW_DEFAULTS" "$BACKUP_DIR/default-ufw"
    [[ -e "$FAIL2BAN_CONFIG" ]] && cp -a "$FAIL2BAN_CONFIG" "$BACKUP_DIR/99-vps-hardening.local"
    [[ -e "$AUTO_UPGRADES_CONFIG" ]] && cp -a "$AUTO_UPGRADES_CONFIG" "$BACKUP_DIR/99-vps-hardening-periodic"
    [[ "$AUTH_MODE" == "publickey" && -e "$ROOT_AUTH_KEYS" ]] && cp -a "$ROOT_AUTH_KEYS" "$BACKUP_DIR/root-authorized_keys"

    : > "$BACKUP_DIR/manifest.env"
    manifest_set BACKUP_FORMAT_VERSION "2"
    manifest_set SCRIPT_VERSION "$HARDENING_VERSION"
    manifest_set BACKUP_CREATED "$(date -Is)"
    manifest_set OS_VERSION_ID "$OS_VERSION_ID"
    manifest_set TIMEZONE_OLD "$old_timezone"
    manifest_set TIMEZONE_NEW "$TIMEZONE"
    manifest_set SSH_PORT_OLD "$CURRENT_SSH_PORT"
    manifest_set SSH_PORT_NEW "$SSH_PORT"
    manifest_set AUTH_MODE_NEW "$AUTH_MODE"
    manifest_set ROOT_AUTH_KEYS_TRACKED "$([[ "$AUTH_MODE" == "publickey" ]] && echo 1 || echo 0)"
    manifest_set ROOT_SSH_DIR_EXISTED "$([[ -d "$ROOT_SSH_DIR" ]] && echo 1 || echo 0)"
    manifest_set ROOT_AUTH_KEYS_EXISTED "$([[ -e "$BACKUP_DIR/root-authorized_keys" ]] && echo 1 || echo 0)"
    if [[ -d "$ROOT_SSH_DIR" ]]; then
        manifest_set ROOT_SSH_DIR_MODE "$(stat -c '%a' "$ROOT_SSH_DIR" 2>/dev/null || true)"
        manifest_set ROOT_SSH_DIR_UID "$(stat -c '%u' "$ROOT_SSH_DIR" 2>/dev/null || true)"
        manifest_set ROOT_SSH_DIR_GID "$(stat -c '%g' "$ROOT_SSH_DIR" 2>/dev/null || true)"
    else
        manifest_set ROOT_SSH_DIR_MODE ""
        manifest_set ROOT_SSH_DIR_UID ""
        manifest_set ROOT_SSH_DIR_GID ""
    fi
    manifest_set SSH_SERVICE_UNIT_OLD "$SSH_SERVICE_UNIT"
    manifest_set SSH_SOCKET_UNIT_OLD "$SSH_SOCKET_UNIT"
    manifest_set SSH_SERVICE_WAS_ACTIVE "$(unit_active_flag "$SSH_SERVICE_UNIT")"
    manifest_set SSH_SERVICE_WAS_ENABLED_STATE "$(unit_enabled_state "$SSH_SERVICE_UNIT")"
    manifest_set SSH_SOCKET_WAS_ACTIVE "$(unit_exists "$SSH_SOCKET_UNIT" && unit_active_flag "$SSH_SOCKET_UNIT" || echo 0)"
    manifest_set SSH_SOCKET_WAS_ENABLED_STATE "$(unit_exists "$SSH_SOCKET_UNIT" && unit_enabled_state "$SSH_SOCKET_UNIT" || true)"
    manifest_set SSH_CONFIG_EXISTED "$([[ -e "$SSH_CONFIG" ]] && echo 1 || echo 0)"
    manifest_set SSH_MANAGED_CONFIG_EXISTED "$([[ -e "$BACKUP_DIR/00-vps-hardening.conf" ]] && echo 1 || echo 0)"
    manifest_set SSH_BANNER_EXISTED "$([[ -e "$BACKUP_DIR/banner.vps-hardening" ]] && echo 1 || echo 0)"
    manifest_set UFW_WAS_INSTALLED "$(pkg_installed_flag ufw)"
    manifest_set UFW_WAS_ACTIVE "$(command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active' && echo 1 || echo 0)"
    manifest_set UFW_DIR_EXISTED "$([[ -d "$BACKUP_DIR/ufw" ]] && echo 1 || echo 0)"
    manifest_set UFW_DEFAULTS_EXISTED "$([[ -e "$BACKUP_DIR/default-ufw" ]] && echo 1 || echo 0)"
    manifest_set FAIL2BAN_WAS_INSTALLED "$(pkg_installed_flag fail2ban)"
    manifest_set FAIL2BAN_WAS_ACTIVE "$(unit_active_flag fail2ban.service)"
    manifest_set FAIL2BAN_WAS_ENABLED_STATE "$(unit_enabled_state fail2ban.service)"
    manifest_set FAIL2BAN_CONFIG_EXISTED "$([[ -e "$BACKUP_DIR/99-vps-hardening.local" ]] && echo 1 || echo 0)"
    manifest_set UNATTENDED_WAS_INSTALLED "$(pkg_installed_flag unattended-upgrades)"
    manifest_set AUTO_UPGRADES_CONFIG_EXISTED "$([[ -e "$BACKUP_DIR/99-vps-hardening-periodic" ]] && echo 1 || echo 0)"
    manifest_set APT_DAILY_TIMER_ACTIVE "$(unit_active_flag apt-daily.timer)"
    manifest_set APT_DAILY_TIMER_ENABLED_STATE "$(unit_enabled_state apt-daily.timer)"
    manifest_set APT_UPGRADE_TIMER_ACTIVE "$(unit_active_flag apt-daily-upgrade.timer)"
    manifest_set APT_UPGRADE_TIMER_ENABLED_STATE "$(unit_enabled_state apt-daily-upgrade.timer)"
    manifest_set CHRONY_WAS_INSTALLED "$(pkg_installed_flag chrony)"
    manifest_set CHRONY_WAS_ACTIVE "$(unit_active_flag chrony.service)"
    manifest_set CHRONY_WAS_ENABLED_STATE "$(unit_enabled_state chrony.service)"
    manifest_set TIMESYNCD_WAS_ACTIVE "$(unit_active_flag systemd-timesyncd.service)"
    manifest_set TIMESYNCD_WAS_ENABLED_STATE "$(unit_enabled_state systemd-timesyncd.service)"
    manifest_set NTPSEC_WAS_ACTIVE "$(unit_active_flag ntpsec.service)"
    manifest_set NTPSEC_WAS_ENABLED_STATE "$(unit_enabled_state ntpsec.service)"
    manifest_set NTP_WAS_ACTIVE "$(unit_active_flag ntp.service)"
    manifest_set NTP_WAS_ENABLED_STATE "$(unit_enabled_state ntp.service)"
    manifest_set HAS_GLOBAL_IPV6 "$HAS_GLOBAL_IPV6"

    ok "已创建 v2 配置备份：$BACKUP_DIR"
}

set_root_password_interactive() {
    CURRENT_STAGE="设置 root 密码"
    printf '\n%b\n' "${BOLD}5. 设置新的 root 登录密码${RESET}"
    printf '%s\n' "下面直接调用系统 passwd root。密码不会进入脚本变量，也不会写入备份或日志。"

    while true; do
        if passwd root; then
            break
        fi
        warn "root 密码修改失败。"
        local retry
        read -r -p "是否重试？[Y/n]: " retry
        case "${retry:-Y}" in
            n|N|no|NO) die "未成功设置 root 密码，停止执行。" ;;
        esac
    done

    local status
    status=$(passwd -S root 2>/dev/null | awk '{print $2}' || true)
    [[ "$status" == "P" ]] || die "root 账户仍不是有效密码状态，停止继续修改 SSH。"
}

install_root_public_key() {
    CURRENT_STAGE="配置 root SSH 公钥"
    [[ "$AUTH_MODE" == "publickey" ]] || return 0
    validate_public_key_line "$SSH_PUBLIC_KEY" || die "准备写入的 SSH 公钥校验失败。"

    mkdir -p "$ROOT_SSH_DIR"
    chmod 700 "$ROOT_SSH_DIR"
    touch "$ROOT_AUTH_KEYS"
    chmod 600 "$ROOT_AUTH_KEYS"
    chown root:root "$ROOT_SSH_DIR" "$ROOT_AUTH_KEYS"

    local existing_fingerprints
    existing_fingerprints=$(ssh-keygen -lf "$ROOT_AUTH_KEYS" 2>/dev/null | awk '{print $2}' || true)
    if [[ -n "$SSH_PUBLIC_KEY_FINGERPRINT" ]] && grep -Fqx -- "$SSH_PUBLIC_KEY_FINGERPRINT" <<< "$existing_fingerprints"; then
        ok "相同指纹的 SSH 公钥已存在于 $ROOT_AUTH_KEYS，跳过重复写入。"
    else
        if [[ -s "$ROOT_AUTH_KEYS" ]]; then
            local last_hex
            last_hex=$(tail -c 1 "$ROOT_AUTH_KEYS" 2>/dev/null | od -An -t x1 | tr -d '[:space:]' || true)
            [[ "$last_hex" == "0a" ]] || printf '\n' >> "$ROOT_AUTH_KEYS"
        fi
        printf '%s\n' "$SSH_PUBLIC_KEY" >> "$ROOT_AUTH_KEYS"
        ok "已保留现有 Key，并将输入的 SSH 公钥追加到 $ROOT_AUTH_KEYS。"
    fi
}

prepare_authentication_material() {
    if [[ "$AUTH_MODE" == "password" ]]; then
        set_root_password_interactive
    else
        install_root_public_key
    fi
}

install_required_packages() {
    CURRENT_STAGE="APT 更新与组件安装"
    log "[1/8] 更新 APT 索引并安装必要组件……"
    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none

    apt-get update
    if [[ "$FULL_UPGRADE" == "1" ]]; then
        apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
    fi
    apt-get install -y ca-certificates curl iproute2 ufw fail2ban unattended-upgrades apt-listchanges

    ok "APT 与必要组件处理完成（不会自动执行 apt autoremove）。"
}

configure_timezone_and_time_sync() {
    CURRENT_STAGE="时区与时间同步"
    log "[2/8] 配置时区并确保已有可用的时间同步服务……"
    timedatectl set-timezone "$TIMEZONE"

    local unit
    for unit in chrony.service systemd-timesyncd.service ntpsec.service ntp.service; do
        if unit_exists "$unit" && systemctl is-active --quiet "$unit" 2>/dev/null; then
            TIME_SYNC_SELECTED="$unit"
            ok "保留现有时间同步服务：$unit"
            return 0
        fi
    done

    if unit_exists systemd-timesyncd.service; then
        systemctl enable --now systemd-timesyncd.service
        TIME_SYNC_SELECTED="systemd-timesyncd.service"
        ok "已启用现有 systemd-timesyncd。"
    else
        apt-get install -y chrony
        systemctl enable --now chrony.service
        TIME_SYNC_SELECTED="chrony.service"
        ok "系统原先没有活动时间同步服务，已安装并启用 Chrony。"
    fi
}

prepare_temporary_ssh_firewall() {
    CURRENT_STAGE="临时放行新 SSH 端口"
    # shellcheck disable=SC1090
    . "$BACKUP_DIR/manifest.env"

    if [[ "${UFW_WAS_ACTIVE:-0}" == "1" ]]; then
        log "[3/8] UFW 当前已启用，先临时放行新 SSH 端口 ${SSH_PORT}/tcp……"
        if [[ "$CURRENT_SSH_PORT" != "$SSH_PORT" ]]; then
            ufw allow "${SSH_PORT}/tcp" comment 'TEMP vps-hardening SSH migration'
            TEMP_UFW_CHANGED=1
        else
            ok "新 SSH 端口与当前端口相同，无需增加临时规则。"
        fi
    else
        log "[3/8] UFW 当前未启用，暂不启用；将在 SSH 验证成功后配置最终规则。"
    fi
}

write_managed_ssh_config() {
    mkdir -p "$(dirname "$SSH_MANAGED_CONFIG")"
    cat > "$SSH_MANAGED_CONFIG" <<EOF_SSH
# Managed by ${SCRIPT_NAME} v${HARDENING_VERSION}
# Backup: ${BACKUP_DIR}

Port ${SSH_PORT}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
HostbasedAuthentication no
UsePAM yes
EOF_SSH

    if [[ "$AUTH_MODE" == "password" ]]; then
        cat >> "$SSH_MANAGED_CONFIG" <<'EOF_AUTH'
PermitRootLogin yes
PasswordAuthentication yes
AuthenticationMethods any
EOF_AUTH
    else
        cat >> "$SSH_MANAGED_CONFIG" <<'EOF_AUTH'
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
EOF_AUTH
    fi

    cat >> "$SSH_MANAGED_CONFIG" <<EOF_SSH

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
EOF_SSH

    cat > "$SSH_BANNER" <<'EOF_BANNER'
*******************************************************************
*  WARNING: Unauthorized access to this system is prohibited.     *
*  All connections may be monitored and recorded.                 *
*******************************************************************
EOF_BANNER

    # Exact Include is intentionally placed first. We do not rewrite the rest of the provider's sshd_config.
    sed -i '\|^[[:space:]]*Include[[:space:]]\+/etc/ssh/sshd_config\.d/00-vps-hardening\.conf[[:space:]]*$|d' "$SSH_CONFIG"
    sed -i "1iInclude ${SSH_MANAGED_CONFIG}" "$SSH_CONFIG"
}

validate_new_ssh_config() {
    /usr/sbin/sshd -t || die "新的 SSH 配置未通过 sshd -t。"

    local effective
    effective=$(/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1)
    grep -q "^port ${SSH_PORT}$" <<< "$effective" || die "SSH 有效配置中端口不是 ${SSH_PORT}。"

    if [[ "$AUTH_MODE" == "password" ]]; then
        grep -q '^permitrootlogin yes$' <<< "$effective" || die "SSH 有效配置未允许 root 密码登录。"
        grep -q '^passwordauthentication yes$' <<< "$effective" || die "SSH 有效配置未开启密码认证。"
        grep -q '^authenticationmethods any$' <<< "$effective" || die "SSH 有效配置仍要求组合认证，无法保证仅用 root 密码登录。"
    else
        grep -Eq '^permitrootlogin (prohibit-password|without-password|yes)$' <<< "$effective" || die "SSH 有效配置未允许 root 公钥登录。"
        grep -q '^passwordauthentication no$' <<< "$effective" || die "SSH 公钥模式下仍允许密码认证。"
        grep -q '^pubkeyauthentication yes$' <<< "$effective" || die "SSH 公钥模式未启用 PubkeyAuthentication。"
        grep -q '^authenticationmethods publickey$' <<< "$effective" || die "SSH 公钥模式未强制 publickey 认证。"
        grep -Eq '^authorizedkeysfile .*\.ssh/authorized_keys' <<< "$effective" || die "SSH 公钥模式的 AuthorizedKeysFile 未包含 .ssh/authorized_keys。"
    fi

    # AllowUsers/DenyUsers/AllowGroups/DenyGroups 支持 OpenSSH pattern，静态脚本不尝试错误地“推断”是否匹配 root。
    # 若存在这类 ACL，只提示；真正的可登录性由后面的第二终端实测把关。
    if grep -Eq '^(allowusers|denyusers|allowgroups|denygroups) ' <<< "$effective"; then
        warn "检测到现有 SSH 用户/组访问控制规则（AllowUsers/DenyUsers/AllowGroups/DenyGroups）。脚本不会覆盖它们，请务必完成第二终端登录实测。"
    fi
}

activate_ssh_service_mode() {
    local socket_enabled=""
    if unit_exists "$SSH_SOCKET_UNIT"; then
        socket_enabled=$(unit_enabled_state "$SSH_SOCKET_UNIT")
    fi

    if unit_exists "$SSH_SOCKET_UNIT" && { systemctl is-active --quiet "$SSH_SOCKET_UNIT" 2>/dev/null || [[ "$socket_enabled" == "enabled" || "$socket_enabled" == "enabled-runtime" ]]; }; then
        warn "检测到 ssh.socket 正在使用或已启用。为确保 sshd_config 的 Port=${SSH_PORT} 在重启后持续生效，将切换为 ${SSH_SERVICE_UNIT} 监听模式。"
        systemctl disable --now "$SSH_SOCKET_UNIT" >/dev/null 2>&1 || true
    fi

    systemctl enable "$SSH_SERVICE_UNIT" >/dev/null 2>&1 || true
    systemctl restart "$SSH_SERVICE_UNIT"
    systemctl is-active --quiet "$SSH_SERVICE_UNIT" || die "$SSH_SERVICE_UNIT 重启后未处于 active 状态。"
}

check_ssh_listener() {
    local listener
    listener=$(port_listener_info "$SSH_PORT")
    [[ -n "$listener" ]] || die "SSH 服务虽已启动，但未检测到 TCP ${SSH_PORT} 监听。"
}

configure_ssh_transactionally() {
    CURRENT_STAGE="事务式 SSH 迁移"
    log "[4/8] 事务式配置 SSH（失败将自动恢复 SSH/UFW）……"
    SSH_TRANSACTION_ACTIVE=1

    prepare_temporary_ssh_firewall
    write_managed_ssh_config
    validate_new_ssh_config
    activate_ssh_service_mode
    check_ssh_listener

    ok "新的 SSH 配置已加载，${SSH_PORT}/tcp 已监听。"
}

show_ssh_status() {
    printf '\n%s\n' "--- SSH 当前状态 ---"
    systemctl --no-pager --full status "$SSH_SERVICE_UNIT" 2>/dev/null | sed -n '1,10p' || true
    printf '%s\n' "--- ${SSH_PORT}/TCP 监听 ---"
    port_listener_info "$SSH_PORT" || true
    printf '%s\n' "---------------------"
}

verify_new_ssh_interactive() {
    CURRENT_STAGE="第二终端 SSH 验证"
    printf '\n%b\n' "${YELLOW}==================== 必须完成 SSH 实测 ====================${RESET}"
    printf '%s\n' "请保持当前窗口不要关闭，然后打开第二个终端窗口实际登录："
    if [[ "$AUTH_MODE" == "password" ]]; then
        printf '%b\n' "${BOLD}ssh -p ${SSH_PORT} root@<你的VPS_IP>${RESET}"
        printf '%s\n' "使用刚刚设置的新 root 密码登录。"
    else
        printf '%b\n' "${BOLD}ssh -i <对应私钥文件> -p ${SSH_PORT} root@<你的VPS_IP>${RESET}"
        printf '%s\n' "请使用与你刚才输入的公钥匹配的私钥；如果私钥已由 ssh-agent 管理，可省略 -i。"
        printf '%s\n' "公钥模式下 SSH 密码认证已关闭，因此必须确认密钥登录真实成功。"
    fi
    printf '%s\n' "如果云厂商有 Security Group / Firewall / ACL，也必须先放行 ${SSH_PORT}/TCP。"
    printf '%s\n' "验证成功后回到本窗口输入 VERIFIED；如失败可输入 STATUS 查看状态，或输入 ROLLBACK 自动恢复 SSH/UFW。"

    local answer
    while true; do
        read -r -p "请输入 VERIFIED / STATUS / ROLLBACK: " answer
        case "$answer" in
            VERIFIED)
                SSH_TRANSACTION_ACTIVE=0
                ok "已确认第二终端登录成功。现在才会收紧最终 UFW。"
                return 0
                ;;
            STATUS)
                show_ssh_status
                ;;
            ROLLBACK)
                rollback_ssh_transaction_best_effort
                if [[ "$AUTH_MODE" == "password" ]]; then
                    err "已按你的选择回滚 SSH/UFW。root 密码仍是新密码。"
                else
                    err "已按你的选择回滚 SSH/UFW/authorized_keys。"
                fi
                exit 2
                ;;
            *) warn "请输入 VERIFIED、STATUS 或 ROLLBACK。" ;;
        esac
    done
}

ufw_fail_safe() {
    err "UFW 最终配置失败。为避免把 SSH 锁在防火墙外，正在尽力禁用 UFW。"
    ufw --force disable >/dev/null 2>&1 || true
    die "UFW 配置未完成；当前脚本已停止。请保持现有 SSH 会话并人工检查。"
}

configure_final_ufw() {
    CURRENT_STAGE="最终 UFW"
    log "[5/8] 配置最终 UFW：只保留 SSH + 443 + 19175……"

    if [[ "$HAS_GLOBAL_IPV6" == "1" ]]; then
        [[ -f "$UFW_DEFAULTS" ]] || ufw_fail_safe
        if grep -q '^IPV6=' "$UFW_DEFAULTS"; then
            sed -i 's/^IPV6=.*/IPV6=yes/' "$UFW_DEFAULTS"
        else
            printf '\nIPV6=yes\n' >> "$UFW_DEFAULTS"
        fi
    fi

    if ! ufw --force reset; then ufw_fail_safe; fi
    if ! ufw default deny incoming; then ufw_fail_safe; fi
    if ! ufw default allow outgoing; then ufw_fail_safe; fi
    if ! ufw limit "${SSH_PORT}/tcp" comment 'SSH root management'; then ufw_fail_safe; fi
    if ! ufw allow 443/tcp comment 'sing-box VLESS'; then ufw_fail_safe; fi
    if ! ufw allow 19175/tcp comment 'sing-box Shadowsocks TCP'; then ufw_fail_safe; fi
    if ! ufw allow 19175/udp comment 'sing-box Shadowsocks UDP'; then ufw_fail_safe; fi
    if ! ufw --force enable; then ufw_fail_safe; fi

    local status
    status=$(LC_ALL=C ufw status verbose)
    grep -q '^Status: active' <<< "$status" || die "UFW 未处于 active 状态。"
    if [[ "$HAS_GLOBAL_IPV6" == "1" ]] && ! grep -q '(v6)' <<< "$status"; then
        die "服务器存在全局 IPv6，但 UFW 状态中未看到 IPv6 规则。请保持当前会话并检查 $UFW_DEFAULTS。"
    fi
    ok "最终 UFW 已启用。"
}

configure_fail2ban() {
    CURRENT_STAGE="Fail2ban"
    log "[6/8] 配置 Fail2ban（独立 drop-in，仅 sshd jail）……"
    mkdir -p /etc/fail2ban/jail.d

    cat > "$FAIL2BAN_CONFIG" <<EOF_F2B
# Managed by ${SCRIPT_NAME} v${HARDENING_VERSION}
[sshd]
enabled = true
backend = systemd
port = ${SSH_PORT}
filter = sshd
banaction = ufw
findtime = 10m
maxretry = 3
bantime = 24h
EOF_F2B

    fail2ban-client -t
    systemctl enable fail2ban.service >/dev/null 2>&1 || true
    systemctl restart fail2ban.service
    systemctl is-active --quiet fail2ban.service || die "Fail2ban 未正常运行。"
    fail2ban-client status sshd >/dev/null 2>&1 || die "Fail2ban 的 sshd jail 未正常启用。"
    ok "Fail2ban sshd jail 已启用。"
}

configure_unattended_upgrades() {
    CURRENT_STAGE="自动安全更新"
    log "[7/8] 配置 Debian 自动安全更新……"

    cat > "$AUTO_UPGRADES_CONFIG" <<'EOF_AUTO'
// Managed by VPS Security Hardening.
// Package-selection policy remains in Debian's packaged 50unattended-upgrades.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF_AUTO

    systemctl enable --now apt-daily.timer >/dev/null 2>&1 || true
    systemctl enable --now apt-daily-upgrade.timer >/dev/null 2>&1 || true

    systemctl is-active --quiet apt-daily.timer || die "apt-daily.timer 未处于 active 状态。"
    systemctl is-active --quiet apt-daily-upgrade.timer || die "apt-daily-upgrade.timer 未处于 active 状态。"
    ok "APT 自动更新 timers 已启用。"
}

rule_present() {
    local status=$1 pattern=$2
    grep -Eq "$pattern" <<< "$status"
}

final_checks() {
    CURRENT_STAGE="最终健康检查"
    log "[8/8] 执行最终健康检查……"

    local failures=0 effective ufw_status passwd_status
    effective=$(/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1)
    ufw_status=$(LC_ALL=C ufw status)
    passwd_status=$(passwd -S root 2>/dev/null | awk '{print $2}' || true)

    check_line() {
        local description=$1
        shift
        if "$@"; then
            printf '%b\n' "${GREEN}[OK]${RESET} $description"
        else
            printf '%b\n' "${RED}[FAIL]${RESET} $description"
            failures=$((failures + 1))
        fi
    }

    if [[ "$AUTH_MODE" == "password" ]]; then
        check_line "root 密码状态有效" test "$passwd_status" = "P"
    else
        check_line "root authorized_keys 存在且非空" test -s "$ROOT_AUTH_KEYS"
        if [[ -n "$SSH_PUBLIC_KEY_FINGERPRINT" ]]; then
            check_line "本次输入的 SSH 公钥指纹已存在" bash -c "ssh-keygen -lf '$ROOT_AUTH_KEYS' 2>/dev/null | awk '{print \$2}' | grep -Fqx '$SSH_PUBLIC_KEY_FINGERPRINT'"
        fi
    fi
    check_line "$SSH_SERVICE_UNIT active" systemctl is-active --quiet "$SSH_SERVICE_UNIT"
    check_line "SSH ${SSH_PORT}/tcp 正在监听" bash -c "ss -H -ltn 'sport = :${SSH_PORT}' | grep -q ."
    if [[ "$AUTH_MODE" == "password" ]]; then
        check_line "PermitRootLogin yes" grep -q '^permitrootlogin yes$' <<< "$effective"
        check_line "PasswordAuthentication yes" grep -q '^passwordauthentication yes$' <<< "$effective"
        check_line "AuthenticationMethods any" grep -q '^authenticationmethods any$' <<< "$effective"
    else
        check_line "root 公钥登录被允许" grep -Eq '^permitrootlogin (prohibit-password|without-password|yes)$' <<< "$effective"
        check_line "PasswordAuthentication no" grep -q '^passwordauthentication no$' <<< "$effective"
        check_line "PubkeyAuthentication yes" grep -q '^pubkeyauthentication yes$' <<< "$effective"
        check_line "AuthenticationMethods publickey" grep -q '^authenticationmethods publickey$' <<< "$effective"
    fi
    check_line "UFW active" grep -q '^Status: active' <<< "$ufw_status"
    check_line "UFW SSH ${SSH_PORT}/tcp" rule_present "$ufw_status" "(^|[[:space:]])${SSH_PORT}/tcp[[:space:]]"
    check_line "UFW 443/tcp" rule_present "$ufw_status" '(^|[[:space:]])443/tcp[[:space:]]'
    check_line "UFW 19175/tcp" rule_present "$ufw_status" '(^|[[:space:]])19175/tcp[[:space:]]'
    check_line "UFW 19175/udp" rule_present "$ufw_status" '(^|[[:space:]])19175/udp[[:space:]]'
    check_line "Fail2ban active" systemctl is-active --quiet fail2ban.service
    check_line "Fail2ban sshd jail active" fail2ban-client status sshd
    check_line "apt-daily.timer active" systemctl is-active --quiet apt-daily.timer
    check_line "apt-daily-upgrade.timer active" systemctl is-active --quiet apt-daily-upgrade.timer

    if [[ "$HAS_GLOBAL_IPV6" == "1" ]]; then
        check_line "UFW IPv6 规则存在" grep -q '(v6)' <<< "$ufw_status"
    fi

    if [[ -n "$TIME_SYNC_SELECTED" ]]; then
        check_line "时间同步服务 ${TIME_SYNC_SELECTED} active" systemctl is-active --quiet "$TIME_SYNC_SELECTED"
    fi

    printf '\n'
    if [[ -z "$(port_listener_info 443)" ]]; then
        warn "[WARN] 443/TCP 当前没有监听；如果 sing-box 尚未安装/启动，这是正常的。"
    else
        ok "[OK] 443/TCP 当前已有服务监听。"
    fi
    if [[ -z "$(port_listener_info 19175)" ]]; then
        warn "[WARN] 19175/TCP 当前没有监听；如果 sing-box 尚未安装/启动，这是正常的。"
    else
        ok "[OK] 19175/TCP 当前已有服务监听。"
    fi

    if [[ -f /var/run/reboot-required ]]; then
        warn "[WARN] 系统更新后检测到 /var/run/reboot-required，建议在确认业务无误后安排重启。"
    fi

    (( failures == 0 )) || die "最终健康检查有 ${failures} 项失败。SSH 已由你实测成功，请保持当前会话并根据上面的 FAIL 项处理。"
    ok "全部关键健康检查通过。"
}

print_summary() {
    local ip_hint
    ip_hint=$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i !~ /:/) {print $i; exit}}' || true)
    ip_hint=${ip_hint:-'<你的VPS_IP>'}

    printf '\n%b\n' "${GREEN}=================================================================${RESET}"
    printf '%b\n' "${GREEN}               VPS Security Hardening v${HARDENING_VERSION} 完成${RESET}"
    printf '%b\n' "${GREEN}=================================================================${RESET}"
    printf '系统           : %s\n' "$OS_PRETTY_NAME"
    printf '时区           : %s\n' "$TIMEZONE"
    printf 'SSH 用户       : root\n'
    printf 'SSH 端口       : %s\n' "$SSH_PORT"
    if [[ "$AUTH_MODE" == "password" ]]; then
        printf '认证方式       : root + password\n'
        printf '登录命令       : ssh -p %s root@%s\n' "$SSH_PORT" "$ip_hint"
        printf '密码登录       : ENABLED\n'
        printf 'SSH 公钥       : 保留系统原有能力，本脚本不主动修改\n'
    else
        printf '认证方式       : root + publickey only\n'
        printf '登录命令       : ssh -i <private-key> -p %s root@%s\n' "$SSH_PORT" "$ip_hint"
        printf '密码登录       : DISABLED (SSH)\n'
        printf 'SSH 公钥       : ENABLED；保留已有 Key 并追加本次输入 Key\n'
        [[ -n "$SSH_PUBLIC_KEY_FINGERPRINT" ]] && printf '公钥指纹       : %s\n' "$SSH_PUBLIC_KEY_FINGERPRINT"
    fi
    printf 'UFW            : ACTIVE\n'
    printf '开放端口       : %s/tcp, 443/tcp, 19175/tcp, 19175/udp\n' "$SSH_PORT"
    printf 'IPv6 防火墙    : %s\n' "$([[ "$HAS_GLOBAL_IPV6" == "1" ]] && echo '已校验' || echo '当前未检测到全局 IPv6')"
    printf 'Fail2ban       : ACTIVE (sshd jail)\n'
    printf '自动安全更新   : apt-daily + apt-daily-upgrade timers ACTIVE\n'
    printf '时间同步       : %s\n' "${TIME_SYNC_SELECTED:-已保留系统现有机制}"
    printf '完整系统升级   : %s\n' "$([[ "$FULL_UPGRADE" == "1" ]] && echo '已执行' || echo '已跳过')"
    printf '备份目录       : %s\n' "$BACKUP_DIR"
    printf '\n'
    warn "当前 SSH 会话仍建议暂时保留，确认 sing-box 和其他必要服务均正常后再关闭。"
    if [[ "$AUTH_MODE" == "password" ]]; then
        warn "回滚可运行仓库中的 rollback.sh；root 密码和已安装/升级的软件包不会被回滚。"
    else
        warn "回滚可恢复本次执行前的 authorized_keys；已安装/升级的软件包不会被回滚。"
    fi
    printf '%b\n' "${GREEN}=================================================================${RESET}"
}

main() {
    parse_args "${1:-}"
    require_root_and_tty

    CURRENT_STAGE="系统预检"
    check_os
    detect_ssh_environment
    check_apt_and_dpkg_state
    check_disk_space
    detect_ipv6

    print_header
    print_preflight_summary
    choose_timezone
    choose_ssh_port
    choose_auth_mode
    choose_upgrade_policy
    warn_reserved_port_usage
    confirm_changes

    capture_state_and_backup
    install_required_packages
    configure_timezone_and_time_sync

    # 从认证材料开始进入 SSH 事务区：公钥模式下，后续失败会恢复 authorized_keys；
    # 密码模式下旧 root 密码无法恢复，但 SSH/UFW 配置仍会回滚。
    SSH_TRANSACTION_ACTIVE=1
    prepare_authentication_material
    configure_ssh_transactionally
    verify_new_ssh_interactive
    configure_final_ufw
    configure_fail2ban
    configure_unattended_upgrades
    final_checks
    print_summary
}

main "$@"

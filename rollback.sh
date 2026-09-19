#!/usr/bin/env bash
set -Eeuo pipefail

readonly HARDENING_VERSION="2.2.3"
readonly BACKUP_ROOT="/root/vps-hardening-backups"
readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly SSH_MANAGED_CONFIG="/etc/ssh/sshd_config.vps-hardening.conf"
readonly SSH_LEGACY_MANAGED_CONFIG="/etc/ssh/sshd_config.d/00-vps-hardening.conf"
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
RESET='\033[0m'

die() { printf '%b\n' "${RED}错误: $*${RESET}" >&2; exit 1; }
warn() { printf '%b\n' "${YELLOW}$*${RESET}"; }
ok() { printf '%b\n' "${GREEN}$*${RESET}"; }

unit_exists() { systemctl cat "$1" >/dev/null 2>&1; }

restore_file() {
    local existed=$1 backup_path=$2 target_path=$3
    if [[ "$existed" == "1" && -e "$backup_path" ]]; then
        mkdir -p "$(dirname "$target_path")"
        cp -a "$backup_path" "$target_path"
    else
        rm -f "$target_path"
    fi
}

restore_enabled_state() {
    local unit=$1 state=${2:-}
    unit_exists "$unit" || return 0
    case "$state" in
        enabled|enabled-runtime) systemctl enable "$unit" >/dev/null 2>&1 || true ;;
        disabled) systemctl disable "$unit" >/dev/null 2>&1 || true ;;
        *) : ;;
    esac
}

restore_active_state() {
    local unit=$1 was_active=${2:-0}
    unit_exists "$unit" || return 0
    if [[ "$was_active" == "1" ]]; then
        systemctl restart "$unit" >/dev/null 2>&1 || systemctl start "$unit" >/dev/null 2>&1 || true
    else
        systemctl stop "$unit" >/dev/null 2>&1 || true
    fi
}

backup_format() {
    local dir=$1
    local manifest="$dir/manifest.env"
    [[ -f "$manifest" ]] || { printf 'unknown'; return; }
    local v
    v=$(grep -E '^BACKUP_FORMAT_VERSION=' "$manifest" | head -n1 | cut -d= -f2- | tr -d "'\"" || true)
    printf '%s' "${v:-legacy}"
}

list_backups() {
    local -a dirs=()
    mapfile -t dirs < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r)
    [[ ${#dirs[@]} -gt 0 ]] || die "没有可用备份。"

    printf '%b\n' "${CYAN}可用备份：${RESET}"
    local i dir fmt
    for i in "${!dirs[@]}"; do
        dir=${dirs[$i]}
        fmt=$(backup_format "$BACKUP_ROOT/$dir")
        printf '  %2d) %s  [format=%s]\n' "$((i+1))" "$dir" "$fmt"
    done
}

select_backup() {
    local mode=${1:-interactive}
    local -a dirs=()
    mapfile -t dirs < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r)
    [[ ${#dirs[@]} -gt 0 ]] || die "没有可用备份。"

    if [[ "$mode" == "latest" ]]; then
        local dir
        for dir in "${dirs[@]}"; do
            if [[ "$(backup_format "$BACKUP_ROOT/$dir")" == "2" ]]; then
                BACKUP_DIR="$BACKUP_ROOT/$dir"
                return
            fi
        done
        die "没有可用的 v2 (format=2) 备份。"
    fi

    list_backups
    local choice
    while true; do
        read -r -p "请选择要恢复的备份 [默认: 1]: " choice
        choice=${choice:-1}
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#dirs[@]} )); then
            BACKUP_DIR="$BACKUP_ROOT/${dirs[$((choice-1))]}"
            return
        fi
        warn "请输入 1-${#dirs[@]} 之间的序号。"
    done
}

print_help() {
    cat <<EOF_HELP
VPS Security Hardening rollback v${HARDENING_VERSION}

用法：
  bash rollback.sh             # 交互选择历史备份
  bash rollback.sh --latest    # 使用最新备份
  bash rollback.sh --list      # 仅列出备份
  bash rollback.sh --help

仅支持 BACKUP_FORMAT_VERSION=2 的备份。
EOF_HELP
}

restore_ssh() {
    restore_file "${SSH_CONFIG_EXISTED:-0}" "$BACKUP_DIR/sshd_config" "$SSH_CONFIG"

    # v2.2.2+ stores the managed file outside sshd_config.d. Older v2 backups stored it as
    # 00-vps-hardening.conf inside sshd_config.d, so restore both layouts safely.
    if [[ -e "$BACKUP_DIR/sshd_config.vps-hardening.conf" || -n "${SSH_LEGACY_MANAGED_CONFIG_EXISTED+x}" ]]; then
        restore_file "${SSH_MANAGED_CONFIG_EXISTED:-0}" "$BACKUP_DIR/sshd_config.vps-hardening.conf" "$SSH_MANAGED_CONFIG"
        restore_file "${SSH_LEGACY_MANAGED_CONFIG_EXISTED:-0}" "$BACKUP_DIR/00-vps-hardening.conf" "$SSH_LEGACY_MANAGED_CONFIG"
    else
        # Legacy v2.0-v2.2.1 backup: SSH_MANAGED_CONFIG_EXISTED referred to the drop-in path.
        rm -f "$SSH_MANAGED_CONFIG"
        restore_file "${SSH_MANAGED_CONFIG_EXISTED:-0}" "$BACKUP_DIR/00-vps-hardening.conf" "$SSH_LEGACY_MANAGED_CONFIG"
    fi

    restore_file "${SSH_BANNER_EXISTED:-0}" "$BACKUP_DIR/banner.vps-hardening" "$SSH_BANNER"

    /usr/sbin/sshd -t || die "恢复后的 SSH 配置未通过 sshd -t。为避免失联，没有切换 SSH listener。请保持当前会话并检查 $SSH_CONFIG。"

    local service_unit=${SSH_SERVICE_UNIT_OLD:-ssh.service}
    local socket_unit=${SSH_SOCKET_UNIT_OLD:-ssh.socket}

    systemctl daemon-reload >/dev/null 2>&1 || true
    restore_enabled_state "$service_unit" "${SSH_SERVICE_WAS_ENABLED_STATE:-}"
    restore_enabled_state "$socket_unit" "${SSH_SOCKET_WAS_ENABLED_STATE:-}"

    if [[ "${SSH_SOCKET_WAS_ACTIVE:-0}" == "1" ]] && unit_exists "$socket_unit"; then
        systemctl stop "$service_unit" >/dev/null 2>&1 || true
        systemctl restart "$socket_unit" >/dev/null 2>&1 || systemctl start "$socket_unit" >/dev/null 2>&1 || die "无法恢复 $socket_unit。"
    elif [[ "${SSH_SERVICE_WAS_ACTIVE:-0}" == "1" ]] && unit_exists "$service_unit"; then
        systemctl stop "$socket_unit" >/dev/null 2>&1 || true
        systemctl restart "$service_unit" >/dev/null 2>&1 || systemctl start "$service_unit" >/dev/null 2>&1 || die "无法恢复 $service_unit。"
    else
        warn "备份显示执行前 SSH service/socket 都不是 active；已恢复配置文件，但没有主动启动新的 SSH listener。"
    fi
}


restore_root_authorized_keys() {
    # v2.0 备份没有 ROOT_AUTH_KEYS_TRACKED；为兼容旧备份，缺少该标记时完全不碰 authorized_keys。
    [[ "${ROOT_AUTH_KEYS_TRACKED:-0}" == "1" ]] || return 0

    restore_file "${ROOT_AUTH_KEYS_EXISTED:-0}" "$BACKUP_DIR/root-authorized_keys" "$ROOT_AUTH_KEYS"

    if [[ "${ROOT_SSH_DIR_EXISTED:-0}" == "1" ]]; then
        [[ -d "$ROOT_SSH_DIR" ]] || mkdir -p "$ROOT_SSH_DIR"
        [[ -n "${ROOT_SSH_DIR_MODE:-}" ]] && chmod "$ROOT_SSH_DIR_MODE" "$ROOT_SSH_DIR" 2>/dev/null || true
        if [[ -n "${ROOT_SSH_DIR_UID:-}" && -n "${ROOT_SSH_DIR_GID:-}" ]]; then
            chown "${ROOT_SSH_DIR_UID}:${ROOT_SSH_DIR_GID}" "$ROOT_SSH_DIR" 2>/dev/null || true
        fi
    elif [[ -d "$ROOT_SSH_DIR" ]] && [[ -z "$(find "$ROOT_SSH_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
        rmdir "$ROOT_SSH_DIR" 2>/dev/null || true
    fi
}

restore_ufw() {
    if [[ "${UFW_DIR_EXISTED:-0}" == "1" && -d "$BACKUP_DIR/ufw" ]]; then
        rm -rf /etc/ufw
        cp -a "$BACKUP_DIR/ufw" /etc/ufw
    fi
    # 如果执行前没有安装 UFW，就没有 /etc/default/ufw；由于回滚不卸载新装软件包，
    # 此时保留软件包自己的默认文件，仅把 UFW 禁用，不删除其 package config。
    if [[ "${UFW_DEFAULTS_EXISTED:-0}" == "1" && -e "$BACKUP_DIR/default-ufw" ]]; then
        cp -a "$BACKUP_DIR/default-ufw" "$UFW_DEFAULTS"
    fi

    if command -v ufw >/dev/null 2>&1; then
        if [[ "${UFW_WAS_ACTIVE:-0}" == "1" ]]; then
            ufw --force enable >/dev/null
            ufw reload >/dev/null 2>&1 || true
        else
            ufw --force disable >/dev/null 2>&1 || true
        fi
    fi
}

restore_fail2ban() {
    restore_file "${FAIL2BAN_CONFIG_EXISTED:-0}" "$BACKUP_DIR/99-vps-hardening.local" "$FAIL2BAN_CONFIG"

    if unit_exists fail2ban.service; then
        if [[ "${FAIL2BAN_WAS_INSTALLED:-0}" == "0" ]]; then
            systemctl disable fail2ban.service >/dev/null 2>&1 || true
        else
            restore_enabled_state fail2ban.service "${FAIL2BAN_WAS_ENABLED_STATE:-}"
        fi
        if [[ "${FAIL2BAN_WAS_ACTIVE:-0}" == "1" ]]; then
            fail2ban-client -t >/dev/null 2>&1 || warn "恢复后的 Fail2ban 配置测试有警告，请人工检查。"
            systemctl restart fail2ban.service >/dev/null 2>&1 || warn "Fail2ban 恢复后未能正常重启。"
        else
            systemctl stop fail2ban.service >/dev/null 2>&1 || true
        fi
    fi
}

restore_auto_updates() {
    restore_file "${AUTO_UPGRADES_CONFIG_EXISTED:-0}" "$BACKUP_DIR/99-vps-hardening-periodic" "$AUTO_UPGRADES_CONFIG"

    restore_enabled_state apt-daily.timer "${APT_DAILY_TIMER_ENABLED_STATE:-}"
    restore_enabled_state apt-daily-upgrade.timer "${APT_UPGRADE_TIMER_ENABLED_STATE:-}"
    restore_active_state apt-daily.timer "${APT_DAILY_TIMER_ACTIVE:-0}"
    restore_active_state apt-daily-upgrade.timer "${APT_UPGRADE_TIMER_ACTIVE:-0}"
}

restore_time_settings() {
    if [[ -n "${TIMEZONE_OLD:-}" ]]; then
        timedatectl set-timezone "$TIMEZONE_OLD" || warn "无法恢复原时区 $TIMEZONE_OLD。"
    fi

    if [[ "${CHRONY_WAS_INSTALLED:-0}" == "0" ]]; then
        unit_exists chrony.service && systemctl disable chrony.service >/dev/null 2>&1 || true
    else
        restore_enabled_state chrony.service "${CHRONY_WAS_ENABLED_STATE:-}"
    fi
    restore_enabled_state systemd-timesyncd.service "${TIMESYNCD_WAS_ENABLED_STATE:-}"
    restore_enabled_state ntpsec.service "${NTPSEC_WAS_ENABLED_STATE:-}"
    restore_enabled_state ntp.service "${NTP_WAS_ENABLED_STATE:-}"
    restore_active_state chrony.service "${CHRONY_WAS_ACTIVE:-0}"
    restore_active_state systemd-timesyncd.service "${TIMESYNCD_WAS_ACTIVE:-0}"
    restore_active_state ntpsec.service "${NTPSEC_WAS_ACTIVE:-0}"
    restore_active_state ntp.service "${NTP_WAS_ACTIVE:-0}"
}

main() {
    [[ $(id -u) -eq 0 ]] || die "必须使用 root 用户执行。"

    case "${1:-}" in
        --help|-h) print_help; exit 0 ;;
    esac

    [[ -d "$BACKUP_ROOT" ]] || die "未找到备份目录 $BACKUP_ROOT。"

    case "${1:-}" in
        --list) list_backups; exit 0 ;;
        --latest) select_backup latest ;;
        "") [[ -t 0 ]] || die "交互选择备份需要 TTY；无人值守可使用 --latest。"; select_backup interactive ;;
        *) die "未知参数: $1" ;;
    esac

    local fmt
    fmt=$(backup_format "$BACKUP_DIR")
    [[ "$fmt" == "2" ]] || die "所选备份格式为 ${fmt}，v2 rollback 只恢复 format=2 的备份。"

    # shellcheck disable=SC1090
    . "$BACKUP_DIR/manifest.env"

    printf '%b\n' "${YELLOW}将从以下 v2 备份恢复配置：${RESET}"
    printf '  %s\n\n' "$BACKUP_DIR"
    printf '%s\n' "将恢复：SSH 配置与 listener 模式、UFW、Fail2ban drop-in、自动更新配置/timers、时区和时间同步服务状态。"
    if [[ "${ROOT_AUTH_KEYS_TRACKED:-0}" == "1" ]]; then
        printf '%s\n' "同时恢复：本次执行前的 /root/.ssh/authorized_keys 状态。"
    fi
    printf '%s\n' "不会恢复：旧 root 密码、已安装的软件包、已升级的软件包版本。"
    printf '%s\n' "如果本次运行来自远程 SSH，请务必保持当前会话。"

    local answer
    read -r -p "确认回滚？请输入 ROLLBACK: " answer
    [[ "$answer" == "ROLLBACK" ]] || die "用户取消。"

    restore_root_authorized_keys
    restore_ssh
    restore_ufw
    restore_fail2ban
    restore_auto_updates
    restore_time_settings

    printf '\n%b\n' "${GREEN}配置回滚完成。${RESET}"
    printf '%s\n' "来源备份: $BACKUP_DIR"
    if [[ "${AUTH_MODE_NEW:-password}" == "password" ]]; then
        printf '%b\n' "${YELLOW}root 密码不会回滚。请继续保留当前会话，并在第二终端验证恢复后的 SSH 登录方式。${RESET}"
    else
        printf '%b\n' "${YELLOW}authorized_keys 已按备份恢复。请继续保留当前会话，并在第二终端验证恢复后的 SSH 登录方式。${RESET}"
    fi
}

main "$@"

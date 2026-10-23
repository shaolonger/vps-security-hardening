#!/usr/bin/env bash
# VPS Security Hardening rollback v2.3.0; compatible with manifest format 2 (v2.2.x).
set -Eeuo pipefail
umask 077

VERSION='2.3.0'
ROOT='/root/vps-hardening-backups'
BACKUP_DIR=''
SSH_CONFIG='/etc/ssh/sshd_config'
SSH_MANAGED='/etc/ssh/sshd_config.vps-hardening.conf'
SSH_LEGACY='/etc/ssh/sshd_config.d/00-vps-hardening.conf'
SSH_BANNER='/etc/ssh/banner.vps-hardening'
KEYS='/root/.ssh/authorized_keys'
F2B_CONFIG='/etc/fail2ban/jail.d/99-vps-hardening.local'
APT_CONFIG='/etc/apt/apt.conf.d/99-vps-hardening-periodic'

die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
log() { printf '[INFO] %s\n' "$*"; }
unit_state() { systemctl is-enabled "$1" 2>/dev/null || true; }
unit_load() { systemctl show "$1" -p LoadState --value 2>/dev/null || true; }
unit_present() { local v; v=$(unit_load "$1"); [[ -n "$v" && "$v" != not-found ]]; }

restore_file() {
    local existed=$1 src=$2 dest=$3
    if [[ "$existed" == 1 && -e "$BACKUP_DIR/$src" ]]; then
        mkdir -p -- "$(dirname "$dest")"
        cp -a -- "$BACKUP_DIR/$src" "$dest"
    else
        rm -f -- "$dest"
    fi
}
restore_enabled() {
    local name=$1 state=$2
    unit_present "$name" || return 0
    case "$state" in
        enabled|enabled-runtime) systemctl enable "$name" || warn "无法启用 $name";;
        disabled) systemctl disable "$name" || warn "无法禁用 $name";;
        *) : ;;
    esac
}
restore_active() {
    local name=$1 was=$2
    unit_present "$name" || return 0
    if [[ "$was" == 1 ]]; then
        systemctl restart "$name" || systemctl start "$name" || warn "无法启动 $name"
    else
        systemctl stop "$name" || warn "无法停止 $name"
    fi
}

list_dirs() {
    [[ -d "$ROOT" ]] || die "未找到备份目录 $ROOT。"
    find "$ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r
}
choose_dir() {
    local mode=$1 name idx=0 num
    local -a dirs=()
    mapfile -t dirs < <(list_dirs)
    ((${#dirs[@]} > 0)) || die '没有可用备份。'
    for name in "${dirs[@]}"; do
        idx=$((idx+1))
        printf '%2d) %s\n' "$idx" "$name"
    done
    [[ "$mode" != list ]] || exit 0
    if [[ "$mode" == latest ]]; then
        for name in "${dirs[@]}"; do
            if [[ -f "$ROOT/$name/manifest.env" ]] && grep -Eq '^BACKUP_FORMAT_VERSION=2$' "$ROOT/$name/manifest.env"; then
                BACKUP_DIR="$ROOT/$name"; return
            fi
        done
        die '未找到格式为 2 的备份。'
    fi
    [[ -t 0 ]] || die '交互选择需要终端。'
    while :; do
        read -r -p '选择备份 [默认1]: ' num || die '读取失败。'
        num=${num:-1}
        if [[ "$num" =~ ^[0-9]+$ ]] && ((10#$num>=1 && 10#$num<=${#dirs[@]})); then
            num=$((10#$num))
            BACKUP_DIR="$ROOT/${dirs[$((num-1))]}"; return
        fi
        warn '请输入有效序号。'
    done
}

restore_ssh() {
    log '恢复 SSH 配置（不恢复 root 密码）'
    restore_file "${SSH_CONFIG_EXISTED:-0}" sshd_config "$SSH_CONFIG"
    if [[ -e "$BACKUP_DIR/sshd_config.vps-hardening.conf" || -n "${SSH_LEGACY_MANAGED_CONFIG_EXISTED+x}" ]]; then
        restore_file "${SSH_MANAGED_CONFIG_EXISTED:-0}" sshd_config.vps-hardening.conf "$SSH_MANAGED"
        restore_file "${SSH_LEGACY_MANAGED_CONFIG_EXISTED:-0}" 00-vps-hardening.conf "$SSH_LEGACY"
    else
        rm -f "$SSH_MANAGED"
        restore_file "${SSH_MANAGED_CONFIG_EXISTED:-0}" 00-vps-hardening.conf "$SSH_LEGACY"
    fi
    restore_file "${SSH_BANNER_EXISTED:-0}" banner.vps-hardening "$SSH_BANNER"
    /usr/sbin/sshd -t || die '回滚后的 sshd 配置检查失败；没有重启 SSH，请保持当前会话。'
    systemctl daemon-reload
    local ssh_unit=${SSH_SERVICE_UNIT_OLD:-ssh.service} socket_unit=${SSH_SOCKET_UNIT_OLD:-ssh.socket}
    restore_enabled "$ssh_unit" "${SSH_SERVICE_WAS_ENABLED_STATE:-}"
    restore_enabled "$socket_unit" "${SSH_SOCKET_WAS_ENABLED_STATE:-}"
    if [[ "${SSH_SOCKET_WAS_ACTIVE:-0}" == 1 ]] && unit_present "$socket_unit"; then
        systemctl stop "$ssh_unit" || true
        systemctl restart "$socket_unit" || systemctl start "$socket_unit" || die '恢复 ssh.socket 失败。'
    elif [[ "${SSH_SERVICE_WAS_ACTIVE:-0}" == 1 ]]; then
        systemctl stop "$socket_unit" >/dev/null 2>&1 || true
        systemctl restart "$ssh_unit" || systemctl start "$ssh_unit" || die '恢复 SSH 服务失败。'
    else
        warn '原 SSH service/socket 都不是 active，未自动启动新监听器。'
    fi
}
restore_keys() {
    [[ "${ROOT_AUTH_KEYS_TRACKED:-0}" == 1 ]] || return 0
    log '恢复原 root authorized_keys'
    restore_file "${ROOT_AUTH_KEYS_EXISTED:-0}" root-authorized_keys "$KEYS"
    if [[ "${ROOT_SSH_DIR_EXISTED:-0}" == 1 ]]; then
        mkdir -p /root/.ssh
        [[ -z "${ROOT_SSH_DIR_MODE:-}" ]] || chmod "$ROOT_SSH_DIR_MODE" /root/.ssh
        if [[ -n "${ROOT_SSH_DIR_UID:-}" && -n "${ROOT_SSH_DIR_GID:-}" ]]; then
            chown "${ROOT_SSH_DIR_UID}:${ROOT_SSH_DIR_GID}" /root/.ssh
        fi
    elif [[ -d /root/.ssh && -z "$(find /root/.ssh -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        rmdir /root/.ssh || true
    fi
}
restore_ufw() {
    log '恢复 UFW 规则'
    if [[ "${UFW_DIR_EXISTED:-0}" == 1 && -d "$BACKUP_DIR/ufw" ]]; then
        rm -rf /etc/ufw
        cp -a "$BACKUP_DIR/ufw" /etc/ufw
    fi
    [[ "${UFW_DEFAULTS_EXISTED:-0}" != 1 ]] || restore_file 1 default-ufw /etc/default/ufw
    if command -v ufw >/dev/null 2>&1; then
        if [[ "${UFW_WAS_ACTIVE:-0}" == 1 ]]; then
            ufw --force enable || warn 'UFW 恢复后未能启用。'
            ufw reload || warn 'UFW reload 失败。'
        else
            ufw --force disable || warn 'UFW disable 失败。'
        fi
    fi
}
restore_fail2ban() {
    log '恢复 Fail2ban'
    restore_file "${FAIL2BAN_CONFIG_EXISTED:-0}" 99-vps-hardening.local "$F2B_CONFIG"
    if unit_present fail2ban.service; then
        if [[ "${FAIL2BAN_WAS_INSTALLED:-0}" != 1 ]]; then
            systemctl disable --now fail2ban.service || true
        else
            restore_enabled fail2ban.service "${FAIL2BAN_WAS_ENABLED_STATE:-}"
            restore_active fail2ban.service "${FAIL2BAN_WAS_ACTIVE:-0}"
        fi
    fi
}
restore_apt() {
    log '恢复 APT 自动更新配置及 timer/service 状态'
    restore_file "${AUTO_UPGRADES_CONFIG_EXISTED:-0}" 99-vps-hardening-periodic "$APT_CONFIG"
    local name prefix orig_state
    # v2.3 records four units (including masked vendor presets); v2.2.x records timers only.
    for name in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service; do
        prefix="APT_UNIT_STATE_${name//[-.]/_}"
        orig_state=${!prefix:-}
        if [[ -z "$orig_state" ]]; then
            case "$name" in
                apt-daily.timer) orig_state=${APT_DAILY_TIMER_ENABLED_STATE:-};;
                apt-daily-upgrade.timer) orig_state=${APT_UPGRADE_TIMER_ENABLED_STATE:-};;
                *) continue;;
            esac
        fi
        if [[ "$orig_state" == masked || "$orig_state" == masked-runtime ]]; then
            systemctl stop "$name" >/dev/null 2>&1 || true
            if [[ "$orig_state" == masked-runtime ]]; then
                systemctl mask --runtime "$name" || warn "无法恢复 $name masked-runtime 状态。"
            else
                systemctl mask "$name" || warn "无法恢复 $name masked 状态。"
            fi
        else
            if [[ "$(unit_state "$name")" == masked || "$(unit_state "$name")" == masked-runtime ]]; then
                systemctl unmask "$name" || warn "无法解除 $name 当前屏蔽。"
            fi
            restore_enabled "$name" "$orig_state"
        fi
    done
    systemctl daemon-reload
    local timer
    for timer in apt-daily.timer apt-daily-upgrade.timer; do
        case "$(unit_state "$timer")" in masked|masked-runtime) continue;; esac
        if [[ "$timer" == apt-daily.timer ]]; then
            restore_active "$timer" "${APT_DAILY_TIMER_ACTIVE:-0}"
        else
            restore_active "$timer" "${APT_UPGRADE_TIMER_ACTIVE:-0}"
        fi
    done
}
restore_time() {
    log '恢复时区与原时间同步服务状态'
    if [[ -n "${TIMEZONE_OLD:-}" ]]; then
        timedatectl set-timezone "$TIMEZONE_OLD" || warn '时区恢复失败。'
    fi
    local name prefix active_key enabled_key
    for name in chrony.service systemd-timesyncd.service ntpsec.service ntp.service; do
        case "$name" in
            chrony.service) prefix=CHRONY;;
            systemd-timesyncd.service) prefix=TIMESYNCD;;
            ntpsec.service) prefix=NTPSEC;;
            ntp.service) prefix=NTP;;
        esac
        enabled_key="${prefix}_WAS_ENABLED_STATE"
        active_key="${prefix}_WAS_ACTIVE"
        restore_enabled "$name" "${!enabled_key:-}"
        restore_active "$name" "${!active_key:-0}"
    done
}

main() {
    (( EUID == 0 )) || die '必须使用 root。'
    case "${1:-}" in
        --help|-h)
            printf 'rollback.sh v%s\n用法：--list | --latest | (交互选择)\n' "$VERSION"; exit 0;;
        --list) choose_dir list;;
        --latest) choose_dir latest;;
        '') choose_dir interactive;;
        *) die "未知参数：$1";;
    esac
    [[ -f "$BACKUP_DIR/manifest.env" ]] || die '备份 manifest 缺失。'
    [[ "$(stat -c %u "$BACKUP_DIR")" == 0 ]] || die '备份目录不是 root 所有。'
    # shellcheck disable=SC1090
    source "$BACKUP_DIR/manifest.env"
    [[ "${BACKUP_FORMAT_VERSION:-}" == 2 ]] || die '仅支持 format=2 的备份。'
    printf '将恢复：%s\n' "$BACKUP_DIR"
    warn '这会恢复旧的 SSH、UFW、Fail2ban、APT 配置；不会恢复 root 密码/旧软件包版本。'
    warn '请确保有 VPS 控制台或保留第二个 SSH 终端。'
    local answer
    read -r -p '确认回滚，请输入 ROLLBACK: ' answer || die '读取失败。'
    [[ "$answer" == ROLLBACK ]] || die '用户取消。'
    restore_keys
    restore_ssh
    restore_ufw
    restore_fail2ban
    restore_apt
    restore_time
    log '回滚完成。请在另一终端验证 SSH 和代理端口。'
}
main "$@"

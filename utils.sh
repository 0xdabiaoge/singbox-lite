#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 打印消息函数
_info() { echo -e "${CYAN}[信息] $1${NC}"; }
_success() { echo -e "${GREEN}[成功] $1${NC}"; }
_warn() { echo -e "${YELLOW}[注意] $1${NC}"; }
_warning() { _warn "$1"; } # 别名兼容
_error() { echo -e "${RED}[错误] $1${NC}"; }

# 检查 root 权限
_check_root() {
    if [[ $EUID -ne 0 ]]; then
        _error "此脚本必须以 root 权限运行。"
        exit 1
    fi
}

export -f _info _success _warn _warning _error

# URL 解码与编码
_url_decode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}
_url_encode() {
    local LC_ALL=C
    local string="${1}"
    local length="${#string}"
    local res=""
    for (( i = 0; i < length; i++ )); do
        local c="${string:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) res="${res}${c}" ;;
            *)
                # 关键修复：某些环境下 printf "'$c" 会输出 4 位 16 进制（如 DFE5），
                # 我们强制只取最后两位，确保符合 %XX 格式。
                local hex=$(printf '%02X' "'$c")
                res="${res}%${hex: -2}"
                ;;
        esac
    done
    echo "${res}"
}
export -f _url_decode _url_encode

# 获取公网 IP (增加本地缓存以减少网络请求)
_get_public_ip() {
    if [ -n "$GLOBAL_SERVER_IP" ]; then
        echo "$GLOBAL_SERVER_IP"
        return
    fi
    local ip=$(timeout 5 curl -s4 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s4 --max-time 2 ipinfo.io/ip 2>/dev/null)
    if [ -z "$ip" ]; then
        ip=$(timeout 5 curl -s6 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s6 --max-time 2 ipinfo.io/ip 2>/dev/null)
    fi
    export GLOBAL_SERVER_IP="$ip"
    echo "$ip"
}
_init_server_ip() {
    export server_ip=$(_get_public_ip)
}

# 检查端口是否被占用
_check_port_occupied() {
    local port=$1
    if command -v ss &>/dev/null; then
        ss -tuln | grep -q ":${port} "
    elif command -v netstat &>/dev/null; then
        netstat -tuln | grep -q ":${port} "
    else
        # 兜底：尝试使用 lsof 或直接 bind 测试 (暂用 false 认为未占用，因为主脚本已预装 iproute2/netstat)
        false
    fi
}
export -f _check_port_occupied

# 系统环境检测 (Systemd vs OpenRC)
_detect_init_system() {
    if [ -f /sbin/openrc-run ] || command -v rc-service &>/dev/null; then
        export INIT_SYSTEM="openrc"
        export SERVICE_FILE="/etc/init.d/sing-box"
    elif command -v systemctl &>/dev/null; then
        # 兼容一些受限环境，通过进程 1 判断
        if [ -d "/run/systemd/system" ] || [ -f "/proc/1/comm" ] && grep -q "systemd" /proc/1/comm 2>/dev/null; then
            export INIT_SYSTEM="systemd"
            export SERVICE_FILE="/etc/systemd/system/sing-box.service"
        else
            export INIT_SYSTEM="systemd"
            export SERVICE_FILE="/etc/systemd/system/sing-box.service"
        fi
    else
        export INIT_SYSTEM="unknown"
        export SERVICE_FILE=""
    fi
}

# 安装 yq 工具 (自动适配架构)
_install_yq() {
    local YQ_BIN="/usr/local/bin/yq"
    if ! command -v yq &>/dev/null; then
        _info "正在安装 yq..."
        local arch=$(uname -m)
        case $arch in
            x86_64|amd64) arch='amd64' ;;
            aarch64|arm64) arch='arm64' ;;
            armv7l) arch='arm' ;;
            *) _error "不支持的架构: $arch"; return 1 ;;
        esac
        wget -qO "$YQ_BIN" "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$arch"
        chmod +x "$YQ_BIN"
    fi
}

# 智能保存 iptables 规则
_save_iptables_rules() {
    [ -z "$INIT_SYSTEM" ] && _detect_init_system
    mkdir -p /etc/iptables 2>/dev/null
    if [ "$INIT_SYSTEM" == "openrc" ]; then
        iptables-save > /etc/iptables/rules-save 2>/dev/null
        rc-update add iptables default 2>/dev/null
    elif [ "$INIT_SYSTEM" == "systemd" ]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        if command -v apt-get &>/dev/null && ! dpkg -l | grep -q iptables-persistent 2>/dev/null; then
            _pkg_install iptables-persistent
        fi
    fi
    _success "Iptables 规则已持久化。"
}

# 原子修改 JSON 文件
_atomic_modify_json() {
    local file="$1"
    local filter="$2"
    [ ! -f "$file" ] && return 1
    local tmp="${file}.tmp"
    if jq "$filter" "$file" > "$tmp"; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
        return 1
    fi
}

# 统一写入 Inbound
_add_inbound_to_config() {
    local config="$1"
    local inbound_json="$2"
    local tag=$(echo "$inbound_json" | jq -r .tag)
    if jq -e ".inbounds[] | select(.tag == \"$tag\")" "$config" >/dev/null 2>&1; then
        _error "Tag '$tag' 已存在。"
        return 1
    fi
    _atomic_modify_json "$config" ".inbounds += [$inbound_json]"
}
# 内存回收机制 (GOMEMLIMIT 计算)
_get_mem_limit() {
    local total_mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    local mem_limit_mb=$((total_mem_mb * 95 / 100))
    local reserved_mb=$((total_mem_mb - mem_limit_mb))
    if [ "$reserved_mb" -lt 40 ]; then mem_limit_mb=$((total_mem_mb - 40)); fi
    [ "$mem_limit_mb" -lt 10 ] && mem_limit_mb=10
    echo "$mem_limit_mb"
}
export -f _get_mem_limit

# 统一服务管理
_manage_service() {
    local action="$1"
    [ -z "$INIT_SYSTEM" ] && _detect_init_system
    
    [ "$action" == "status" ] || _info "正在使用 ${INIT_SYSTEM} 执行: $action..."
    case "$INIT_SYSTEM" in
        systemd)
            if [ "$action" == "status" ]; then systemctl status sing-box --no-pager -l; return; fi
            systemctl "$action" sing-box
            ;;
        openrc)
            if [ "$action" == "status" ]; then rc-service sing-box status; return; fi
            rc-service sing-box "$action"
            ;;
        *) _error "不支持的服务管理系统" ;;
    esac
    [ "$action" != "status" ] && _success "sing-box 服务已 $action"
}
export -f _manage_service
# 智能包管理安装器 (Smart Package Manager)
# 解决小内存 VPS 上 apt-get update 导致 OOM/死机的问题
_pkg_install() {
    local pkgs="$*"
    [ -z "$pkgs" ] && return 0

    if command -v apk &>/dev/null; then
        # Alpine: 使用 --no-cache 保持轻量
        apk add --no-cache $pkgs >/dev/null 2>&1
    elif command -v apt-get &>/dev/null; then
        # Debian/Ubuntu: 
        # 1. 尝试直接安装 (防止在 128MB 机器上 update 导致内存溢出)
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >/dev/null 2>&1; then
            _info "首次直接安装失败，尝试微核查索引后重试..."
            # 2. 只有失败后才尝试 update
            apt-get update -qq >/dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >/dev/null 2>&1
        fi
    elif command -v yum &>/dev/null; then
        yum install -y $pkgs >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y $pkgs >/dev/null 2>&1
    fi
}
export -f _pkg_install

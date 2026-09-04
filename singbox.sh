#!/bin/bash

# 配置、元数据、私钥和临时文件默认仅 root 可读写。
umask 077

# 基础路径定义
export SCRIPT_VERSION="27"
export DEFAULT_SNI="www.amd.com"
export WS_EARLY_DATA_SIZE="2560"
export WS_EARLY_DATA_HEADER="Sec-WebSocket-Protocol"
SELF_SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SELF_SCRIPT_PATH")"
SINGBOX_DIR="/usr/local/etc/sing-box"
SINGBOX_FIXED_VERSION="1.13.21"
SINGBOX_CORE_LOCK_FILE="${SINGBOX_DIR}/core-version.lock"
GITHUB_RAW_BASE="https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main"
SCRIPT_UPDATE_URL="${GITHUB_RAW_BASE}/singbox.sh"

# --- 核心工具函数 ---

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'
ORANGE='\033[0;33m'

# 打印消息函数
_info() { echo -e "${CYAN}[信息] $1${NC}" >&2; }
_success() { echo -e "${GREEN}[成功] $1${NC}" >&2; }
_warn() { echo -e "${YELLOW}[注意] $1${NC}" >&2; }
_warning() { _warn "$1"; } # 别名兼容
_error() { echo -e "${RED}[错误] $1${NC}" >&2; }

# Podman 容器通常没有 NET_ADMIN，nftables 转发会由 advanced_relay.sh
# 自动降级到 sing-box 用户态转发。检测到该环境时不安装不会被使用的
# 可选包，避免 128M 容器在 apk 解包时触发 OOM。
_is_podman_environment() {
    [ -f /run/.containerenv ] && return 0
    grep -qaE 'libpod|podman' /proc/1/cgroup /proc/1/environ 2>/dev/null
}

# BusyBox flock 不支持 util-linux 的 -w 参数；两者都支持 -n。
# 使用短间隔轮询实现有界等待，保证 Alpine 与 Debian 共用同一套锁语义。
_flock_wait() {
    local fd="$1" timeout="${2:-30}" attempts i
    [[ "$fd" =~ ^[0-9]+$ && "$timeout" =~ ^[0-9]+$ ]] || return 1
    attempts=$((timeout * 10))
    for ((i = 0; i <= attempts; i++)); do
        flock -n "$fd" 2>/dev/null && return 0
        ((i < attempts)) && sleep 0.1
    done
    return 1
}

# 所有脚本组件约定使用同一把状态锁。外层事务持锁时会导出
# SINGBOXLITE_LOCK_HELD=1，避免原子写函数重复加锁造成父子死锁。
_with_state_lock() {
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" = "1" ]; then
        "$@"
        return $?
    fi
    if ! command -v flock &>/dev/null; then
        _error "缺少 flock，拒绝在无共享锁保护下修改配置；请先安装 util-linux。"
        return 1
    fi

    (
        mkdir -p "$SINGBOX_DIR" 2>/dev/null || exit 1
        exec 9>"${SINGBOX_DIR}/.singboxlite.lock" || exit 1
        if ! _flock_wait 9 30; then
            _error "等待 singbox-lite 状态锁超时，请稍后重试。"
            exit 1
        fi
        export SINGBOXLITE_LOCK_HELD=1
        "$@"
    )
}

_secure_state_permissions() {
    [ -d "$SINGBOX_DIR" ] && chmod 700 "$SINGBOX_DIR" 2>/dev/null || true
    local path
    for path in \
        "$CONFIG_FILE" "$CLASH_YAML_FILE" "$METADATA_FILE" "$ARGO_METADATA_FILE" \
        "${SINGBOX_DIR}/relay.json" "${SINGBOX_DIR}/relay_links.json" \
        "${SINGBOX_DIR}/relay_pf.json" "$SINGBOX_CORE_LOCK_FILE" "/usr/local/etc/xray/config.json" \
        "/usr/local/etc/xray/metadata.json"; do
        [ -f "$path" ] && chmod 600 "$path" 2>/dev/null || true
    done
    for path in "$SINGBOX_DIR"/*.key /usr/local/etc/xray/*.key; do
        [ -f "$path" ] && chmod 600 "$path" 2>/dev/null || true
    done
}

# 检查 root 权限
_check_root() {
    if [[ $EUID -ne 0 ]]; then
        _error "此脚本必须以 root 权限运行。"
        exit 1
    fi
}

# 编解码器 (纯 Bash 稳健实现)
_url_decode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}
_url_encode() {
    # [修复] 使用 jq 内建 @uri 过滤器，完美处理 UTF-8 多字节字符
    # jq 是必装依赖，@uri 以字节为单位执行标准 percent-encoding
    printf '%s' "$1" | jq -sRr @uri
}

_ws_path_with_early_data() {
    local ws_path="${1:-/}"
    if [[ "$ws_path" == *"ed="* ]]; then
        printf '%s' "$ws_path"
        return
    fi
    if [[ "$ws_path" == *"?"* ]]; then
        printf '%s&ed=%s' "$ws_path" "$WS_EARLY_DATA_SIZE"
    else
        printf '%s?ed=%s' "$ws_path" "$WS_EARLY_DATA_SIZE"
    fi
}

_cert_sha256_hex() {
    local cert_path="$1"
    [ -f "$cert_path" ] || return 1
    openssl x509 -in "$cert_path" -noout -fingerprint -sha256 2>/dev/null | \
        awk -F= 'NR==1 { gsub(":", "", $2); print tolower($2) }'
}

_tls_insecure_params() {
    local skip_verify="$1"
    local cert_path="$2"
    local insecure_param=""
    if [[ "$skip_verify" == "true" ]]; then
        local cert_pcs=$(_cert_sha256_hex "$cert_path")
        # Xray 已在 2026-06-01 后移除 allowInsecure；同时携带
        # insecure=1 与 pcs 会让新核心直接拒绝配置。能固定自签叶证书
        # 时只使用证书指纹，无法计算时才保留旧参数作为兼容兜底。
        if [ -n "$cert_pcs" ]; then
            insecure_param="&pcs=${cert_pcs}"
        else
            insecure_param="&insecure=1"
        fi
    fi
    printf '%s' "$insecure_param"
}

_append_pcs_to_tls_link() {
    local url="$1"
    local cert_path="$2"
    [ -n "$url" ] || return 0
    [[ "$url" == *"pcs="* ]] && { printf '%s' "$url"; return 0; }

    local cert_pcs=$(_cert_sha256_hex "$cert_path")
    [ -n "$cert_pcs" ] || { printf '%s' "$url"; return 0; }

    local body="$url"
    local fragment=""
    if [[ "$url" == *"#"* ]]; then
        body="${url%%#*}"
        fragment="#${url#*#}"
    fi

    local sep="&"
    [[ "$body" != *"?"* ]] && sep="?"
    printf '%s%s%s%s' "$body" "$sep" "pcs=${cert_pcs}" "$fragment"
}

_ss_base64_encode() {
    # Shadowsocks SIP002 规范要求 Base64 编码不带填充 (No Padding)
    printf '%s' "$1" | base64 | tr -d '\n\r ' | sed 's/=//g'
}

# 公网 IP 获取 (带全局缓存)
_get_public_ip() {
    [ -n "$server_ip" ] && [ "$server_ip" != "null" ] && { echo "$server_ip"; return; }
    local ip=$(timeout 5 curl -fsS4 --max-time 2 https://icanhazip.com 2>/dev/null || timeout 5 curl -fsS4 --max-time 2 https://ipinfo.io/ip 2>/dev/null)
    [ -z "$ip" ] && ip=$(timeout 5 curl -fsS6 --max-time 2 https://icanhazip.com 2>/dev/null || timeout 5 curl -fsS6 --max-time 2 https://ipinfo.io/ip 2>/dev/null)
    server_ip="$ip"
    echo "$ip"
}
_get_ip() { _get_public_ip; } # 别名兼容

# 系统环境检测
_detect_init_system() {
    if [ -f /sbin/openrc-run ] || command -v rc-service &>/dev/null; then
        export INIT_SYSTEM="openrc"
        export SERVICE_FILE="/etc/init.d/sing-box"
    elif command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        export INIT_SYSTEM="systemd"
        export SERVICE_FILE="/etc/systemd/system/sing-box.service"
    else
        export INIT_SYSTEM="direct"
        export SERVICE_FILE=""
    fi
}

# 端口占用检查
_check_port_occupied() {
    local port=$1
    local proto=${2:-tcp}
    if [[ "$proto" == "tcp" ]]; then
        if command -v ss &>/dev/null; then
            ss -lnpt | grep -q ":${port} " && return 0
        else
            netstat -lnpt | grep -q ":${port} " && return 0
        fi
    else
        if command -v ss &>/dev/null; then
            ss -lnpu | grep -q ":${port} " && return 0
        else
            netstat -lnpu | grep -q ":${port} " && return 0
        fi
    fi
    return 1
}

_is_pid_running_cmd() {
    local pid="$1"
    local pattern="$2"
    [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1 ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    if [ -r "/proc/${pid}/cmdline" ]; then
        tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | grep -Fq "$pattern"
    else
        ps -p "$pid" -o args= 2>/dev/null | grep -Fq "$pattern"
    fi
}

_is_pid_file_running_cmd() {
    local pid_file="$1"
    local pattern="$2"
    local pid
    [ -s "$pid_file" ] || return 1
    pid=$(cat "$pid_file" 2>/dev/null)
    _is_pid_running_cmd "$pid" "$pattern"
}

_prepare_singbox_runtime_pid() {
    local legacy_pid_file="/tmp/sing-box.pid"
    mkdir -p "$RUNTIME_DIR" || return 1
    chmod 700 "$RUNTIME_DIR" 2>/dev/null || return 1

    if _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
        rm -f -- "$legacy_pid_file"
        return 0
    fi
    rm -f -- "$PID_FILE"

    # 仅迁移能通过 cmdline 校验的旧 PID，绝不盲信 /tmp 中的内容。
    if _is_pid_file_running_cmd "$legacy_pid_file" "$SINGBOX_BIN"; then
        local legacy_pid
        legacy_pid=$(cat "$legacy_pid_file" 2>/dev/null)
        printf '%s\n' "$legacy_pid" > "$PID_FILE" || return 1
        chmod 600 "$PID_FILE" 2>/dev/null || return 1
    fi
    rm -f -- "$legacy_pid_file"
}

# 根据 inbound 类型判断其实际监听的传输层，并允许在改端口时排除自身
# 及自身的 HY2 原生 hop 子节点。
_check_port_in_singbox_file() {
    local file="$1" port="$2" proto="${3:-tcp}" exclude_tag="${4:-}"
    [ -s "$file" ] || return 1
    jq -e --argjson port "$port" --arg proto "$proto" --arg exclude "$exclude_tag" '
        def transports:
            if (.type == "hysteria2" or .type == "tuic") then ["udp"]
            elif (.type == "shadowsocks" or .type == "mixed") then ["tcp", "udp"]
            elif .type == "direct" then
                ((.network // "tcp") | if . == "tcp+udp" then ["tcp", "udp"] else [.] end)
            else ["tcp"] end;
        .inbounds[]?
        | select((.listen_port | tonumber?) == $port)
        | select($exclude == "" or (.tag != $exclude and ((.tag // "") | startswith($exclude + "-hop-") | not)))
        | select(transports | index($proto) != null)
    ' "$file" >/dev/null 2>&1
}

_check_port_in_xray_config() {
    local port="$1" proto="${2:-tcp}"
    local xray_config="/usr/local/etc/xray/config.json"
    [ -s "$xray_config" ] || return 1
    jq -e --argjson port "$port" --arg proto "$proto" '
        def transports:
            ((.streamSettings.network // .settings.network // "tcp") | ascii_downcase) as $network
            | if ($network == "quic" or $network == "udp") then ["udp"]
              elif ($network == "tcp,udp" or $network == "tcp+udp") then ["tcp", "udp"]
              elif .protocol == "shadowsocks" then ["tcp", "udp"]
              else ["tcp"] end;
        .inbounds[]?
        | select((.port | tonumber?) == $port)
        | select(transports | index($proto) != null)
    ' "$xray_config" >/dev/null 2>&1
}

_check_port_in_pf_metadata() {
    local port="$1" proto="${2:-tcp}"
    local pf_meta="${SINGBOX_DIR}/relay_pf.json"
    [ -s "$pf_meta" ] || return 1
    jq -e --arg port "$port" --arg proto "$proto" '
        to_entries[]?
        | select(.key == $port)
        | (.value.network // "tcp") as $network
        | select($network == $proto or $network == "tcp+udp")
    ' "$pf_meta" >/dev/null 2>&1
}

# 兼容旧调用；默认检查主 sing-box 的 TCP 监听。
_check_port_in_config() {
    local port="$1" proto="${2:-tcp}" exclude_tag="${3:-}"
    _check_port_in_singbox_file "$CONFIG_FILE" "$port" "$proto" "$exclude_tag"
}

# 综合端口碰撞检测：系统监听、主配置、中转配置、Xray、端口转发和
# HY2 跳跃范围统一检查；TCP/UDP 分开判断。
_check_port_conflict() {
    local port="$1" requested_proto="${2:-tcp}" silent="${3:-false}" exclude_tag="${4:-}" skip_system="${5:-false}"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        [ "$silent" != "true" ] && _error "端口 ${port} 无效，应为 1-65535。"
        return 0
    fi

    local protocols=""
    case "$requested_proto" in
        tcp) protocols="tcp" ;;
        udp) protocols="udp" ;;
        tcp+udp|udp+tcp|both) protocols="tcp udp" ;;
        *) protocols="$requested_proto" ;;
    esac

    local proto source
    for proto in $protocols; do
        source=""
        if _check_port_in_singbox_file "$CONFIG_FILE" "$port" "$proto" "$exclude_tag"; then
            source="主 sing-box 配置"
        elif _check_port_in_singbox_file "${SINGBOX_DIR}/relay.json" "$port" "$proto" ""; then
            source="中转 relay.json"
        elif _check_port_in_xray_config "$port" "$proto"; then
            source="Xray 配置"
        elif _check_port_in_pf_metadata "$port" "$proto"; then
            source="端口转发规则"
        elif [ "$skip_system" != "true" ] && _check_port_occupied "$port" "$proto"; then
            source="系统监听"
        fi
        if [ -n "$source" ]; then
            [ "$silent" != "true" ] && _error "${proto^^} 端口 ${port} 已被${source}占用。"
            return 0
        fi

        if [ "$proto" = "udp" ]; then
            local hop_conflict
            hop_conflict=$(_find_udp_hop_conflict_in_range "$port" "$port" "$exclude_tag")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                [ "$silent" != "true" ] && _error "UDP 端口 ${port} 落在已有 HY2 端口跳跃范围 ${c_range} 内（${c_name}, ${c_tag}, ${c_mode}）。"
                return 0
            fi
        fi
    done
    return 1
}

_find_pf_udp_conflict_in_range() {
    local start="$1" end="$2"
    local pf_meta="${SINGBOX_DIR}/relay_pf.json"
    [ -f "$pf_meta" ] || return 1
    jq -r --argjson start "$start" --argjson end "$end" '
        to_entries[]
        | (.key | tonumber?) as $port
        | select($port != null and $port >= $start and $port <= $end)
        | select(.value.network == "udp" or .value.network == "tcp+udp")
        | [
            .key,
            (.value.name // "端口转发"),
            (.value.network_display // .value.network // "UDP"),
            ((.value.target_addr // "") + ":" + ((.value.target_port // "") | tostring))
          ]
        | @tsv
    ' "$pf_meta" 2>/dev/null | head -n 1
}

_find_udp_hop_conflict_in_range() {
    local start="$1" end="$2" exclude_tag="${3:-}"
    local conflict=""
    if [ -f "$METADATA_FILE" ]; then
        conflict=$(jq -r --argjson start "$start" --argjson end "$end" --arg exclude "$exclude_tag" '
            to_entries[]
            | select(.key != $exclude)
            | select(.value.portHopping)
            | (.value.portHopping | capture("^(?<start>[0-9]+)-(?<end>[0-9]+)$")?) as $range
            | select($range != null)
            | ($range.start | tonumber) as $other_start
            | ($range.end | tonumber) as $other_end
            | select($start <= $other_end and $end >= $other_start)
            | [
                .key,
                (.value.name // .key),
                .value.portHopping,
                ("主HY2/" + (.value.portHoppingMode // "unknown"))
              ]
            | @tsv
        ' "$METADATA_FILE" 2>/dev/null | head -n 1)
        [ -n "$conflict" ] && { echo "$conflict"; return 0; }
    fi

    local relay_links="${SINGBOX_DIR}/relay_links.json"
    if [ -f "$relay_links" ]; then
        conflict=$(jq -r --argjson start "$start" --argjson end "$end" --arg exclude "$exclude_tag" '
            to_entries[]
            | select(.key != $exclude)
            | select(.value.port_hopping)
            | (.value.port_hopping | capture("^(?<start>[0-9]+)-(?<end>[0-9]+)$")?) as $range
            | select($range != null)
            | ($range.start | tonumber) as $other_start
            | ($range.end | tonumber) as $other_end
            | select($start <= $other_end and $end >= $other_start)
            | [
                .key,
                (.value.node_name // .key),
                .value.port_hopping,
                "中转HY2/nftables"
              ]
            | @tsv
        ' "$relay_links" 2>/dev/null | head -n 1)
        [ -n "$conflict" ] && { echo "$conflict"; return 0; }
    fi

    return 1
}

# nftables 规则管理 (独立表，避免污染系统其他防火墙规则)
export NFT_TABLE="singboxlite"
export NFT_PERSIST_FILE="/etc/nftables.d/singboxlite.nft"

_nft_ensure_base() {
    command -v nft &>/dev/null || return 1
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || nft add table inet "$NFT_TABLE" >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" prerouting >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" prerouting '{ type nat hook prerouting priority -100; policy accept; }' >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" output >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" output '{ type nat hook output priority -100; policy accept; }' >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" postrouting >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" postrouting '{ type nat hook postrouting priority 100; policy accept; }' >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" forward >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" forward '{ type filter hook forward priority 0; policy accept; }' >/dev/null 2>&1 || return 1
}

_nft_delete_rules_by_comment() {
    local comment="$1"
    local table_dump tables entries chain handle delete_failed=0
    command -v nft &>/dev/null || return 0
    if ! table_dump=$(nft -a list table inet "$NFT_TABLE" 2>/dev/null); then
        tables=$(nft list tables 2>/dev/null) || return 1
        if ! printf '%s\n' "$tables" | grep -Eq "^[[:space:]]*table[[:space:]]+inet[[:space:]]+${NFT_TABLE}[[:space:]]*$"; then
            return 0
        fi
        return 1
    fi
    entries=$(printf '%s\n' "$table_dump" | awk -v c="comment \"$comment\"" '
        /^[[:space:]]*chain / { chain=$2 }
        index($0, c) && /# handle / { print chain, $NF }
    ') || return 1
    [ -z "$entries" ] && return 0
    while read -r chain handle; do
        [ -n "$chain" ] && [ -n "$handle" ] || continue
        nft delete rule inet "$NFT_TABLE" "$chain" handle "$handle" >/dev/null 2>&1 || delete_failed=1
    done <<< "$entries"
    [ "$delete_failed" -eq 0 ]
}

_nft_port_expr() {
    local start="$1" end="$2"
    if [ "$start" = "$end" ]; then
        echo "$start"
    else
        echo "${start}-${end}"
    fi
}

_nft_apply_redirect_rule() {
    local action="$1" start_port="$2" end_port="$3" target_port="$4" comment="$5"
    if [ "${MAIN_CREATE_TX_ACTIVE:-0}" = "1" ] && [ "${MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE:-0}" != "1" ]; then
        return 1
    fi
    if [ "$action" = "delete" ]; then
        command -v nft >/dev/null 2>&1 || return 1
        _nft_delete_rules_by_comment "$comment"
        return $?
    fi
    _nft_ensure_base || return 1
    _nft_delete_rules_by_comment "$comment" || return 1
    nft add rule inet "$NFT_TABLE" prerouting udp dport "$(_nft_port_expr "$start_port" "$end_port")" redirect to ":${target_port}" comment "$comment" >/dev/null 2>&1
}

_nft_can_redirect() {
    local test_port="${1:-65530}" target_port="${2:-65531}" comment="singboxlite-test-redirect-$$"
    _nft_apply_redirect_rule add "$test_port" "$test_port" "$target_port" "$comment" || return 1
    _nft_apply_redirect_rule delete "$test_port" "$test_port" "$target_port" "$comment" || return 1
    return 0
}

_save_nftables_rules() {
    command -v nft &>/dev/null || return 0
    mkdir -p /etc/nftables.d || return 1
    local persist_tmp
    persist_tmp=$(mktemp "${NFT_PERSIST_FILE}.tmp.XXXXXX") || return 1
    if ! nft list table inet "$NFT_TABLE" > "$persist_tmp" 2>/dev/null; then
        rm -f -- "$persist_tmp"
        return 1
    fi
    chmod 600 "$persist_tmp" 2>/dev/null || true
    mv -f "$persist_tmp" "$NFT_PERSIST_FILE" || { rm -f -- "$persist_tmp"; return 1; }

    if [ ! -f /etc/nftables.conf ]; then
        {
            echo '#!/usr/sbin/nft -f'
            echo 'include "/etc/nftables.d/*.nft"'
        } > /etc/nftables.conf || return 1
    elif ! grep -q 'singboxlite\.nft\|/etc/nftables\.d/\*\.nft' /etc/nftables.conf 2>/dev/null; then
        echo 'include "/etc/nftables.d/singboxlite.nft"' >> /etc/nftables.conf || return 1
    fi
    if command -v systemctl &>/dev/null; then
        systemctl enable nftables >/dev/null 2>&1 || true
    fi
    if command -v rc-update &>/dev/null; then
        rc-update add nftables default >/dev/null 2>&1 || true
    fi
    return 0
}

_remove_nftables_rules() {
    if command -v nft &>/dev/null; then
        nft delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true
    fi
    rm -f "$NFT_PERSIST_FILE"
    if [ -f /etc/nftables.conf ]; then
        sed -i '\|/etc/nftables.d/singboxlite.nft|d' /etc/nftables.conf 2>/dev/null || true
    fi
}

# 公网 IP 初始化
_init_server_ip() {
    _info "正在获取服务器公网 IP..."
    server_ip=$(_get_public_ip)
    if [ -z "$server_ip" ] || [ "$server_ip" == "null" ]; then
        _warn "自动获取 IP 失败，将回退到 127.0.0.1"
        server_ip="127.0.0.1"
    else
        _success "当前服务器公网 IP: ${server_ip}"
    fi
}

# 统一服务管理
_manage_service() {
    local action="$1"

    # 容器时间通常继承宿主机；但部分 Podman 服务商会封锁 UDP/123。
    # sing-box 的内置 NTP 初始化失败属于致命错误，因此 Podman 仅移除本脚本
    # 曾自动写入的默认项，用户自行配置的 NTP 则保留不动。
    if [[ "$action" == "restart" || "$action" == "start" ]]; then
        if _is_podman_environment; then
            if [ -s "$CONFIG_FILE" ] && jq -e '.ntp == {"enabled":true,"server":"time.apple.com","server_port":123,"interval":"30m"}' "$CONFIG_FILE" >/dev/null 2>&1; then
                _atomic_modify_json "$CONFIG_FILE" 'del(.ntp)' 2>/dev/null || return 1
            fi
        elif [ -s "$CONFIG_FILE" ] && ! jq -e '.ntp' "$CONFIG_FILE" >/dev/null 2>&1; then
            _info "检测到内核配置缺失内置时间同步(NTP)模块，正在自动注入防重放保护补丁..."
            _atomic_modify_json "$CONFIG_FILE" '.ntp = {"enabled": true, "server": "time.apple.com", "server_port": 123, "interval": "30m"}' 2>/dev/null
        fi
        _ensure_relay_config || return 1
        local preflight_result
        if ! preflight_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
            _error "拒绝启动：config.json + relay.json 组合配置无效。"
            echo "$preflight_result"
            return 1
        fi
        _secure_state_permissions
    fi

    [ -z "$INIT_SYSTEM" ] && _detect_init_system
    [ "$action" == "status" ] || _info "正在使用 ${INIT_SYSTEM} 执行: $action..."
    case "$INIT_SYSTEM" in
        systemd)
            if [ "$action" == "status" ]; then systemctl status sing-box --no-pager -l; return; fi
            # Containers and rapid successive management operations can exhaust
            # systemd's start-rate counter even when the configuration is valid.
            # Clear the counter before an explicit operator start/restart.
            if [ "$action" == "start" ] || [ "$action" == "restart" ]; then
                systemctl reset-failed sing-box >/dev/null 2>&1 || true
            fi
            systemctl "$action" sing-box 8>&- 9>&- 219>&- ;;
        openrc)
            if [ "$action" == "status" ]; then rc-service sing-box status; return; fi
            rc-service sing-box "$action" 8>&- 9>&- 219>&- ;;
        direct)
            if ! _prepare_singbox_runtime_pid; then
                _error "无法准备受保护的运行目录: ${RUNTIME_DIR}"
                return 1
            fi
            case "$action" in
                start)
                    if _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                        _success "sing-box 已在 direct 模式运行。"
                        return 0
                    fi
                    rm -f "$PID_FILE"
                    [ -s "${SINGBOX_DIR}/relay.json" ] || echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
                    nohup env GOMEMLIMIT="$(_get_mem_limit)MiB" \
                        "$SINGBOX_BIN" run -c "$CONFIG_FILE" -c "${SINGBOX_DIR}/relay.json" \
                        >> "$LOG_FILE" 2>&1 8>&- 9>&- 219>&- &
                    echo $! > "$PID_FILE"
                    chmod 600 "$PID_FILE" 2>/dev/null || true
                    sleep 1
                    if ! _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                        _error "sing-box 启动后立即退出，请检查日志。"
                        rm -f "$PID_FILE"
                        return 1
                    fi
                    _success "sing-box 已以 direct 后台模式启动。"
                    ;;
                stop)
                    if [ -s "$PID_FILE" ]; then
                        local pid
                        pid=$(cat "$PID_FILE" 2>/dev/null)
                        if _is_pid_running_cmd "$pid" "$SINGBOX_BIN"; then
                            kill "$pid" 2>/dev/null
                        fi
                    fi
                    rm -f "$PID_FILE"
                    _success "sing-box direct 后台进程已停止。"
                    ;;
                restart)
                    _manage_service stop
                    sleep 1
                    _manage_service start
                    ;;
                status)
                    if _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                        _success "sing-box direct 后台模式运行中 (PID: $(cat "$PID_FILE"))"
                    else
                        rm -f "$PID_FILE"
                        _warn "sing-box direct 后台模式未运行。"
                        return 1
                    fi
                    ;;
                *) _error "direct 模式不支持的服务操作: $action"; return 1 ;;
            esac
            ;;
        *) _error "不支持的服务管理系统" ;;
    esac
}

# 智能包管理
_pkg_install() {
    local pkgs="$*"
    [ -z "$pkgs" ] && return 0
    if command -v apk &>/dev/null; then
        apk add --no-cache $pkgs >/dev/null 2>&1
    elif command -v apt-get &>/dev/null; then
        # 全新 LXC/容器上 apt 缓存可能为空，必须先 update
        if [ ! -d "/var/lib/apt/lists" ] || [ "$(ls -A /var/lib/apt/lists/ 2>/dev/null | wc -l)" -le 1 ]; then
            apt-get update -qq >/dev/null 2>&1
        fi
        # 128M Podman 中一次解析/解包整批依赖会把 apt 推到 cgroup 上限，常见结果是
        # 第一次 apt-get 被 OOM kill、第二次依靠部分安装状态侥幸成功。容器内改为逐包、
        # 禁用 recommends 和 dpkg PTY，主动压低峰值内存；普通 LXC/KVM 仍保留批量安装。
        if _is_podman_environment; then
            local pkg
            for pkg in $pkgs; do
                if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
                    continue
                fi
                if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                    -o Dpkg::Use-Pty=0 -o Acquire::Languages=none "$pkg" >/dev/null 2>&1; then
                    apt-get update -qq -o Acquire::Languages=none >/dev/null 2>&1 || return 1
                    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                        -o Dpkg::Use-Pty=0 -o Acquire::Languages=none "$pkg" >/dev/null 2>&1 || return 1
                fi
            done
        else
            DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >/dev/null 2>&1 || {
                # 兜底：如果安装失败，强制刷新索引后重试
                apt-get update -qq >/dev/null 2>&1
                DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >/dev/null 2>&1
            }
        fi
    elif command -v yum &>/dev/null; then yum install -y $pkgs >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then dnf install -y $pkgs >/dev/null 2>&1
    else
        return 1
    fi
}

# 原子修改 JSON/YAML 文件
_atomic_modify_json() {
    local file="$1" filter="$2"
    shift 2
    [ ! -f "$file" ] && return 1
    _with_state_lock _atomic_modify_json_locked "$file" "$filter" "$@"
}
_atomic_modify_json_locked() {
    local file="$1" filter="$2"
    shift 2
    local tmp
    tmp=$(mktemp "${file}.tmp.XXXXXX") || return 1
    if jq "$@" "$filter" "$file" > "$tmp" && jq empty "$tmp" >/dev/null 2>&1; then
        chmod 600 "$tmp" 2>/dev/null || true
        if ! mv -f "$tmp" "$file"; then
            _error "替换 JSON 失败: $file"
            rm -f "$tmp"
            return 1
        fi
    else
        _error "修改 JSON 失败: $file"
        rm -f "$tmp"
        return 1
    fi
}
_atomic_modify_yaml() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    _with_state_lock _atomic_modify_yaml_locked "$file" "$filter"
}
_atomic_modify_yaml_locked() {
    local file="$1" filter="$2"
    local tmp
    tmp=$(mktemp "${file}.tmp.XXXXXX") || return 1
    cp "$file" "$tmp" || { rm -f "$tmp"; return 1; }
    if ${YQ_BINARY} eval "$filter" -i "$tmp" 2>/dev/null; then
        chmod 600 "$tmp" 2>/dev/null || true
        mv -f "$tmp" "$file" || { rm -f "$tmp"; return 1; }
    else
        _error "修改 YAML 失败: $file"
        rm -f "$tmp"
        return 1
    fi
}

_ensure_relay_config_locked() {
    if [ ! -s "$RELAY_CONFIG_FILE" ]; then
        local tmp
        tmp=$(mktemp "${RELAY_CONFIG_FILE}.tmp.XXXXXX") || return 1
        printf '%s\n' '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$tmp"
        chmod 600 "$tmp" 2>/dev/null || true
        mv -f "$tmp" "$RELAY_CONFIG_FILE" || { rm -f "$tmp"; return 1; }
    fi
    jq empty "$RELAY_CONFIG_FILE" >/dev/null 2>&1
}

_ensure_relay_config() {
    mkdir -p "$SINGBOX_DIR" || return 1
    _with_state_lock _ensure_relay_config_locked
}

# 服务始终同时加载 config.json 和 relay.json；所有校验必须复现真实启动参数。
_check_combined_config_files() {
    local binary="${1:-$SINGBOX_BIN}" main_config="${2:-$CONFIG_FILE}" relay_config="${3:-$RELAY_CONFIG_FILE}"
    [ -x "$binary" ] || { _error "sing-box 核心不可执行: $binary"; return 1; }
    [ -s "$main_config" ] || { _error "主配置不存在或为空: $main_config"; return 1; }
    [ -s "$relay_config" ] || { _error "中转配置不存在或为空: $relay_config"; return 1; }
    "$binary" check -c "$main_config" -c "$relay_config"
}

# 将菜单中的传统 DNS 地址表示转换为 sing-box 1.12+ typed server。
# 1.14 已移除 legacy address 字段；域名上游额外使用本地 bootstrap，避免自解析循环。
_build_dns_config_json() {
    local address="$1" strategy="$2" type server port path resolver="" server_json
    case "$strategy" in
        prefer_ipv4|prefer_ipv6|ipv4_only|ipv6_only) ;;
        *) return 1 ;;
    esac

    if [ "$address" = "local" ]; then
        jq -cn --arg strategy "$strategy" '{servers:[{type:"local",tag:"dns-local",prefer_go:true}],final:"dns-local",strategy:$strategy}'
        return $?
    elif [[ "$address" =~ ^https://(\[[^]]+\]|[^/:]+)(:([0-9]+))?(/.*)?$ ]]; then
        type="https"; server="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]:-443}"; path="${BASH_REMATCH[4]:-/dns-query}"
    elif [[ "$address" =~ ^tls://(\[[^]]+\]|[^/:]+)(:([0-9]+))?/?$ ]]; then
        type="tls"; server="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]:-853}"; path=""
    elif [[ "$address" =~ ^tcp://(\[[^]]+\]|[^/:]+)(:([0-9]+))?/?$ ]]; then
        type="tcp"; server="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]:-53}"; path=""
    elif [[ "$address" =~ ^udp://(\[[^]]+\]|[^/:]+)(:([0-9]+))?/?$ ]]; then
        type="udp"; server="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]:-53}"; path=""
    elif [[ "$address" != *"://"* && "$address" != *[[:space:]]* ]]; then
        type="udp"; server="$address"; port="53"; path=""
    else
        return 1
    fi

    server="${server#[}"; server="${server%]}"
    [ -n "$server" ] && [[ "$port" =~ ^[0-9]+$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || return 1
    [[ "$server" =~ ^[0-9.]+$ || "$server" == *:* ]] || resolver="dns-bootstrap"

    server_json=$(jq -cn \
        --arg type "$type" --arg server "$server" --argjson port "$((10#$port))" \
        --arg path "$path" --arg resolver "$resolver" '
        {type:$type,tag:"dns-local",server:$server,server_port:$port}
        + (if $type == "https" then {path:$path} else {} end)
        + (if $resolver != "" then {domain_resolver:$resolver} else {} end)
    ') || return 1

    if [ -n "$resolver" ]; then
        jq -cn --argjson server "$server_json" --arg strategy "$strategy" \
            '{servers:[{type:"local",tag:"dns-bootstrap",prefer_go:true},$server],final:"dns-local",strategy:$strategy}'
    else
        jq -cn --argjson server "$server_json" --arg strategy "$strategy" \
            '{servers:[$server],final:"dns-local",strategy:$strategy}'
    fi
}

# --- 资源与环境管理 ---

# 系统时间同步 (解决 TLS 握手 EOF 问题)
_sync_system_time() {
    _info "正在检查并同步系统时间..."
    local current_year=$(date +%Y)
    [ "$current_year" -lt 2024 ] && _warning "系统时间滞后，正在强制同步..."
    # 采用三级同步策略提升鲁棒性 (NTP -> HTTP -> Package)
    if _pkg_install ntpdate >/dev/null 2>&1 && command -v ntpdate &>/dev/null; then
        ntpdate -u ntp.aliyun.com >/dev/null 2>&1 || ntpdate -u pool.ntp.org >/dev/null 2>&1
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        _pkg_install chrony >/dev/null 2>&1
        chronyd -q 'server ntp.aliyun.com iburst' >/dev/null 2>&1
    else
        # 最后的屏障：通过 HTTP 头部修正时间 (防御 UDP 123 拦截)
        local http_time=$(curl -sI --max-time 3 https://www.google.com | grep -i '^date:' | cut -f2- -d' ')
        if [ -n "$http_time" ]; then
            # [修复] 先尝试 GNU date 直接设置，失败后尝试 epoch 方式 (兼容 BusyBox)
            if ! date -s "$http_time" >/dev/null 2>&1; then
                local epoch=$(date -d "$http_time" +%s 2>/dev/null)
                [ -n "$epoch" ] && date -s "@$epoch" >/dev/null 2>&1
            fi
        fi
    fi
    _info "当前时间：$(date)"
}

# Clash YAML 节点管理
_get_proxy_field() {
    local proxy_name="$1" field="$2"
    export PROXY_NAME="$proxy_name"
    ${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME)) | '"$field" "${CLASH_YAML_FILE}" 2>/dev/null | head -n 1
}
_add_node_to_yaml() {
    local proxy_json="$1"
    _with_state_lock _add_node_to_yaml_locked "$proxy_json"
}
_add_node_to_yaml_locked() {
    local proxy_json="$1"
    local proxy_name
    proxy_name=$(echo "$proxy_json" | jq -r .name)
    [ -n "$proxy_name" ] && [ "$proxy_name" != "null" ] || { _error "节点名称为空，拒绝写入共享 YAML。"; return 1; }
    export PROXY_NAME="$proxy_name"
    if ${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME)) | .name' "$CLASH_YAML_FILE" 2>/dev/null | grep -Fxq "$proxy_name"; then
        _error "共享 Clash YAML 已存在同名节点 [$proxy_name]；为避免跨模块覆盖，请更换名称。"
        return 1
    fi
    if ! ${YQ_BINARY} eval '.proxy-groups[] | select(.name == "节点选择") | .name' "$CLASH_YAML_FILE" 2>/dev/null | grep -Fxq '节点选择'; then
        _error "共享 Clash YAML 缺少 [节点选择] 分组，拒绝写入孤立代理。"
        return 1
    fi
    local yaml_backup
    yaml_backup=$(mktemp "${CLASH_YAML_FILE}.add.backup.XXXXXX") || return 1
    cp -p "$CLASH_YAML_FILE" "$yaml_backup" || { rm -f "$yaml_backup"; return 1; }
    _atomic_modify_yaml "$CLASH_YAML_FILE" ".proxies |= . + [${proxy_json}]" || { mv -f "$yaml_backup" "$CLASH_YAML_FILE"; return 1; }
    export PROXY_NAME="$proxy_name"
    if ! _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxy-groups[] | select(.name == "节点选择") | .proxies) = ((((.proxy-groups[] | select(.name == "节点选择") | .proxies) // []) + [env(PROXY_NAME)]) | unique)'; then
        mv -f "$yaml_backup" "$CLASH_YAML_FILE"
        return 1
    fi
    rm -f "$yaml_backup"
}
_remove_node_from_yaml() {
    local proxy_name="$1"
    _with_state_lock _remove_node_from_yaml_locked "$proxy_name"
}
_remove_node_from_yaml_locked() {
    local proxy_name="$1"
    export PROXY_NAME="$proxy_name"
    local yaml_backup
    yaml_backup=$(mktemp "${CLASH_YAML_FILE}.remove.backup.XXXXXX") || return 1
    cp -p "$CLASH_YAML_FILE" "$yaml_backup" || { rm -f "$yaml_backup"; return 1; }
    _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == env(PROXY_NAME)))' || { mv -f "$yaml_backup" "$CLASH_YAML_FILE"; return 1; }
    if ! _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxy-groups[] | .proxies) |= (((. // []) | map(select(. != env(PROXY_NAME)))))'; then
        mv -f "$yaml_backup" "$CLASH_YAML_FILE"
        return 1
    fi
    rm -f "$yaml_backup"
}
_find_proxy_name() {
    local port="$1" type="$2" tag="$3" proxy_name=""
    if [ -n "$tag" ] && [ -f "$METADATA_FILE" ]; then
        local yaml_enabled
        yaml_enabled=$(jq -r --arg t "$tag" '.[$t].yaml // empty' "$METADATA_FILE" 2>/dev/null)
        [ "$yaml_enabled" = "false" ] && return 0
        proxy_name=$(jq -r --arg t "$tag" '.[$t].name // empty' "$METADATA_FILE" 2>/dev/null)
        [ -n "$proxy_name" ] && { echo "$proxy_name"; return 0; }
    fi
    local yaml_type="$type"
    case "$type" in
        shadowtls|shadowsocks) yaml_type="ss" ;;
        socks) yaml_type="socks5" ;;
    esac
    if [ -s "$CLASH_YAML_FILE" ] && [ -x "$YQ_BINARY" ]; then
        export LOOKUP_PORT="$port" LOOKUP_TYPE="$yaml_type"
        proxy_name=$(${YQ_BINARY} eval '.proxies[] | select(.port == (env(LOOKUP_PORT) | tonumber) and .type == env(LOOKUP_TYPE)) | .name' "$CLASH_YAML_FILE" 2>/dev/null | head -n 1)
        if [ -z "$proxy_name" ] || [ "$proxy_name" = "null" ]; then
            proxy_name=$(${YQ_BINARY} eval '.proxies[] | select(.port == (env(LOOKUP_PORT) | tonumber)) | .name' "$CLASH_YAML_FILE" 2>/dev/null | head -n 1)
        fi
    fi
    echo "$proxy_name"
}

_is_argo_inbound_tag() {
    local tag="$1"
    [[ "$tag" == argo-* ]] && return 0
    [ -s "$ARGO_METADATA_FILE" ] && jq -e --arg tag "$tag" 'has($tag)' "$ARGO_METADATA_FILE" >/dev/null 2>&1
}

_is_shadowtls_inner_tag() {
    local tag="$1"
    [ -s "$CONFIG_FILE" ] || return 1
    jq -e --arg tag "$tag" '.inbounds[]? | select(.type == "shadowtls" and .detour == $tag)' "$CONFIG_FILE" >/dev/null 2>&1
}

# 仅列出主脚本可管理的外层节点：排除 Argo、HY2 hop 以及 ShadowTLS 内层。
_list_main_primary_inbounds() {
    [ -s "$CONFIG_FILE" ] || return 0
    local node tag port
    while IFS= read -r node; do
        [ -n "$node" ] || continue
        tag=$(printf '%s' "$node" | jq -r '.tag // empty')
        port=$(printf '%s' "$node" | jq -r '.listen_port // empty')
        [ -n "$tag" ] && [ -n "$port" ] || continue
        [[ "$tag" == *"-hop-"* ]] && continue
        _is_argo_inbound_tag "$tag" && continue
        _is_shadowtls_inner_tag "$tag" && continue
        printf '%s\n' "$node"
    done < <(jq -c '.inbounds[]?' "$CONFIG_FILE" 2>/dev/null)
}

_is_protected_yaml_name() {
    local name="$1"
    [ -n "$name" ] || return 1
    if [ -s "$ARGO_METADATA_FILE" ] && jq -e --arg name "$name" 'to_entries[]? | select(.value.name == $name)' "$ARGO_METADATA_FILE" >/dev/null 2>&1; then
        return 0
    fi
    if [ -s "/usr/local/etc/xray/metadata.json" ] && jq -e --arg name "$name" 'to_entries[]? | select(.value.name == $name)' /usr/local/etc/xray/metadata.json >/dev/null 2>&1; then
        return 0
    fi
    if [ -s "${SINGBOX_DIR}/relay_links.json" ] && jq -e --arg name "$name" 'to_entries[]? | select(.value.node_name == $name)' "${SINGBOX_DIR}/relay_links.json" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

_validate_protected_yaml_metadata() {
    local metadata_path
    for metadata_path in \
        "$ARGO_METADATA_FILE" \
        "/usr/local/etc/xray/metadata.json" \
        "${SINGBOX_DIR}/relay_links.json"; do
        [ -e "$metadata_path" ] || continue
        if [ ! -f "$metadata_path" ] || [ ! -s "$metadata_path" ] \
            || ! jq -e 'type == "object"' "$metadata_path" >/dev/null 2>&1; then
            _error "共享 YAML 所有权元数据无效，拒绝执行破坏性操作: $metadata_path"
            return 1
        fi
    done
}

_safe_remove_main_credential() {
    local path="$1" resolved resolved_dir trusted_dir
    [ -f "$path" ] || return 0
    resolved=$(readlink -f "$path" 2>/dev/null) || return 1
    trusted_dir=$(readlink -f "$SINGBOX_DIR" 2>/dev/null) || return 1
    resolved_dir=$(dirname "$resolved")
    if [ "$resolved_dir" != "$trusted_dir" ]; then
        _warn "拒绝删除 sing-box 配置目录顶层以外的证书或私钥: $resolved"
        return 1
    fi
    case "${resolved##*/}" in
        *.pem|*.key) ;;
        *) _warn "拒绝删除非证书/私钥文件: $resolved"; return 1 ;;
    esac
    if grep -Fq -- "$resolved" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>/dev/null; then
        _warn "证书仍被保留节点引用，跳过删除: $resolved"
        return 0
    fi
    rm -f -- "$resolved"
}

_rollback_main_node_creation() {
    local tag="$1"
    [ -n "$tag" ] || return 1
    local node detour cert key hop hop_mode port
    node=$(jq -c --arg tag "$tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" 2>/dev/null | head -n 1)
    detour=$(printf '%s' "$node" | jq -r '.detour // empty' 2>/dev/null)
    cert=$(printf '%s' "$node" | jq -r '.tls.certificate_path // empty' 2>/dev/null)
    key=$(printf '%s' "$node" | jq -r '.tls.key_path // empty' 2>/dev/null)
    port=$(printf '%s' "$node" | jq -r '.listen_port // empty' 2>/dev/null)
    hop=$(jq -r --arg tag "$tag" '.[$tag].portHopping // empty' "$METADATA_FILE" 2>/dev/null)
    hop_mode=$(jq -r --arg tag "$tag" '.[$tag].portHoppingMode // empty' "$METADATA_FILE" 2>/dev/null)
    _atomic_modify_json "$CONFIG_FILE" '
        .inbounds |= map(select(.tag != $tag and .tag != $detour and (((.tag // "") | startswith($tag + "-hop-")) | not)))
    ' --arg tag "$tag" --arg detour "$detour" >/dev/null 2>&1 || true
    _atomic_modify_json "$METADATA_FILE" 'del(.[$tag], .[$detour])' --arg tag "$tag" --arg detour "$detour" >/dev/null 2>&1 || true
    if [ -n "$hop" ] && [ "$hop_mode" != "native" ]; then
        _nft_apply_redirect_rule delete "${hop%-*}" "${hop#*-}" "$port" "singboxlite-hy2-hop-${tag}" \
            || _warn "局部回滚未能删除端口跳跃规则，将由外层完整事务恢复。"
        _save_nftables_rules \
            || _warn "局部回滚未能持久化 nftables，将由外层完整事务恢复。"
    fi
    # 外层创建事务会按完整凭据快照统一恢复；局部回滚不得提前删除用户文件。
    if [ "${MAIN_CREATE_TX_ACTIVE:-0}" != "1" ]; then
        _safe_remove_main_credential "$cert"
        _safe_remove_main_credential "$key"
    fi
    _error "共享 YAML 写入失败，已回滚刚创建的运行配置。"
}

# 内存限额计算
_get_mem_limit() {
    local total_mem_mb=0 cgroup_limit="" candidate_mb=0
    local limit limit_file

    total_mem_mb=$(awk '/^MemTotal:/{print int($2 / 1024); exit}' /proc/meminfo 2>/dev/null)
    [[ "$total_mem_mb" =~ ^[0-9]+$ ]] || total_mem_mb=0

    # cgroup v2 的 memory.high 也可能比 memory.max 更早触发回收；取系统
    # 可见内存、memory.max 和 memory.high 中最小的有效值，兼容嵌套容器。
    if [ -r /sys/fs/cgroup/memory.max ]; then
        for limit_file in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.high; do
            [ -r "$limit_file" ] || continue
            cgroup_limit=$(cat "$limit_file" 2>/dev/null)
            if [[ "$cgroup_limit" =~ ^[0-9]+$ ]] && [ "$cgroup_limit" -lt 9223372036854771712 ] 2>/dev/null; then
                candidate_mb=$((cgroup_limit / 1024 / 1024))
                if [ "$candidate_mb" -gt 0 ] && { [ "$total_mem_mb" -eq 0 ] || [ "$candidate_mb" -lt "$total_mem_mb" ]; }; then
                    total_mem_mb=$candidate_mb
                fi
            fi
        done
    elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        cgroup_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null)
        if [[ "$cgroup_limit" =~ ^[0-9]+$ ]] && [ "$cgroup_limit" -lt 9223372036854771712 ] 2>/dev/null; then
            candidate_mb=$((cgroup_limit / 1024 / 1024))
            if [ "$candidate_mb" -gt 0 ] && { [ "$total_mem_mb" -eq 0 ] || [ "$candidate_mb" -lt "$total_mem_mb" ]; }; then
                total_mem_mb=$candidate_mb
            fi
        fi
    fi

    [ "$total_mem_mb" -gt 0 ] || total_mem_mb=128

    if [ "$total_mem_mb" -le 128 ]; then
        # 128MB 机器保留更多空间给内核、TLS、socket 缓冲和测速客户端。
        limit=$((total_mem_mb * 5 / 16))
    elif [ "$total_mem_mb" -le 256 ]; then
        limit=$((total_mem_mb * 50 / 100))
    elif [ "$total_mem_mb" -le 512 ]; then
        limit=$((total_mem_mb * 65 / 100))
    else
        limit=$((total_mem_mb * 80 / 100))
    fi

    [ "$limit" -lt 32 ] && limit=32
    echo "$limit"
}

# 页缓存由内核按内存压力自动回收。容器中 /proc/sys/vm/drop_caches 可能
# 意外映射到宿主机全局开关，主动写入会影响整台宿主机，甚至触发容器重启。
_release_install_cache() {
    sync 2>/dev/null || true
    return 0
}

# 安装 yq
_install_yq() {
    if [ ! -x "$YQ_BINARY" ] || ! "$YQ_BINARY" --version >/dev/null 2>&1; then
        _info "安装 yq..."
        local arch
        arch=$(uname -m)
        case $arch in
            x86_64|amd64) arch='amd64' ;;
            aarch64|arm64) arch='arm64' ;;
            armv7l|armv7|armhf) arch='arm' ;;
            *) _error "yq 不支持当前架构: $(uname -m)"; return 1 ;;
        esac
        local asset="yq_linux_${arch}"
        local release_json release_tag release_base
        release_json=$(curl -fsSL --max-time 15 https://api.github.com/repos/mikefarah/yq/releases/latest 2>/dev/null) || true
        release_tag=$(printf '%s' "$release_json" | jq -r '.tag_name // empty' 2>/dev/null)
        if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            _error "无法解析 yq 官方 release tag。"
            return 1
        fi
        release_base="https://github.com/mikefarah/yq/releases/download/${release_tag}"

        local tmp_yq checksums_tmp order_tmp
        tmp_yq=$(mktemp "$(dirname "$YQ_BINARY")/.yq.new.XXXXXX") || return 1
        checksums_tmp=$(mktemp /tmp/singboxlite-yq-checksums.XXXXXX) || { rm -f -- "$tmp_yq"; return 1; }
        order_tmp=$(mktemp /tmp/singboxlite-yq-order.XXXXXX) || { rm -f -- "$tmp_yq" "$checksums_tmp"; return 1; }
        if ! wget -qO "$tmp_yq" "${release_base}/${asset}" \
            || ! wget -qO "$checksums_tmp" "${release_base}/checksums" \
            || ! wget -qO "$order_tmp" "${release_base}/checksums_hashes_order"; then
            rm -f -- "$tmp_yq" "$checksums_tmp" "$order_tmp"
            _error "yq 或官方校验文件下载失败。"
            return 1
        fi

        local sha_line sha_field expected_sha actual_sha
        sha_line=$(grep -n -x -m 1 'SHA-256' "$order_tmp" | cut -d: -f1)
        if ! [[ "$sha_line" =~ ^[0-9]+$ ]]; then
            rm -f -- "$tmp_yq" "$checksums_tmp" "$order_tmp"
            _error "yq 官方校验文件缺少 SHA-256 定义。"
            return 1
        fi
        sha_field=$((sha_line + 1))
        expected_sha=$(awk -v name="$asset" -v field="$sha_field" '
            $1 == name { count++; value=$field }
            END { if (count == 1) print tolower(value) }
        ' "$checksums_tmp")
        actual_sha=$(openssl dgst -sha256 "$tmp_yq" 2>/dev/null | awk '{print tolower($NF)}')
        if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || [ "$actual_sha" != "$expected_sha" ]; then
            rm -f -- "$tmp_yq" "$checksums_tmp" "$order_tmp"
            _error "yq SHA-256 校验失败，拒绝安装。"
            return 1
        fi
        rm -f -- "$checksums_tmp" "$order_tmp"

        if ! chmod 755 "$tmp_yq" || ! "$tmp_yq" --version >/dev/null 2>&1 \
            || ! mv -f "$tmp_yq" "$YQ_BINARY"; then
            rm -f -- "$tmp_yq"
            _error "yq 下载或完整性自检失败。"
            return 1
        fi
    fi
}

# --- 核心变量定义 ---
export SINGBOX_DIR="/usr/local/etc/sing-box"
export SINGBOX_BIN="/usr/local/bin/sing-box"
export SINGBOX_FIXED_VERSION="1.13.21"
export SINGBOX_CORE_LOCK_FILE="${SINGBOX_DIR}/core-version.lock"
export YQ_BINARY="/usr/local/bin/yq"
export CONFIG_FILE="${SINGBOX_DIR}/config.json"
export RELAY_CONFIG_FILE="${SINGBOX_DIR}/relay.json"
export CLASH_YAML_FILE="${SINGBOX_DIR}/clash.yaml"
export METADATA_FILE="${SINGBOX_DIR}/metadata.json"
export ARGO_METADATA_FILE="${SINGBOX_DIR}/argo_metadata.json"
export LOG_FILE="/var/log/sing-box.log"
export ARGO_LOG_FILE="/var/log/singbox_argo.log"
export RUNTIME_DIR="/run/singboxlite"
export PID_FILE="${RUNTIME_DIR}/sing-box.pid"
export CLOUDFLARED_BIN="/usr/local/bin/cloudflared"
export XRAY_RUNTIME_DIR="${RUNTIME_DIR}"
export XRAY_PID_FILE="${XRAY_RUNTIME_DIR}/xray.pid"
export DEP_STATE_FILE="${SINGBOX_DIR}/dependencies.ok"
export DEP_STATE_VERSION="20260831-lowmem-1"
_detect_init_system
case "$INIT_SYSTEM" in
    openrc) export SERVICE_FILE="/etc/init.d/sing-box" ;;
    systemd) export SERVICE_FILE="/etc/systemd/system/sing-box.service" ;;
    *) export SERVICE_FILE="" ;;
esac

export -f _info _success _warn _warning _error _flock_wait _url_encode _url_decode _ws_path_with_early_data _cert_sha256_hex _tls_insecure_params _get_public_ip _detect_init_system _sync_system_time _release_install_cache _atomic_modify_json _atomic_modify_json_locked _atomic_modify_yaml _atomic_modify_yaml_locked _with_state_lock _manage_service _pkg_install _get_proxy_field _add_node_to_yaml _add_node_to_yaml_locked _remove_node_from_yaml _remove_node_from_yaml_locked _find_proxy_name _nft_ensure_base _nft_delete_rules_by_comment _nft_port_expr _nft_apply_redirect_rule _nft_can_redirect _save_nftables_rules _remove_nftables_rules

server_ip=""
BATCH_MODE=false
VIEW_LINKS_TMP=""
_cleanup_main_temp_files() {
    [ -z "${VIEW_LINKS_TMP:-}" ] || rm -f -- "$VIEW_LINKS_TMP"
}
trap _cleanup_main_temp_files EXIT
# 依赖安装
_install_dependencies() {
    local force="${1:-false}"
    if [ "$force" != "true" ] && [ -s "$DEP_STATE_FILE" ] && grep -qx "$DEP_STATE_VERSION" "$DEP_STATE_FILE" 2>/dev/null; then
        local missing_cached=""
        for cmd in bash jq curl wget openssl tar unzip flock; do
            if ! command -v "$cmd" &>/dev/null; then
                missing_cached="$missing_cached $cmd"
            fi
        done
        if ! _is_podman_environment && ! command -v nft &>/dev/null; then
            missing_cached="$missing_cached nftables"
        fi
        if [ -z "$missing_cached" ] && [ -x "$YQ_BINARY" ]; then
            return 0
        fi
        [ ! -x "$YQ_BINARY" ] && missing_cached="$missing_cached yq"
        _warn "依赖缓存存在，但关键工具缺失:${missing_cached}，将执行一次修复安装。"
    fi

    # 核心依赖：脚本运行的绝对前提，必须全部装上
    local lock_pkg="util-linux"
    command -v apk &>/dev/null && lock_pkg="util-linux-misc"
    local core_pkgs="bash curl jq openssl wget tar unzip ca-certificates ${lock_pkg}"
    # 可选依赖：部分功能需要，即使装失败也不致命
    local optional_pkgs="procps nftables socat iproute2 cron lsof"

    # Podman 的网络能力由容器运行时决定，即使安装 nftables 也无法写入
    # 主机 netfilter；在容器中跳过整组可选包，只保留脚本核心依赖。
    if _is_podman_environment; then
        optional_pkgs=""
        _info "检测到 Podman 容器：跳过 nftables 等可选依赖，使用 sing-box 用户态转发"
    fi
    
    # 针对不同发行版的 cron 包名适配
    if command -v apk &>/dev/null; then
        optional_pkgs="${optional_pkgs/cron/dcron}"
    elif ! command -v apt-get &>/dev/null && ! command -v yum &>/dev/null && ! command -v dnf &>/dev/null; then
        optional_pkgs="${optional_pkgs/cron/cronie}"
    fi

    _info "正在安装核心依赖..."
    _pkg_install $core_pkgs
    if ! command -v flock &>/dev/null; then
        # Alpine 版本间拆包名称有差异；其余发行版均由 util-linux 提供。
        _pkg_install util-linux 2>/dev/null || true
    fi
    
    if [ -n "$optional_pkgs" ]; then
        _info "正在安装可选依赖..."
        _pkg_install $optional_pkgs 2>/dev/null || {
            # 可选依赖批量安装失败时逐个尝试
            _warn "部分可选依赖批量安装遇到冲突，正在逐个重试..."
            for pkg in $optional_pkgs; do
                _pkg_install "$pkg" 2>/dev/null || true
            done
        }
    fi
    
    _install_yq

    # [修复] Alpine 上 dcron 安装后需手动启动 cron 守护进程
    if command -v apk &>/dev/null; then
        if command -v crond &>/dev/null; then
            # BusyBox 自带 crond 并不代表系统存在 dcron 的 OpenRC 服务；
            # 定时任务守护进程属于可选能力，不能让核心安装继承失败状态。
            rc-service dcron start 2>/dev/null || true
            rc-update add dcron default 2>/dev/null || true
        fi
    fi

    # 关键依赖验证：如果核心工具缺失则无法继续
    local missing=""
    for cmd in bash jq curl wget openssl tar unzip flock; do
        if ! command -v "$cmd" &>/dev/null; then
            missing="$missing $cmd"
        fi
    done
    if [ ! -x "$YQ_BINARY" ]; then
        missing="$missing yq"
    fi
    if [ -n "$missing" ]; then
        _error "以下关键依赖安装失败:${missing}"
        _error "请使用系统包管理器手动安装这些工具（如 apk add / apt-get install / yum install）"
        exit 1
    fi

    mkdir -p "$SINGBOX_DIR"
    printf '%s\n' "$DEP_STATE_VERSION" > "$DEP_STATE_FILE"
}

# 确保 nftables 可用，并检测实际 netfilter 写入能力
_ensure_nftables() {
    if ! command -v nft &>/dev/null; then
        _info "未检测到 nftables，尝试安装..."
        _pkg_install nftables
        if ! command -v nft &>/dev/null; then
            _error "nftables 安装失败。"
            return 1
        fi
        _success "nftables 安装成功。"
    fi

    if ! _nft_can_redirect 65530 65531; then
        _warn "nftables 命令存在，但当前环境无 netfilter 写权限（容器/LXC 无特权模式）。"
        _warn "端口转发将自动使用 sing-box 引擎代替。"
        return 2
    fi

    return 0
}

_singbox_core_is_locked() {
    [ -s "$SINGBOX_CORE_LOCK_FILE" ]
}

_write_singbox_core_lock() {
    local tmp
    mkdir -p "$SINGBOX_DIR" || return 1
    tmp=$(mktemp "${SINGBOX_CORE_LOCK_FILE}.tmp.XXXXXX") || return 1
    if ! printf '%s\n' "$SINGBOX_FIXED_VERSION" > "$tmp" \
        || ! chmod 600 "$tmp" \
        || ! mv -f "$tmp" "$SINGBOX_CORE_LOCK_FILE"; then
        rm -f -- "$tmp"
        return 1
    fi
}

_install_sing_box() {
    local requested_version="${1:-latest}"
    local api_url requested_label
    case "$requested_version" in
        latest)
            api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
            requested_label="最新稳定版"
            ;;
        "$SINGBOX_FIXED_VERSION")
            api_url="https://api.github.com/repos/SagerNet/sing-box/releases/tags/v${SINGBOX_FIXED_VERSION}"
            requested_label="固定版 v${SINGBOX_FIXED_VERSION}"
            ;;
        *)
            _error "不允许安装未授权的 sing-box 版本: ${requested_version}"
            return 1
            ;;
    esac
    _info "正在安装 ${requested_label} sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; return 1 ;;
    esac
    
    # 检测 C 库类型：Alpine 等系统使用 musl，需要下载对应版本
    local libc_suffix=""
    if ldd --version 2>&1 | grep -qi musl || [ -f /etc/alpine-release ]; then
        _info "检测到 musl libc (Alpine 等系统)，将下载 musl 版本..."
        libc_suffix="-musl"
    fi
    
    local search_pattern="linux-${arch_tag}${libc_suffix}.tar.gz"
    local asset_info release_tag release_draft release_prerelease
    local asset_count asset_name download_url asset_digest release_version expected_asset_name
    if ! asset_info=$(curl -fsSL --retry 3 --connect-timeout 10 "$api_url" | jq -r --arg pattern "$search_pattern" '
        [.assets[] | select(.name | endswith($pattern))] as $matches
        | [(.tag_name // ""),
           (if (.draft | type) == "boolean" then .draft else true end),
           (if (.prerelease | type) == "boolean" then .prerelease else true end),
           ($matches | length), ($matches[0].name // ""),
           ($matches[0].browser_download_url // ""), ($matches[0].digest // "")]
        | @tsv
    '); then
        _error "无法读取 sing-box 官方发布信息。"
        return 1
    fi
    IFS=$'\t' read -r release_tag release_draft release_prerelease asset_count asset_name download_url asset_digest <<< "$asset_info"
    if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || [ "$release_draft" != "false" ] || [ "$release_prerelease" != "false" ]; then
        _error "sing-box 官方发布元数据无效或不是稳定版，已拒绝安装。"
        return 1
    fi
    release_version="${release_tag#v}"
    if [ "$requested_version" != "latest" ] && [ "$release_version" != "$requested_version" ]; then
        _error "固定版响应不匹配：请求 v${requested_version}，实际为 ${release_tag}。"
        return 1
    fi
    if [ "$asset_count" != "1" ]; then
        _error "sing-box 官方发布中目标资产数量异常 (${asset_count:-无法解析})，已拒绝安装。"
        return 1
    fi
    expected_asset_name="sing-box-${release_version}-linux-${arch_tag}${libc_suffix}.tar.gz"
    if [ "$asset_name" != "$expected_asset_name" ] || [ -z "$download_url" ] \
        || [[ "$download_url" != "https://github.com/SagerNet/sing-box/releases/download/${release_tag}/${expected_asset_name}" ]]; then
        _error "无法获取可信的 sing-box 下载链接 (搜索: ${search_pattern})。"
        return 1
    fi
    if [[ ! "$asset_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        _error "sing-box 官方资产缺少有效的 API SHA-256 摘要，已拒绝替换核心。"
        return 1
    fi

    local temp_dir extracted_bin expected actual staged_bin digest_file extracted_version
    mkdir -p /var/tmp || { _error "创建安装临时目录失败。"; return 1; }
    # 上一次安装若被 OOM/SIGKILL 终止，退出清理不会执行。只清理本脚本
    # 使用的精确目录，避免残留的 90MB 二进制继续挤占容器内存配额。
    local stale_dir stale_pid
    for stale_dir in /var/tmp/.singbox-install.*; do
        [ -d "$stale_dir" ] || continue
        stale_pid=""
        [ -s "${stale_dir}/.active" ] && stale_pid=$(cat "${stale_dir}/.active" 2>/dev/null)
        if [ -n "$stale_pid" ] && kill -0 "$stale_pid" 2>/dev/null; then
            continue
        fi
        rm -rf -- "$stale_dir"
    done
    temp_dir=$(mktemp -d /var/tmp/.singbox-install.XXXXXX) || { _error "创建临时目录失败。"; return 1; }
    printf '%s\n' "$$" > "${temp_dir}/.active"
    digest_file="${temp_dir}/.archive.sha256"

    _info "正在下载并校验 sing-box 安装包..."
    if command -v sha256sum &>/dev/null; then
        wget -qO- "$download_url" | tee >(sha256sum > "$digest_file") | tar -xzf - -C "$temp_dir"
    else
        wget -qO- "$download_url" | tee >(openssl dgst -sha256 > "$digest_file") | tar -xzf - -C "$temp_dir"
    fi
    local -a stream_status=("${PIPESTATUS[@]}")
    if [ "${stream_status[0]:-1}" -ne 0 ] || [ "${stream_status[2]:-1}" -ne 0 ]; then
        _error "sing-box 安装包下载失败。"
        rm -rf "$temp_dir"
        return 1
    fi
    local digest_wait=0
    while [ ! -s "$digest_file" ] && [ "$digest_wait" -lt 50 ]; do
        sleep 0.1
        digest_wait=$((digest_wait + 1))
    done
    expected="${asset_digest#sha256:}"
    if command -v sha256sum &>/dev/null; then
        actual=$(awk '{print $1}' "$digest_file" 2>/dev/null)
    else
        actual=$(awk '{print $NF}' "$digest_file" 2>/dev/null)
    fi
    if [ -z "$expected" ] || [ -z "$actual" ] || [ "${expected,,}" != "${actual,,}" ]; then
        _error "sing-box 安装包 SHA-256 校验失败，已拒绝替换核心。"
        rm -rf "$temp_dir"
        return 1
    fi

    extracted_bin=$(find "$temp_dir" -name sing-box -type f 2>/dev/null | head -n 1)
    if [ -z "$extracted_bin" ]; then
        _error "解压后未找到 sing-box 二进制文件。"
        rm -rf "$temp_dir"
        return 1
    fi
    chmod 755 "$extracted_bin" || { rm -rf "$temp_dir"; return 1; }
    if ! "$extracted_bin" version >/dev/null 2>&1; then
        _error "下载的 sing-box 核心无法执行，已拒绝安装。"
        rm -rf "$temp_dir"
        return 1
    fi
    extracted_version=$("$extracted_bin" version 2>/dev/null | sed -n 's/^sing-box version \([^[:space:]]*\).*/\1/p' | head -n 1)
    if [ "$extracted_version" != "$release_version" ]; then
        _error "下载核心版本与官方发布不匹配：期望 v${release_version}，实际 v${extracted_version:-未知}。"
        rm -rf "$temp_dir"
        return 1
    fi

    # 在触碰旧核心之前，用新核心校验真实的双配置组合。
    if [ -s "$CONFIG_FILE" ]; then
        local validation_relay="$RELAY_CONFIG_FILE"
        if [ ! -s "$validation_relay" ]; then
            validation_relay="${temp_dir}/relay.json"
            printf '%s\n' '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$validation_relay"
        fi
        local validation_result
        if ! validation_result=$(_check_combined_config_files "$extracted_bin" "$CONFIG_FILE" "$validation_relay" 2>&1); then
            _error "新核心无法加载当前 config.json + relay.json，已取消更新："
            echo "$validation_result"
            rm -rf "$temp_dir"
            return 1
        fi
    fi

    mkdir -p "$(dirname "$SINGBOX_BIN")" || { rm -rf "$temp_dir"; return 1; }
    staged_bin=$(mktemp "$(dirname "$SINGBOX_BIN")/.sing-box.new.XXXXXX") || { rm -rf "$temp_dir"; return 1; }
    rm -f -- "$staged_bin"
    if ! mv -f -- "$extracted_bin" "$staged_bin"; then
        # /var/tmp 与安装目录通常位于同一文件系统；跨文件系统时再退回
        # cp，保证原子替换流程仍可用。
        if ! cp -- "$extracted_bin" "$staged_bin"; then
            rm -f -- "$staged_bin"; rm -rf -- "$temp_dir"; return 1
        fi
    fi
    chmod 755 "$staged_bin" || { rm -f -- "$staged_bin"; rm -rf -- "$temp_dir"; return 1; }

    SINGBOX_UPDATE_BACKUP=""
    SINGBOX_UPDATE_HAD_OLD="false"
    if [ -f "$SINGBOX_BIN" ]; then
        SINGBOX_UPDATE_HAD_OLD="true"
        SINGBOX_UPDATE_BACKUP="$(dirname "$SINGBOX_BIN")/.sing-box.rollback.$$"
        cp -p "$SINGBOX_BIN" "$SINGBOX_UPDATE_BACKUP" || {
            rm -f "$staged_bin"; rm -rf "$temp_dir"; return 1;
        }
    fi
    if ! mv -f "$staged_bin" "$SINGBOX_BIN"; then
        rm -f "$staged_bin" "$SINGBOX_UPDATE_BACKUP"
        rm -rf "$temp_dir"
        return 1
    fi

    rm -rf "$temp_dir"
    _release_install_cache
    SINGBOX_STAGED_VERSION="$release_version"
    _success "sing-box v${release_version} 已安全暂存: ${SINGBOX_BIN}"
}

_rollback_singbox_binary() {
    if [ "${SINGBOX_UPDATE_HAD_OLD:-false}" = "true" ] && [ -s "${SINGBOX_UPDATE_BACKUP:-}" ]; then
        mv -f "$SINGBOX_UPDATE_BACKUP" "$SINGBOX_BIN" && chmod 755 "$SINGBOX_BIN"
    elif [ "${SINGBOX_UPDATE_HAD_OLD:-false}" != "true" ]; then
        rm -f "$SINGBOX_BIN"
    fi
    SINGBOX_UPDATE_BACKUP=""
}

_commit_singbox_binary() {
    [ -n "${SINGBOX_UPDATE_BACKUP:-}" ] && rm -f "$SINGBOX_UPDATE_BACKUP"
    SINGBOX_UPDATE_BACKUP=""
}

_install_cloudflared() {
    if [ -x "${CLOUDFLARED_BIN}" ] && "${CLOUDFLARED_BIN}" --version >/dev/null 2>&1; then
        _info "cloudflared 已安装: $(${CLOUDFLARED_BIN} --version 2>&1 | head -n1)"
        return 0
    fi
    
    _info "正在安装依据环境所需的组件 (ca-certificates)..."
    _pkg_install ca-certificates # 关键修复：Alpine 等精简系统必须有证书才能进行 TLS 握手
    
    _info "正在安装 cloudflared..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='arm' ;;
        *) _error "不支持的架构：$arch"; return 1 ;;
    esac
    
    local asset_name="cloudflared-linux-${arch_tag}"
    local asset_count asset_info download_url asset_digest expected actual
    if ! asset_info=$(curl -fsSL --retry 3 --connect-timeout 10 https://api.github.com/repos/cloudflare/cloudflared/releases/latest | jq -r --arg name "$asset_name" '
        [.assets[] | select(.name == $name)] as $matches
        | [($matches | length), ($matches[0].browser_download_url // ""), ($matches[0].digest // "")]
        | @tsv
    '); then
        _error "无法读取 cloudflared 官方发布信息。"
        return 1
    fi
    IFS=$'\t' read -r asset_count download_url asset_digest <<< "$asset_info"
    if [ "$asset_count" != "1" ]; then
        _error "cloudflared 官方发布中目标资产数量异常 (${asset_count:-无法解析})。"
        return 1
    fi
    if [[ "$download_url" != https://github.com/cloudflare/cloudflared/releases/download/* ]] \
        || [[ ! "$asset_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        _error "cloudflared 官方资产缺少可信下载地址或 API SHA-256 摘要，已拒绝安装。"
        return 1
    fi

    mkdir -p "$(dirname "$CLOUDFLARED_BIN")" || return 1
    local tmp_cloudflared
    tmp_cloudflared=$(mktemp "$(dirname "$CLOUDFLARED_BIN")/.cloudflared.new.XXXXXX") || return 1
    if ! wget -qO "$tmp_cloudflared" "$download_url"; then
        rm -f "$tmp_cloudflared"
        _error "cloudflared 下载失败!"
        return 1
    fi
    expected="${asset_digest#sha256:}"
    if command -v sha256sum &>/dev/null; then
        actual=$(sha256sum "$tmp_cloudflared" | awk '{print $1}')
    else
        actual=$(openssl dgst -sha256 "$tmp_cloudflared" 2>/dev/null | awk '{print $NF}')
    fi
    if [ -z "$actual" ] || [ "${actual,,}" != "$expected" ]; then
        rm -f -- "$tmp_cloudflared"
        _error "cloudflared SHA-256 校验失败，已拒绝安装。"
        return 1
    fi
    chmod 755 "$tmp_cloudflared" || { rm -f "$tmp_cloudflared"; return 1; }
    if ! "$tmp_cloudflared" --version >/dev/null 2>&1; then
        rm -f "$tmp_cloudflared"
        _error "下载的 cloudflared 无法执行，已拒绝安装。"
        return 1
    fi
    mv -f "$tmp_cloudflared" "$CLOUDFLARED_BIN" || { rm -f "$tmp_cloudflared"; return 1; }
    
    _success "cloudflared 安装成功: $(${CLOUDFLARED_BIN} --version 2>&1 | head -n1)"
}

# --- Argo Tunnel 功能 ---

_prepare_argo_runtime_dir() {
    if [ -L "$RUNTIME_DIR" ]; then
        _error "Argo 运行目录不能是符号链接: $RUNTIME_DIR"
        return 1
    fi
    mkdir -p "$RUNTIME_DIR" || return 1
    chmod 700 "$RUNTIME_DIR" 2>/dev/null || return 1
}

_argo_pid_file() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
    printf '%s/argo-%s.pid\n' "$RUNTIME_DIR" "$port"
}

_argo_log_file() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
    printf '/var/log/singbox_argo_%s.log\n' "$port"
}

_migrate_legacy_argo_state() {
    local port="$1" pid_file legacy_pid_file legacy_log_file legacy_pid=""
    pid_file=$(_argo_pid_file "$port") || return 1
    _prepare_argo_runtime_dir || return 1
    legacy_pid_file="/tmp/singbox_argo_${port}.pid"
    legacy_log_file="/tmp/singbox_argo_${port}.log"

    if _is_pid_file_running_cmd "$pid_file" "$CLOUDFLARED_BIN"; then
        rm -f -- "$legacy_pid_file" "$legacy_log_file"
        return 0
    fi
    rm -f -- "$pid_file"

    # /tmp 旧 PID 只有在不是符号链接且 cmdline 确认为 cloudflared 时才迁移。
    if [ -s "$legacy_pid_file" ] && [ ! -L "$legacy_pid_file" ]; then
        legacy_pid=$(cat "$legacy_pid_file" 2>/dev/null)
        if _is_pid_running_cmd "$legacy_pid" "$CLOUDFLARED_BIN"; then
            printf '%s\n' "$legacy_pid" > "$pid_file" || return 1
            chmod 600 "$pid_file" 2>/dev/null || { rm -f -- "$pid_file"; return 1; }
        fi
    fi
    rm -f -- "$legacy_pid_file" "$legacy_log_file"
}

_argo_domain_resolves() {
    local domain="$1" remote_ip="" dns_json=""
    [[ "$domain" =~ ^[A-Za-z0-9-]+\.trycloudflare\.com$ ]] || return 1

    if command -v getent >/dev/null 2>&1; then
        getent ahostsv4 "$domain" >/dev/null 2>&1 && return 0
        getent hosts "$domain" >/dev/null 2>&1 && return 0
    fi
    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$domain" >/dev/null 2>&1 && return 0
    fi

    # 系统递归解析器可能缓存刚创建域名的 NXDOMAIN。Quick Tunnel 属于
    # Cloudflare 服务，额外用其 DoH 端点核验公开记录，避免本机负缓存误判。
    if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        dns_json=$(curl -fsS --connect-timeout 5 --max-time 10 \
            -H 'accept: application/dns-json' --get \
            --data-urlencode "name=${domain}" --data-urlencode 'type=A' \
            'https://1.1.1.1/dns-query' 2>/dev/null || true)
        printf '%s' "$dns_json" | jq -e '
            (.Status == 0) and any(.Answer[]?; (.type == 1 or .type == 28) and ((.data // "") | length > 0))
        ' >/dev/null 2>&1 && return 0
    fi

    # 精简容器可能同时缺少 getent/nslookup。curl 即使收到后端协议错误，
    # 只要已经解析并连接到边缘节点，也会填充 remote_ip。
    remote_ip=$(curl -ksS --connect-timeout 5 --max-time 8 -o /dev/null \
        -w '%{remote_ip}' "https://${domain}/" 2>/dev/null || true)
    [ -n "$remote_ip" ]
}

_start_argo_tunnel() {
    local target_port="$1"
    local protocol="$2"
    local token="$3" # 可选，用于固定隧道
    local retry_count="${4:-0}"
    
    # 基于端口生成独立的受保护 PID 和日志路径，并迁移旧 /tmp 状态。
    local pid_file log_file
    pid_file=$(_argo_pid_file "$target_port") || { _error "无效的 Argo 内部端口: $target_port"; return 1; }
    log_file=$(_argo_log_file "$target_port") || return 1
    _migrate_legacy_argo_state "$target_port" || return 1
    
    _info "正在启动 Argo 隧道 (端口: $target_port)..." >&2
    
    # 检查该端口对应的隧道是否已在运行
    if [ -f "$pid_file" ]; then
        local old_pid
        old_pid=$(cat "$pid_file" 2>/dev/null)
        if _is_pid_running_cmd "$old_pid" "$CLOUDFLARED_BIN"; then
            _warning "检测到端口 $target_port 的 Argo 隧道已在运行 (PID: $old_pid)" >&2
            return 0
        fi
    fi
    
    # 清理旧日志和同步时间
    rm -f -- "$pid_file" "$log_file"
    : > "$log_file" || return 1
    chmod 600 "$log_file" 2>/dev/null || return 1
    _sync_system_time
    
    if [ -n "$token" ]; then
        # --- Token 固定隧道模式 ---
        _info "启动固定隧道 (Token 模式)..." >&2
        
        # 强制锁定 protocol http2 (h2)，防止 QUIC (UDP) 被阻断导致连接失败
        # 增加 --no-autoupdate 防止在精简系统上因自更新导致的意外进程挂起
        nohup "${CLOUDFLARED_BIN}" tunnel --protocol http2 --no-autoupdate run --token "$token" > "${log_file}" 2>&1 &
            
        local cf_pid=$!
        printf '%s\n' "$cf_pid" > "${pid_file}"
        chmod 600 "$pid_file" 2>/dev/null || true
        
        sleep 5
        if ! _is_pid_running_cmd "$cf_pid" "$CLOUDFLARED_BIN"; then
             _error "cloudflared 进程已退出！" >&2
             _error "Token 可能无效，或者网络连接被拒绝。" >&2
             echo "--- 错误日志 (最后 20 行) ---" >&2
             cat "${log_file}" | tail -20 >&2
             echo "-----------------------------"
             rm -f -- "$pid_file"
             return 1
        fi
        _enable_argo_watchdog
        _success "Argo 固定隧道 (端口: $target_port) 启动成功!" >&2
        return 0
    else
        # --- URL 临时隧道模式 ---
        _info "启动临时隧道，指向 127.0.0.1:${target_port}..." >&2
        
        # 优化：强制指定 http2 协议并禁用自动更新
        nohup "${CLOUDFLARED_BIN}" tunnel --protocol http2 --no-autoupdate --url "http://127.0.0.1:${target_port}" \
            --logfile "${log_file}" \
            > /dev/null 2>&1 &
        
        local cf_pid=$!
        printf '%s\n' "$cf_pid" > "${pid_file}"
        chmod 600 "$pid_file" 2>/dev/null || true
        
        # 等待隧道启动并获取域名
        _info "等待隧道建立 (最多30秒)..." >&2
        
        local tunnel_domain=""
        local wait_count=0
        local max_wait=30
        
        while [ $wait_count -lt $max_wait ]; do
            sleep 2
            wait_count=$((wait_count + 2))
            
            # 检查进程是否还在运行
            if ! _is_pid_running_cmd "$cf_pid" "$CLOUDFLARED_BIN"; then
                _error "cloudflared 进程已退出，请检查日志: ${log_file}" >&2
                cat "${log_file}" 2>/dev/null | tail -20 >&2
                return 1
            fi
            
            # 优化域名提取正则表达式，确保无论日志格式如何变化都能准确抓取
            if [ -f "${log_file}" ]; then
                tunnel_domain=$(grep -oE 'https?://[a-zA-Z0-9-]+\.trycloudflare\.com' "${log_file}" 2>/dev/null | head -n 1 | sed -E 's|https?://||')
                if [ -n "$tunnel_domain" ]; then
                    break
                fi
            fi
            echo -n "." >&2
        done
        echo "" >&2
        
        if [ -n "$tunnel_domain" ]; then
            _info "域名已获取，正在等待 DNS 发布 (最多90秒)..." >&2
            local dns_wait=0 dns_ready=false
            while [ "$dns_wait" -lt 90 ]; do
                if _argo_domain_resolves "$tunnel_domain"; then
                    dns_ready=true
                    break
                fi
                if ! _is_pid_running_cmd "$cf_pid" "$CLOUDFLARED_BIN"; then
                    break
                fi
                sleep 5
                dns_wait=$((dns_wait + 5))
            done

            if [ "$dns_ready" != true ]; then
                _warn "Cloudflare 已分配临时域名，但 DNS 尚未发布，正在清理本次隧道。" >&2
                _is_pid_running_cmd "$cf_pid" "$CLOUDFLARED_BIN" && kill "$cf_pid" 2>/dev/null
                wait "$cf_pid" 2>/dev/null || true
                rm -f -- "$pid_file" "$log_file"
                if [ "$retry_count" -lt 1 ]; then
                    _warn "正在自动重新申请一次临时域名..." >&2
                    _start_argo_tunnel "$target_port" "$protocol" "" "$((retry_count + 1))"
                    return $?
                fi
                _error "Cloudflare 临时域名连续两次未完成 DNS 发布，请稍后重试。" >&2
                return 1
            fi

            _info "域名已发布，正在进行稳定性测试 (5秒)..." >&2
            sleep 5
            if ! _is_pid_running_cmd "$cf_pid" "$CLOUDFLARED_BIN"; then
                 _error "稳定性测试失败：cloudflared 进程异常退出。" >&2
                 cat "${log_file}" 2>/dev/null | tail -n 10 >&2
                 return 1
            fi

            _enable_argo_watchdog
            _success "Argo 临时隧道建立成功: ${tunnel_domain}" >&2
            echo "$tunnel_domain"
            return 0
        else
            _error "获取临时域名超时。请检查网络。日志最后几行：" >&2
            cat "${log_file}" 2>/dev/null | tail -n 5 >&2
            _is_pid_running_cmd "$cf_pid" "$CLOUDFLARED_BIN" && kill "$cf_pid" 2>/dev/null
            rm -f "${pid_file}"
            return 1
        fi
    fi
}

_stop_argo_tunnel() {
    local target_port="$1"
    local pid_file log_file
    pid_file=$(_argo_pid_file "$target_port") || return 1
    log_file=$(_argo_log_file "$target_port") || return 1
    _migrate_legacy_argo_state "$target_port" || return 1

    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null)
        if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
            kill "$pid" 2>/dev/null
            _success "Argo 隧道 (端口: $target_port) 已停止"
        fi
    fi
    rm -f -- "$pid_file" "$log_file" "/tmp/singbox_argo_${target_port}.pid" "/tmp/singbox_argo_${target_port}.log"
}

_stop_all_argo_tunnels() {
    _info "正在停止所有 Argo 隧道..."
    local stopped_any=false
    local pid_file filename port

    # 优先按元数据停止，可兼容尚未迁移的旧 /tmp PID。
    if [ -s "$ARGO_METADATA_FILE" ]; then
        while IFS= read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            _stop_argo_tunnel "$port"
            stopped_any=true
        done < <(jq -r '.[].local_port // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
    fi

    for pid_file in "$RUNTIME_DIR"/argo-*.pid; do
        [ -e "$pid_file" ] || continue
        filename=$(basename "$pid_file")
        port=${filename#argo-}
        port=${port%.pid}
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        _stop_argo_tunnel "$port"
        stopped_any=true
    done
    for pid_file in /tmp/singbox_argo_*.pid; do
        [ -e "$pid_file" ] || continue
        filename=$(basename "$pid_file")
        port=${filename#singbox_argo_}
        port=${port%.pid}
        [[ "$port" =~ ^[0-9]+$ ]] || { rm -f -- "$pid_file"; continue; }
        _stop_argo_tunnel "$port"
        stopped_any=true
    done
    if [ "$stopped_any" = false ]; then
        _warn "未找到本脚本记录的 Argo PID 文件，未执行全局 cloudflared 清理。"
    fi
}

# ============================================================
# 统一 Argo 节点创建函数 (消除 VLESS/Trojan 重复代码)
# 参数: $1 = 协议类型 ("vless" 或 "trojan")
# ============================================================
_add_argo_node() {
    local protocol="$1"
    local protocol_label=""
    local proto_name=""
    case "$protocol" in
        vless) protocol_label="VLESS-WS"; proto_name="Vless" ;;
        trojan) protocol_label="Trojan-WS"; proto_name="Trojan" ;;
        *) _error "不支持的 Argo 协议: $protocol"; return 1 ;;
    esac

    _info "--- 创建 ${protocol_label} + Argo 隧道节点 ---"

    # 安装 cloudflared
    _install_cloudflared || return 1

    # === [公共] 内部端口分配 ===
    read -p "请输入 Argo 内部监听端口 (回车随机生成): " input_port
    local port="$input_port"

    while true; do
        if [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ]; then
            _check_port_conflict "$port" "tcp" && port="" && continue
            _info "已使用监听端口: ${port}"
            break
        else
            [ -n "$port" ] && _warning "端口格式无效，将重新生成..."
            # 使用内建算法生成随机端口 (10000-60000)，移除 shuf 依赖
            port=$(( $(od -An -tu2 -N2 /dev/urandom | tr -d ' ') % 50001 + 10000 ))
            _info "正在尝试分配随机内部端口: ${port}..."
        fi
    done

    # === [公共] WebSocket 路径 ===
    read -p "请输入 WebSocket 路径 (回车随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已生成随机路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    # === [协议特定] Trojan 密码输入 ===
    local password=""
    if [ "$protocol" == "trojan" ]; then
        read -p "请输入 Trojan 密码 (回车随机生成): " password
        if [ -z "$password" ]; then
            password=$(${SINGBOX_BIN} generate rand --hex 16)
            _info "已生成随机密码: ${password}"
        fi
    fi

    # === [公共] 隧道模式选择 ===
    echo ""
    echo "请选择隧道模式:"
    echo "  1. 临时隧道 (无需配置, 随机域名, 不稳定，重启失效)"
    echo "  2. 固定隧道 (需 Token, 自定义域名, 稳定持久，重启不失效)"
    read -p "请选择 [1/2] (默认: 1): " tunnel_mode
    tunnel_mode=${tunnel_mode:-1}

    local token=""
    local tunnel_domain=""
    local argo_type="temp"

    if [ "$tunnel_mode" == "2" ]; then
        argo_type="fixed"
        _info "您选择了 [固定隧道] 模式。"
        echo ""
        _info "请粘贴 Cloudflare Tunnel Token (支持直接粘贴CF网页端所给出的任何安装命令):"
        read -p "Token: " input_token
        # 自动提取 Token
        token=$(echo "$input_token" | grep -oE 'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1)
        if [ -z "$token" ]; then
             token=$(echo "$input_token" | grep -oE 'ey[A-Za-z0-9_-]{20,}' | head -1)
        fi
        if [ -z "$token" ]; then
             token="$input_token"
        fi

        if [ -z "$token" ]; then _error "Token 不能为空"; return 1; fi
        _info "已识别 Token (前20位): ${token:0:20}..."

        echo ""
        _info "请输入该 Tunnel 绑定的域名 (用于生成客户端配置):"
        read -p "域名 (例如 tunnel.example.com): " input_domain
        if [ -z "$input_domain" ]; then _error "域名不能为空"; return 1; fi
        tunnel_domain="$input_domain"

        echo ""
        _info "【重要提示】请务必去 Cloudflare Dashboard 配置该 Tunnel 的 Public Hostname:"
        _info "  Public Hostname: ${tunnel_domain}"
        _info "  Service: http://localhost:${port}"
        echo ""
        read -n 1 -s -r -p "确认配置无误后，按任意键继续..."
        echo ""
    else
        _info "您选择了 [临时隧道] 模式。"
    fi

    # === [公共] 节点名称 ===
    local default_prefix="Argo-Temp"
    if [ "$argo_type" == "fixed" ]; then
        default_prefix="Argo-Fixed"
    fi
    local default_name="${default_prefix}-${proto_name}-${port}"

    echo ""
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    # === [协议特定] 生成凭据、tag 和 Inbound ===
    local tag="argo-${protocol}-ws-${port}"
    local uuid=""
    local inbound_json=""

    if [ "$protocol" == "vless" ]; then
        uuid=$(${SINGBOX_BIN} generate uuid)
        inbound_json=$(jq -n \
            --arg t "$tag" \
            --arg p "$port" \
            --arg u "$uuid" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "type": "vless",
                "tag": $t,
                "listen": "127.0.0.1",
                "listen_port": ($p|tonumber),
                "users": [{"uuid": $u, "flow": ""}],
                "transport": {
                    "type": "ws",
                    "path": $wsp,
                    "max_early_data": $ed,
                    "early_data_header_name": $edh
                }
            }')
    elif [ "$protocol" == "trojan" ]; then
        inbound_json=$(jq -n \
            --arg t "$tag" \
            --arg p "$port" \
            --arg pw "$password" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "type": "trojan",
                "tag": $t,
                "listen": "127.0.0.1",
                "listen_port": ($p|tonumber),
                "users": [{"password": $pw}],
                "transport": {
                    "type": "ws",
                    "path": $wsp,
                    "max_early_data": $ed,
                    "early_data_header_name": $edh
                }
            }')
    fi

    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    # === [公共] 重启 + 启动隧道 ===
    _manage_service "restart"
    sleep 2

    if [ "$argo_type" == "fixed" ]; then
        if ! _start_argo_tunnel "$port" "${protocol}-ws" "$token"; then
             _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
             _manage_service "restart"
             return 1
        fi
    else
        local real_domain=$(_start_argo_tunnel "$port" "${protocol}-ws")
        if [ -z "$real_domain" ] || [ "$real_domain" == "" ]; then
            _error "隧道启动失败，正在回滚配置..."
            _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
            _manage_service "restart"
            return 1
        fi
        tunnel_domain="$real_domain"
    fi

    # === [协议特定] 保存元数据 ===
    local credential_key="" credential_val=""
    if [ "$protocol" == "vless" ]; then
        credential_key="uuid"; credential_val="$uuid"
    else
        credential_key="password"; credential_val="$password"
    fi

    local argo_meta=$(jq -n \
        --arg tag "$tag" \
        --arg name "$name" \
        --arg domain "$tunnel_domain" \
        --arg port "$port" \
        --arg cred_val "$credential_val" \
        --arg cred_key "$credential_key" \
        --arg path "$ws_path" \
        --arg protocol "${protocol}-ws" \
        --arg type "$argo_type" \
        --arg token "$token" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        '{($tag): {name: $name, domain: $domain, local_port: ($port|tonumber), ($cred_key): $cred_val, path: $path, protocol: $protocol, type: $type, token: $token, created_at: $created}}')

    if [ ! -f "$ARGO_METADATA_FILE" ]; then
        echo '{}' > "$ARGO_METADATA_FILE"
    fi
    _atomic_modify_json "$ARGO_METADATA_FILE" ". + $argo_meta"

    # === [协议特定] Clash 配置 + 分享链接 ===
    local proxy_json=""
    if [ "$protocol" == "vless" ]; then
        proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$tunnel_domain" \
            --arg u "$uuid" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "name": $n,
                "type": "vless",
                "server": $s,
                "port": 443,
                "uuid": $u,
                "tls": true,
                "udp": true,
                "skip-cert-verify": false,
                "network": "ws",
                "servername": $s,
                "ws-opts": {
                    "path": $wsp,
                    "max-early-data": $ed,
                    "early-data-header-name": $edh,
                    "headers": {
                        "Host": $s
                    }
                }
            }')
    elif [ "$protocol" == "trojan" ]; then
        proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$tunnel_domain" \
            --arg pw "$password" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "name": $n,
                "type": "trojan",
                "server": $s,
                "port": 443,
                "password": $pw,
                "udp": true,
                "skip-cert-verify": false,
                "network": "ws",
                "sni": $s,
                "ws-opts": {
                    "path": $wsp,
                    "max-early-data": $ed,
                    "early-data-header-name": $edh,
                    "headers": {
                        "Host": $s
                    }
                }
            }')
    fi

    if ! _add_node_to_yaml "$proxy_json"; then
        _stop_argo_tunnel "$port"
        _atomic_modify_json "$CONFIG_FILE" 'del(.inbounds[] | select(.tag == $tag))' --arg tag "$tag" >/dev/null 2>&1 || true
        _atomic_modify_json "$ARGO_METADATA_FILE" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
        return 1
    fi

    # === [公共] 启用守护 + 显示结果 ===
    # 守护是 Argo 节点的完整性条件；失败时回滚本次节点，避免产生
    # 表面创建成功但重启后无法自愈的半成品状态。
    if ! _enable_argo_watchdog; then
        _stop_argo_tunnel "$port"
        _atomic_modify_json "$CONFIG_FILE" 'del(.inbounds[] | select(.tag == $tag))' --arg tag "$tag" >/dev/null 2>&1 || true
        _atomic_modify_json "$ARGO_METADATA_FILE" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
        _remove_node_from_yaml "$name" >/dev/null 2>&1 || true
        _manage_service "restart" >/dev/null 2>&1 || true
        return 1
    fi

    echo ""
    _success "${protocol_label} + Argo 节点创建成功!"
    echo "-------------------------------------------"
    echo -e "节点名称: ${GREEN}${name}${NC}"
    echo -e "隧道类型: ${CYAN}${argo_type}${NC}"
    echo -e "隧道域名: ${CYAN}${tunnel_domain}${NC}"
    echo -e "本地端口: ${port}"
    echo "-------------------------------------------"
    
    # 使用统一链接生成器进行展示与持久化
    if [ "$protocol" == "vless" ]; then
        _show_node_link "vless-ws" "$name" "$tunnel_domain" "443" "$tag" "$uuid" "$ws_path"
    else
        _show_node_link "trojan-ws" "$name" "$tunnel_domain" "443" "$tag" "$password" "$ws_path"
    fi
    
    echo "-------------------------------------------"
    if [ "$argo_type" == "temp" ]; then
        _warning "注意: 临时隧道每次重启域名会变化！"
    fi
}

# 保留原始函数名作为薄包装器，确保向后兼容
_add_argo_vless_ws() { _add_argo_node "vless"; }

_add_argo_trojan_ws() { _add_argo_node "trojan"; }

_view_argo_nodes() {
    _info "--- Argo 隧道节点信息 ---"
    
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE")" -eq 0 ]; then
        _warning "没有 Argo 隧道节点。"
        return
    fi
    
    echo "==================================================="
    # 遍历并显示
    jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.type)|\(.value.protocol)|\(.value.local_port)|\(.value.domain)|\(.value.uuid // "")|\(.value.path // "")|\(.value.password // "")"' "$ARGO_METADATA_FILE" | \
    while IFS='|' read -r tag name argo_type protocol port domain uuid path password; do
        echo -e "节点: ${GREEN}${name}${NC}"
        echo -e "  协议: ${protocol}"
        echo -e "  端口: ${port}"
        
        # 检查状态
        local pid_file
        _migrate_legacy_argo_state "$port" >/dev/null 2>&1 || true
        pid_file=$(_argo_pid_file "$port")
        local state="${RED}已停止${NC}"
        local running_domain=""
        
        # [M4] 一次读取 PID 到变量，避免重复 cat
        local pid=""
        if [ -f "$pid_file" ]; then pid=$(cat "$pid_file" 2>/dev/null); fi
        if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
             state="${GREEN}运行中${NC} (PID: $pid)"
             # 如果是临时的，尝试从 log 读最新域名
             if [ "$argo_type" == "temp" ] || [ -z "$domain" ] || [ "$domain" == "null" ]; then
                  local log_file
                  log_file=$(_argo_log_file "$port")
                  local temp_domain=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "$log_file" 2>/dev/null | tail -1 | sed 's|https://||')
                   [ -n "$temp_domain" ] && domain="$temp_domain"
             fi
             running_domain="$domain"
        fi
        
        if [ -n "$domain" ] && [ "$domain" != "null" ]; then
             local link=""
             
             # [新架构] 优先使用持久化链接
             link=$(jq -r --arg t "$tag" '.[$t].share_link // empty' "$ARGO_METADATA_FILE")
             
              if [ -z "$link" ] || [ "$link" == "null" ]; then
                  local safe_name=$(_url_encode "$name")
                  local ed_path=$(_ws_path_with_early_data "$path")
                  local safe_path=$(_url_encode "$ed_path")
                  
                  if [[ "$protocol" == "vless-ws" ]]; then
                      link="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${safe_path}&sni=${domain}#${safe_name}"
                 elif [[ "$protocol" == "trojan-ws" ]]; then
                     local safe_pw=$(_url_encode "$password")
                     link="trojan://${safe_pw}@${domain}:443?security=tls&type=ws&host=${domain}&path=${safe_path}&sni=${domain}#${safe_name}"
                 fi
             fi

             if [ -n "$link" ]; then
                  echo -e "  ${YELLOW}链接:${NC} $link"
             fi
        fi
        echo "-------------------------------------------"
    done
    
    echo -e "${YELLOW}提示: 请使用 [9] 重启隧道 来刷新所有节点状态或获取新临时域名。${NC}"
    echo "==================================================="
}

_delete_argo_node() {
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE")" -eq 0 ]; then
        _warning "没有 Argo 隧道节点可删除。"
        return
    fi
    
    _info "--- 删除 Argo 隧道节点 ---"
    
    # 读取所有节点到数组
    local i=1
    local keys=()
    local names=()
    local ports=()
    
    # 必须使用 while read 处理 process substitution 避免子 shell 问题
    while IFS='|' read -r key name port; do
        keys+=("$key")
        names+=("$name")
        ports+=("$port")
        echo -e " ${CYAN}$i)${NC} ${name} (端口: $port)"
        ((i++))
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)"' "$ARGO_METADATA_FILE")
    
    if [ ${#keys[@]} -eq 0 ]; then
         _warning "读取元数据失败。"
         return
    fi

    echo " 0) 返回"
    read -p "请选择要删除的节点: " choice
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#keys[@]}" ]; then
        _error "无效输入"
        return
    fi
    
    if [ "$choice" -eq 0 ]; then return; fi
    
    local idx=$((choice - 1))
    local selected_key="${keys[$idx]}"
    local selected_name="${names[$idx]}"
    local selected_port="${ports[$idx]}"
    
    _info "正在删除节点: ${selected_name} (端口: ${selected_port})..."
    
    # 1. 停止该节点的隧道进程
    _stop_argo_tunnel "$selected_port"
    
    # 2. 从 sing-box 配置文件中移除 inbound
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$selected_key\"))"
    
    # 3. 删除 Argo 元数据
    _atomic_modify_json "$ARGO_METADATA_FILE" 'del(.[$tag])' --arg tag "$selected_key"
    
    # 4. 删除 Clash 配置
    _remove_node_from_yaml "$selected_name"
    
    # 5. 检查是否还有节点，如果没有则禁用守护进程
    if [ "$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null)" -eq 0 ]; then
        _disable_argo_watchdog
    fi

    # 6. 重启 sing-box
    _manage_service "restart"
    
    _success "节点 ${selected_name} 已删除！"
}

_stop_argo_menu() {
    _info "--- 停止 Argo 隧道进程 (保留配置) ---"
    # 复用选择逻辑
    local i=1
    local keys=()
    local names=()
    local ports=()
    
    while IFS='|' read -r key name port; do
        keys+=("$key")
        names+=("$name")
        ports+=("$port")
        echo -e " ${CYAN}$i)${NC} ${name} (端口: $port)"
        ((i++))
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)"' "$ARGO_METADATA_FILE")
    
    echo " a) 停止所有运行中的隧道"
    echo " 0) 返回"
    read -p "请选择: " choice
    
    if [ "$choice" == "a" ]; then
        _stop_all_argo_tunnels
        _success "所有隧道已停止指令发送。"
        return
    fi
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#keys[@]}" ]; then
        _error "无效输入"
        return
    fi
    if [ "$choice" -eq 0 ]; then return; fi
    
    local idx=$((choice - 1))
    local selected_port="${ports[$idx]}"
    
    _stop_argo_tunnel "$selected_port"
}

_restart_argo_tunnel_menu() {
    _info "--- 重启 Argo 隧道 ---"
    
     if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE")" -eq 0 ]; then
        _warning "没有 Argo 隧道节点。"
        return
    fi

    # 选择逻辑
    local i=1
    local keys=()
    local names=()
    local ports=()
    local protocols=()
    local types=()
    local tokens=()
    
    while IFS='|' read -r key name port proto type token; do
        keys+=("$key")
        names+=("$name")
        ports+=("$port")
        protocols+=("$proto")
        types+=("$type")
        tokens+=("$token")
        echo -e " ${CYAN}$i)${NC} ${name} (端口: $port)"
        ((i++))
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)|\(.value.protocol)|\(.value.type)|\(.value.token)"' "$ARGO_METADATA_FILE")
    
    echo " a) 重启所有节点"
    echo " 0) 返回"
    read -p "请选择: " choice
    
    local selected_indices=()
    if [ "$choice" == "a" ]; then
        # 生成所有索引
        for ((j=0; j<${#keys[@]}; j++)); do selected_indices+=("$j"); done
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -gt 0 ] && [ "$choice" -le "${#keys[@]}" ]; then
        selected_indices+=($((choice - 1)))
    else
        if [ "$choice" -ne 0 ]; then _error "无效输入"; fi
        return
    fi

    # 增强参数提取，为同步链接做准备
    local names=() ports=() protocols=() types=() tokens=() tags=() uuids=() passwords=() paths=()
    while IFS='|' read -r key name port proto type token uuid pw path; do
        tags+=("$key")
        names+=("$name")
        ports+=("$port")
        protocols+=("$proto")
        types+=("$type")
        tokens+=("$token")
        uuids+=("$uuid")
        passwords+=("$pw")
        paths+=("$path")
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)|\(.value.protocol)|\(.value.type)|\(.value.token // "")|\(.value.uuid // "")|\(.value.password // "")|\(.value.path // "")"' "$ARGO_METADATA_FILE")

    for i in "${!selected_indices[@]}"; do
        local idx="${selected_indices[$i]}"
        local tag="${tags[$idx]}"
        local name="${names[$idx]}"
        local port="${ports[$idx]}"
        local proto_full="${protocols[$idx]}"
        local type="${types[$idx]}"
        local token="${tokens[$idx]}"
        local uuid="${uuids[$idx]}"
        local password="${passwords[$idx]}"
        local ws_path="${paths[$idx]}"
        
        # 提取 protocol 简写用于 _start_argo_tunnel (vless/trojan)
        local proto_short="vless"
        [[ "$proto_full" == "trojan-ws" ]] && proto_short="trojan"

        _info "正在重启: $name (端口: $port)..."
        
        # 停止
        _stop_argo_tunnel "$port"
        sleep 1
        
        # 启动
        local new_domain=""
        if [ "$type" == "fixed" ]; then
            if _start_argo_tunnel "$port" "$proto_short-ws" "$token"; then
                 new_domain=$(jq -r --arg tag "$tag" '.[$tag].domain // empty' "$ARGO_METADATA_FILE")
            else
                 _error "固定隧道重启失败: $name"
            fi
        else
            new_domain=$(_start_argo_tunnel "$port" "$proto_short-ws")
            if [ -n "$new_domain" ]; then
                 _atomic_modify_json "$ARGO_METADATA_FILE" '.[$tag].domain = $domain' \
                     --arg tag "$tag" --arg domain "$new_domain"
                 _success "更新临时域名: $new_domain"
                 
                 # [同步链接] 临时域名变动，立即重新持久化链接
                 if [[ "$proto_full" == "vless-ws" ]]; then
                     _show_node_link "vless-ws" "$name" "$new_domain" "443" "$tag" "$uuid" "$ws_path" >/dev/null
                 else
                     _show_node_link "trojan-ws" "$name" "$new_domain" "443" "$tag" "$password" "$ws_path" >/dev/null
                 fi
            else
                 _error "临时隧道重启失败: $name"
            fi
        fi
    done
    _success "操作完成。"
}

# --- Argo 守护进程逻辑 ---

_argo_keepalive() {
    # keepalive 使用受保护运行目录中的 flock，避免可预测 /tmp 锁和并发重启。
    _prepare_argo_runtime_dir || return 1
    command -v flock >/dev/null 2>&1 || { _error "缺少 flock，Argo 守护任务已拒绝无锁运行。"; return 1; }
    exec 7>"${RUNTIME_DIR}/argo-keepalive.lock" || return 1
    flock -n 7 || { exec 7>&-; return 0; }

    # --- 性能优化: 日志轮转 (10MB) ---
    local max_size=$((10 * 1024 * 1024))
    local log_size
    for log in "$LOG_FILE" "$ARGO_LOG_FILE"; do
        log_size=0
        [ -f "$log" ] && log_size=$(wc -c < "$log" 2>/dev/null || echo 0)
        if [[ "$log_size" =~ ^[0-9]+$ ]] && [ "$log_size" -ge "$max_size" ]; then
            local log_tmp
            log_tmp=$(mktemp "${log}.tmp.XXXXXX") || continue
            if tail -n 1000 "$log" > "$log_tmp"; then
                chmod 600 "$log_tmp" 2>/dev/null || true
                mv -f "$log_tmp" "$log"
            else
                rm -f "$log_tmp"
            fi
        fi
    done

    # 如果元数据文件不存在或为空，不需要守护
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null)" -eq 0 ]; then
        flock -u 7 2>/dev/null || true
        exec 7>&-
        return
    fi

    # 遍历所有节点。这里不能使用 TSV 配合 IFS=$'\t'：临时隧道的 token
    # 必然为空，而 Bash 会折叠连续的空白 IFS 字符，导致 protocol/name/uuid
    # 整体左移，守护重启后甚至会把 UUID 误写成节点名称。逐条读取紧凑 JSON
    # 可同时正确保留空字段以及名称、路径中的空格和分隔符。
    local entry tag port type token protocol name uuid password path
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        tag=$(jq -r '.key // empty' <<< "$entry")
        port=$(jq -r '.value.local_port // empty' <<< "$entry")
        type=$(jq -r '.value.type // ""' <<< "$entry")
        token=$(jq -r '.value.token // ""' <<< "$entry")
        protocol=$(jq -r '.value.protocol // "vless-ws"' <<< "$entry")
        name=$(jq -r '.value.name // ""' <<< "$entry")
        uuid=$(jq -r '.value.uuid // ""' <<< "$entry")
        password=$(jq -r '.value.password // ""' <<< "$entry")
        path=$(jq -r '.value.path // ""' <<< "$entry")
        [ -z "$tag" ] && continue
        [[ "$port" =~ ^[0-9]+$ ]] || {
            logger "sing-box-watchdog: Ignoring invalid Argo metadata entry: $tag"
            continue
        }
        
        local pid_file
        _migrate_legacy_argo_state "$port" >/dev/null 2>&1 || true
        pid_file=$(_argo_pid_file "$port")
        local is_running=false
        
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file" 2>/dev/null)
            if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
                is_running=true
            fi
        fi
        
        if [ "$is_running" = false ]; then
            logger "sing-box-watchdog: Detected dead tunnel for $tag (Port: $port). Restarting..."
            
            # 提取 protocol 简写用于 _start_argo_tunnel (vless/trojan)
            local proto_short="vless"
            [[ "$protocol" == "trojan-ws" ]] && proto_short="trojan"

            if [ "$type" == "fixed" ] && [ -n "$token" ]; then
                 if _start_argo_tunnel "$port" "$proto_short-ws" "$token"; then
                     logger "sing-box-watchdog: Fixed tunnel $tag restarted successfully."
                 else
                     logger "sing-box-watchdog: Failed to restart fixed tunnel $tag."
                 fi
            else
                 # 临时隧道
                 local new_domain=$(_start_argo_tunnel "$port" "$proto_short-ws")
                 if [ -n "$new_domain" ]; then
                      # 更新元数据
                      _atomic_modify_json "$ARGO_METADATA_FILE" '.[$tag].domain = $domain' \
                          --arg tag "$tag" --arg domain "$new_domain"
                      logger "sing-box-watchdog: Temp tunnel $tag restarted with new domain: $new_domain"
                      
                      # [同步链接] 临时域名变动，静默更新持久化链接
                      if [[ "$protocol" == "vless-ws" ]]; then
                          _show_node_link "vless-ws" "$name" "$new_domain" "443" "$tag" "$uuid" "$path" >/dev/null
                      else
                          _show_node_link "trojan-ws" "$name" "$new_domain" "443" "$tag" "$password" "$path" >/dev/null
                      fi
                 else
                      logger "sing-box-watchdog: Failed to restart temp tunnel $tag."
                 fi
            fi
        fi
    done < <(jq -c 'to_entries[]' "$ARGO_METADATA_FILE" 2>/dev/null)
    flock -u 7 2>/dev/null || true
    exec 7>&-
}

_ensure_argo_cron() {
    local cron_pkg="cron"
    local services=(cron crond cronie)
    local service_name started=false

    if command -v apk &>/dev/null; then
        cron_pkg="dcron"
        services=(dcron crond)
    elif ! command -v apt-get &>/dev/null; then
        cron_pkg="cronie"
        services=(crond cronie)
    fi

    if ! command -v crontab &>/dev/null; then
        _info "正在按需安装 Argo 守护依赖: ${cron_pkg}..."
        if ! _pkg_install "$cron_pkg" || ! command -v crontab &>/dev/null; then
            _error "安装 Argo 守护依赖失败，未创建不受守护的隧道节点。"
            return 1
        fi
    fi

    case "${INIT_SYSTEM:-}" in
        systemd)
            for service_name in "${services[@]}"; do
                if systemctl enable --now "${service_name}.service" >/dev/null 2>&1; then
                    started=true
                    break
                fi
            done
            ;;
        openrc)
            for service_name in "${services[@]}"; do
                if rc-service "$service_name" start >/dev/null 2>&1; then
                    rc-update add "$service_name" default >/dev/null 2>&1 || true
                    started=true
                    break
                fi
            done
            ;;
        *)
            if command -v service &>/dev/null; then
                for service_name in "${services[@]}"; do
                    if service "$service_name" start >/dev/null 2>&1; then
                        started=true
                        break
                    fi
                done
            fi
            ;;
    esac

    if [ "$started" != true ]; then
        _error "Cron 服务启动失败，无法启用 Argo 自动守护。"
        return 1
    fi
}

_enable_argo_watchdog() {
    # Podman 低内存安装会跳过可选包；仅在使用 Argo 时按需安装 cron。
    local job="* * * * * bash ${SELF_SCRIPT_PATH} keepalive >/dev/null 2>&1"

    _ensure_argo_cron || return 1
    if crontab -l 2>/dev/null | grep -Fq "$job"; then
        return 0
    fi

    _info "正在添加后台守护进程 (Watchdog)..."
    if (crontab -l 2>/dev/null; echo "$job") | crontab -; then
        _success "守护进程已启用！(每分钟检查并自动修复失效隧道)"
        return 0
    fi

    _error "添加 Crontab 失败，未创建不受守护的隧道节点。"
    return 1
}

_disable_argo_watchdog() {
    local job="bash ${SELF_SCRIPT_PATH} keepalive"
    
    if crontab -l 2>/dev/null | grep -Fq "$job"; then
        _info "正在移除后台守护进程..."
        crontab -l 2>/dev/null | grep -Fv "$job" | crontab -
        _success "守护进程已移除。"
    fi
}

_uninstall_argo() {
    _warning "！！！警告！！！"
    _warning "本操作将删除所有 Argo 隧道节点和 cloudflared 程序。"
    echo ""
    echo "即将删除的内容："
    echo -e "  ${RED}-${NC} cloudflared 程序: ${CLOUDFLARED_BIN}"
    echo -e "  ${RED}-${NC} 所有 Argo 日志文件和元数据文件"
    
    if [ -f "$ARGO_METADATA_FILE" ]; then
        local argo_count=$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null || echo "0")
        echo -e "  ${RED}-${NC} Argo 节点数量: ${argo_count} 个"
    fi
    
    echo ""
    read -p "$(echo -e ${YELLOW}"确定要卸载 Argo 服务吗? (y/N): "${NC})" confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "卸载已取消。"
        return
    fi
    
    _info "正在卸载 Argo 服务..."
    
    # 1. 停止所有隧道进程
    _stop_all_argo_tunnels
    
    # 2. 删除 sing-box 中的 Argo inbound 配置
    if [ -f "$ARGO_METADATA_FILE" ]; then
        # 先保存键数组；不要依赖空白拆词，也不要把键直接拼进 jq 程序。
        local tags=()
        mapfile -t tags < <(jq -r 'keys[]' "$ARGO_METADATA_FILE" 2>/dev/null)
        local tag node_name
        for tag in "${tags[@]}"; do
             if [ -n "$tag" ]; then
                _info "正在删除 Argo 隧道: $tag ..."
                node_name=$(jq -r --arg tag "$tag" '.[$tag].name // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
                _atomic_modify_json "$ARGO_METADATA_FILE" 'del(.[$tag])' --arg tag "$tag" 2>/dev/null
                _atomic_modify_json "$CONFIG_FILE" 'del(.inbounds[] | select(.tag == $tag))' --arg tag "$tag"
                
                if [ -n "$node_name" ] && [ "$node_name" != "null" ]; then
                    _remove_node_from_yaml "$node_name"
                fi
             fi
        done
    fi
    
    # 3. 移除守护进程
    _disable_argo_watchdog

    # 4. 删除 cloudflared 和相关文件及服务
    _info "正在清理 cloudflared 文件及服务..."
    
    if command -v systemctl &>/dev/null; then
        systemctl stop cloudflared >/dev/null 2>&1
        systemctl disable cloudflared >/dev/null 2>&1
    fi
    
    _stop_all_argo_tunnels 2>/dev/null
    
    # 删除所有 PID/LOG 文件；旧 /tmp PID 已由 _stop_all_argo_tunnels 校验后处理。
    rm -f "$RUNTIME_DIR"/argo-*.pid /var/log/singbox_argo_*.log
    rm -f /tmp/singbox_argo_*.pid /tmp/singbox_argo_*.log
    rm -f "${CLOUDFLARED_BIN}" "${ARGO_METADATA_FILE}"
    rm -rf "/etc/cloudflared"
    
    # 4. 重启 sing-box
    _manage_service "restart"
    
    _success "Argo 服务已完全卸载！"
    _success "已释放 cloudflared 占用的空间。"
}

_view_argo_logs() {
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null)" -eq 0 ]; then
        _warning "当前没有任何 Argo 隧道节点。"
        return
    fi

    _info "--- 选择要查看日志的 Argo 隧道 ---"
    local tags=()
    mapfile -t tags < <(jq -r 'keys[]' "$ARGO_METADATA_FILE")
    local i=1
    local tag_list=()
    local tag name port
    for tag in "${tags[@]}"; do
        name=$(jq -r --arg tag "$tag" '.[$tag].name // empty' "$ARGO_METADATA_FILE")
        port=$(jq -r --arg tag "$tag" '.[$tag].local_port // empty' "$ARGO_METADATA_FILE")
        echo "  ${i}) ${name} (端口: ${port})"
        tag_list[$i]=$tag
        ((i++))
    done
    echo "  0) 返回上级菜单"
    read -p "请输入选项: " log_choice
    [[ "$log_choice" == "0" || -z "$log_choice" ]] && return

    local selected_tag=${tag_list[$log_choice]}
    if [ -n "$selected_tag" ]; then
        port=$(jq -r --arg tag "$selected_tag" '.[$tag].local_port // empty' "$ARGO_METADATA_FILE")
        local log_file
        log_file=$(_argo_log_file "$port")
        if [ -f "$log_file" ]; then
            _info "正在查看隧道日志 [${selected_tag}]，按 Ctrl+C 退出。"
            tail -f "$log_file"
        else
            _error "日志文件不存在: ${log_file}"
        fi
    else
        _error "无效选项"
    fi
}

_sync_argo_early_data() {
    local config_updated=false
    local links_updated=false
    local yaml_updated=false

    export WS_ED="$WS_EARLY_DATA_SIZE"
    export WS_EDH="$WS_EARLY_DATA_HEADER"

    if [ -s "$CONFIG_FILE" ] && jq -e 'any(.inbounds[]?; ((.tag // "" | startswith("argo-")) and ((.transport.type // "") == "ws") and (((.transport.max_early_data // 0) != (env.WS_ED | tonumber)) or ((.transport.early_data_header_name // "") != env.WS_EDH))))' "$CONFIG_FILE" >/dev/null 2>&1; then
        _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select((.tag // "" | startswith("argo-")) and ((.transport.type // "") == "ws")) | .transport.max_early_data) = (env.WS_ED | tonumber) | (.inbounds[] | select((.tag // "" | startswith("argo-")) and ((.transport.type // "") == "ws")) | .transport.early_data_header_name) = env.WS_EDH' || return 1
        config_updated=true
    fi

    if [ -s "$ARGO_METADATA_FILE" ]; then
        while IFS=$'\t' read -r tag protocol name domain uuid password path share_link; do
            [ -z "$tag" ] && continue
            [[ "$protocol" != "vless-ws" && "$protocol" != "trojan-ws" ]] && continue
            [[ -z "$domain" || "$domain" == "null" ]] && continue

            if [ -s "$CLASH_YAML_FILE" ] && [ -x "$YQ_BINARY" ] && [ -n "$name" ] && [ "$name" != "null" ]; then
                export PROXY_NAME="$name"
                local yaml_needs_update
                yaml_needs_update=$(${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME) and .network == "ws" and (((.["ws-opts"]["max-early-data"] // "") | tostring) != strenv(WS_ED) or (.["ws-opts"]["early-data-header-name"] // "") != env(WS_EDH))) | .name' "$CLASH_YAML_FILE" 2>/dev/null | head -n 1)
                if [ -n "$yaml_needs_update" ] && [ "$yaml_needs_update" != "null" ]; then
                    _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(PROXY_NAME) and .network == "ws") | .["ws-opts"]["max-early-data"]) = (env(WS_ED) | tonumber) | (.proxies[] | select(.name == env(PROXY_NAME) and .network == "ws") | .["ws-opts"]["early-data-header-name"]) = env(WS_EDH)' >/dev/null 2>&1 && yaml_updated=true
                fi
            fi

            if [[ "$share_link" == *"ed%3D${WS_EARLY_DATA_SIZE}"* || "$share_link" == *"ed=${WS_EARLY_DATA_SIZE}"* ]]; then
                continue
            fi

            if [[ "$protocol" == "vless-ws" && -n "$uuid" && "$uuid" != "null" ]]; then
                _show_node_link "vless-ws" "$name" "$domain" "443" "$tag" "$uuid" "$path" >/dev/null
                links_updated=true
            elif [[ "$protocol" == "trojan-ws" && -n "$password" && "$password" != "null" ]]; then
                _show_node_link "trojan-ws" "$name" "$domain" "443" "$tag" "$password" "$path" >/dev/null
                links_updated=true
            fi
        done < <(jq -r 'to_entries[] | [.key, (.value.protocol // "vless-ws"), (.value.name // ""), (.value.domain // ""), (.value.uuid // ""), (.value.password // ""), (.value.path // "/"), (.value.share_link // "")] | @tsv' "$ARGO_METADATA_FILE" 2>/dev/null)
    fi

    if [ "$config_updated" = true ]; then
        _info "已为既有 Argo WS 节点补齐 Early Data 配置，正在重启 sing-box..."
        _manage_service restart
    elif [ "$links_updated" = true ] || [ "$yaml_updated" = true ]; then
        _info "已同步既有 Argo WS 节点的 Early Data 客户端配置。"
    fi
}

_argo_menu() {
    _sync_argo_early_data
    while true; do
        clear
        echo -e "${CYAN}"
        echo '  ╔═══════════════════════════════════════╗'
        echo '  ║           Argo 隧道节点管理           ║'
        echo '  ╚═══════════════════════════════════════╝'
        echo -e "${NC}"
        
        echo -e "  ${CYAN}【创建节点】${NC}"
        echo -e "    ${GREEN}[1]${NC} 创建 VLESS-WS + Argo 节点"
        echo -e "    ${GREEN}[2]${NC} 创建 Trojan-WS + Argo 节点"
        echo ""
        
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${GREEN}[3]${NC} 查看 Argo 节点信息"
        echo -e "    ${GREEN}[4]${NC} 查看 Argo 隧道日志"
        echo -e "    ${GREEN}[5]${NC} 删除 Argo 节点"
        echo ""
        
        echo -e "  ${CYAN}【隧道控制】${NC}"
        echo -e "    ${RED}[6]${NC} 卸载 Argo 服务"
        echo -e "    ${GREEN}[7]${NC} 重启 Argo 隧道"
        echo ""
        
        echo -e "  ─────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        
        read -p "  请输入选项 [0-7]: " choice

        case $choice in
            1) _add_argo_vless_ws ;;
            2) _add_argo_trojan_ws ;;
            3) _view_argo_nodes ;;
            4) _view_argo_logs ;;
            5) _delete_argo_node ;;
            6) _uninstall_argo ;;
            7) _restart_argo_tunnel_menu ;;
            0) break ;;
            *) _error "无效选项" ;;
        esac
        echo ""
        read -n 1 -s -r -p "按任意键继续..."
    done
}

# --- 服务与配置管理 ---

_create_systemd_service() {
    local mem_limit_mb=$(_get_mem_limit)
    
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Environment="GOMEMLIMIT=${mem_limit_mb}MiB"
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE} -c ${SINGBOX_DIR}/relay.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
}

_create_openrc_service() {
    # 确保日志文件存在
    touch "${LOG_FILE}"
    local mem_limit_mb=$(_get_mem_limit)
    
    cat > "$SERVICE_FILE" <<EOF
#!/sbin/openrc-run

description="sing-box service"
export GOMEMLIMIT="${mem_limit_mb}MiB"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE} -c ${SINGBOX_DIR}/relay.json"
# 使用 supervise-daemon 实现守护和重启
supervisor="supervise-daemon"
respawn_delay=3
respawn_max=0

pidfile="${PID_FILE}"
# supervise-daemon 自动将 stdout/stderr 重定向功能需要 openrc 版本支持
# 如果不支持，日志可能不会输出到文件，但服务能正常运行
output_log="${LOG_FILE}"
error_log="${LOG_FILE}"

start_pre() {
    checkpath -d -m 0700 ${RUNTIME_DIR}
}

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$SERVICE_FILE"
}

_create_service_files() {
    
    _info "正在创建 ${INIT_SYSTEM} 服务文件..."
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _create_systemd_service
        systemctl daemon-reload
        systemctl enable sing-box
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        touch "$LOG_FILE"
        _create_openrc_service
        rc-update add sing-box default
    elif [ "$INIT_SYSTEM" == "direct" ]; then
        touch "$LOG_FILE"
        _info "当前容器没有 systemd/openrc，将使用 direct 后台模式管理 sing-box。"
        return 0
    fi
    _success "${INIT_SYSTEM} 服务创建并启用成功。"
}

# 每 48 小时清空一次本脚本产生的运行日志，避免小磁盘被持续写满。
_cleanup_runtime_logs() {
    local state_file="${SINGBOX_DIR}/.last_log_cleanup"
    local now last
    now=$(date +%s 2>/dev/null) || return 1
    last=$(cat "$state_file" 2>/dev/null)

    # 首次启用时立即清理一次，先释放可能已经被占满的磁盘空间。
    if ! [[ "$last" =~ ^[0-9]+$ ]]; then
        last=0
    fi
    [ $((now - last)) -lt 172800 ] && return 0

    local log
    for log in "$LOG_FILE" "$ARGO_LOG_FILE" /var/log/xray.log /var/log/singbox_argo_*.log; do
        [ -f "$log" ] && : > "$log"
    done
    printf '%s\n' "$now" > "$state_file"
}

_setup_log_cleanup() {
    command -v crontab >/dev/null 2>&1 || {
        _warning "未找到 crontab，无法启用每 2 天自动清理日志。"
        return 1
    }

    local tag="# sing-box-log-cleanup"
    local job="17 * * * * bash ${SELF_SCRIPT_PATH} cleanup-logs >/dev/null 2>&1 ${tag}"
    local current
    current=$(crontab -l 2>/dev/null || true)
    if ! printf '%s\n' "$current" | grep -Fq "$tag"; then
        { printf '%s\n' "$current"; printf '%s\n' "$job"; } | sed '/^$/d' | crontab - || return 1
    fi
    _cleanup_runtime_logs
}

_remove_log_cleanup() {
    local tag="# sing-box-log-cleanup"
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -Fq "$tag"; then
        crontab -l 2>/dev/null | grep -Fv "$tag" | crontab -
    fi
    rm -f "${SINGBOX_DIR}/.last_log_cleanup"
}


# 注意: _manage_service 已在上方定义，此处不再重复定义

_view_log() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _info "按 Ctrl+C 退出日志查看。"
        journalctl -u sing-box -f --no-pager
    else # 适用于 openrc 和 direct 模式
        if [ ! -f "$LOG_FILE" ]; then
            _warning "日志文件 ${LOG_FILE} 不存在。"
            return
        fi
        _info "按 Ctrl+C 退出日志查看 (日志文件: ${LOG_FILE})。"
        tail -f "$LOG_FILE"
    fi
}

_remove_scheduled_restart_components() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl disable --now sing-box-restart.timer >/dev/null 2>&1 || true
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service sing-box-timer stop >/dev/null 2>&1 || true
    fi
    if command -v rc-update >/dev/null 2>&1; then
        rc-update del sing-box-timer default >/dev/null 2>&1 || true
    fi

    rm -f /etc/systemd/system/sing-box-restart.timer \
        /etc/systemd/system/sing-box-restart.service \
        /etc/init.d/sing-box-timer /usr/local/bin/sb-timer.sh

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed sing-box-restart.service sing-box-restart.timer >/dev/null 2>&1 || true
    fi
}

_uninstall() {
    _warning "！！！警告！！！"
    _warning "本操作将停止并禁用 [主脚本] 服务 (sing-box)，"
    _warning "删除所有相关文件 (包括二进制、组件脚本、别名及配置文件)。"
    
    echo ""
    echo "即将删除以下内容："
    echo -e "  ${RED}-${NC} 主配置与脚本目录: ${SINGBOX_DIR}"
    echo -e "  ${RED}-${NC} sing-box 二进制: ${SINGBOX_BIN}"
    echo -e "  ${RED}-${NC} yq 二进制: ${YQ_BINARY}"
    [ -f "${CLOUDFLARED_BIN}" ] && echo -e "  ${RED}-${NC} cloudflared 二进制: ${CLOUDFLARED_BIN}"
    [ -f "/usr/local/bin/xray" ] && echo -e "  ${RED}-${NC} Xray 核心及配置: /usr/local/etc/xray/"
    echo -e "  ${RED}-${NC} 系统别名: /usr/local/bin/sb"
    echo -e "  ${RED}-${NC} 管理脚本: ${SELF_SCRIPT_PATH}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm_main
    [[ "$confirm_main" != "y" && "$confirm_main" != "Y" ]] && _info "卸载已取消。" && return

    # 1. Argo 必须在删除元数据前停止，否则会失去受控 PID 到端口的映射，
    # 留下仍在运行的 cloudflared 进程。
    _disable_argo_watchdog 2>/dev/null || true
    _stop_all_argo_tunnels 2>/dev/null || true

    # 2. 停止主服务，并清理服务定义与定时重启组件。
    _manage_service "stop" >/dev/null 2>&1 || true
    _remove_scheduled_restart_components
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl disable --now sing-box >/dev/null 2>&1 || true
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-service sing-box stop >/dev/null 2>&1 || true
        rc-update del sing-box default >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/sing-box.service /etc/init.d/sing-box "$PID_FILE"
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed sing-box.service >/dev/null 2>&1 || true
    fi

    # 3. 仍在配置和元数据存在时清理 cron 与 nftables 状态。
    _info "正在清理运行规则与配置文件..."
    _remove_log_cleanup
    local pf_meta="${SINGBOX_DIR}/relay_pf.json"
    [ ! -f "$pf_meta" ] && pf_meta="${SINGBOX_DIR}/pf_metadata.json"
    if [ -f "$pf_meta" ] && command -v jq &>/dev/null; then
        if crontab -l 2>/dev/null | grep -qF "# pf-dns-auto-refresh"; then
            crontab -l 2>/dev/null | grep -vF "# pf-dns-auto-refresh" | crontab -
        fi
    fi
    _remove_nftables_rules

    rm -f "${CLOUDFLARED_BIN}" "$RUNTIME_DIR"/argo-*.pid "$RUNTIME_DIR"/argo-keepalive.lock
    rm -f /tmp/singbox_argo_*.pid /tmp/singbox_argo_*.log
    rm -f "${ARGO_LOG_FILE}" /var/log/singbox_argo_*.log
    rm -rf /etc/cloudflared

    # 4. 即使核心文件已部分丢失，也清理残留的 Xray 服务与状态。
    if [ -f "/usr/local/bin/xray" ] || [ -d "/usr/local/etc/xray" ] \
        || [ -f /etc/systemd/system/xray.service ] || [ -f /etc/init.d/xray ]; then
        _info "正在清理 Xray 核心..."
    fi
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl disable --now xray >/dev/null 2>&1 || true
    fi
    if command -v rc-service >/dev/null 2>&1; then rc-service xray stop >/dev/null 2>&1 || true; fi
    if command -v rc-update >/dev/null 2>&1; then rc-update del xray default >/dev/null 2>&1 || true; fi
    rm -f /etc/systemd/system/xray.service /etc/init.d/xray /usr/local/bin/xray "$XRAY_PID_FILE"
    rm -rf /usr/local/etc/xray
    rm -f /var/log/xray.log
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed xray.service >/dev/null 2>&1 || true
    fi

    rm -rf "${SINGBOX_DIR}"
    rm -f "${LOG_FILE}"

    # 5. 清理组件脚本与别名 (双重清理，防止目录合并后的物理残留)
    _info "正在清理周边环境..."
    rm -f "${SINGBOX_DIR}/parser.sh" "${SINGBOX_DIR}/advanced_relay.sh" "${SINGBOX_DIR}/xray_manager.sh"
    rm -f "${SCRIPT_DIR}/parser.sh" "${SCRIPT_DIR}/advanced_relay.sh" "${SCRIPT_DIR}/xray_manager.sh"
    rm -f "/usr/local/bin/sb"
    
    # 6. 处理主程序 (考虑与线路机共用)
    local relay_script="/root/relay-install.sh"
    if [ -f "$relay_script" ]; then
        _warn "检测到 [线路机] 脚本存在，为保持其运行，将 [保留] sing-box 主程序。"
    else
        _info "正在删除 sing-box 主程序..."
        rm -f "${SINGBOX_BIN}" "${YQ_BINARY}"
    fi

    rmdir "$RUNTIME_DIR" >/dev/null 2>&1 || true

    _success "清理完成。脚本已自毁。再见！"
    [ -f "${SELF_SCRIPT_PATH}" ] && rm -f "${SELF_SCRIPT_PATH}"
    exit 0
}

_initialize_config_files() {
    mkdir -p ${SINGBOX_DIR}
    if [ ! -s "$CONFIG_FILE" ]; then
        # 初始化包含完整 dns 配置和路由策略的基础文件，以支持中转第三方域名节点
        cat > "$CONFIG_FILE" << 'EOF'
{
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m"
  },
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "dns-local",
        "prefer_go": true
      }
    ],
    "final": "dns-local",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [],
    "final": "direct",
    "default_domain_resolver": {
      "server": "dns-local",
      "strategy": "prefer_ipv4"
    }
  }
}
EOF
    fi
    [ -s "$METADATA_FILE" ] || echo "{}" > "$METADATA_FILE"
    
    # [关键修复] 初始化 relay.json - 服务启动命令会加载这个文件
    # 必须确保在服务运行前此文件物理存在，否则 sing-box 会 Fatal 退出
    local RELAY_JSON="${SINGBOX_DIR}/relay.json"
    if [ ! -s "$RELAY_JSON" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_JSON"
        _info "已初始化中转配置文件: $RELAY_JSON"
    fi
    if [ ! -s "$CLASH_YAML_FILE" ]; then
        _info "正在创建全新的 clash.yaml 配置文件..."
        cat > "$CLASH_YAML_FILE" << 'EOF'
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
bind-address: '*'
mode: rule
log-level: info
ipv6: true
find-process-mode: strict
external-controller: '127.0.0.1:9090'
profile:
  store-selected: true
  store-fake-ip: true
unified-delay: true
tcp-concurrent: true
ntp:
  enable: true
  write-to-system: false
  server: ntp.aliyun.com
  port: 123
  interval: 30
dns:
  enable: true
  respect-rules: true
  use-system-hosts: true
  prefer-h3: false
  listen: '0.0.0.0:1053'
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  fake-ip-filter:
    - +.lan
    - +.local
    - localhost.ptlogin2.qq.com
    - +.msftconnecttest.com
    - +.msftncsi.com
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 'https://1.1.1.1/dns-query'
    - 'https://dns.quad9.net/dns-query'
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 'https://1.0.0.1/dns-query'
    - 'https://9.9.9.10/dns-query'
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
  strict-route: false
  dns-hijack:
    - 'any:53'
  device: SakuraiTunnel
  endpoint-independent-nat: true
proxies: []
proxy-groups:
  - name: 节点选择
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
EOF
    fi
}

_init_relay_config() {
    # 确保中转配置文件存在 (隔离配置)
    if [ ! -s "$RELAY_CONFIG_FILE" ]; then
        _ensure_relay_config || return 1
        _info "已初始化中转配置文件"
    fi
}

_cleanup_legacy_config() {
    # 检查并清理 config.json 中残留的旧版中转配置 (tag 以 relay-out- 开头的 outbound)
    # 这些残留会导致路由冲突，使主脚本节点误走中转线路
    local needs_restart=false
    
    if jq -e '.outbounds[] | select(.tag | startswith("relay-out-"))' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "检测到旧版中转残留配置，正在清理..."
        if ! cp -p "$CONFIG_FILE" "${CONFIG_FILE}.bak_legacy"; then
            _error "无法创建旧版中转配置清理快照，已取消清理。"
            return 1
        fi
        chmod 600 "${CONFIG_FILE}.bak_legacy" 2>/dev/null || true
        _atomic_modify_json "$CONFIG_FILE" '
            .outbounds = ((.outbounds // []) | map(select(((.tag // "") | startswith("relay-out-")) | not)))
            | .route = (.route // {"rules":[]})
            | .route.rules = ((.route.rules // []) | map(select(((.outbound // "") | startswith("relay-out-")) | not)))
            | if any(.outbounds[]?; .tag == "direct") then . else .outbounds = [{"type":"direct","tag":"direct"}] + .outbounds end
        ' || return 1
        
        _success "配置清理完成。相关中转已被迁移至独立配置文件 (relay.json)。"
        needs_restart=true
    fi
    
    # [关键修复] 确保 route.final 设置为 "direct"
    # 这是核心修复：当 config.json 和 relay.json 合并时，relay-out-* outbound 会被插入到 outbounds 列表前面
    # 如果没有 route.final，sing-box 会使用列表中的第一个 outbound 作为默认出口，导致主节点流量走中转
    if ! jq -e '.route.final == "direct"' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "检测到 route.final 未设置或不正确，正在修复..."
        
        _atomic_modify_json "$CONFIG_FILE" 'if .route then .route.final = "direct" else .route = {"rules":[],"final":"direct"} end' || return 1
        
        _success "route.final 已设置为 direct，主节点流量将走本机 IP。"
        needs_restart=true
    fi
    
    if [ "$needs_restart" = true ]; then
        return 0
    fi
    return 1
}

_check_and_fix_dns() {
    # 热修复：1.补充缺失的 DNS 模块，2.将容易引起出站路由绑定死循环（连接被秒重置）的 auto_detect_interface 清除
    # 3. 为未设置策略的旧配置补充 prefer_ipv4，4.让 local DNS 避开 Linux 上可能阻塞的 systemd-resolved D-Bus 路径
    # 保留用户在 DNS 菜单中明确选择的地址和解析策略。
    if [ ! -f "$CONFIG_FILE" ]; then return; fi
    
    local has_dns legacy_dns has_auto_detect dns_strategy has_default_resolver local_dns_needs_prefer_go
    has_dns=$(jq 'has("dns")' "$CONFIG_FILE" 2>/dev/null)
    legacy_dns=$(jq 'any(.dns.servers[]?; has("address") or ((.type // "") == "")) or any(.dns.rules[]?; has("outbound"))' "$CONFIG_FILE" 2>/dev/null)
    has_auto_detect=$(jq 'try .route.auto_detect_interface catch false' "$CONFIG_FILE" 2>/dev/null)
    dns_strategy=$(jq -r '.dns.strategy // ""' "$CONFIG_FILE" 2>/dev/null)
    has_default_resolver=$(jq '(.route.default_domain_resolver // null) != null' "$CONFIG_FILE" 2>/dev/null)
    local_dns_needs_prefer_go=$(jq 'any(.dns.servers[]?; ((.type // "") == "local") and ((.prefer_go // false) != true))' "$CONFIG_FILE" 2>/dev/null)
    local needs_restart=false
    
    if [ "$has_dns" == "false" ] || [ "$legacy_dns" == "true" ] || [ "$has_auto_detect" == "true" ] || [ -z "$dns_strategy" ] || [ "$has_default_resolver" != "true" ] || [ "$local_dns_needs_prefer_go" == "true" ]; then
        _warn "检测到 DNS/路由配置需要兼容性修复，正在自动处理..."
        
        local backup_file
        backup_file=$(mktemp "${CONFIG_FILE}.dnsfix.backup.XXXXXX") || return 1
        cp -p "$CONFIG_FILE" "$backup_file" || { rm -f "$backup_file"; return 1; }
        local legacy_address="local" new_dns replace_dns="false"
        if [ "$legacy_dns" = "true" ]; then
            legacy_address=$(jq -r '.dns.servers[0].address // "local"' "$CONFIG_FILE" 2>/dev/null)
            replace_dns="true"
        elif [ "$has_dns" = "false" ]; then
            replace_dns="true"
        fi
        case "$dns_strategy" in prefer_ipv4|prefer_ipv6|ipv4_only|ipv6_only) ;; *) dns_strategy="prefer_ipv4" ;; esac
        new_dns=$(_build_dns_config_json "$legacy_address" "$dns_strategy") || {
            _error "无法迁移旧 DNS 地址：${legacy_address}"
            rm -f "$backup_file"
            return 1
        }
        if _atomic_modify_json "$CONFIG_FILE" '
            if $replace_dns then .dns = $dns else . end
            | .dns.servers |= map(if ((.type // "") == "local") then . + {prefer_go:true} else . end)
            | .route = (.route // {"rules":[]})
            | .route.default_domain_resolver = {"server":"dns-local","strategy":$strategy}
            | del(.route.auto_detect_interface)
        ' --argjson replace_dns "$replace_dns" --argjson dns "$new_dns" --arg strategy "$dns_strategy"; then
            local check_result
            if ! check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
                _error "DNS 热修复未通过组合配置校验，已回滚："
                echo "$check_result"
                mv -f "$backup_file" "$CONFIG_FILE"
                return 1
            fi
            rm -f "$backup_file"
            _success "DNS 与路由参数热修复完成！"
            needs_restart=true
        else
            _error "高级修复应用失败，已恢复原配置。"
            mv -f "$backup_file" "$CONFIG_FILE"
        fi
    fi

    if [ -f "$CLASH_YAML_FILE" ] && [ -x "$YQ_BINARY" ]; then
        local clash_ipv6=$(${YQ_BINARY} eval '.ipv6 // false' "$CLASH_YAML_FILE" 2>/dev/null)
        local clash_dns_ipv6=$(${YQ_BINARY} eval '.dns.ipv6 // false' "$CLASH_YAML_FILE" 2>/dev/null)
        if [ "$clash_ipv6" != "true" ] || [ "$clash_dns_ipv6" != "true" ]; then
            if _atomic_modify_yaml "$CLASH_YAML_FILE" '.ipv6 = true | .dns.ipv6 = true' >/dev/null 2>&1; then
                _success "已开启 clash.yaml 的 IPv6 与 DNS IPv6 支持。"
            else
                _warn "clash.yaml IPv6 自动修复失败，请手动检查 YAML 格式。"
            fi
        fi
    fi
    
    if [ "$needs_restart" == "true" ]; then
        return 0
    fi
    return 1
}

_generate_self_signed_cert() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"

    _info "正在为 ${domain} 生成支持 SAN 的高级自签名证书..."
    
    # 创建临时配置文件用于生成 SAN
    local openssl_config=$(mktemp)
    cat > "$openssl_config" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = ${domain}
[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${domain}
DNS.2 = *.${domain}
EOF

    # 使用 RSA 2048 生成证书 (CF 回源兼容性更佳)
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
        -keyout "$key_path" -out "$cert_path" \
        -config "$openssl_config" >/dev/null 2>&1
    
    local status=$?
    rm -f "$openssl_config"

    if [ $status -ne 0 ]; then
        _error "为 ${domain} 生成证书失败！"
        rm -f "$cert_path" "$key_path"
        return 1
    fi
    _success "证书 ${cert_path} (含 SAN) 已成功生成。"
    return 0
}

# 注意: _atomic_modify_json, _atomic_modify_yaml, _get_proxy_field, _add_node_to_yaml, _remove_node_from_yaml
# 均在上方统一定义，此处不再重复定义以避免不一致

# 显示节点分享链接（在添加节点后调用）
# 参数: $1=协议类型, $2=节点名称, $3=服务器IP(用于链接), $4=端口, $5=节点TAG, 其他参数根据协议不同
_show_node_link() {
    local type="$1"
    local name="$2"
    local link_ip="$3"
    local port="$4"
    local tag="$5"
    local metadata_ip="$link_ip"
    metadata_ip="${metadata_ip#[}"
    metadata_ip="${metadata_ip%]}"
    # [关键修复] 处理 IPv6 括号包裹逻辑
    if [[ "$link_ip" == *":"* ]] && [[ "$link_ip" != "["* ]]; then
        link_ip="[${link_ip}]"
    fi

    shift 5
    
    local url=""
    
    case "$type" in
        "vless-reality")
            # 参数: uuid, sni, public_key, short_id, flow
            local uuid="$1" pk="$3" sid="$4" flow="${5:-xtls-rprx-vision}"
            # 对 SNI 执行终极保底与净化
            local sni=$(echo "$2" | xargs)
            [[ -z "$sni" ]] && sni="$DEFAULT_SNI"
            
            url="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "${pk}")&fp=chrome&type=tcp&flow=${flow}&sni=${sni}&sid=${sid}#$(_url_encode "$name")"
            ;;
        "vless-ws-tls")
            # 参数: uuid, sni, ws_path, skip_verify
            local uuid="$1" sni="${2:-$DEFAULT_SNI}" ws_path="$3" skip_verify="$4" cert_path="$5"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=ws&host=${sni}&path=$(_url_encode "$ws_path")&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "vless-grpc-tls")
            # 参数: uuid, sni, service_name, skip_verify, cert_path
            local uuid="$1" sni="${2:-$DEFAULT_SNI}" service_name="$3" skip_verify="$4" cert_path="$5"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=grpc&serviceName=$(_url_encode "$service_name")&authority=${sni}&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "vless-tcp")
            # 参数: uuid
            local uuid="$1"
            url="vless://${uuid}@${link_ip}:${port}?encryption=none&type=tcp#$(_url_encode "$name")"
            ;;
        "trojan-ws-tls")
            # 参数: password, sni, ws_path, skip_verify
            local password="$1" sni="${2:-$DEFAULT_SNI}" ws_path="$3" skip_verify="$4" cert_path="$5"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="trojan://${password}@${link_ip}:${port}?security=tls&type=ws&host=${sni}&path=$(_url_encode "$ws_path")&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "hysteria2")
            # 参数: password, sni, obfs_password(可选), port_hopping(可选)
            local password="$1" sni="${2:-$DEFAULT_SNI}" obfs_password="$3" port_hopping="$4"
            local obfs_param=""; [[ -n "$obfs_password" ]] && obfs_param="&obfs=salamander&obfs-password=$(_url_encode "${obfs_password}")"
            local hop_param=""; [[ -n "$port_hopping" ]] && hop_param="&mport=${port_hopping}&ports=${port_hopping}"
            local cert_path="${SINGBOX_DIR}/${tag}.pem"
            local pin_param=""
            local cert_pcs=$(_cert_sha256_hex "$cert_path")
            [ -n "$cert_pcs" ] && pin_param="&pinSHA256=${cert_pcs}"
            url="hysteria2://${password}@${link_ip}:${port}?sni=${sni}&insecure=1${obfs_param}${hop_param}${pin_param}#$(_url_encode "$name")"
            ;;
        "tuic")
            # 参数: uuid, password, sni
            local uuid="$1" password="$2" sni="${3:-$DEFAULT_SNI}"
            url="tuic://${uuid}:${password}@${link_ip}:${port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$name")"
            ;;
        "anytls")
            # 参数: password, sni, skip_verify
            local password="$1" sni="${2:-$DEFAULT_SNI}" skip_verify="$3" cert_path="$4"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="anytls://${password}@${link_ip}:${port}?security=tls&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "any-reality")
            # 参数: password, sni, public_key, short_id
            local password="$1" sni="${2:-$DEFAULT_SNI}" public_key="$3" short_id="$4"
            url="anytls://${password}@${link_ip}:${port}?security=reality&sni=${sni}&fp=chrome&pbk=$(_url_encode "${public_key}")&sid=${short_id}&type=tcp&headerType=none#$(_url_encode "$name")"
            ;;
        "shadowsocks")
            # 参数: method, password
            local method="$1" password="$2"
            local userinfo=$(printf '%s' "${method}:${password}" | base64 | tr -d '\n\r ' | tr '+/' '-_' | tr -d '=')
            url="ss://${userinfo}@${link_ip}:${port}#$(_url_encode "$name")"
            ;;
        "shadowsocks-shadowtls")
            # 参数: method, pw, spw, sni
            local method="$1" pw="$2" spw="$3" sni="$4"
            url=""
            echo -e "${YELLOW}====== [客户端配置参考片段 (Clash Meta / Mihomo)] ======${NC}"
            echo -e "  - name: \"${name}\""
            echo -e "    type: ss"
            echo -e "    server: ${link_ip}"
            echo -e "    port: ${port}"
            echo -e "    cipher: ${method}"
            echo -e "    password: ${pw}"
            echo -e "    plugin: shadow-tls"
            echo -e "    plugin-opts:"
            echo -e "      host: ${sni}"
            echo -e "      password: ${spw}"
            echo -e "      version: 3"
            echo -e "${YELLOW}========================================================${NC}"
            echo -e "${CYAN}[提示] ShadowTLS 需要特定的客户端配置。${NC}"
            echo -e "${CYAN}您也可以直接打开本机位于 ${YELLOW}/usr/local/etc/sing-box/clash.yaml${CYAN} 的配置文件，${NC}"
            echo -e "${CYAN}找到对应节点的 YAML 代码块，并复制到您的客户端中使用！${NC}"
            ;;
        "vless-ws")
            # Argo 专用: uuid, path
            local uuid="$1" ws_path="$2"
            local ed_path=$(_ws_path_with_early_data "$ws_path")
            url="vless://${uuid}@${link_ip}:443?encryption=none&security=tls&type=ws&host=${link_ip}&path=$(_url_encode "$ed_path")&sni=${link_ip}#$(_url_encode "$name")"
            ;;
        "trojan-ws")
            # Argo 专用: password, path
            local password="$1" ws_path="$2"
            local ed_path=$(_ws_path_with_early_data "$ws_path")
            url="trojan://$(_url_encode "${password}")@${link_ip}:443?security=tls&type=ws&host=${link_ip}&path=$(_url_encode "$ed_path")&sni=${link_ip}#$(_url_encode "$name")"
            ;;
        "socks")
            # 参数: username, password
            local username="$1" password="$2"
            echo ""
            _info "节点信息: 服务器: ${link_ip}, 端口: ${port}, 用户名: ${username}, 密码: ${password}"
            ;;
    esac
    
    if [ -n "$url" ]; then
        echo ""
        local clean_url=$(echo "$url" | sed 's/&insecure=1//g' | sed 's/&pcs=[a-fA-F0-9]*//g')
        if [ "$clean_url" != "$url" ] && [[ "$type" != "anytls" ]] && [[ "$type" != "hysteria2" ]] && [[ "$type" != "tuic" ]] && [[ "$type" != "vless-reality" ]] && [[ "$type" != "any-reality" ]]; then
            echo -e "${YELLOW}═══════════════ 🔗 直连分享链接 (含防劫持指纹) ═══════════════${NC}"
            echo -e "${CYAN}${url}${NC}"
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${YELLOW}═════════════ 🔗 CF优选专用链接 (纯净版，无指纹冲突) ═════════════${NC}"
            echo -e "${CYAN}${clean_url}${NC}"
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
            echo -e "${CYAN}[提示] 如果您套用了 Cloudflare，请导入 ${YELLOW}CF优选专用链接${CYAN} 以避免握手失败！${NC}"
        else
            echo -e "${YELLOW}═══════════════════ 分享链接 ═══════════════════${NC}"
            echo -e "${CYAN}${url}${NC}"
            echo -e "${YELLOW}═════════════════════════════════════════════════${NC}"
        fi
        
        # [持久化] 将生成的链接存入元数据，防止查看时由于动态提取导致的 SNI 丢失
        if [ -n "$tag" ] && [ "$tag" != "null" ]; then
            if [[ "$tag" == argo-* ]]; then
                _atomic_modify_json "$ARGO_METADATA_FILE" '. + {($tag): ((.[$tag] // {}) + {share_link:$url, name:$name})}' \
                    --arg tag "$tag" --arg url "$url" --arg name "$name" || return 1
            else
                _atomic_modify_json "$METADATA_FILE" '
                    . + {($tag): ((.[$tag] // {}) + {
                        share_link:$url,
                        name:$name,
                        owner:"singbox-main",
                        variant:$variant,
                        clientServer:$server
                    } | if has("yaml") then . else .yaml = true end)}
                ' --arg tag "$tag" --arg url "$url" --arg name "$name" --arg variant "$type" --arg server "$metadata_ip" || return 1
            fi
        fi
    fi
    # SOCKS5 与 ShadowTLS 没有通用的单行分享链接，但同样保存规范化元数据，
    # 使“修改节点”不需要从 YAML 或备注名称猜测连接地址和具体变种。
    if [ -n "$tag" ] && [ "$tag" != "null" ] && [[ "$tag" != argo-* ]]; then
        _atomic_modify_json "$METADATA_FILE" '
            . + {($tag): ((.[$tag] // {}) + {
                name:$name,
                owner:"singbox-main",
                variant:$variant,
                clientServer:$server
            } | if has("yaml") then . else .yaml = true end)}
        ' --arg tag "$tag" --arg name "$name" --arg variant "$type" --arg server "$metadata_ip" || return 1
    fi
    return 0
}

_show_cdn_guidance() {
    local domain="$1"
    local port="$2"
    echo ""
    echo -e "${YELLOW}══════════════════ 🔧 如何开启 Cloudflare CDN 优选 ══════════════════${NC}"
    _info "如果您希望开启 CDN 并在之后使用优选域名/IP，请按照以下步骤配置："
    _info "1. ${CYAN}【CF 后台】${NC}将该域名的解析记录开启小黄云 (${ORANGE}Proxied${NC})。"
    _info "2. ${CYAN}【CF 后台】${NC}在 [SSL/TLS] 菜单中，将加密模式设为: ${GREEN}Full (完全)${NC}。"
    if [ "$port" != "443" ]; then
        _warn "3. 您的服务器监听的是 ${port} 端口。请在 [Rules] -> [Origin Rules] 中配置："
        _warn "   - 主机名 包含 \"${domain}\" -> 重写到端口: ${port}"
    else
        _info "3. 您的服务器已监听 443 端口，无需设置 Origin Rules。"
    fi
    _info "4. ${CYAN}【客户端】${NC}修改配置：地址改为优选域名/IP，端口改为 ${GREEN}443${NC}。"
    _info "   (注：Host/SNI 必须保持为您的域名 ${domain})"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════${NC}"
}

_show_grpc_cdn_guidance() {
    local domain="$1"
    local port="$2"
    echo ""
    echo -e "${YELLOW}══════════════════ 🔧 VLESS gRPC + Cloudflare 配置提示 ══════════════════${NC}"
    _info "1. ${CYAN}【CF 后台】${NC}将该域名的解析记录开启小黄云 (${ORANGE}Proxied${NC})。"
    _info "2. ${CYAN}【CF 后台】${NC}在 [SSL/TLS] 菜单中，将加密模式设为: ${GREEN}Full (完全)${NC}。"
    _info "3. ${CYAN}【CF 后台】${NC}在 [Network] 菜单中确认 gRPC 已开启。"
    if [ "$port" != "443" ]; then
        _warn "4. 您的服务器监听的是 ${port} 端口。请在 [Rules] -> [Origin Rules] 中配置："
        _warn "   - 主机名 包含 \"${domain}\" -> 重写到端口: ${port}"
    else
        _info "4. 您的服务器已监听 443 端口，无需设置 Origin Rules。"
    fi
    _info "5. ${CYAN}【客户端】${NC}地址可改为优选域名/IP，端口改为 ${GREEN}443${NC}。"
    _info "   (注：SNI 必须保持为您的域名 ${domain}，gRPC serviceName 必须保持一致)"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════${NC}"
}


_add_vless_ws_tls() {
    local camouflage_domain=""
    local port=""
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        [[ -n "$BATCH_IP" ]] && client_server_addr="$BATCH_IP"
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_WS_TLS_DOMAIN:-$BATCH_SNI}"
    else
        _info "--- VLESS (WebSocket+TLS) 设置向导 ---"
        _info "请输入客户端用于“连接”的地址:"
        _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
        _info "  - (其他) 您也可以手动输入一个IP或域名"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}
        
        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi

        _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
        _info " (例如: xxx.741865.xyz)"
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

        while true; do
            read -p "请输入监听端口 (直连模式下首推 443 端口): " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi

    # 客户端连接端口默认与监听端口一致 (直连模式)
    local client_port="$port"

    # --- 步骤 4: 路径 ---
    local ws_path=""
    if [ "$BATCH_MODE" = "true" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
    else
        read -p "请输入 WebSocket 路径 (回车则随机生成): " input_ws_path
        if [ -z "$input_ws_path" ]; then
            ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
            _info "已为您生成随机 WebSocket 路径: ${ws_path}"
        else
            ws_path="$input_ws_path"
            [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
        fi
    fi

    # 提前定义 tag，用于证书文件命名
    local tag="vless-ws-in-${port}"
    local cert_path=""
    local key_path=""
    local skip_verify=false

    # --- 步骤 5: 证书选择 ---
    local cert_choice="1"
    if [ "$BATCH_MODE" = "true" ]; then
        cert_choice="1"
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (适合CF回源/直连跳过验证)"
        echo "  2) 手动上传证书文件 (acme.sh签发/Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
    fi

    if [ "$cert_choice" == "1" ]; then
        # 自签名证书
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
        skip_verify=true
        _info "已生成自签名证书，客户端将跳过证书验证。"
    else
        # 手动上传证书
        _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
        _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
        _info "  - (或)   使用 Cloudflare 源服务器证书"
        read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
        [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

        read -p "请输入私钥文件 .key 的完整路径: " key_path
        [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
        
        # 询问是否跳过验证
        read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
        if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
            skip_verify=true
            _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
        fi
    fi
    
    # [!] 自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-VLESS-WS-${port}"
    else
        local default_name="VLESS-WS-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    
    # Inbound (服务器端) 配置
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg sn "$camouflage_domain" \
        --arg wsp "$ws_path" \
        '{
            "type": "vless",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"uuid": $u, "flow": ""}],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # Proxy (客户端) 配置
    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$client_port" \
            --arg u "$uuid" \
            --arg sn "$camouflage_domain" \
            --arg wsp "$ws_path" \
            --arg skip_verify_bool "$skip_verify" \
            --arg host_header "$camouflage_domain" \
            '{
                "name": $n,
                "type": "vless",
                "server": $s,
                "port": ($p|tonumber),
                "uuid": $u,
                "encryption": "none",
                "tls": true,
                "udp": true,
                "skip-cert-verify": ($skip_verify_bool == "true"),
                "network": "ws",
                "sni": $sn,
                "ws-opts": {
                    "path": $wsp,
                    "headers": {
                        "Host": $host_header
                    }
                }
            }')
            
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    _success "VLESS (WebSocket+TLS) 节点 [${name}] 添加成功!"
    _success "客户端连接地址 (server): ${client_server_addr}"
    _success "客户端连接端口 (port): ${client_port}"
    _success "客户端伪装域名 (sni/Host): ${camouflage_domain}"
    
    # CDN 指引 (仅在非批量模式下详细显示)
    [ "$BATCH_MODE" != "true" ] && _show_cdn_guidance "${camouflage_domain}" "${port}"

    # IPv6 处理用于链接
    local link_ip="$client_server_addr"
    _show_node_link "vless-ws-tls" "$name" "$link_ip" "$client_port" "$tag" "$uuid" "$camouflage_domain" "$ws_path" "$skip_verify" "$cert_path" || return 1
}

_add_vless_grpc_tls() {
    local camouflage_domain=""
    local port=""
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        [[ -n "$BATCH_IP" ]] && client_server_addr="$BATCH_IP"
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_GRPC_TLS_DOMAIN:-$BATCH_SNI}"
    else
        _info "--- VLESS (gRPC+TLS) 设置向导 ---"
        _info "请输入客户端用于“连接”的地址:"
        _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
        _info "  - (其他) 您也可以手动输入一个IP或域名"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}

        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi

        _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
        _info " (例如: xxx.741865.xyz)"
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

        while true; do
            read -p "请输入监听端口 (直连模式下首推 443 端口): " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi

    local client_port="$port"

    local generated_service_name="grpc-$(${SINGBOX_BIN} generate rand --hex 4)"
    local service_name=""
    if [ "$BATCH_MODE" = "true" ]; then
        service_name="${BATCH_GRPC_SERVICE_NAME:-$generated_service_name}"
    else
        read -p "请输入 gRPC serviceName (回车则随机生成: ${generated_service_name}): " input_service_name
        service_name=${input_service_name:-$generated_service_name}
        service_name=$(echo "$service_name" | xargs)
        [[ -z "$service_name" ]] && _error "gRPC serviceName 不能为空" && return 1
        _info "gRPC serviceName: ${service_name}"
    fi

    local tag="vless-grpc-in-${port}"
    local cert_path=""
    local key_path=""
    local skip_verify=false

    local cert_choice="1"
    if [ "$BATCH_MODE" = "true" ]; then
        cert_choice="1"
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (适合CF回源/直连跳过验证)"
        echo "  2) 手动上传证书文件 (acme.sh签发/Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
    fi

    if [ "$cert_choice" == "1" ]; then
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
        skip_verify=true
        _info "已生成自签名证书，客户端将跳过证书验证。"
    else
        _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
        _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
        _info "  - (或)   使用 Cloudflare 源服务器证书"
        read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
        [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

        read -p "请输入私钥文件 .key 的完整路径: " key_path
        [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1

        read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
        if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
            skip_verify=true
            _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
        fi
    fi

    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-VLESS-gRPC-${port}"
    else
        local default_name="VLESS-gRPC-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)

    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg sn "$camouflage_domain" \
        --arg svc "$service_name" \
        '{
            "type": "vless",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"uuid": $u, "flow": ""}],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "alpn": ["h2"],
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "grpc",
                "service_name": $svc
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$client_port" \
            --arg u "$uuid" \
            --arg sn "$camouflage_domain" \
            --arg svc "$service_name" \
            --arg skip_verify_bool "$skip_verify" \
            '{
                "name": $n,
                "type": "vless",
                "server": $s,
                "port": ($p|tonumber),
                "uuid": $u,
                "encryption": "none",
                "tls": true,
                "udp": true,
                "skip-cert-verify": ($skip_verify_bool == "true"),
                "network": "grpc",
                "servername": $sn,
                "grpc-opts": {
                    "grpc-service-name": $svc
                }
            }')

    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    _success "VLESS (gRPC+TLS) 节点 [${name}] 添加成功!"
    _success "客户端连接地址 (server): ${client_server_addr}"
    _success "客户端连接端口 (port): ${client_port}"
    _success "客户端伪装域名 (sni): ${camouflage_domain}"
    _success "gRPC serviceName: ${service_name}"

    [ "$BATCH_MODE" != "true" ] && _show_grpc_cdn_guidance "${camouflage_domain}" "${port}"

    local link_ip="$client_server_addr"
    _show_node_link "vless-grpc-tls" "$name" "$link_ip" "$client_port" "$tag" "$uuid" "$camouflage_domain" "$service_name" "$skip_verify" "$cert_path" || return 1
}

_add_trojan_ws_tls() {
    local camouflage_domain=""
    local port=""
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        [[ -n "$BATCH_IP" ]] && client_server_addr="$BATCH_IP"
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_WS_TLS_DOMAIN:-$BATCH_SNI}"
    else
        _info "--- Trojan (WebSocket+TLS) 设置向导 ---"
        _info "请输入客户端用于“连接”的地址:"
        _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
        _info "  - (其他) 您也可以手动输入一个IP或域名"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}
        
        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi

        _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

        while true; do
            read -p "请输入监听端口 (直连模式下首推 443 端口): " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi

    # 客户端连接端口默认与监听端口一致 (直连模式)
    local client_port="$port"

    # --- 步骤 4: 路径 ---
    local ws_path=""
    if [ "$BATCH_MODE" = "true" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
    else
        read -p "请输入 WebSocket 路径 (回车则随机生成): " input_ws_path
        if [ -z "$input_ws_path" ]; then
            ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
            _info "已为您生成随机 WebSocket 路径: ${ws_path}"
        else
            ws_path="$input_ws_path"
            [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
        fi
    fi

    # 提前定义 tag，用于证书文件命名
    local tag="trojan-ws-in-${port}"
    local cert_path=""
    local key_path=""
    local skip_verify=false

    # --- 步骤 5: 证书选择 ---
    if [ "$BATCH_MODE" = "true" ]; then
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
        skip_verify=true
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (适合CF回源/直连跳过验证)"
        echo "  2) 手动上传证书文件 (acme.sh签发/Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
        if [ "$cert_choice" == "1" ]; then
            cert_path="${SINGBOX_DIR}/${tag}.pem"
            key_path="${SINGBOX_DIR}/${tag}.key"
            _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
            skip_verify=true
            _info "已生成自签名证书，客户端将跳过证书验证。"
        else
            # 手动上传证书
            _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
            _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
            _info "  - (或)   使用 Cloudflare 源服务器证书"
            read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
            [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

            read -p "请输入私钥文件 .key 的完整路径: " key_path
            [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
            
            # 询问是否跳过验证
            read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
            if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
                skip_verify=true
                _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
            fi
        fi
    fi

    # [!] Trojan: 使用密码
    local password=""
    if [ "$BATCH_MODE" = "true" ]; then
        password=$(${SINGBOX_BIN} generate rand --hex 16)
    else
        read -p "请输入 Trojan 密码 (回车则随机生成): " input_pw
        if [ -z "$input_pw" ]; then
            password=$(${SINGBOX_BIN} generate rand --hex 16)
            _info "已为您生成随机密码: ${password}"
        else
            password="$input_pw"
        fi
    fi

    # [!] 自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-Trojan-WS-${port}"
    else
        local default_name="Trojan-WS-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    # Inbound (服务器端) 配置
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg sn "$camouflage_domain" \
        --arg wsp "$ws_path" \
        '{
            "type": "trojan",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"password": $pw}],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # Proxy (客户端) 配置
    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$client_port" \
            --arg pw "$password" \
            --arg sn "$camouflage_domain" \
            --arg wsp "$ws_path" \
            --arg skip_verify_bool "$skip_verify" \
            --arg host_header "$camouflage_domain" \
            '{
                "name": $n,
                "type": "trojan",
                "server": $s,
                "port": ($p|tonumber),
                "password": $pw,
                "udp": true,
                "skip-cert-verify": ($skip_verify_bool == "true"),
                "network": "ws",
                "sni": $sn,
                "ws-opts": {
                    "path": $wsp,
                    "headers": {
                        "Host": $host_header
                    }
                }
            }')
            
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    _success "Trojan (WebSocket+TLS) 节点 [${name}] 添加成功!"
    _success "客户端连接地址 (server): ${client_server_addr}"
    _success "客户端连接端口 (port): ${client_port}"
    _success "客户端伪装域名 (sni/Host): ${camouflage_domain}"
    
    # CDN 指引 (仅在非批量模式下详细显示)
    [ "$BATCH_MODE" != "true" ] && _show_cdn_guidance "${camouflage_domain}" "${port}"

    # IPv6 处理用于链接
    local link_ip="$client_server_addr"
    _show_node_link "trojan-ws-tls" "$name" "$link_ip" "$client_port" "$tag" "$password" "$camouflage_domain" "$ws_path" "$skip_verify" "$cert_path" || return 1
}

_create_anytls_tls_node() {
    local node_ip="$1"
    local port="$2"
    local server_name="$3"
    local password="$4"
    local name="$5"

    # --- 步骤 4: 证书选择 ---
    local cert_choice="1"
    if [ "$BATCH_MODE" = "true" ]; then
        cert_choice="1"
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (推荐)"
        echo "  2) 手动上传证书文件 (Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
    fi
    
    local cert_path=""
    local key_path=""
    local skip_verify=true  # 默认跳过验证 (自签证书需要)
    local tag="anytls-in-${port}"
    
    if [ "$cert_choice" == "1" ]; then
        # 自签名证书
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1
        _info "已生成自签名证书，客户端将跳过证书验证。"
    else
        # 手动上传证书
        _info "请输入 ${server_name} 对应的证书文件路径。"
        read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
        [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1
        
        read -p "请输入私钥文件 .key 的完整路径: " key_path
        [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
        
        # 询问是否跳过验证
        read -p "$(echo -e ${YELLOW}"您是否正在使用自签名证书或Cloudflare源证书? (y/N): "${NC})" use_self_signed
        if [[ "$use_self_signed" == "y" || "$use_self_signed" == "Y" ]]; then
            skip_verify=true
            _warning "已启用 'skip-cert-verify: true'，客户端将跳过证书验证。"
        else
            skip_verify=false
        fi
    fi
    
    # IPv6 处理
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"
    [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    # --- 生成 Inbound 配置 (包含 padding_scheme) ---
    # padding_scheme 是 AnyTLS 的核心功能，用于流量填充对抗检测
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sn "$server_name" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        '{
            "type": "anytls",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"name": "default", "password": $pw}],
            "padding_scheme": [
                "stop=2",
                "0=100-200",
                "1=100-200"
            ],
            "tls": {
                "enabled": true,
                "alpn": ["http/1.1"],
                "certificate_path": $cp,
                "key_path": $kp
            }
        }')
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    
    # --- 生成 Clash YAML 配置 ---
    # 根据用户提供的格式：包含 client-fingerprint, udp, alpn
    local proxy_json=$(jq -n \
        --arg n "$name" \
        --arg s "$yaml_ip" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sn "$server_name" \
        --arg skip_verify_bool "$skip_verify" \
        '{
            "name": $n,
            "type": "anytls",
            "server": $s,
            "port": ($p|tonumber),
            "password": $pw,
            "client-fingerprint": "chrome",
            "udp": true,
            "idle-session-check-interval": 30,
            "idle-session-timeout": 30,
            "min-idle-session": 0,
            "sni": $sn,
            "alpn": ["h2", "http/1.1"],
            "skip-cert-verify": ($skip_verify_bool == "true")
        }')
    
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    
    # --- 保存元数据 ---
    local meta_json
    meta_json=$(jq -n --arg n "$name" --arg sn "$server_name" '{name:$n, server_name:$sn, yaml:true}')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1
    
    # --- 生成分享链接 ---
    local insecure_param=""
    if [ "$skip_verify" == "true" ]; then
        insecure_param="&insecure=1"
    fi
    local share_link="anytls://${password}@${link_ip}:${port}?security=tls&sni=${server_name}${insecure_param}&type=tcp#$(_url_encode "$name")"
    
    _success "AnyTLS 节点 [${name}] 添加成功!"
    _show_node_link "anytls" "$name" "$link_ip" "$port" "$tag" "$password" "$server_name" "$skip_verify" "$cert_path" || return 1
}

_create_anyreality_node() {
    local node_ip="$1"
    local port="$2"
    local server_name="$3"
    local password="$4"
    local name="$5"
    local tag="any-reality-in-${port}"

    local keypair private_key public_key short_id
    keypair=$(${SINGBOX_BIN} generate reality-keypair)
    private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    short_id=$(${SINGBOX_BIN} generate rand --hex 8)

    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sn "$server_name" \
        --arg pk "$private_key" \
        --arg sid "$short_id" \
        '{
            "type": "anytls",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"name": "default", "password": $pw}],
            "padding_scheme": [],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": $sn,
                        "server_port": 443
                    },
                    "private_key": $pk,
                    "short_id": [$sid]
                }
            }
        }')

    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    local link_ip="$node_ip"
    [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local share_link="anytls://${password}@${link_ip}:${port}?security=reality&sni=${server_name}&fp=chrome&pbk=$(_url_encode "$public_key")&sid=${short_id}&type=tcp&headerType=none#$(_url_encode "$name")"
    local meta_json
    meta_json=$(jq -n \
        --arg type "any-reality" \
        --arg sn "$server_name" \
        --arg pub "$public_key" \
        --arg sid "$short_id" \
        --arg link "$share_link" \
        --arg n "$name" \
        '{type:$type, name:$n, server_name:$sn, publicKey:$pub, shortId:$sid, share_link:$link, yaml:false}')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    _success "Any-Reality 节点 [${name}] 添加成功!"
    _warning "Any-Reality 为 AnyTLS + Reality，Mihomo/Clash 不支持，已跳过写入 clash.yaml。"
    _show_node_link "any-reality" "$name" "$link_ip" "$port" "$tag" "$password" "$server_name" "$public_key" "$short_id" || return 1
}

_add_anytls() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local server_name="www.amd.com"
    local mode_choice="1"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="${BATCH_SNI:-www.amd.com}"
        mode_choice="${BATCH_ANYTLS_MODE:-1}"
    else
        _info "--- 添加 AnyTLS / Any-Reality 节点 ---"
        echo "请选择节点协议:"
        echo "  1) AnyTLS"
        echo "  2) Any-Reality"
        echo "  1,2) 同时创建 AnyTLS 和 Any-Reality"
        read -p "请选择 [1/2/1,2] (默认: 1): " mode_choice
        mode_choice=${mode_choice:-1}
        mode_choice=$(echo "$mode_choice" | tr '，' ',' | xargs)
        case "$mode_choice" in
            1|2|1,2|2,1|"1 2"|"2 1") ;;
            *) _error "无效选择"; return 1 ;;
        esac

        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入起始监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            if [[ "$mode_choice" == "1,2" || "$mode_choice" == "2,1" || "$mode_choice" == "1 2" || "$mode_choice" == "2 1" ]]; then
                local reality_port=$((port + 1))
                if [ "$reality_port" -gt 65535 ]; then
                    _error "同时创建两个节点时，起始端口不能为 65535。"
                    continue
                fi
                _check_port_conflict "$reality_port" "tcp" && continue
            fi
            break
        done
        read -p "请输入伪装域名/SNI (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
    fi

    local password=""
    if [ "$BATCH_MODE" = "true" ]; then
        password=$(${SINGBOX_BIN} generate uuid)
    else
        read -p "请输入密码/UUID (回车则随机生成，两种模式共用): " input_pw
        password=${input_pw:-$(${SINGBOX_BIN} generate uuid)}
    fi

    local created=false
    case "$mode_choice" in
        1)
            local name
            if [ "$BATCH_MODE" = "true" ]; then
                name="Batch-AnyTLS-${port}"
            else
                local default_name="AnyTLS-${port}"
                read -p "请输入 AnyTLS 节点名称 (默认: ${default_name}): " custom_name
                name=${custom_name:-$default_name}
            fi
            _create_anytls_tls_node "$node_ip" "$port" "$server_name" "$password" "$name" || return 1
            created=true
            ;;
        2)
            local name
            if [ "$BATCH_MODE" = "true" ]; then
                name="Batch-Any-Reality-${port}"
            else
                local default_name="Any-Reality-${port}"
                read -p "请输入 Any-Reality 节点名称 (默认: ${default_name}): " custom_name
                name=${custom_name:-$default_name}
            fi
            _create_anyreality_node "$node_ip" "$port" "$server_name" "$password" "$name" || return 1
            created=true
            ;;
        1,2|2,1|"1 2"|"2 1")
            local tls_port="$port"
            local reality_port=$((port + 1))
            local tls_name reality_name
            if [ "$BATCH_MODE" = "true" ]; then
                tls_name="Batch-AnyTLS-${tls_port}"
                reality_name="Batch-Any-Reality-${reality_port}"
            else
                local default_tls_name="AnyTLS-${tls_port}"
                local default_reality_name="Any-Reality-${reality_port}"
                _info "同时创建时，Any-Reality 将使用端口 ${reality_port}。"
                read -p "请输入 AnyTLS 节点名称 (默认: ${default_tls_name}): " custom_tls_name
                tls_name=${custom_tls_name:-$default_tls_name}
                read -p "请输入 Any-Reality 节点名称 (默认: ${default_reality_name}): " custom_reality_name
                reality_name=${custom_reality_name:-$default_reality_name}
            fi
            _create_anytls_tls_node "$node_ip" "$tls_port" "$server_name" "$password" "$tls_name" || return 1
            _create_anyreality_node "$node_ip" "$reality_port" "$server_name" "$password" "$reality_name" || return 1
            created=true
            ;;
    esac

    [ "$created" = true ]
}

_add_vless_reality() {
    [ -z "$server_ip" ] && server_ip=$(_get_ip)
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local server_name="www.amd.com"
    local port=""
    local name=""

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        # 批量模式变量预加载，增加多层保底，防止变量泄露
        server_name=$(echo "${BATCH_SNI}" | xargs)
        [[ -z "$server_name" ]] && server_name="$DEFAULT_SNI"
        name="Batch-VLESS-TCP-Reality-Vision-${port}"
        # 批量模式下如果不显式指定，可能丢失 IP，此处进行双重保险
        [ -z "$node_ip" ] && node_ip="$server_ip"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入伪装域名 (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
        local default_name="VLESS-TCP-REALITY-VISION-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local keypair=$(${SINGBOX_BIN} generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(${SINGBOX_BIN} generate rand --hex 8)
    local tag="vless-in-${port}"
    # IPv6处理：YAML用原始IP，链接用带[]的IP
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\"}}" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    _success "VLESS + TCP + Reality + Vision 节点 [${name}] 添加成功!"
    _show_node_link "vless-reality" "$name" "$link_ip" "$port" "$tag" "$uuid" "$server_name" "$public_key" "$short_id" || return 1
}

_add_vless_tcp() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        if [ -z "$port" ]; then
            _error "批量创建错误: BATCH_PORT 为空，跳过 VLESS (TCP) 安装。"
            return 1
        fi
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi
    # [!] 自定义名称 (批量模式下自动分配)
    local default_name="VLESS-TCP-${port}"
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-TCP-${port}"
    else
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-tcp-in-${port}"
    # IPv6处理：YAML用原始IP，链接用带[]的IP
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":""}],"tls":{"enabled":false}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":false,"network":"tcp"}')
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    _success "VLESS (TCP) 节点 [${name}] 添加成功!"
    _show_node_link "vless-tcp" "$name" "$link_ip" "$port" "$tag" "$uuid" || return 1
}

_add_hysteria2() {
    [ -z "$server_ip" ] && server_ip=$(_get_ip)
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local server_name="www.amd.com"
    local obfs_password=""
    local port_hopping=""
    local use_multiport="false"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        if [ -z "$port" ]; then
            _error "批量创建错误: BATCH_PORT 为空，跳过 Hysteria2 安装。"
            return 1
        fi
        server_name="$BATCH_SNI"
        # 批量模式 double check
        [ -z "$node_ip" ] && node_ip="$server_ip"
        [ "$BATCH_HY2_OBFS" != "none" ] && obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        port_hopping="$BATCH_HY2_HOP"
        if [ -n "$port_hopping" ]; then
            local port_range_start=$(echo $port_hopping | cut -d'-' -f1)
            local port_range_end=$(echo $port_hopping | cut -d'-' -f2)
            if [ "$port_range_start" -lt 1 ] || [ "$port_range_end" -gt 65535 ] || [ "$port_range_start" -gt "$port_range_end" ]; then
                _error "批量创建错误: HY2 端口跳跃范围 ${port_hopping} 无效。"
                return 1
            fi
            local pf_conflict
            pf_conflict=$(_find_pf_udp_conflict_in_range "$port_range_start" "$port_range_end")
            if [ -n "$pf_conflict" ]; then
                local c_port c_name c_net c_target
                IFS=$'\t' read -r c_port c_name c_net c_target <<< "$pf_conflict"
                _error "批量创建错误: HY2 端口跳跃范围 ${port_hopping} 覆盖已有 ${c_net} 端口转发入口 ${c_port}（${c_name} -> ${c_target}）。"
                return 1
            fi
            local hop_conflict
            hop_conflict=$(_find_udp_hop_conflict_in_range "$port_range_start" "$port_range_end" "hy2-in-${port}")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                _error "批量创建错误: HY2 端口跳跃范围 ${port_hopping} 与已有跳跃范围 ${c_range} 重叠。"
                _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。"
                return 1
            fi
            use_multiport="true"
        fi
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "udp" && continue
            break
        done
        read -p "请输入伪装域名 (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
    fi

    local tag="hy2-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1

    local password=""
    if [ "$BATCH_MODE" = "true" ]; then
        password=$(${SINGBOX_BIN} generate rand --hex 16)
    else
        read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
        read -p "是否开启 QUIC 流量混淆 (salamander)? (y/N): " h_choice
        if [[ "$h_choice" == "y" ]]; then
            obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        fi
        read -p "是否开启端口跳跃? (y/N): " hop_choice
        if [[ "$hop_choice" == "y" ]]; then
            read -p "请输入端口范围 (如 20000-30000): " port_range
            if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                port_range_start="${BASH_REMATCH[1]}"
                port_range_end="${BASH_REMATCH[2]}"
                if [ "$port_range_start" -lt 1 ] || [ "$port_range_end" -gt 65535 ] || [ "$port_range_start" -gt "$port_range_end" ]; then
                    _error "端口跳跃范围无效。"
                    return 1
                fi
                local pf_conflict
                pf_conflict=$(_find_pf_udp_conflict_in_range "$port_range_start" "$port_range_end")
                if [ -n "$pf_conflict" ]; then
                    local c_port c_name c_net c_target
                    IFS=$'\t' read -r c_port c_name c_net c_target <<< "$pf_conflict"
                    _error "端口跳跃范围 ${port_range} 覆盖了已有 ${c_net} 端口转发入口 ${c_port}（${c_name} -> ${c_target}）。"
                    _error "请调整跳跃范围或先删除/修改该端口转发规则。"
                    return 1
                fi
                local hop_conflict
                hop_conflict=$(_find_udp_hop_conflict_in_range "$port_range_start" "$port_range_end" "$tag")
                if [ -n "$hop_conflict" ]; then
                    local c_tag c_name c_range c_mode
                    IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                    _error "端口跳跃范围 ${port_range} 与已有跳跃范围 ${c_range} 重叠。"
                    _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请调整跳跃范围。"
                    return 1
                fi
                port_hopping="$port_range"
                use_multiport="true"
            fi
        fi
    fi
    
    # [!] 自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-Hysteria2-${port}"
    else
        local default_name="Hysteria2-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi
    
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local up="${up_speed:-100}"
    local down="${down_speed:-100}"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # [!] 多端口监听模式逻辑：优先使用 nftables，失败则降级到 JSON Inbound (带数量保护)
    local port_hopping_mode=""
    if [ "$use_multiport" == "true" ] && [ -n "$port_hopping" ]; then
        if _nft_apply_redirect_rule add "$port_range_start" "$port_range_end" "$port" "singboxlite-hy2-hop-${tag}"; then
            if ! _save_nftables_rules; then
                _error "端口跳跃 nftables 规则持久化失败。"
                return 1
            fi
            port_hopping_mode="nftables"
            _success "已启动底层 nftables 高效 UDP 端口跳跃范围映射: ${port_hopping} -> ${port}"
        fi

        if [ "$port_hopping_mode" != "nftables" ]; then
            _warn "发现防火墙受限 (无 nftables redirect 写权限)，准备降级至 Sing-box 原生多实例监听方案..."
            local hop_count=$((port_range_end - port_range_start + 1))
            if [ "$hop_count" -le 1000 ]; then
                _info "正在生成原生大量监听配置块 (${port_range_start}-${port_range_end})..."
                local batch_array="[]"
                local skipped=0
                for ((p=port_range_start; p<=port_range_end; p++)); do
                    if [ "$p" -eq "$port" ]; then continue; fi
                    if _check_port_conflict "$p" "udp" "true"; then ((skipped++)); continue; fi
                    local hop_tag="${tag}-hop-${p}"
                    batch_array=$(echo "$batch_array" | jq --arg t "$hop_tag" --arg p "$p" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" --arg op "$obfs_password" \
                        '. += [{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end]')
                done
                _atomic_modify_json "$CONFIG_FILE" ".inbounds += $batch_array | .inbounds |= unique_by(.tag)" || return 1
                local added_count=$(echo "$batch_array" | jq 'length')
                port_hopping_mode="native"
                _success "安全降级成功：已硬编码 ${added_count} 个原生辅助监听节点 (跳过 ${skipped} 个冲突端口)。"
            else
                _error "降级失败：目标跳跃端口数量 (${hop_count}) 超出低配原生环境的内存承载安全阈值 (1000)！"
                _warn "鉴于当前系统容器不支持内核级 nftables 重定向，且端口数量超配，已自动取消该节点的跳跃设定。"
                port_hopping=""
                port_hopping_mode=""
            fi
        fi
    fi
    
    # 保存元数据（包含端口跳跃信息）
    local meta_json=$(jq -n --arg up "$up" --arg down "$down" --arg op "$obfs_password" --arg hop "$port_hopping" --arg hop_mode "$port_hopping_mode" \
        '{ "up": $up, "down": $down } | if $op != "" then .obfsPassword = $op else . end | if $hop != "" then .portHopping = $hop else . end | if $hop_mode != "" then .portHoppingMode = $hop_mode else . end')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    # Clash 配置中的端口（如果有端口跳跃，使用范围格式）
    local clash_ports="$port"
    if [ -n "$port_hopping" ]; then
        clash_ports="$port_hopping"
    fi
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg ports "$clash_ports" --arg pw "$password" --arg sn "$server_name" --arg up "$up" --arg down "$down" --arg op "$obfs_password" --arg hop "$port_hopping" \
        '{
            "name": $n,
            "type": "hysteria2",
            "server": $s,
            "port": ($p|tonumber),
            "password": $pw,
            "sni": $sn,
            "skip-cert-verify": true,
            "alpn": ["h3"],
            "up": ($up|tonumber),
            "down": ($down|tonumber)
        } | if $op != "" then .obfs = "salamander" | .["obfs-password"] = $op else . end | if $hop != "" then .ports = $hop else . end')
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    
    _success "Hysteria2 节点 [${name}] 添加成功!"
    
    # 显示端口跳跃信息
    if [ -n "$port_hopping" ]; then
        _info "端口跳跃范围: ${port_hopping}"
    fi
    
    _show_node_link "hysteria2" "$name" "$link_ip" "$port" "$tag" "$password" "$server_name" "$obfs_password" "$port_hopping" || return 1
}

_add_tuic() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local server_name="www.amd.com"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="${BATCH_SNI:-www.amd.com}"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "udp" && continue
            break
        done
        read -p "请输入伪装域名 (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
    fi

    local tag="tuic-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1

    local uuid=$(${SINGBOX_BIN} generate uuid); local password=$(${SINGBOX_BIN} generate rand --hex 16)
    
    # [!] 自主生成与名称分配
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-TUICv5-${port}"
    else
        local default_name="TUICv5-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sn "$server_name" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    _success "TUICv5 节点 [${name}] 添加成功!"
    _show_node_link "tuic" "$name" "$link_ip" "$port" "$tag" "$uuid" "$password" "$server_name" || return 1
}

_generate_shadowsocks_password() {
    local method="$1" key_length
    case "$method" in
        2022-blake3-aes-128-gcm) key_length=16 ;;
        2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305) key_length=32 ;;
        aes-128-gcm|aes-256-gcm|chacha20-ietf-poly1305|xchacha20-ietf-poly1305)
            ${SINGBOX_BIN} generate rand --hex 16
            return
            ;;
        *) _error "不支持的 Shadowsocks 加密方式: ${method}"; return 1 ;;
    esac
    ${SINGBOX_BIN} generate rand --base64 "$key_length"
}

_add_shadowsocks_menu() {
    local choice=""
    if [ "$BATCH_MODE" = "true" ]; then
        choice="$BATCH_SS_VARIANT"
    else
        clear
        echo "========================================"
        _info "          添加 Shadowsocks 节点"
        echo "========================================"
        echo " [经典 SS]"
        echo " 1) aes-128-gcm"
        echo " 2) aes-256-gcm"
        echo " 3) chacha20-ietf-poly1305"
        echo " 4) xchacha20-ietf-poly1305"
        echo " [SS-2022 (强抗重放保护)]"
        echo " 5) 2022-blake3-aes-128-gcm"
        echo " 6) 2022-blake3-aes-256-gcm"
        echo " 7) 2022-blake3-chacha20-poly1305"
        echo " 8) 2022-blake3-aes-256-gcm (带 Padding)"
        echo " [SS-2022 + ShadowTLS (完美伪装组合)]"
        echo " 9) 2022-blake3-aes-256-gcm + ShadowTLS v3"
        echo " 0) 返回"
        echo "========================================"
        read -r -p "请选择加密方式 [0-9]: " choice
    fi

    local method="" password="" name_prefix="" use_multiplex=false use_shadowtls=false
    case $choice in
        1)
            method="aes-128-gcm"
            name_prefix="SS-aes128"
            ;;
        2)
            method="aes-256-gcm"
            name_prefix="SS-aes256"
            ;;
        3)
            method="chacha20-ietf-poly1305"
            name_prefix="SS-chacha20"
            ;;
        4)
            method="xchacha20-ietf-poly1305"
            name_prefix="SS-xchacha20"
            ;;
        5)
            method="2022-blake3-aes-128-gcm"
            name_prefix="SS-2022-aes128"
            ;;
        6)
            method="2022-blake3-aes-256-gcm"
            name_prefix="SS-2022-aes256"
            ;;
        7)
            method="2022-blake3-chacha20-poly1305"
            name_prefix="SS-2022-chacha20"
            ;;
        8)
            method="2022-blake3-aes-256-gcm"
            name_prefix="SS-2022-Padding"
            use_multiplex=true
            _info "已启用 Multiplex + Padding 模式"
            _warning "注意：客户端也必须启用 Multiplex + Padding 才能连接！"
            ;;
        9)
            method="2022-blake3-aes-256-gcm"
            name_prefix="SS-ShadowTLS"
            use_shadowtls=true
            ;;
        0) return 1 ;;
        *) _error "无效输入"; return 1 ;;
    esac
    password=$(_generate_shadowsocks_password "$method") || return 1

    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    fi
    
    # [!] 新增：自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-${name_prefix}-${port}"
    else
        local default_name="${name_prefix}-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi
    
    local shadowtls_password=""
    local shadowtls_sni="www.amd.com"
    if [ "$use_shadowtls" == "true" ]; then
        shadowtls_password=$(${SINGBOX_BIN} generate rand --hex 16)
        read -p "请输入 ShadowTLS 伪装白名单域名 (默认: www.amd.com): " custom_sni
        shadowtls_sni=${custom_sni:-www.amd.com}
    fi

    local tag="${name_prefix}-in-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    # 根据是否启用 Multiplex 或 ShadowTLS 生成不同配置
    local inbound_json=""
    local shadowtls_inner_tag=""
    local jq_modify_expr=".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)"
    
    if [ "$use_shadowtls" == "true" ]; then
        local ss_tag="${tag}-ss"
        shadowtls_inner_tag="$ss_tag"
        inbound_json=$(jq -n --arg t "$tag" --arg st "$ss_tag" --arg p "$port" --arg m "$method" --arg pw "$password" --arg spw "$shadowtls_password" --arg sni "$shadowtls_sni" \
            '[
                {
                    "type": "shadowtls",
                    "tag": $t,
                    "listen": "::",
                    "listen_port": ($p|tonumber),
                    "version": 3,
                    "users": [
                        {
                            "password": $spw
                        }
                    ],
                    "handshake": {
                        "server": $sni,
                        "server_port": 443
                    },
                    "detour": $st
                },
                {
                    "type": "shadowsocks",
                    "tag": $st,
                    "method": $m,
                    "password": $pw
                }
            ]')
        jq_modify_expr=".inbounds += $inbound_json | .inbounds |= unique_by(.tag)"
    elif [ "$use_multiplex" == "true" ]; then
        # 带 Multiplex + Padding 的配置
        inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "type": "shadowsocks",
                "tag": $t,
                "listen": "::",
                "listen_port": ($p|tonumber),
                "method": $m,
                "password": $pw,
                "multiplex": {
                    "enabled": true,
                    "padding": true
                }
            }')
        jq_modify_expr=".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)"
    else
        # 标准配置
        inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "type": "shadowsocks",
                "tag": $t,
                "listen": "::",
                "listen_port": ($p|tonumber),
                "method": $m,
                "password": $pw
            }')
        jq_modify_expr=".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)"
    fi
    _atomic_modify_json "$CONFIG_FILE" "$jq_modify_expr" || return 1

    # YAML 配置也需要根据特定状态生成
    local proxy_json=""
    if [ "$use_shadowtls" == "true" ]; then
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg m "$method" --arg pw "$password" --arg spw "$shadowtls_password" --arg sni "$shadowtls_sni" \
            '{
                "name": $n,
                "type": "ss",
                "server": $s,
                "port": ($p|tonumber),
                "cipher": $m,
                "password": $pw,
                "plugin": "shadow-tls",
                "plugin-opts": {
                    "host": $sni,
                    "password": $spw,
                    "version": 3
                }
            }')
    elif [ "$use_multiplex" == "true" ]; then
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "name": $n,
                "type": "ss",
                "server": $s,
                "port": ($p|tonumber),
                "cipher": $m,
                "password": $pw,
                "smux": {
                    "enabled": true,
                    "padding": true
                }
            }')
    else
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "name": $n,
                "type": "ss",
                "server": $s,
                "port": ($p|tonumber),
                "cipher": $m,
                "password": $pw
            }')
    fi
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }

    # ShadowTLS 没有标准单行分享链接，仍需记录归属和内外层关系，供
    # 查看、删除、改端口及“删除全部”进行精准管理。
    if [ "$use_shadowtls" = "true" ]; then
        _atomic_modify_json "$METADATA_FILE" '. + {($tag): ((.[$tag] // {}) + {name:$name, owner:"singbox-main", yaml:true, composite:"shadowtls", inner_tag:$inner})}' \
            --arg tag "$tag" --arg name "$name" --arg inner "$shadowtls_inner_tag" || return 1
    fi

    _success "Shadowsocks (${method}) 节点 [${name}] 添加成功!"
    if [ "$use_multiplex" == "true" ]; then
        _info "Multiplex + Padding 已启用，客户端需配置对应选项"
    fi
    if [ "$use_shadowtls" == "true" ]; then
        _show_node_link "shadowsocks-shadowtls" "$name" "$link_ip" "$port" "$tag" "$method" "$password" "$shadowtls_password" "$shadowtls_sni" || return 1
    else
        _show_node_link "shadowsocks" "$name" "$link_ip" "$port" "$tag" "$method" "$password" || return 1
    fi
    return 0
}

_add_socks() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local username=""
    local password=""

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        if [ -z "$port" ]; then
            _error "批量创建错误: BATCH_PORT 为空，跳过 SOCKS5 安装。"
            return 1
        fi
        username=$(${SINGBOX_BIN} generate rand --hex 8)
        password=$(${SINGBOX_BIN} generate rand --hex 16)
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
        read -p "请输入用户名 (默认随机): " username; username=${username:-$(${SINGBOX_BIN} generate rand --hex 8)}
        read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
    fi
    local tag="socks-in-${port}"
    local name="Batch-SOCKS5-${port}"
    [ "$BATCH_MODE" != "true" ] && name="SOCKS5-${port}"
    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"type":"socks","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"username":$u,"password":$pw}]}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"name":$n,"type":"socks5","server":$s,"port":($p|tonumber),"username":$u,"password":$pw}')
    _add_node_to_yaml "$proxy_json" || { _rollback_main_node_creation "$tag"; return 1; }
    _atomic_modify_json "$METADATA_FILE" '. + {($tag): ((.[$tag] // {}) + {name:$name, owner:"singbox-main", yaml:true})}' \
        --arg tag "$tag" --arg name "$name" || return 1
    _success "SOCKS5 节点添加成功!"
    _show_node_link "socks" "$name" "$display_ip" "$port" "$tag" "$username" "$password" || return 1
}

_view_nodes() {
    local primary_nodes
    primary_nodes=$(_list_main_primary_inbounds)
    if [ -z "$primary_nodes" ]; then _warning "当前没有可由主节点菜单管理的节点（Argo 请在 Argo 菜单管理）。"; return; fi

    local node_count
    node_count=$(printf '%s\n' "$primary_nodes" | awk 'NF {count++} END {print count+0}')
    _info "--- 当前节点信息 (共 ${node_count} 个) ---"

    # 每个进程使用独立临时文件，避免并发查看互相覆盖。
    local links_tmp
    links_tmp=$(mktemp /tmp/singbox_links.XXXXXX) || { _error "无法创建临时订阅文件。"; return 1; }
    VIEW_LINKS_TMP="$links_tmp"
    
    # [资源优化] 传递紧凑 JSON，循环内用单次 jq 提取 tag/type/port (3次→1次)
    while IFS= read -r node; do
        # 合并3次字段提取为1次
        local _base_fields
        _base_fields=$(echo "$node" | jq -r '[.tag, .type, (.listen_port|tostring)] | @tsv')
        local tag type port
        IFS=$'\t' read -r tag type port <<< "$_base_fields"
        
        # 使用统一查找函数
        local proxy_name_to_find=$(_find_proxy_name "$port" "$type" "$tag")

        # 创建显示名称，优先使用 clash.yaml 中的名称，失败则回退到 tag
        local meta_name=$(jq -r --arg t "$tag" '.[$t].name // empty' "$METADATA_FILE" 2>/dev/null)
        local display_name=${proxy_name_to_find:-${meta_name:-$tag}}

        # 优先使用 metadata.json 中的 IP (用于 REALITY 和 TCP)
        local display_server=$(_get_proxy_field "$proxy_name_to_find" ".server")
        # 移除方括号
        local display_ip=$(echo "$display_server" | tr -d '[]')
        # IPv6链接格式：添加[]
        local link_ip="$display_ip"; [[ "$display_ip" == *":"* ]] && link_ip="[$display_ip]"
        
        echo "-------------------------------------"
        # [!] 已修改：使用 display_name
        _info " 节点: ${display_name}"
        local url=""
        
        # [新架构] 优先使用持久化生成的链接（从极源解决动态提取可能存在的 SNI 丢失死角）
        url=$(jq -r --arg t "$tag" '.[$t].share_link // empty' "$METADATA_FILE")
        if { [ -z "$url" ] || [ "$url" == "null" ]; } && [[ "$tag" == argo-* ]] && [ -f "$ARGO_METADATA_FILE" ]; then
            url=$(jq -r --arg t "$tag" '.[$t].share_link // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
        fi
        
        if [ -n "$url" ] && [ "$url" != "null" ]; then
            : # 直接使用持久化链接
        else
            case "$type" in
            "vless")
                # [资源优化] 合并 VLESS 关键字段读取，避免循环内多次 jq
                local _vless_fields
                # [加固] 智能回溯 SNI: 优先 .tls.server_name, 备选 .tls.reality.handshake.server, 保底 www.amd.com
            _vless_fields=$(echo "$node" | jq -r '[.users[0].uuid, (.users[0].flow // ""), (.tls.reality.enabled // false | tostring), (.transport.type // ""), (.tls.enabled // false | tostring), (.tls.server_name // .tls.reality.handshake.server // "www.amd.com"), (.tls.certificate_path // ""), (.transport.path // ""), (.transport.service_name // "")] | @tsv')
            IFS=$'\t' read -r uuid flow is_reality transport_type tls_enabled tls_sn cert_path ws_path grpc_service_name <<< "$_vless_fields"
                
                # [加固] 确保 Reality 模式下的流量控制字段非空 (v2rayN 要求)
                [ "$is_reality" == "true" ] && [ -z "$flow" ] && flow="xtls-rprx-vision"
                
                if [ "$is_reality" == "true" ]; then
                    # [修复] 放弃对 Base64/Hex 密钥使用 @tsv，避免损坏
                    local pk=$(jq -r --arg t "$tag" '.[$t].publicKey // empty' "$METADATA_FILE")
                    local sid=$(jq -r --arg t "$tag" '.[$t].shortId // empty' "$METADATA_FILE")
                    local sn="$tls_sn"
                    local fp="chrome"
                    url="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "${pk}")&fp=${fp}&type=tcp&flow=${flow}&sni=${sn}&sid=${sid}#$(_url_encode "$display_name")"
                elif [ "$transport_type" == "ws" ]; then
                    # ws_path 已在上方合并提取
                    local sn="$tls_sn"
                    [ -z "$sn" ] || [ "$sn" == "null" ] && sn=$(_get_proxy_field "$proxy_name_to_find" ".servername")
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=ws&host=${sn}&path=$(_url_encode "$ws_path")&sni=${sn}#$(_url_encode "$display_name")"
                    
                    # Argo 节点元数据已迁移到 argo_metadata.json
                    local argo_domain=""
                    if [[ "$tag" == argo-* ]] && [ -f "$ARGO_METADATA_FILE" ]; then
                        argo_domain=$(jq -r --arg t "$tag" '.[$t].domain // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
                    fi
                    if [ -n "$argo_domain" ] && [ "$argo_domain" != "null" ]; then
                        local argo_ws_path=$(_ws_path_with_early_data "$ws_path")
                        url="vless://${uuid}@${argo_domain}:443?security=tls&encryption=none&type=ws&host=${argo_domain}&path=$(_url_encode "$argo_ws_path")&sni=${argo_domain}#$(_url_encode "$display_name")"
                    fi
                elif [ "$transport_type" == "grpc" ]; then
                    local sn="$tls_sn"
                    [ -z "$sn" ] || [ "$sn" == "null" ] && sn=$(_get_proxy_field "$proxy_name_to_find" ".servername")
                    [ -z "$sn" ] || [ "$sn" == "null" ] && sn="$DEFAULT_SNI"
                    local svc="$grpc_service_name"
                    if [ -z "$svc" ] || [ "$svc" == "null" ]; then
                        svc=$(_get_proxy_field "$proxy_name_to_find" '.["grpc-opts"]["grpc-service-name"]')
                    fi
                    [ -z "$svc" ] || [ "$svc" == "null" ] && svc="grpc"
                    local skip_verify=$(_get_proxy_field "$proxy_name_to_find" '.["skip-cert-verify"]')
                    local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=grpc&serviceName=$(_url_encode "$svc")&sni=${sn}${insecure_param}#$(_url_encode "$display_name")"
                elif [ "$tls_enabled" == "true" ]; then
                    local sn="$tls_sn"
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=tcp&sni=${sn}#$(_url_encode "$display_name")"
                else
                    url="vless://${uuid}@${link_ip}:${port}?encryption=none&type=tcp#$(_url_encode "$display_name")"
                fi
                ;;
            "trojan")
                # [资源优化] 合并3次jq为1次
                local _trojan_fields
                _trojan_fields=$(echo "$node" | jq -r '[.users[0].password, (.transport.type // ""), (.transport.path // "")] | @tsv')
                local password transport_type ws_path
                IFS=$'\t' read -r password transport_type ws_path <<< "$_trojan_fields"
                
                if [ "$transport_type" == "ws" ]; then
                    local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                    url="trojan://${password}@${link_ip}:${port}?security=tls&type=ws&host=${sn}&path=$(_url_encode "$ws_path")&sni=${sn}#$(_url_encode "$display_name")"
                    
                    # Argo 节点元数据已迁移到 argo_metadata.json
                    local argo_domain=""
                    if [[ "$tag" == argo-* ]] && [ -f "$ARGO_METADATA_FILE" ]; then
                        argo_domain=$(jq -r --arg t "$tag" '.[$t].domain // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
                    fi
                    if [ -n "$argo_domain" ] && [ "$argo_domain" != "null" ]; then
                        local argo_ws_path=$(_ws_path_with_early_data "$ws_path")
                        url="trojan://${password}@${argo_domain}:443?security=tls&type=ws&host=${argo_domain}&path=$(_url_encode "$argo_ws_path")&sni=${argo_domain}#$(_url_encode "$display_name")"
                    fi
                else
                    local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                    url="trojan://${password}@${link_ip}:${port}?security=tls&type=tcp&sni=${sn}#$(_url_encode "$display_name")"
                fi
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn="$tls_sn"
                [ -z "$sn" ] || [ "$sn" == "null" ] && sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                # [修复] 放弃对混合类型元数据使用 @tsv，避免损坏
                local op=$(jq -r --arg t "$tag" '.[$t].obfsPassword // empty' "$METADATA_FILE")
                local hop=$(jq -r --arg t "$tag" '.[$t].portHopping // empty' "$METADATA_FILE")
                local obfs_param=""; [[ -n "$op" && "$op" != "null" ]] && obfs_param="&obfs=salamander&obfs-password=$(_url_encode "${op}")"
                # 端口跳跃参数
                local hop_param=""; [[ -n "$hop" && "$hop" != "null" ]] && hop_param="&mport=${hop}&ports=${hop}"
                url="hysteria2://${pw}@${link_ip}:${port}?sni=${sn}&insecure=1${obfs_param}${hop_param}#$(_url_encode "$display_name")"
                ;;
            "tuic")
                # [资源优化] 合并2次jq为1次
                local uuid pw
                IFS=$'\t' read -r uuid pw <<< "$(echo "$node" | jq -r '[.users[0].uuid, .users[0].password] | @tsv')"
                local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                url="tuic://${uuid}:${pw}@${link_ip}:${port}?sni=${sn}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$display_name")"
                ;;
            "anytls")
                # [资源优化] 合并2次jq为1次
                local pw sn
                # [加固] 允许 server_name 回溯
                IFS=$'\t' read -r pw sn <<< "$(echo "$node" | jq -r '[.users[0].password, (.tls.server_name // "www.amd.com")] | @tsv')"
                local skip_verify=$(_get_proxy_field "$proxy_name_to_find" ".skip-cert-verify")
                local insecure_param=""
                if [ "$skip_verify" == "true" ]; then
                    insecure_param="&insecure=1"
                fi
                url="anytls://${pw}@${link_ip}:${port}?security=tls&sni=${sn}${insecure_param}&type=tcp#$(_url_encode "$display_name")"
                ;;
            "shadowsocks")
                # [资源优化] 合并2次jq为1次
                local method password
                IFS=$'\t' read -r method password <<< "$(echo "$node" | jq -r '[.method, .password] | @tsv')"
                url="ss://$(_url_encode "${method}:${password}")@${link_ip}:${port}#$(_url_encode "$display_name")"
                ;;
            "socks")
                # [资源优化] 合并2次jq为1次
                local u p
                IFS=$'\t' read -r u p <<< "$(echo "$node" | jq -r '[.users[0].username, .users[0].password] | @tsv')"
                _info "  类型: SOCKS5, 地址: $display_server, 端口: $port, 用户: $u, 密码: $p"
                ;;
        esac
        fi
        [ -n "$url" ] && echo -e "  ${YELLOW}分享链接:${NC} ${url}"
        # 收集链接到临时文件
        [ -n "$url" ] && echo "$url" >> "$links_tmp"
    done <<< "$primary_nodes"
    echo "-------------------------------------"
    
    # 生成聚合 Base64 选项
    if [ -s "$links_tmp" ]; then
        echo ""
        read -p "是否生成聚合 Base64 订阅? (y/N): " gen_base64
        if [[ "$gen_base64" == "y" || "$gen_base64" == "Y" ]]; then
            echo ""
            _info "=== 聚合 Base64 订阅 ==="
            local base64_result=$(base64 < "$links_tmp" | tr -d '\n')
            echo -e "${CYAN}${base64_result}${NC}"
            echo ""
            _success "可直接复制上方内容导入 v2rayN 等客户端"
        fi
    fi
    rm -f -- "$links_tmp"
    VIEW_LINKS_TMP=""
}

_restore_full_transaction_snapshot() {
    local backup_dir="$1" restart_required="$2" context="$3"
    local restore_rc=0
    if ! _main_create_tx_restore "$backup_dir" "$restart_required"; then
        restore_rc=1
    fi
    if [ "$restore_rc" -eq 0 ]; then
        rm -rf -- "$backup_dir" || _warn "事务已恢复，但快照目录清理失败: $backup_dir"
        _error "${context}未提交，已恢复操作前的配置、凭据与 nftables 状态。"
    else
        _error "${context}失败且回滚不完整，请立即检查配置、凭据、服务与 nftables。"
        _error "为便于人工恢复，事务快照已保留: $backup_dir"
    fi
    return "$restore_rc"
}

_rollback_port_modify_state() {
    local backup_dir="$1" restart_required="$2"
    _restore_full_transaction_snapshot "$backup_dir" "$restart_required" "端口修改"
}

_delete_one_main_node_locked() (
    local tag="$1" type="$2" port="$3" display_name="$4" proxy_name="$5"
    _is_argo_inbound_tag "$tag" && { _error "Argo 内部节点受保护，请使用 Argo 菜单管理。"; return 1; }
    _validate_protected_yaml_metadata || return 1

    local node_count node_json node_fields
    node_count=$(jq -r --arg tag "$tag" '[.inbounds[]? | select(.tag == $tag)] | length' "$CONFIG_FILE" 2>/dev/null) || return 1
    [ "$node_count" = "1" ] || { _error "节点已不存在或 tag 不唯一，可能已被其他操作修改。"; return 1; }
    node_json=$(jq -c --arg tag "$tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" 2>/dev/null) || return 1
    local actual_type actual_port
    node_fields=$(printf '%s' "$node_json" | jq -r '[.type // "", (.listen_port // "" | tostring)] | @tsv') || return 1
    IFS=$'\t' read -r actual_type actual_port <<< "$node_fields"
    if [ "$actual_type" != "$type" ] || [ "$actual_port" != "$port" ]; then
        _error "节点状态在选择后已变化，已取消删除，请重新选择。"
        return 1
    fi
    proxy_name=$(_find_proxy_name "$actual_port" "$actual_type" "$tag")

    local detour cert_path key_path node_metadata node_type outbound_tag
    detour=$(printf '%s' "$node_json" | jq -r 'if .type == "shadowtls" then (.detour // "") else "" end')
    if [ "$actual_type" = "shadowtls" ]; then
        [ -n "$detour" ] || { _error "ShadowTLS 外层缺少 detour，拒绝删除。"; return 1; }
        [ "$(jq -r --arg tag "$detour" '[.inbounds[]? | select(.tag == $tag)] | length' "$CONFIG_FILE" 2>/dev/null)" = "1" ] || {
            _error "ShadowTLS 内层状态异常，拒绝删除以避免误伤。"
            return 1
        }
    fi
    cert_path=$(printf '%s' "$node_json" | jq -r '.tls.certificate_path // empty')
    key_path=$(printf '%s' "$node_json" | jq -r '.tls.key_path // empty')
    node_metadata=$(jq -c --arg tag "$tag" '.[$tag] // {}' "$METADATA_FILE" 2>/dev/null) || return 1
    node_type=$(printf '%s' "$node_metadata" | jq -r '.type // empty') || return 1
    outbound_tag=$(jq -r --arg inbound "$tag" '[.route.rules[]? | select(.inbound == $inbound) | .outbound // empty][0] // empty' "$CONFIG_FILE" 2>/dev/null) || return 1

    local backup_dir
    backup_dir=$(mktemp -d /tmp/.singbox-delete.XXXXXX) || return 1
    if ! _main_create_tx_snapshot "$backup_dir"; then
        _error "无法完整创建删除事务快照，操作尚未开始。"
        rm -rf -- "$backup_dir"
        return 1
    fi
    local delete_committed=0 delete_restart_attempted=0
    trap 'delete_rc=$?; trap - EXIT INT TERM; if [ "$delete_committed" -ne 1 ]; then if ! _restore_full_transaction_snapshot "$backup_dir" "$delete_restart_attempted" "节点删除"; then delete_rc=1; fi; fi; exit "$delete_rc"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    if ! _atomic_modify_json "$CONFIG_FILE" '
        .inbounds |= map(select(
            .tag != $tag and .tag != $detour and (((.tag // "") | startswith($tag + "-hop-")) | not)
        ))
        | .route = (.route // {"rules":[]})
        | .route.rules = ((.route.rules // []) | map(select(.inbound != $tag)))
        | if $remove_outbound and $outbound != "" then .outbounds = ((.outbounds // []) | map(select(.tag != $outbound))) else . end
    ' --arg tag "$tag" --arg detour "$detour" --arg outbound "$outbound_tag" --argjson remove_outbound "$([ "$node_type" = "third-party-adapter" ] && echo true || echo false)"; then
        return 1
    fi
    _atomic_modify_json "$METADATA_FILE" 'del(.[$tag], .[$detour])' --arg tag "$tag" --arg detour "$detour" || {
        return 1
    }

    if [ -n "$proxy_name" ] && ! _is_protected_yaml_name "$proxy_name"; then
        _remove_node_from_yaml "$proxy_name" || {
            return 1
        }
    elif [ -n "$proxy_name" ]; then
        _warn "同名代理仍被 Argo/Xray/中转引用，已保留共享 YAML 条目: $proxy_name"
    fi

    local check_result
    if ! check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
        _error "删除后的组合配置校验失败，已回滚："
        echo "$check_result"
        return 1
    fi
    local port_hopping port_hopping_mode
    port_hopping=$(printf '%s' "$node_metadata" | jq -r '.portHopping // empty')
    port_hopping_mode=$(printf '%s' "$node_metadata" | jq -r '.portHoppingMode // empty')
    if [ -n "$port_hopping" ] && [ "$port_hopping_mode" != "native" ]; then
        if [ ! -f "${backup_dir}/nft.available" ]; then
            _error "无法快照 nftables 状态，拒绝删除使用 nftables 端口跳跃的节点。"
            return 1
        fi
        if ! _nft_apply_redirect_rule delete "${port_hopping%-*}" "${port_hopping#*-}" "$port" "singboxlite-hy2-hop-${tag}" \
            || ! _save_nftables_rules; then
            _error "删除节点的 nftables 跳跃规则失败，正在回滚完整删除事务。"
            return 1
        fi
    fi
    delete_restart_attempted=1
    if ! _manage_service restart; then
        _error "服务重启失败，正在恢复删除前状态。"
        return 1
    fi
    _safe_remove_main_credential "$cert_path"
    _safe_remove_main_credential "$key_path"
    delete_committed=1
    trap - EXIT INT TERM
    rm -rf -- "$backup_dir" || _warn "删除事务快照目录清理失败: $backup_dir"
    _success "节点 ${display_name} 已删除！"
)

_delete_all_main_nodes_locked() (
    _validate_protected_yaml_metadata || return 1
    local primary_nodes
    primary_nodes=$(_list_main_primary_inbounds)
    [ -n "$primary_nodes" ] || { _warning "没有可删除的主 sing-box 节点。"; return 0; }

    local backup_dir names_file credential_paths_file hop_file
    backup_dir=$(mktemp -d /tmp/.singbox-delete-all.XXXXXX) || return 1
    if ! _main_create_tx_snapshot "$backup_dir"; then
        _error "无法完整创建批量删除事务快照，操作尚未开始。"
        rm -rf -- "$backup_dir"
        return 1
    fi
    local delete_all_committed=0 delete_all_restart_attempted=0
    trap 'delete_all_rc=$?; trap - EXIT INT TERM; if [ "$delete_all_committed" -ne 1 ]; then if ! _restore_full_transaction_snapshot "$backup_dir" "$delete_all_restart_attempted" "批量删除"; then delete_all_rc=1; fi; fi; exit "$delete_all_rc"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    names_file="$backup_dir/names"
    credential_paths_file="$backup_dir/credential-paths"
    hop_file="$backup_dir/hops"
    if ! : > "$names_file" || ! : > "$credential_paths_file" || ! : > "$hop_file"; then
        return 1
    fi

    local node node_fields tag type port proxy_name cert key
    while IFS= read -r node; do
        [ -n "$node" ] || continue
        node_fields=$(printf '%s' "$node" | jq -r '[.tag,.type,(.listen_port|tostring),(.tls.certificate_path // ""),(.tls.key_path // "")] | @tsv') || return 1
        IFS=$'\t' read -r tag type port cert key <<< "$node_fields"
        proxy_name=$(_find_proxy_name "$port" "$type" "$tag")
        if [ -n "$proxy_name" ]; then printf '%s\n' "$proxy_name" >> "$names_file" || return 1; fi
        if [ -n "$cert" ]; then printf '%s\n' "$cert" >> "$credential_paths_file" || return 1; fi
        if [ -n "$key" ]; then printf '%s\n' "$key" >> "$credential_paths_file" || return 1; fi
    done <<< "$primary_nodes"
    if ! jq -r 'to_entries[]? | select(.value.portHopping) | [.key,.value.portHopping,(.value.portHoppingMode // "")] | @tsv' "$METADATA_FILE" 2>/dev/null > "$hop_file"; then
        return 1
    fi

    local argo_tags='[]'
    if [ -s "$ARGO_METADATA_FILE" ]; then
        argo_tags=$(jq -c 'keys' "$ARGO_METADATA_FILE" 2>/dev/null) || {
            _error "Argo 元数据无效，拒绝批量删除以避免误删受保护节点。"
            return 1
        }
    fi
    if ! _atomic_modify_json "$CONFIG_FILE" '
        [.inbounds[]? | (.tag // "") as $tag | select(((($tag | startswith("argo-")) or ($argo | index($tag) != null))) | not) | $tag] as $removed
        | [.route.rules[]? | .inbound as $in | select(($in | type) == "string" and ($removed | index($in) != null)) | .outbound] as $removed_outbounds
        | .inbounds |= map((.tag // "") as $tag | select(($tag | startswith("argo-")) or ($argo | index($tag) != null)))
        | .route = (.route // {"rules":[]})
        | .route.rules = ((.route.rules // []) | map(.inbound as $in | select(((($in | type) == "string") and ($removed | index($in) != null)) | not)))
        | .outbounds = ((.outbounds // []) | map(select((.tag as $tag | $removed_outbounds | index($tag)) == null)))
    ' --argjson argo "$argo_tags"; then
        return 1
    fi
    _atomic_modify_json "$METADATA_FILE" '{}' || {
        return 1
    }

    sort -u "$names_file" | while IFS= read -r proxy_name; do
        [ -n "$proxy_name" ] || continue
        if _is_protected_yaml_name "$proxy_name"; then
            _warn "共享 YAML 条目仍归属 Argo/Xray/中转，已保留: $proxy_name"
        else
            _remove_node_from_yaml "$proxy_name" || exit 1
        fi
    done
    local yaml_pipeline_status=("${PIPESTATUS[@]}")
    if [ "${yaml_pipeline_status[0]:-1}" -ne 0 ] || [ "${yaml_pipeline_status[1]:-1}" -ne 0 ]; then
        return 1
    fi

    local check_result
    if ! check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
        _error "批量删除后的组合配置校验失败，已回滚："
        echo "$check_result"
        return 1
    fi

    local nft_cleanup_needed=0 nft_cleanup_failed=0
    while IFS=$'\t' read -r tag hop hop_mode; do
        [ -n "$tag" ] && [ -n "$hop" ] || continue
        if [ "$hop_mode" != "native" ]; then
            local target_port
            target_port=$(printf '%s' "$tag" | grep -oE '[0-9]+$')
            nft_cleanup_needed=1
            if [ ! -f "${backup_dir}/nft.available" ]; then
                nft_cleanup_failed=1
                break
            fi
            _nft_apply_redirect_rule delete "${hop%-*}" "${hop#*-}" "$target_port" "singboxlite-hy2-hop-${tag}" || {
                nft_cleanup_failed=1
                break
            }
        fi
    done < "$hop_file"
    if [ "$nft_cleanup_failed" -ne 0 ] || { [ "$nft_cleanup_needed" -eq 1 ] && ! _save_nftables_rules; }; then
        _error "批量删除 nftables 跳跃规则失败，正在回滚完整事务。"
        return 1
    fi

    delete_all_restart_attempted=1
    if ! _manage_service restart; then
        _error "服务重启失败，已恢复删除前状态。"
        return 1
    fi

    sort -u "$credential_paths_file" | while IFS= read -r path; do _safe_remove_main_credential "$path"; done
    delete_all_committed=1
    trap - EXIT INT TERM
    rm -rf -- "$backup_dir" || _warn "批量删除事务快照目录清理失败: $backup_dir"
    _success "主 sing-box 节点已全部删除；Argo、Xray、中转配置均已保留。"
)

_delete_node() {
    local primary_nodes
    primary_nodes=$(_list_main_primary_inbounds)
    if [ -z "$primary_nodes" ]; then _warning "当前没有可由主节点菜单删除的节点。"; return; fi
    _info "--- 节点删除 ---"

    local inbound_tags=() inbound_ports=() inbound_types=() display_names=() proxy_names=()
    local i=1 node tag type port proxy_name meta_name display_name
    while IFS= read -r node; do
        [ -n "$node" ] || continue
        IFS=$'\t' read -r tag type port <<< "$(printf '%s' "$node" | jq -r '[.tag,.type,(.listen_port|tostring)] | @tsv')"
        proxy_name=$(_find_proxy_name "$port" "$type" "$tag")
        meta_name=$(jq -r --arg tag "$tag" '.[$tag].name // empty' "$METADATA_FILE" 2>/dev/null)
        display_name=${proxy_name:-${meta_name:-$tag}}
        inbound_tags+=("$tag"); inbound_ports+=("$port"); inbound_types+=("$type")
        display_names+=("$display_name"); proxy_names+=("$proxy_name")
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${port}"
        ((i++))
    done <<< "$primary_nodes"

    echo ""
    echo -e "  ${RED}99)${NC} 删除所有主 sing-box 节点（保留 Argo/Xray/中转）"
    local num
    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    [[ "$num" =~ ^[0-9]+$ ]] || return
    [ "$num" -eq 0 ] && return
    if [ "$num" -eq 99 ]; then
        local confirm_all
        read -p "$(echo -e ${RED}"确定删除所有主 sing-box 节点? 输入 yes 确认: "${NC})" confirm_all
        [ "$confirm_all" = "yes" ] || { _info "删除已取消。"; return; }
        _with_state_lock _delete_all_main_nodes_locked
        return
    fi
    local count=${#inbound_tags[@]}
    [ "$num" -le "$count" ] || { _error "编号超出范围。"; return; }
    local index=$((num - 1)) confirm
    read -p "$(echo -e ${YELLOW}"确定要删除节点 ${display_names[$index]} 吗? (y/N): "${NC})" confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { _info "删除已取消。"; return; }
    _with_state_lock _delete_one_main_node_locked \
        "${inbound_tags[$index]}" "${inbound_types[$index]}" "${inbound_ports[$index]}" \
        "${display_names[$index]}" "${proxy_names[$index]}"
}

_check_config() {
    _info "正在按服务真实启动方式检查 config.json + relay.json..."
    _ensure_relay_config || return 1
    local result
    if result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
        _success "config.json + relay.json 组合配置校验通过。"
        return 0
    else
        _error "组合配置检查失败:"
        echo "$result"
        return 1
    fi
}

_apply_dns_config() {
    _with_state_lock _apply_dns_config_locked "$@"
}

_apply_dns_config_locked() {
    local dns_address="$1"
    local dns_strategy="$2"
    local tmp_file
    tmp_file=$(mktemp "${CONFIG_FILE}.dns.tmp.XXXXXX") || return 1
    local backup_file="${CONFIG_FILE}.bak_dns_$(date +%Y%m%d_%H%M%S)"
    local check_result

    _ensure_relay_config || { rm -f "$tmp_file"; return 1; }

    local new_dns
    new_dns=$(_build_dns_config_json "$dns_address" "$dns_strategy") || {
        _error "DNS 地址格式不受支持。"
        rm -f "$tmp_file"
        return 1
    }
    if ! jq --argjson dns "$new_dns" --arg strategy "$dns_strategy" '
        .dns = $dns
        | .route = (.route // {"rules":[]})
        | .route.default_domain_resolver = {"server":"dns-local","strategy":$strategy}
    ' "$CONFIG_FILE" > "$tmp_file"; then
        _error "生成 DNS 配置失败。"
        rm -f "$tmp_file"
        return 1
    fi

    if ! check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$tmp_file" "$RELAY_CONFIG_FILE" 2>&1); then
        _error "新的 DNS 配置未通过 config.json + relay.json 组合校验，原配置未修改："
        echo "$check_result"
        rm -f "$tmp_file"
        return 1
    fi

    chmod 600 "$tmp_file" 2>/dev/null || true
    if ! cp -p "$CONFIG_FILE" "$backup_file" || ! mv -f "$tmp_file" "$CONFIG_FILE"; then
        _error "保存 DNS 配置失败。"
        rm -f "$tmp_file"
        return 1
    fi
    chmod 600 "$CONFIG_FILE" "$backup_file" 2>/dev/null || true

    if ! _manage_service restart; then
        _error "DNS 修改后服务重启失败，正在回滚。"
        cp -p "$backup_file" "$CONFIG_FILE"
        _manage_service restart >/dev/null 2>&1 || true
        return 1
    fi
    _success "DNS 配置已保存并通过组合校验，备份文件：${backup_file}"
}

_dns_config_menu() {
    local current_address current_strategy choice dns_address dns_strategy

    while true; do
        current_address=$(jq -r '
            (.dns.servers[]? | select(.tag == "dns-local")) as $s
            | if $s.type == "local" then "local"
              elif $s.type == "https" then "https://" + $s.server + (if ($s.server_port // 443) == 443 then "" else ":" + ($s.server_port|tostring) end) + ($s.path // "/dns-query")
              elif $s.type == "tls" then "tls://" + $s.server + (if ($s.server_port // 853) == 853 then "" else ":" + ($s.server_port|tostring) end)
              elif ($s.type == "tcp" or $s.type == "udp") then $s.type + "://" + $s.server + (if ($s.server_port // 53) == 53 then "" else ":" + ($s.server_port|tostring) end)
              else "未设置" end
        ' "$CONFIG_FILE" 2>/dev/null)
        current_strategy=$(jq -r '.dns.strategy // "prefer_ipv4"' "$CONFIG_FILE" 2>/dev/null)
        [ -z "$current_address" ] || [ "$current_address" = "null" ] && current_address="未设置"
        [ -z "$current_strategy" ] || [ "$current_strategy" = "null" ] && current_strategy="prefer_ipv4"

        clear
        echo -e "${CYAN}"
        echo "  ╔═══════════════════════════════════════╗"
        echo "  ║          sing-box DNS 设置            ║"
        echo "  ╚═══════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "  当前 DNS:  ${GREEN}${current_address}${NC}"
        echo -e "  当前策略:  ${GREEN}${current_strategy}${NC}"
        echo ""
        echo -e "    ${GREEN}[1]${NC} 系统 DNS（local）"
        echo -e "    ${GREEN}[2]${NC} 阿里 DNS（DoH）"
        echo -e "    ${GREEN}[3]${NC} 腾讯 DNSPod（DoH）"
        echo -e "    ${GREEN}[4]${NC} Cloudflare（DoH）"
        echo -e "    ${GREEN}[5]${NC} Google（DoH）"
        echo -e "    ${GREEN}[6]${NC} 自定义 DNS 地址"
        echo -e "    ${GREEN}[7]${NC} 修改域名解析策略"
        echo -e "    ${GREEN}[8]${NC} 查看完整 DNS 配置"
        echo ""
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        read -p "  请输入选项 [0-8]: " choice

        dns_address=""
        dns_strategy="$current_strategy"
        case "$choice" in
            1) dns_address="local" ;;
            2) dns_address="https://dns.alidns.com/dns-query" ;;
            3) dns_address="https://doh.pub/dns-query" ;;
            4) dns_address="https://1.1.1.1/dns-query" ;;
            5) dns_address="https://dns.google/dns-query" ;;
            6)
                echo ""
                echo "  支持 local、IP、udp://、tcp://、tls://、https:// 等 sing-box DNS 地址。"
                read -r -p "  请输入 DNS 地址（留空取消）: " dns_address
                [ -z "$dns_address" ] && continue
                if [[ "$dns_address" =~ [[:space:]] ]]; then
                    _error "DNS 地址不能包含空白字符。"
                    read -n 1 -s -r -p "按任意键继续..."
                    continue
                fi
                ;;
            7)
                echo ""
                echo "    1) prefer_ipv4（推荐，IPv4 优先）"
                echo "    2) prefer_ipv6（IPv6 优先）"
                echo "    3) ipv4_only（仅 IPv4）"
                echo "    4) ipv6_only（仅 IPv6）"
                read -p "  请选择解析策略 [1-4]: " strategy_choice
                case "$strategy_choice" in
                    1) dns_strategy="prefer_ipv4" ;;
                    2) dns_strategy="prefer_ipv6" ;;
                    3) dns_strategy="ipv4_only" ;;
                    4) dns_strategy="ipv6_only" ;;
                    *) _error "无效输入。"; read -n 1 -s -r -p "按任意键继续..."; continue ;;
                esac
                dns_address="$current_address"
                if [ "$dns_address" = "未设置" ]; then
                    dns_address="local"
                fi
                ;;
            8)
                echo ""
                jq '.dns' "$CONFIG_FILE" 2>/dev/null || _error "无法读取 DNS 配置。"
                echo ""
                read -n 1 -s -r -p "按任意键继续..."
                continue
                ;;
            0) return ;;
            *) _error "无效输入，请重试。"; read -n 1 -s -r -p "按任意键继续..."; continue ;;
        esac

        echo ""
        _info "准备设置 DNS 为 ${dns_address}，解析策略为 ${dns_strategy}。"
        read -r -p "  确认保存并重启 sing-box？[Y/n]: " confirm
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            continue
        fi
        _apply_dns_config "$dns_address" "$dns_strategy"
        echo ""
        read -n 1 -s -r -p "按任意键继续..."
    done
}

_detect_main_node_variant() {
    local tag="$1"
    jq -r --arg tag "$tag" '
        .inbounds[]? | select(.tag == $tag) |
        if .type == "vless" and (.tls.reality.enabled // false) then "vless-reality"
        elif .type == "vless" and .transport.type == "ws" then "vless-ws-tls"
        elif .type == "vless" and .transport.type == "grpc" then "vless-grpc-tls"
        elif .type == "vless" then "vless-tcp"
        elif .type == "trojan" and .transport.type == "ws" then "trojan-ws-tls"
        elif .type == "anytls" and (.tls.reality.enabled // false) then "any-reality"
        elif .type == "anytls" then "anytls"
        elif .type == "hysteria2" then "hysteria2"
        elif .type == "tuic" then "tuic"
        elif .type == "shadowtls" then "shadowsocks-shadowtls"
        elif .type == "shadowsocks" then "shadowsocks"
        elif .type == "socks" then "socks"
        else "unsupported"
        end
    ' "$CONFIG_FILE" 2>/dev/null | head -n 1
}

_normalize_client_server() {
    local value="$1"
    value="${value#[}"
    value="${value%]}"
    printf '%s' "$value"
}

_legacy_link_server() {
    local link="$1" authority
    [ -n "$link" ] || return 1
    authority="${link#*://}"
    authority="${authority%%[/?#]*}"
    authority="${authority##*@}"
    if [[ "$authority" == \[*\]:* ]]; then
        authority="${authority#\[}"
        authority="${authority%%\]*}"
    else
        authority="${authority%:*}"
    fi
    [ -n "$authority" ] || return 1
    printf '%s' "$authority"
}

_validate_tls_key_pair() {
    local cert_path="$1" key_path="$2" cert_pub key_pub
    # ACME 客户端通常用符号链接指向续签后的实际证书；只要链接当前可解析为
    # 普通文件就应保留原路径，让后续续签无需再次修改节点。
    [ -f "$cert_path" ] || { _error "证书文件不存在或链接失效: $cert_path"; return 1; }
    [ -f "$key_path" ] || { _error "私钥文件不存在或链接失效: $key_path"; return 1; }
    openssl x509 -in "$cert_path" -noout >/dev/null 2>&1 || { _error "证书格式无效。"; return 1; }
    openssl pkey -in "$key_path" -noout >/dev/null 2>&1 || { _error "私钥格式无效或需要交互密码。"; return 1; }
    cert_pub=$(openssl x509 -in "$cert_path" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null) || return 1
    key_pub=$(openssl pkey -in "$key_path" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null) || return 1
    [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ] || { _error "证书与私钥不匹配。"; return 1; }
}

# 以服务器配置和规范化元数据为唯一事实源，完整重建客户端 YAML 与分享链接。
_refresh_modified_node_artifacts() {
    local tag="$1" old_proxy_name="$2"
    local node variant port metadata name client_server share_link proxy_name
    node=$(jq -c --arg tag "$tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" 2>/dev/null | head -n 1) || return 1
    [ -n "$node" ] || { _error "无法重建节点产物：节点不存在。"; return 1; }
    variant=$(_detect_main_node_variant "$tag")
    [ "$variant" != "unsupported" ] || { _error "暂不支持修改该节点类型。"; return 1; }
    port=$(printf '%s' "$node" | jq -r '.listen_port') || return 1
    metadata=$(jq -c --arg tag "$tag" '.[$tag] // {}' "$METADATA_FILE" 2>/dev/null) || return 1
    name=$(printf '%s' "$metadata" | jq -r '.name // empty')
    proxy_name="$old_proxy_name"
    if [ -z "$proxy_name" ]; then
        proxy_name=$(_find_proxy_name "$port" "$(printf '%s' "$node" | jq -r '.type')" "$tag")
    fi
    [ -n "$name" ] || name="$proxy_name"
    [ -n "$name" ] || name="$tag"
    client_server=$(printf '%s' "$metadata" | jq -r '.clientServer // empty')
    if [ -z "$client_server" ] && [ -n "$proxy_name" ]; then
        client_server=$(_get_proxy_field "$proxy_name" '.server // ""')
    fi
    if [ -z "$client_server" ]; then
        share_link=$(printf '%s' "$metadata" | jq -r '.share_link // empty')
        client_server=$(_legacy_link_server "$share_link" 2>/dev/null || true)
    fi
    [ -n "$client_server" ] || client_server=$(_get_public_ip)
    client_server=$(_normalize_client_server "$client_server")
    [ -n "$client_server" ] || { _error "无法确定客户端连接地址。"; return 1; }

    _atomic_modify_json "$METADATA_FILE" '
        . + {($tag): ((.[$tag] // {}) + {
            name:$name, owner:"singbox-main", variant:$variant, clientServer:$server
        } | if has("yaml") then . else .yaml = ($variant != "any-reality") end)}
    ' --arg tag "$tag" --arg name "$name" --arg variant "$variant" --arg server "$client_server" || return 1

    local yaml_enabled
    yaml_enabled=$(jq -r --arg tag "$tag" '.[$tag].yaml // true' "$METADATA_FILE" 2>/dev/null)
    if [ "$yaml_enabled" = "true" ]; then
        [ -n "$proxy_name" ] || { _error "找不到节点对应的 Clash YAML 条目。"; return 1; }
        export OLD_NAME="$proxy_name" NEW_NAME="$name" NODE_SERVER="$client_server" NODE_PORT="$port"
        _atomic_modify_yaml "$CLASH_YAML_FILE" '
            (.proxies[] | select(.name == env(OLD_NAME))) |=
                (.name = env(NEW_NAME) | .server = env(NODE_SERVER) | .port = (env(NODE_PORT) | tonumber))
            | (.proxy-groups[].proxies[] | select(. == env(OLD_NAME))) = env(NEW_NAME)
        ' || return 1
        proxy_name="$name"
    fi

    local uuid password username method sni public_key short_id cert_path key_path skip_verify
    local path service_name obfs_password hop up down inner_tag shadow_password
    case "$variant" in
        vless-reality)
            uuid=$(printf '%s' "$node" | jq -r '.users[0].uuid')
            sni=$(printf '%s' "$node" | jq -r '.tls.reality.handshake.server // .tls.server_name // empty')
            public_key=$(jq -r --arg tag "$tag" '.[$tag].publicKey // empty' "$METADATA_FILE")
            short_id=$(printf '%s' "$node" | jq -r '.tls.reality.short_id[0] // empty')
            [ -n "$public_key" ] || { _error "Reality 公钥元数据缺失，无法安全重建客户端配置。"; return 1; }
            if [ "$yaml_enabled" = "true" ]; then
                export NODE_UUID="$uuid" NODE_SNI="$sni" NODE_PUBLIC_KEY="$public_key" NODE_SHORT_ID="$short_id"
                _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.uuid = env(NODE_UUID) | .servername = env(NODE_SNI) | .["reality-opts"]["public-key"] = env(NODE_PUBLIC_KEY) | .["reality-opts"]["short-id"] = env(NODE_SHORT_ID))' || return 1
            fi
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$uuid" "$sni" "$public_key" "$short_id" "xtls-rprx-vision" || return 1
            ;;
        vless-ws-tls|vless-grpc-tls)
            uuid=$(printf '%s' "$node" | jq -r '.users[0].uuid')
            sni=$(printf '%s' "$node" | jq -r '.tls.server_name // empty')
            cert_path=$(printf '%s' "$node" | jq -r '.tls.certificate_path // empty')
            key_path=$(printf '%s' "$node" | jq -r '.tls.key_path // empty')
            skip_verify=$(_get_proxy_field "$name" '.["skip-cert-verify"] // false')
            export NODE_UUID="$uuid" NODE_SNI="$sni" NODE_SKIP_VERIFY="$skip_verify"
            if [ "$variant" = "vless-ws-tls" ]; then
                path=$(printf '%s' "$node" | jq -r '.transport.path // "/"')
                export NODE_PATH="$path"
                _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.uuid = env(NODE_UUID) | .sni = env(NODE_SNI) | ."skip-cert-verify" = (env(NODE_SKIP_VERIFY) == "true") | .["ws-opts"].path = env(NODE_PATH) | .["ws-opts"].headers.Host = env(NODE_SNI))' || return 1
                _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$uuid" "$sni" "$path" "$skip_verify" "$cert_path" || return 1
            else
                service_name=$(printf '%s' "$node" | jq -r '.transport.service_name // empty')
                export NODE_SERVICE="$service_name"
                _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.uuid = env(NODE_UUID) | .servername = env(NODE_SNI) | ."skip-cert-verify" = (env(NODE_SKIP_VERIFY) == "true") | .["grpc-opts"]["grpc-service-name"] = env(NODE_SERVICE))' || return 1
                _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$uuid" "$sni" "$service_name" "$skip_verify" "$cert_path" || return 1
            fi
            ;;
        vless-tcp)
            uuid=$(printf '%s' "$node" | jq -r '.users[0].uuid')
            export NODE_UUID="$uuid"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))).uuid = env(NODE_UUID)' || return 1
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$uuid" || return 1
            ;;
        trojan-ws-tls)
            password=$(printf '%s' "$node" | jq -r '.users[0].password')
            sni=$(printf '%s' "$node" | jq -r '.tls.server_name // empty')
            path=$(printf '%s' "$node" | jq -r '.transport.path // "/"')
            cert_path=$(printf '%s' "$node" | jq -r '.tls.certificate_path // empty')
            key_path=$(printf '%s' "$node" | jq -r '.tls.key_path // empty')
            skip_verify=$(_get_proxy_field "$name" '.["skip-cert-verify"] // false')
            export NODE_PASSWORD="$password" NODE_SNI="$sni" NODE_PATH="$path" NODE_SKIP_VERIFY="$skip_verify"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.password = env(NODE_PASSWORD) | .sni = env(NODE_SNI) | ."skip-cert-verify" = (env(NODE_SKIP_VERIFY) == "true") | .["ws-opts"].path = env(NODE_PATH) | .["ws-opts"].headers.Host = env(NODE_SNI))' || return 1
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$password" "$sni" "$path" "$skip_verify" "$cert_path" || return 1
            ;;
        anytls)
            password=$(printf '%s' "$node" | jq -r '.users[0].password')
            sni=$(printf '%s' "$node" | jq -r '.tls.server_name // empty')
            [ -n "$sni" ] || sni=$(_get_proxy_field "$name" '.sni // ""')
            cert_path=$(printf '%s' "$node" | jq -r '.tls.certificate_path // empty')
            key_path=$(printf '%s' "$node" | jq -r '.tls.key_path // empty')
            skip_verify=$(_get_proxy_field "$name" '.["skip-cert-verify"] // false')
            export NODE_PASSWORD="$password" NODE_SNI="$sni" NODE_SKIP_VERIFY="$skip_verify"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.password = env(NODE_PASSWORD) | .sni = env(NODE_SNI) | ."skip-cert-verify" = (env(NODE_SKIP_VERIFY) == "true"))' || return 1
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$password" "$sni" "$skip_verify" "$cert_path" || return 1
            ;;
        any-reality)
            password=$(printf '%s' "$node" | jq -r '.users[0].password')
            sni=$(printf '%s' "$node" | jq -r '.tls.reality.handshake.server // .tls.server_name // empty')
            public_key=$(jq -r --arg tag "$tag" '.[$tag].publicKey // empty' "$METADATA_FILE")
            short_id=$(printf '%s' "$node" | jq -r '.tls.reality.short_id[0] // empty')
            [ -n "$public_key" ] || { _error "Any-Reality 公钥元数据缺失，无法安全重建分享链接。"; return 1; }
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$password" "$sni" "$public_key" "$short_id" || return 1
            ;;
        hysteria2)
            password=$(printf '%s' "$node" | jq -r '.users[0].password')
            sni=$(printf '%s' "$node" | jq -r '.tls.server_name // empty')
            [ -n "$sni" ] || sni=$(_get_proxy_field "$name" '.sni // ""')
            obfs_password=$(printf '%s' "$node" | jq -r '.obfs.password // empty')
            hop=$(jq -r --arg tag "$tag" '.[$tag].portHopping // empty' "$METADATA_FILE")
            up=$(jq -r --arg tag "$tag" '.[$tag].up // "100"' "$METADATA_FILE")
            down=$(jq -r --arg tag "$tag" '.[$tag].down // "100"' "$METADATA_FILE")
            cert_path=$(printf '%s' "$node" | jq -r '.tls.certificate_path // empty')
            key_path=$(printf '%s' "$node" | jq -r '.tls.key_path // empty')
            export NODE_PASSWORD="$password" NODE_SNI="$sni" NODE_OBFS="$obfs_password" NODE_HOP="$hop" NODE_UP="$up" NODE_DOWN="$down"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.password = env(NODE_PASSWORD) | .sni = env(NODE_SNI) | .up = (env(NODE_UP) | tonumber) | .down = (env(NODE_DOWN) | tonumber))' || return 1
            if [ -n "$obfs_password" ]; then
                _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.obfs = "salamander" | ."obfs-password" = env(NODE_OBFS))' || return 1
            else
                _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == env(NEW_NAME)) | .obfs, .proxies[] | select(.name == env(NEW_NAME)) | ."obfs-password")' || return 1
            fi
            if [ -n "$hop" ]; then
                _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))).ports = env(NODE_HOP)' || return 1
            else
                _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == env(NEW_NAME)) | .ports)' || return 1
            fi
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$password" "$sni" "$obfs_password" "$hop" || return 1
            ;;
        tuic)
            uuid=$(printf '%s' "$node" | jq -r '.users[0].uuid')
            password=$(printf '%s' "$node" | jq -r '.users[0].password')
            sni=$(printf '%s' "$node" | jq -r '.tls.server_name // empty')
            [ -n "$sni" ] || sni=$(_get_proxy_field "$name" '.sni // ""')
            cert_path=$(printf '%s' "$node" | jq -r '.tls.certificate_path // empty')
            key_path=$(printf '%s' "$node" | jq -r '.tls.key_path // empty')
            export NODE_UUID="$uuid" NODE_PASSWORD="$password" NODE_SNI="$sni"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.uuid = env(NODE_UUID) | .password = env(NODE_PASSWORD) | .sni = env(NODE_SNI))' || return 1
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$uuid" "$password" "$sni" || return 1
            ;;
        shadowsocks)
            method=$(printf '%s' "$node" | jq -r '.method')
            password=$(printf '%s' "$node" | jq -r '.password')
            export NODE_METHOD="$method" NODE_PASSWORD="$password"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.cipher = env(NODE_METHOD) | .password = env(NODE_PASSWORD))' || return 1
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$method" "$password" || return 1
            ;;
        shadowsocks-shadowtls)
            inner_tag=$(printf '%s' "$node" | jq -r '.detour // empty')
            shadow_password=$(printf '%s' "$node" | jq -r '.users[0].password')
            sni=$(printf '%s' "$node" | jq -r '.handshake.server // empty')
            method=$(jq -r --arg tag "$inner_tag" '.inbounds[]? | select(.tag == $tag) | .method // empty' "$CONFIG_FILE")
            password=$(jq -r --arg tag "$inner_tag" '.inbounds[]? | select(.tag == $tag) | .password // empty' "$CONFIG_FILE")
            export NODE_METHOD="$method" NODE_PASSWORD="$password" NODE_SHADOW_PASSWORD="$shadow_password" NODE_SNI="$sni"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.cipher = env(NODE_METHOD) | .password = env(NODE_PASSWORD) | .["plugin-opts"].host = env(NODE_SNI) | .["plugin-opts"].password = env(NODE_SHADOW_PASSWORD))' || return 1
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$method" "$password" "$shadow_password" "$sni" || return 1
            ;;
        socks)
            username=$(printf '%s' "$node" | jq -r '.users[0].username')
            password=$(printf '%s' "$node" | jq -r '.users[0].password')
            export NODE_USERNAME="$username" NODE_PASSWORD="$password"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME))) |= (.username = env(NODE_USERNAME) | .password = env(NODE_PASSWORD))' || return 1
            _show_node_link "$variant" "$name" "$client_server" "$port" "$tag" "$username" "$password" || return 1
            ;;
    esac

    if [ -n "${cert_path:-}" ] && [ -n "${key_path:-}" ]; then
        local cert_mode="custom" cert_sha
        [[ "$cert_path" == "$SINGBOX_DIR/"* && "$key_path" == "$SINGBOX_DIR/"* ]] && cert_mode="self_signed"
        cert_sha=$(_cert_sha256_hex "$cert_path" 2>/dev/null || true)
        _atomic_modify_json "$METADATA_FILE" '.[$tag] += {serverName:$sni,certMode:$mode,certificatePath:$cert,keyPath:$key,certSha256:$sha,skipVerify:($skip == "true")}' \
            --arg tag "$tag" --arg sni "${sni:-}" --arg mode "$cert_mode" --arg cert "$cert_path" --arg key "$key_path" --arg sha "$cert_sha" --arg skip "${skip_verify:-false}" || return 1
    elif [ -n "${sni:-}" ]; then
        _atomic_modify_json "$METADATA_FILE" '.[$tag].serverName = $sni' --arg tag "$tag" --arg sni "$sni" || return 1
    fi
}

_modify_port() (
    local preset_tag="${1:-}"
    local primary_nodes
    primary_nodes=$(_list_main_primary_inbounds)
    if [ -z "$primary_nodes" ]; then
        _warning "当前没有可由主节点菜单修改的节点（Argo 请在 Argo 菜单管理）。"
        return
    fi
    
    _info "--- 修改节点端口 ---"
    
    # 列出所有节点
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local display_names=()
    
    local i=1 preset_num=""
    # [资源优化] 合并3次jq为1次 + 使用公共函数 _find_proxy_name 替代内联查找
    local node
    while IFS= read -r node; do
        [ -n "$node" ] || continue
        local tag type port
        IFS=$'\t' read -r tag type port <<< "$(printf '%s' "$node" | jq -r '[.tag,.type,(.listen_port|tostring)] | @tsv')"

        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")
        
        # [M1] 使用公共函数替代内联重复的代理名查找逻辑
        local proxy_name_to_find=$(_find_proxy_name "$port" "$type" "$tag")
        
        local meta_name=$(jq -r --arg t "$tag" '.[$t].name // empty' "$METADATA_FILE" 2>/dev/null)
        local display_name=${proxy_name_to_find:-${meta_name:-$tag}}
        display_names+=("$display_name")
        [ -n "$preset_tag" ] && [ "$tag" = "$preset_tag" ] && preset_num="$i"
        
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${GREEN}${port}${NC}"
        ((i++))
    done <<< "$primary_nodes"
    
    local num=""
    if [ -n "$preset_tag" ]; then
        [ -n "$preset_num" ] || { _error "指定的节点不存在或不可修改。"; return 1; }
        num="$preset_num"
    else
        read -p "请输入要修改端口的节点编号 (输入 0 返回): " num
    fi
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    
    local count=${#inbound_tags[@]}
    if [ "$num" -gt "$count" ]; then
        _error "编号超出范围。"
        return
    fi
    
    local index=$((num - 1))
    local tag_to_modify=${inbound_tags[$index]}
    local type_to_modify=${inbound_types[$index]}
    local old_port=${inbound_ports[$index]}
    local display_name_to_modify=${display_names[$index]}
    local selected_detour selected_metadata
    if ! selected_detour=$(jq -r --arg tag "$tag_to_modify" '.inbounds[]? | select(.tag == $tag) | .detour // empty' "$CONFIG_FILE" 2>/dev/null); then
        _error "无法读取所选节点的 detour 信息。"
        return 1
    fi
    selected_metadata=$(jq -cS --arg tag "$tag_to_modify" '.[$tag] // {}' "$METADATA_FILE" 2>/dev/null) || {
        _error "无法读取所选节点元数据。"
        return 1
    }
    local shadowtls_inner_tag=""
    if [ "$type_to_modify" = "shadowtls" ]; then
        shadowtls_inner_tag="$selected_detour"
        [ -n "$shadowtls_inner_tag" ] || { _error "ShadowTLS 外层缺少 detour，拒绝修改以避免产生孤儿节点。"; return 1; }
    fi
    local hop_info=""
    local hop_mode=""
    local hop_range_input=""
    local final_hop_info=""
    local final_hop_start=""
    local final_hop_end=""
    
    _info "当前节点: ${display_name_to_modify} (${type_to_modify})"
    _info "当前端口: ${old_port}"
    
    if [ "$type_to_modify" = "hysteria2" ] && [ -f "$METADATA_FILE" ] && jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
        hop_info=$(jq -r ".\"$tag_to_modify\".portHopping // \"\"" "$METADATA_FILE" 2>/dev/null)
        hop_mode=$(jq -r ".\"$tag_to_modify\".portHoppingMode // \"\"" "$METADATA_FILE" 2>/dev/null)
        if [ -n "$hop_info" ] && [ -z "$hop_mode" ]; then
            if jq -e --arg prefix "${tag_to_modify}-hop-" '.inbounds[] | select(.tag | startswith($prefix))' "$CONFIG_FILE" >/dev/null 2>&1; then
                hop_mode="native"
            else
                hop_mode="nftables"
            fi
        fi
    fi
    
    read -p "请输入新的端口号: " new_port
    
    # 验证端口
    if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        _error "无效的端口号！"
        return
    fi
    
    if [ "$new_port" -eq "$old_port" ]; then
        _warning "新端口与当前端口相同，无需修改。"
        return
    fi
    
    local listen_proto="tcp"
    [[ "$type_to_modify" == "hysteria2" || "$type_to_modify" == "tuic" ]] && listen_proto="udp"
    [ "$type_to_modify" = "shadowsocks" ] && listen_proto="tcp+udp"
    if _check_port_conflict "$new_port" "$listen_proto" "false" "$tag_to_modify"; then return; fi

    if [[ "$type_to_modify" == "hysteria2" || "$type_to_modify" == "tuic" ]]; then
        local new_port_hop_conflict
        new_port_hop_conflict=$(_find_udp_hop_conflict_in_range "$new_port" "$new_port" "$tag_to_modify")
        if [ -n "$new_port_hop_conflict" ]; then
            local c_tag c_name c_range c_mode
            IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$new_port_hop_conflict"
            _error "新端口 ${new_port} 落在已有 HY2 端口跳跃范围 ${c_range} 内。"
            _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请换端口。"
            return
        fi
    fi
    
    if [ -n "$hop_info" ]; then
        _info "检测到当前 HY2 节点启用了端口跳跃 (${hop_mode:-unknown}): ${hop_info}"
        read -p "请输入新的端口跳跃范围（直接回车保留原范围，输入 none 关闭）: " hop_range_input
        if [ -z "$hop_range_input" ]; then
            final_hop_info="$hop_info"
        elif [ "$hop_range_input" = "none" ]; then
            final_hop_info=""
        else
            if [[ ! "$hop_range_input" =~ ^[0-9]+-[0-9]+$ ]]; then
                _error "端口跳跃范围格式无效，应为 start-end。"
                return
            fi
            final_hop_start="${hop_range_input%-*}"
            final_hop_end="${hop_range_input#*-}"
            if [ "$final_hop_start" -lt 1 ] || [ "$final_hop_end" -gt 65535 ] || [ "$final_hop_start" -gt "$final_hop_end" ]; then
                _error "端口跳跃范围无效。"
                return
            fi
            local pf_conflict
            pf_conflict=$(_find_pf_udp_conflict_in_range "$final_hop_start" "$final_hop_end")
            if [ -n "$pf_conflict" ]; then
                local c_port c_name c_net c_target
                IFS=$'\t' read -r c_port c_name c_net c_target <<< "$pf_conflict"
                _error "端口跳跃范围 ${hop_range_input} 覆盖了已有 ${c_net} 端口转发入口 ${c_port}（${c_name} -> ${c_target}）。"
                _error "请调整跳跃范围或先删除/修改该端口转发规则。"
                return
            fi
            local hop_conflict
            hop_conflict=$(_find_udp_hop_conflict_in_range "$final_hop_start" "$final_hop_end" "$tag_to_modify")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                _error "端口跳跃范围 ${hop_range_input} 与已有跳跃范围 ${c_range} 重叠。"
                _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请调整跳跃范围。"
                return
            fi
            final_hop_info="$hop_range_input"
        fi
    fi
    
    if [ -n "$final_hop_info" ]; then
        final_hop_start="${final_hop_info%-*}"
        final_hop_end="${final_hop_info#*-}"
        if [ "$hop_mode" = "native" ] && [ $((final_hop_end - final_hop_start + 1)) -gt 1000 ]; then
            _error "原生 HY2 跳跃最多允许 1000 个端口；当前范围包含 $((final_hop_end - final_hop_start + 1)) 个。"
            return 1
        fi
    fi

    local modify_lock_owned="false"
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" != "1" ]; then
        if ! command -v flock &>/dev/null; then
            _error "缺少 flock，拒绝无锁修改节点端口。"
            return 1
        fi
        exec 8>"${SINGBOX_DIR}/.singboxlite.lock" || return 1
        if ! _flock_wait 8 30; then exec 8>&-; _error "等待状态锁超时。"; return 1; fi
        export SINGBOXLITE_LOCK_HELD=1
        modify_lock_owned="true"
    fi

    local modify_backup_dir modify_restart_attempted=0
    modify_backup_dir=$(mktemp -d /tmp/.singbox-modify-port.XXXXXX) || {
        if [ "$modify_lock_owned" = "true" ]; then export SINGBOXLITE_LOCK_HELD=0; flock -u 8; exec 8>&-; fi
        return 1
    }
    if ! _main_create_tx_snapshot "$modify_backup_dir"; then
        _error "无法完整创建改端口事务快照，操作尚未开始。"
        rm -rf -- "$modify_backup_dir"
        if [ "$modify_lock_owned" = "true" ]; then export SINGBOXLITE_LOCK_HELD=0; flock -u 8; exec 8>&-; fi
        return 1
    fi
    local modify_committed=0
    trap 'modify_rc=$?; trap - EXIT INT TERM; if [ "$modify_committed" -ne 1 ]; then if ! _rollback_port_modify_state "$modify_backup_dir" "$modify_restart_attempted"; then modify_rc=1; fi; fi; if [ "$modify_lock_owned" = "true" ]; then export SINGBOXLITE_LOCK_HELD=0; flock -u 8; exec 8>&-; fi; exit "$modify_rc"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    _validate_protected_yaml_metadata || return 1

    # 用户交互留在锁外；持锁后必须重新读取并严格比对所选对象，拒绝基于旧状态提交。
    local locked_count locked_node locked_type locked_port locked_detour locked_metadata locked_fields
    local locked_hop_info="" locked_hop_mode=""
    locked_count=$(jq -r --arg tag "$tag_to_modify" '[.inbounds[]? | select(.tag == $tag)] | length' "$CONFIG_FILE" 2>/dev/null) || return 1
    [ "$locked_count" = "1" ] || { _error "目标节点在选择后已删除或 tag 不唯一，请重新操作。"; return 1; }
    locked_node=$(jq -c --arg tag "$tag_to_modify" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" 2>/dev/null) || return 1
    locked_fields=$(printf '%s' "$locked_node" | jq -r '[.type // "", (.listen_port // "" | tostring), (.detour // "")] | @tsv') || return 1
    IFS=$'\t' read -r locked_type locked_port locked_detour <<< "$locked_fields"
    if [ "$locked_type" != "$type_to_modify" ] || [ "$locked_port" != "$old_port" ] || [ "$locked_detour" != "$selected_detour" ]; then
        _error "目标节点的类型、旧端口或 detour 在选择后已变化，请重新操作。"
        return 1
    fi
    _is_argo_inbound_tag "$tag_to_modify" && { _error "目标已变为 Argo 受保护节点，拒绝修改。"; return 1; }
    [[ "$tag_to_modify" == *"-hop-"* ]] && { _error "端口跳跃辅助节点不能单独修改。"; return 1; }
    _is_shadowtls_inner_tag "$tag_to_modify" && { _error "ShadowTLS 内层节点不能单独修改。"; return 1; }
    if [ "$type_to_modify" = "shadowtls" ]; then
        [ "$(jq -r --arg tag "$shadowtls_inner_tag" '[.inbounds[]? | select(.tag == $tag)] | length' "$CONFIG_FILE" 2>/dev/null)" = "1" ] || {
            _error "ShadowTLS 内层节点在选择后发生变化，拒绝修改。"
            return 1
        }
    fi
    locked_metadata=$(jq -cS --arg tag "$tag_to_modify" '.[$tag] // {}' "$METADATA_FILE" 2>/dev/null) || return 1
    if [ "$locked_metadata" != "$selected_metadata" ]; then
        _error "目标节点元数据在选择后已变化，请重新操作。"
        return 1
    fi
    if [ "$type_to_modify" = "hysteria2" ]; then
        locked_hop_info=$(printf '%s' "$locked_metadata" | jq -r '.portHopping // empty') || return 1
        locked_hop_mode=$(printf '%s' "$locked_metadata" | jq -r '.portHoppingMode // empty') || return 1
        if [ -n "$locked_hop_info" ] && [ -z "$locked_hop_mode" ]; then
            if jq -e --arg prefix "${tag_to_modify}-hop-" '.inbounds[]? | select((.tag // "") | startswith($prefix))' "$CONFIG_FILE" >/dev/null 2>&1; then
                locked_hop_mode="native"
            else
                locked_hop_mode="nftables"
            fi
        fi
        if [ "$locked_hop_info" != "$hop_info" ] || [ "$locked_hop_mode" != "$hop_mode" ]; then
            _error "目标节点的端口跳跃状态在选择后已变化，请重新操作。"
            return 1
        fi
    fi

    # 锁内重新执行所有端口和跳跃范围冲突检查，消除交互期间的 TOCTOU。
    if _check_port_conflict "$new_port" "$listen_proto" "false" "$tag_to_modify"; then
        _error "新端口在等待锁期间出现冲突，已取消修改。"
        return 1
    fi
    if [[ "$type_to_modify" == "hysteria2" || "$type_to_modify" == "tuic" ]]; then
        local locked_new_port_hop_conflict
        locked_new_port_hop_conflict=$(_find_udp_hop_conflict_in_range "$new_port" "$new_port" "$tag_to_modify")
        [ -z "$locked_new_port_hop_conflict" ] || { _error "新端口在等待锁期间落入其他 HY2 跳跃范围，已取消修改。"; return 1; }
    fi
    if [ -n "$final_hop_info" ]; then
        local locked_pf_conflict locked_hop_conflict
        locked_pf_conflict=$(_find_pf_udp_conflict_in_range "$final_hop_start" "$final_hop_end")
        [ -z "$locked_pf_conflict" ] || { _error "新跳跃范围在等待锁期间出现端口转发冲突，已取消修改。"; return 1; }
        locked_hop_conflict=$(_find_udp_hop_conflict_in_range "$final_hop_start" "$final_hop_end" "$tag_to_modify")
        [ -z "$locked_hop_conflict" ] || { _error "新跳跃范围在等待锁期间与其他节点冲突，已取消修改。"; return 1; }
    fi

    local proposed_new_tag proposed_new_inner proposed_old_proxy_name proposed_new_proxy_name
    proposed_new_tag=$(echo "$tag_to_modify" | sed "s/${old_port}/${new_port}/g")
    if [ "$proposed_new_tag" != "$tag_to_modify" ] && jq -e --arg tag "$proposed_new_tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "新 tag 已被其他节点占用: $proposed_new_tag"
        return 1
    fi
    if [ "$proposed_new_tag" != "$tag_to_modify" ] && jq -e --arg tag "$proposed_new_tag" 'has($tag)' "$METADATA_FILE" >/dev/null 2>&1; then
        _error "新 tag 已被其他元数据占用: $proposed_new_tag"
        return 1
    fi
    if [ "$type_to_modify" = "shadowtls" ]; then
        if [[ "$shadowtls_inner_tag" == "$tag_to_modify"* ]]; then
            proposed_new_inner="${proposed_new_tag}${shadowtls_inner_tag#${tag_to_modify}}"
        else
            proposed_new_inner=$(echo "$shadowtls_inner_tag" | sed "s/${old_port}/${new_port}/g")
        fi
        if [ "$proposed_new_inner" != "$shadowtls_inner_tag" ] && jq -e --arg tag "$proposed_new_inner" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" >/dev/null 2>&1; then
            _error "新的 ShadowTLS 内层 tag 已被占用: $proposed_new_inner"
            return 1
        fi
    fi

    if [ "$proposed_new_tag" != "$tag_to_modify" ] \
        && [[ "$type_to_modify" == "hysteria2" || "$type_to_modify" == "tuic" || "$type_to_modify" == "anytls" ]]; then
        local proposed_old_cert="${SINGBOX_DIR}/${tag_to_modify}.pem"
        local proposed_old_key="${SINGBOX_DIR}/${tag_to_modify}.key"
        local proposed_new_cert="${SINGBOX_DIR}/${proposed_new_tag}.pem"
        local proposed_new_key="${SINGBOX_DIR}/${proposed_new_tag}.key"
        local old_cert_present=0 old_key_present=0
        { [ -e "$proposed_old_cert" ] || [ -L "$proposed_old_cert" ]; } && old_cert_present=1
        { [ -e "$proposed_old_key" ] || [ -L "$proposed_old_key" ]; } && old_key_present=1
        if [ "$old_cert_present" -ne "$old_key_present" ]; then
            _error "旧证书与私钥不成对，拒绝修改端口。"
            return 1
        fi
        if [ "$old_cert_present" -eq 1 ] && { [ ! -f "$proposed_old_cert" ] || [ -L "$proposed_old_cert" ] || [ ! -f "$proposed_old_key" ] || [ -L "$proposed_old_key" ]; }; then
            _error "旧证书或私钥不是可安全迁移的普通文件，拒绝修改端口。"
            return 1
        fi
        if [ -e "$proposed_new_cert" ] || [ -L "$proposed_new_cert" ] || [ -e "$proposed_new_key" ] || [ -L "$proposed_new_key" ]; then
            _error "新 tag 对应的证书或私钥路径已存在，拒绝覆盖。"
            return 1
        fi
    fi

    proposed_old_proxy_name=$(_find_proxy_name "$old_port" "$type_to_modify" "$tag_to_modify")
    if [ -n "$proposed_old_proxy_name" ]; then
        if _is_protected_yaml_name "$proposed_old_proxy_name"; then
            _error "该 Clash 节点名仍被 Argo/Xray/中转共享引用，拒绝原地改名或改端口: $proposed_old_proxy_name"
            return 1
        fi
        proposed_new_proxy_name=$(echo "$proposed_old_proxy_name" | sed "s/${old_port}/${new_port}/g")
        if [ "$proposed_new_proxy_name" != "$proposed_old_proxy_name" ]; then
            export PROXY_NAME="$proposed_new_proxy_name"
            if ${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME)) | .name' "$CLASH_YAML_FILE" 2>/dev/null | grep -Fxq "$proposed_new_proxy_name"; then
                _error "共享 Clash YAML 已存在目标节点名: $proposed_new_proxy_name"
                return 1
            fi
        fi
    fi

    # 在完整 nft 快照之后执行探针；探针清理失败也必须触发整表回滚。
    if [ "$hop_mode" = "nftables" ] && [ -n "$hop_info" ] && [ ! -f "${modify_backup_dir}/nft.available" ]; then
        _error "无法快照 nftables 状态，拒绝修改使用 nftables 端口跳跃的节点。"
        return 1
    fi
    if [ "$hop_mode" = "nftables" ] && [ -n "$final_hop_info" ]; then
        local nft_probe_comment="singboxlite-hy2-hop-probe-$$"
        if ! _nft_apply_redirect_rule add "$final_hop_start" "$final_hop_end" "$new_port" "$nft_probe_comment" \
            || ! _nft_apply_redirect_rule delete "$final_hop_start" "$final_hop_end" "$new_port" "$nft_probe_comment"; then
            _error "新的 HY2 nftables 跳跃规则探针未能完整创建并清理。"
            return 1
        fi
    fi
    
    _info "正在修改端口: ${old_port} -> ${new_port}"
    
    # 1. 修改 config.json 主节点端口（按 tag 精确匹配，避免过滤 hop 子节点后索引错位）
    _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$tag_to_modify\") | .listen_port) = $new_port" || return
    
    # 2. 修改 clash.yaml (全链路同步模式)
    local old_proxy_name="$proposed_old_proxy_name"
    if [ -n "$old_proxy_name" ]; then
        # 生成新名字：将名字中的旧端口替换为新端口
        local new_proxy_name="$proposed_new_proxy_name"
        
        export OLD_NAME="$old_proxy_name"
        export NEW_NAME="$new_proxy_name"
        export NEW_PORT_VAL="$new_port"
        
        # 原子改名与改端口
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(OLD_NAME)) | .name) = env(NEW_NAME)' || return 1
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME)) | .port) = (env(NEW_PORT_VAL)|tonumber)' || return 1
        
        # 全局同步更新所有分组中的引用
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxy-groups[].proxies[] | select(. == env(OLD_NAME))) = env(NEW_NAME)' || return 1
        
        if [ -n "$final_hop_info" ]; then
            export NEW_PORTS_VAL="$final_hop_info"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME)) | .ports) = env(NEW_PORTS_VAL)' || return 1
        elif [ -n "$hop_info" ]; then
            _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == env(NEW_NAME)) | .ports)' || return 1
        fi
        
        _info "Clash 节点名同步: ${old_proxy_name} -> ${new_proxy_name}"
    fi
    
    # 3. 同步更新元数据中的备注名与 HY2 跳跃状态。分享链接在所有
    # 服务端、YAML 和 tag 变更完成后由统一构建器重新生成。
    if [ -f "$METADATA_FILE" ]; then
        if jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
            local current_meta_name
            current_meta_name=$(jq -r ".\"$tag_to_modify\".name // \"\"" "$METADATA_FILE")
            if [ -n "$current_meta_name" ]; then
                local new_meta_name
                new_meta_name=$(echo "$current_meta_name" | sed "s/${old_port}/${new_port}/g")
                if [ "$new_meta_name" != "$current_meta_name" ]; then
                    _atomic_modify_json "$METADATA_FILE" ".\"$tag_to_modify\".name = \"$new_meta_name\"" || return
                fi
            fi
            if [ -n "$hop_info" ]; then
                if [ -n "$final_hop_info" ]; then
                    _atomic_modify_json "$METADATA_FILE" ".\"$tag_to_modify\".portHopping = \"$final_hop_info\"" || return
                    if [ -n "$hop_mode" ]; then
                        _atomic_modify_json "$METADATA_FILE" ".\"$tag_to_modify\".portHoppingMode = \"$hop_mode\"" || return
                    fi
                else
                    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_modify\".portHopping, .\"$tag_to_modify\".portHoppingMode)" || return
                fi
            fi
        fi
    fi

    # 4. 通用 tag 重命名（所有含端口的 tag 都可能需要更新）
    local new_tag=$(echo "$tag_to_modify" | sed "s/${old_port}/${new_port}/g")
    if [ "$new_tag" != "$tag_to_modify" ]; then
        # 4a. 处理证书文件重命名（仅 Hysteria2, TUIC, AnyTLS 有独立证书）
        if [ "$type_to_modify" == "hysteria2" ] || [ "$type_to_modify" == "tuic" ] || [ "$type_to_modify" == "anytls" ]; then
            local old_cert="${SINGBOX_DIR}/${tag_to_modify}.pem"
            local old_key="${SINGBOX_DIR}/${tag_to_modify}.key"
            local new_cert="${SINGBOX_DIR}/${new_tag}.pem"
            local new_key="${SINGBOX_DIR}/${new_tag}.key"
            if [ -f "$old_cert" ] && [ -f "$old_key" ]; then
                mv -- "$old_cert" "$new_cert" || return 1
                mv -- "$old_key" "$new_key" || return 1
                _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$tag_to_modify\") | .tls.certificate_path) = \"$new_cert\"" || return
                _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$tag_to_modify\") | .tls.key_path) = \"$new_key\"" || return
            fi
        fi
        
        # 4b. 更新 config.json 中主节点的 tag；ShadowTLS 同步迁移内层 tag 和 detour。
        local new_shadowtls_inner_tag="$shadowtls_inner_tag"
        if [ "$type_to_modify" = "shadowtls" ]; then
            if [[ "$shadowtls_inner_tag" == "$tag_to_modify"* ]]; then
                new_shadowtls_inner_tag="${new_tag}${shadowtls_inner_tag#${tag_to_modify}}"
            else
                new_shadowtls_inner_tag=$(echo "$shadowtls_inner_tag" | sed "s/${old_port}/${new_port}/g")
            fi
            _atomic_modify_json "$CONFIG_FILE" '
                (.inbounds[] | select(.tag == $outer) | .tag) = $new_outer
                | (.inbounds[] | select(.tag == $new_outer) | .detour) = $new_inner
                | (.inbounds[] | select(.tag == $old_inner) | .tag) = $new_inner
                | .route = (.route // {"rules":[]})
                | .route.rules = ((.route.rules // []) | map(
                    if .inbound == $outer then .inbound = $new_outer
                    elif .inbound == $old_inner then .inbound = $new_inner
                    elif ((.inbound // null) | type) == "array" then
                        .inbound |= map(if . == $outer then $new_outer elif . == $old_inner then $new_inner else . end)
                    else . end
                  ))
            ' --arg outer "$tag_to_modify" --arg new_outer "$new_tag" --arg old_inner "$shadowtls_inner_tag" --arg new_inner "$new_shadowtls_inner_tag" || return
        else
            _atomic_modify_json "$CONFIG_FILE" '
                (.inbounds[] | select(.tag == $old) | .tag) = $new
                | .route = (.route // {"rules":[]})
                | .route.rules = ((.route.rules // []) | map(
                    if .inbound == $old then .inbound = $new
                    elif ((.inbound // null) | type) == "array" then .inbound |= map(if . == $old then $new else . end)
                    else . end
                  ))
            ' \
                --arg old "$tag_to_modify" --arg new "$new_tag" || return
        fi
        
        # 4c. 迁移 metadata.json 中的 key (旧tag -> 新tag)
        if [ -f "$METADATA_FILE" ] && jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
            local meta_content=$(jq --arg tag "$tag_to_modify" '.[$tag]' "$METADATA_FILE")
            if [ "$type_to_modify" = "shadowtls" ]; then
                meta_content=$(printf '%s' "$meta_content" | jq --arg inner "$new_shadowtls_inner_tag" '.inner_tag = $inner')
            fi
            _atomic_modify_json "$METADATA_FILE" 'del(.[$old]) | . + {($new):$meta}' \
                --arg old "$tag_to_modify" --arg new "$new_tag" --argjson meta "$meta_content" || return
        fi
        
        _info "Tag 同步: ${tag_to_modify} -> ${new_tag}"
    fi
    
    # 5. 联动更新端口跳跃规则
    local final_tag="${new_tag:-$tag_to_modify}"
    if [ -n "$hop_info" ]; then
        if [ "$hop_mode" = "nftables" ]; then
            local old_hop_start="${hop_info%-*}"
            local old_hop_end="${hop_info#*-}"

            if [ -n "$final_hop_info" ]; then
                if [ "$final_tag" != "$tag_to_modify" ]; then
                    # 新注释先创建成功，再删除旧规则，始终保留一条可用映射。
                    _nft_apply_redirect_rule add "$final_hop_start" "$final_hop_end" "$new_port" "singboxlite-hy2-hop-${final_tag}" || {
                        _error "创建新的端口跳跃 nftables 规则失败。"
                        return 1
                    }
                    _nft_apply_redirect_rule delete "$old_hop_start" "$old_hop_end" "$old_port" "singboxlite-hy2-hop-${tag_to_modify}" || {
                        _error "删除旧的端口跳跃 nftables 规则失败。"
                        return 1
                    }
                else
                    _nft_apply_redirect_rule delete "$old_hop_start" "$old_hop_end" "$old_port" "singboxlite-hy2-hop-${tag_to_modify}" || {
                        _error "删除旧的端口跳跃 nftables 规则失败。"
                        return 1
                    }
                    if ! _nft_apply_redirect_rule add "$final_hop_start" "$final_hop_end" "$new_port" "singboxlite-hy2-hop-${final_tag}"; then
                        _error "创建新的端口跳跃 nftables 规则失败。"
                        return 1
                    fi
                fi
                _save_nftables_rules || {
                    _error "持久化端口跳跃 nftables 规则失败。"
                    return 1
                }
                _info "已将端口跳跃映射从 ${old_port} 联动更新到 ${new_port}，范围: ${final_hop_info}"
            else
                # === 无新跳跃范围：仅删除旧规则 ===
                _nft_apply_redirect_rule delete "$old_hop_start" "$old_hop_end" "$old_port" "singboxlite-hy2-hop-${tag_to_modify}" || {
                    _error "删除端口跳跃 nftables 规则失败。"
                    return 1
                }
                _save_nftables_rules || {
                    _error "持久化端口跳跃 nftables 规则失败。"
                    return 1
                }
                _info "已移除端口跳跃映射。"
            fi
        elif [ "$hop_mode" = "native" ]; then
            _atomic_modify_json "$CONFIG_FILE" ".inbounds |= map(select(.tag | startswith(\"${tag_to_modify}-hop-\") | not))" || return
            if [ -n "$new_tag" ] && [ "$new_tag" != "$tag_to_modify" ]; then
                _atomic_modify_json "$CONFIG_FILE" ".inbounds |= map(select(.tag | startswith(\"${new_tag}-hop-\") | not))" || return
            fi
            if [ -n "$final_hop_info" ]; then
                local cert_path="${SINGBOX_DIR}/${final_tag}.pem"
                local key_path="${SINGBOX_DIR}/${final_tag}.key"
                local hy2_password=$(jq -r --arg t "$final_tag" '.inbounds[] | select(.tag == $t) | .users[0].password // ""' "$CONFIG_FILE")
                local hy2_obfs_password=$(jq -r --arg t "$final_tag" '.inbounds[] | select(.tag == $t) | .obfs.password // ""' "$CONFIG_FILE")
                local batch_array="[]"
                local skipped=0
                local p
                for ((p=final_hop_start; p<=final_hop_end; p++)); do
                    if [ "$p" -eq "$new_port" ]; then continue; fi
                    local skip_live="false"
                    if [ "$p" -ge "${hop_info%-*}" ] && [ "$p" -le "${hop_info#*-}" ]; then skip_live="true"; fi
                    # metadata key 已在上方迁移为 final_tag；排除旧 tag 会把节点
                    # 自己的跳跃范围误判为冲突，导致所有原生子入站被跳过。
                    if _check_port_conflict "$p" "udp" "true" "$final_tag" "$skip_live"; then ((skipped++)); continue; fi
                    local hop_tag="${final_tag}-hop-${p}"
                    batch_array=$(echo "$batch_array" | jq --arg t "$hop_tag" --arg p "$p" --arg pw "$hy2_password" --arg cert "$cert_path" --arg key "$key_path" --arg op "$hy2_obfs_password" '. += [{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end]')
                done
                if [ "$(echo "$batch_array" | jq 'length')" -gt 0 ]; then
                    _atomic_modify_json "$CONFIG_FILE" ".inbounds += $batch_array" || return
                fi
                _info "已重建原生端口跳跃子节点，范围: ${final_hop_info}"
                if [ "$skipped" -gt 0 ]; then
                    _warning "有 ${skipped} 个跳跃端口因冲突被跳过。"
                fi
            else
                _info "已移除原生端口跳跃子节点。"
            fi
        fi
    fi

    # 不再对旧链接做字符串替换；从最终配置和元数据完整重建，避免端口数字
    # 误伤密码/UUID，也确保证书指纹、SNI、认证信息与 HY2 跳跃参数一致。
    local final_proxy_name="${proposed_new_proxy_name:-$proposed_old_proxy_name}"
    _refresh_modified_node_artifacts "$final_tag" "$final_proxy_name" || return 1
    
    local modify_check_result
    if ! modify_check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
        _error "端口修改后的组合配置校验失败："
        echo "$modify_check_result"
        return 1
    fi
    modify_restart_attempted=1
    if ! _manage_service restart; then
        _error "端口修改后服务重启失败。"
        return 1
    fi
    modify_committed=1
    trap - EXIT INT TERM
    rm -rf -- "$modify_backup_dir" || _warn "端口修改事务快照目录清理失败: $modify_backup_dir"
    if [ "$modify_lock_owned" = "true" ]; then
        export SINGBOXLITE_LOCK_HELD=0
        flock -u 8
        exec 8>&-
    fi
    _success "端口修改成功: ${old_port} -> ${new_port}"
)

_modify_node_apply() (
    local tag="$1" expected_node="$2" expected_metadata="$3" old_proxy_name="$4" action="$5"
    shift 5
    local arg1="${1:-}" arg2="${2:-}" arg3="${3:-}" arg4="${4:-}" arg5="${5:-}"
    local lock_owned="false"
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" != "1" ]; then
        command -v flock >/dev/null 2>&1 || { _error "缺少 flock，拒绝无锁修改节点。"; return 1; }
        exec 8>"${SINGBOX_DIR}/.singboxlite.lock" || return 1
        if ! _flock_wait 8 30; then exec 8>&-; _error "等待状态锁超时。"; return 1; fi
        export SINGBOXLITE_LOCK_HELD=1
        lock_owned="true"
    fi

    local backup_dir restart_attempted=0 restart_needed=0 committed=0
    backup_dir=$(mktemp -d /tmp/.singbox-modify-node.XXXXXX) || return 1
    if ! _main_create_tx_snapshot "$backup_dir"; then
        _error "无法完整创建节点修改事务快照，操作尚未开始。"
        rm -rf -- "$backup_dir"
        if [ "$lock_owned" = "true" ]; then export SINGBOXLITE_LOCK_HELD=0; flock -u 8; exec 8>&-; fi
        return 1
    fi
    export MAIN_CREATE_TX_ACTIVE=1
    if [ -f "${backup_dir}/nft.available" ]; then
        export MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE=1
    else
        export MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE=0
    fi
    trap 'modify_rc=$?; trap - EXIT INT TERM; if [ "$committed" -ne 1 ]; then if ! _restore_full_transaction_snapshot "$backup_dir" "$restart_attempted" "节点修改"; then modify_rc=1; fi; fi; export MAIN_CREATE_TX_ACTIVE=0 MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE=0; if [ "$lock_owned" = "true" ]; then export SINGBOXLITE_LOCK_HELD=0; flock -u 8; exec 8>&-; fi; exit "$modify_rc"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    _validate_protected_yaml_metadata || return 1
    _is_argo_inbound_tag "$tag" && { _error "Argo 节点只能在 Argo 菜单修改。"; return 1; }
    [[ "$tag" == *"-hop-"* ]] && { _error "HY2 跳跃辅助入站不能单独修改。"; return 1; }
    _is_shadowtls_inner_tag "$tag" && { _error "ShadowTLS 内层不能单独修改。"; return 1; }

    local current_node current_metadata variant type port
    current_node=$(jq -cS --arg tag "$tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" 2>/dev/null | head -n 1) || return 1
    current_metadata=$(jq -cS --arg tag "$tag" '.[$tag] // {}' "$METADATA_FILE" 2>/dev/null) || return 1
    if [ "$current_node" != "$expected_node" ] || [ "$current_metadata" != "$expected_metadata" ]; then
        _error "节点在选择后已被其他操作修改，请重新进入菜单。"
        return 1
    fi
    variant=$(_detect_main_node_variant "$tag")
    type=$(printf '%s' "$current_node" | jq -r '.type')
    port=$(printf '%s' "$current_node" | jq -r '.listen_port')
    [ "$variant" != "unsupported" ] || { _error "暂不支持修改该节点类型。"; return 1; }

    case "$action" in
        name)
            if [ -n "$old_proxy_name" ] && [ "$arg1" != "$old_proxy_name" ]; then
                export PROXY_NAME="$arg1"
                if ${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME)) | .name' "$CLASH_YAML_FILE" 2>/dev/null | grep -Fxq "$arg1"; then
                    _error "共享 Clash YAML 已存在同名节点: $arg1"
                    return 1
                fi
            fi
            _atomic_modify_json "$METADATA_FILE" '.[$tag].name = $value' --arg tag "$tag" --arg value "$arg1" || return 1
            ;;
        address)
            _atomic_modify_json "$METADATA_FILE" '.[$tag].clientServer = $value' --arg tag "$tag" --arg value "$arg1" || return 1
            ;;
        auth)
            case "$variant" in
                vless-*) _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .users[0].uuid) = $value' --arg tag "$tag" --arg value "$arg1" || return 1 ;;
                trojan-ws-tls|hysteria2|anytls|any-reality)
                    _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .users[0].password) = $value' --arg tag "$tag" --arg value "$arg1" || return 1 ;;
                tuic)
                    _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .users[0]) |= (.uuid = $uuid | .password = $password)' --arg tag "$tag" --arg uuid "$arg1" --arg password "$arg2" || return 1 ;;
                shadowsocks)
                    _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .password) = $value' --arg tag "$tag" --arg value "$arg1" || return 1 ;;
                shadowsocks-shadowtls)
                    local inner_tag
                    inner_tag=$(printf '%s' "$current_node" | jq -r '.detour // empty')
                    [ -n "$inner_tag" ] || { _error "ShadowTLS 内层 tag 缺失。"; return 1; }
                    _atomic_modify_json "$CONFIG_FILE" '
                        (.inbounds[] | select(.tag == $tag) | .users[0].password) = $outer
                        | (.inbounds[] | select(.tag == $inner) | .password) = $inner_password
                    ' --arg tag "$tag" --arg inner "$inner_tag" --arg outer "$arg1" --arg inner_password "$arg2" || return 1
                    ;;
                socks)
                    _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .users[0]) |= (.username = $username | .password = $password)' --arg tag "$tag" --arg username "$arg1" --arg password "$arg2" || return 1 ;;
            esac
            restart_needed=1
            ;;
        identity)
            case "$variant" in
                vless-reality|any-reality)
                    _atomic_modify_json "$CONFIG_FILE" '
                        (.inbounds[] | select(.tag == $tag) | .tls.server_name) = $sni
                        | (.inbounds[] | select(.tag == $tag) | .tls.reality.handshake.server) = $sni
                    ' --arg tag "$tag" --arg sni "$arg1" || return 1
                    ;;
                shadowsocks-shadowtls)
                    _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .handshake.server) = $sni' --arg tag "$tag" --arg sni "$arg1" || return 1
                    ;;
                vless-ws-tls|vless-grpc-tls|trojan-ws-tls|anytls|hysteria2|tuic)
                    local cert_path key_path skip_verify
                    if [ "$arg2" = "self_signed" ]; then
                        cert_path="${SINGBOX_DIR}/${tag}.pem"
                        key_path="${SINGBOX_DIR}/${tag}.key"
                        _generate_self_signed_cert "$arg1" "$cert_path" "$key_path" || return 1
                        skip_verify="true"
                    else
                        cert_path="$arg3"
                        key_path="$arg4"
                        skip_verify="$arg5"
                        _validate_tls_key_pair "$cert_path" "$key_path" || return 1
                    fi
                    _atomic_modify_json "$CONFIG_FILE" '
                        (.inbounds[] | select(.tag == $tag) | .tls) |=
                            (.server_name = $sni | .certificate_path = $cert | .key_path = $key)
                    ' --arg tag "$tag" --arg sni "$arg1" --arg cert "$cert_path" --arg key "$key_path" || return 1
                    if [ -n "$old_proxy_name" ]; then
                        export OLD_NAME="$old_proxy_name" NODE_SKIP_VERIFY="$skip_verify"
                        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(OLD_NAME)))."skip-cert-verify" = (env(NODE_SKIP_VERIFY) == "true")' || return 1
                    fi
                    ;;
            esac
            restart_needed=1
            ;;
        transport)
            case "$variant" in
                vless-ws-tls|trojan-ws-tls)
                    _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .transport.path) = $value' --arg tag "$tag" --arg value "$arg1" || return 1 ;;
                vless-grpc-tls)
                    _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .transport.service_name) = $value' --arg tag "$tag" --arg value "$arg1" || return 1 ;;
                *) _error "该节点没有可修改的传输路径。"; return 1 ;;
            esac
            restart_needed=1
            ;;
        reality_keys)
            [[ "$variant" == "vless-reality" || "$variant" == "any-reality" ]] || return 1
            local keypair private_key public_key short_id
            keypair=$(${SINGBOX_BIN} generate reality-keypair) || return 1
            private_key=$(printf '%s\n' "$keypair" | awk '/PrivateKey/ {print $2; exit}')
            public_key=$(printf '%s\n' "$keypair" | awk '/PublicKey/ {print $2; exit}')
            short_id=$(${SINGBOX_BIN} generate rand --hex 8) || return 1
            [ -n "$private_key" ] && [ -n "$public_key" ] && [ -n "$short_id" ] || { _error "Reality 密钥生成失败。"; return 1; }
            _atomic_modify_json "$CONFIG_FILE" '
                (.inbounds[] | select(.tag == $tag) | .tls.reality.private_key) = $private
                | (.inbounds[] | select(.tag == $tag) | .tls.reality.short_id) = [$sid]
            ' --arg tag "$tag" --arg private "$private_key" --arg sid "$short_id" || return 1
            _atomic_modify_json "$METADATA_FILE" '.[$tag] |= (. + {publicKey:$public,shortId:$sid})' --arg tag "$tag" --arg public "$public_key" --arg sid "$short_id" || return 1
            restart_needed=1
            ;;
        hy2_obfs)
            [ "$variant" = "hysteria2" ] || return 1
            if [ -n "$arg1" ]; then
                _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag) | .obfs) = {type:"salamander",password:$password}' --arg tag "$tag" --arg password "$arg1" || return 1
                _atomic_modify_json "$METADATA_FILE" '.[$tag].obfsPassword = $password' --arg tag "$tag" --arg password "$arg1" || return 1
            else
                _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select(.tag == $tag)) |= del(.obfs)' --arg tag "$tag" || return 1
                _atomic_modify_json "$METADATA_FILE" 'del(.[$tag].obfsPassword)' --arg tag "$tag" || return 1
            fi
            restart_needed=1
            ;;
        hy2_bandwidth)
            [ "$variant" = "hysteria2" ] || return 1
            _atomic_modify_json "$METADATA_FILE" '.[$tag] |= (. + {up:$up,down:$down})' --arg tag "$tag" --arg up "$arg1" --arg down "$arg2" || return 1
            ;;
        hy2_hop)
            [ "$variant" = "hysteria2" ] || return 1
            local old_hop old_mode start end count pf_conflict hop_conflict new_mode=""
            old_hop=$(printf '%s' "$current_metadata" | jq -r '.portHopping // empty')
            old_mode=$(printf '%s' "$current_metadata" | jq -r '.portHoppingMode // empty')
            if [ -n "$old_hop" ] && [ -z "$old_mode" ]; then
                if jq -e --arg prefix "${tag}-hop-" '.inbounds[]? | select((.tag // "") | startswith($prefix))' "$CONFIG_FILE" >/dev/null 2>&1; then old_mode="native"; else old_mode="nftables"; fi
            fi
            if [ -n "$arg1" ]; then
                start="${arg1%-*}"; end="${arg1#*-}"; count=$((end - start + 1))
                pf_conflict=$(_find_pf_udp_conflict_in_range "$start" "$end" || true)
                [ -z "$pf_conflict" ] || { _error "跳跃范围覆盖已有端口转发入口。"; return 1; }
                hop_conflict=$(_find_udp_hop_conflict_in_range "$start" "$end" "$tag" || true)
                [ -z "$hop_conflict" ] || { _error "跳跃范围与其他 HY2 节点冲突。"; return 1; }
            fi
            _atomic_modify_json "$CONFIG_FILE" '.inbounds |= map(select((((.tag // "") | startswith($prefix))) | not))' --arg prefix "${tag}-hop-" || return 1
            if [ "$old_mode" = "nftables" ] && [ -n "$old_hop" ]; then
                _nft_apply_redirect_rule delete "${old_hop%-*}" "${old_hop#*-}" "$port" "singboxlite-hy2-hop-${tag}" || return 1
            fi
            if [ -n "$arg1" ]; then
                if _nft_apply_redirect_rule add "$start" "$end" "$port" "singboxlite-hy2-hop-${tag}" && _save_nftables_rules; then
                    new_mode="nftables"
                else
                    _nft_delete_rules_by_comment "singboxlite-hy2-hop-${tag}" >/dev/null 2>&1 || true
                    [ "$count" -le 1000 ] || { _error "当前环境不能使用 nftables，原生跳跃最多允许 1000 个端口。"; return 1; }
                    local main_node password obfs_password cert_path key_path batch_array="[]" p hop_tag
                    main_node=$(jq -c --arg tag "$tag" '.inbounds[] | select(.tag == $tag)' "$CONFIG_FILE")
                    password=$(printf '%s' "$main_node" | jq -r '.users[0].password')
                    obfs_password=$(printf '%s' "$main_node" | jq -r '.obfs.password // empty')
                    cert_path=$(printf '%s' "$main_node" | jq -r '.tls.certificate_path')
                    key_path=$(printf '%s' "$main_node" | jq -r '.tls.key_path')
                    for ((p=start; p<=end; p++)); do
                        [ "$p" -eq "$port" ] && continue
                        _check_port_conflict "$p" "udp" "true" "$tag" && continue
                        hop_tag="${tag}-hop-${p}"
                        batch_array=$(printf '%s' "$batch_array" | jq --arg t "$hop_tag" --argjson p "$p" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" --arg op "$obfs_password" '. += [{type:"hysteria2",tag:$t,listen:"::",listen_port:$p,users:[{password:$pw}],tls:{enabled:true,alpn:["h3"],certificate_path:$cert,key_path:$key}} | if $op != "" then .obfs={type:"salamander",password:$op} else . end]') || return 1
                    done
                    _atomic_modify_json "$CONFIG_FILE" '.inbounds += $nodes' --argjson nodes "$batch_array" || return 1
                    new_mode="native"
                fi
                _atomic_modify_json "$METADATA_FILE" '.[$tag] |= (. + {portHopping:$hop,portHoppingMode:$mode})' --arg tag "$tag" --arg hop "$arg1" --arg mode "$new_mode" || return 1
            else
                [ "$old_mode" != "nftables" ] || _save_nftables_rules || return 1
                _atomic_modify_json "$METADATA_FILE" 'del(.[$tag].portHopping, .[$tag].portHoppingMode)' --arg tag "$tag" || return 1
            fi
            restart_needed=1
            ;;
        *) _error "未知节点修改动作。"; return 1 ;;
    esac

    # HY2 原生跳跃的所有子入站必须跟随主节点的密码、混淆和证书变化。
    if [ "$variant" = "hysteria2" ]; then
        local main_after hy2_password hy2_obfs cert_after key_after sni_after
        main_after=$(jq -c --arg tag "$tag" '.inbounds[] | select(.tag == $tag)' "$CONFIG_FILE") || return 1
        hy2_password=$(printf '%s' "$main_after" | jq -r '.users[0].password')
        hy2_obfs=$(printf '%s' "$main_after" | jq -r '.obfs.password // empty')
        cert_after=$(printf '%s' "$main_after" | jq -r '.tls.certificate_path')
        key_after=$(printf '%s' "$main_after" | jq -r '.tls.key_path')
        sni_after=$(printf '%s' "$main_after" | jq -r '.tls.server_name // empty')
        _atomic_modify_json "$CONFIG_FILE" '
            .inbounds |= map(
                if ((.tag // "") | startswith($prefix)) then
                    .users = [{password:$password}]
                    | .tls.certificate_path = $cert | .tls.key_path = $key
                    | if $sni != "" then .tls.server_name = $sni else . end
                    | if $obfs != "" then .obfs = {type:"salamander",password:$obfs} else del(.obfs) end
                else . end)
        ' --arg prefix "${tag}-hop-" --arg password "$hy2_password" --arg obfs "$hy2_obfs" --arg cert "$cert_after" --arg key "$key_after" --arg sni "$sni_after" || return 1
    fi

    _refresh_modified_node_artifacts "$tag" "$old_proxy_name" || return 1
    local check_result
    if ! check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
        _error "节点修改后的组合配置校验失败："
        echo "$check_result"
        return 1
    fi
    if [ "$restart_needed" -eq 1 ]; then
        restart_attempted=1
        _manage_service restart || { _error "节点修改后服务重启失败。"; return 1; }
    fi
    committed=1
    trap - EXIT INT TERM
    rm -rf -- "$backup_dir" || _warn "节点修改事务快照清理失败: $backup_dir"
    export MAIN_CREATE_TX_ACTIVE=0 MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE=0
    if [ "$lock_owned" = "true" ]; then export SINGBOXLITE_LOCK_HELD=0; flock -u 8; exec 8>&-; fi
    _success "节点修改已保存并通过配置校验。"
)

_confirm_node_change() {
    local confirm
    read -r -p "确认保存并应用本次修改？[Y/n]: " confirm
    [[ "$confirm" =~ ^[Nn]$ ]] && return 1
    _modify_node_apply "$@"
}

_modify_node() {
    local primary_nodes node i=1 num count index tag type port display_name proxy_name variant
    local tags=() types=() ports=() names=()
    primary_nodes=$(_list_main_primary_inbounds)
    [ -n "$primary_nodes" ] || { _warning "当前没有可修改的主节点。"; return; }
    _info "--- 修改节点 ---"
    while IFS= read -r node; do
        [ -n "$node" ] || continue
        IFS=$'\t' read -r tag type port <<< "$(printf '%s' "$node" | jq -r '[.tag,.type,(.listen_port|tostring)] | @tsv')"
        proxy_name=$(_find_proxy_name "$port" "$type" "$tag")
        display_name=$(jq -r --arg tag "$tag" '.[$tag].name // empty' "$METADATA_FILE" 2>/dev/null)
        display_name=${display_name:-${proxy_name:-$tag}}
        tags+=("$tag"); types+=("$type"); ports+=("$port"); names+=("$display_name")
        variant=$(_detect_main_node_variant "$tag")
        echo -e "  ${CYAN}${i})${NC} ${display_name} (${YELLOW}${variant}${NC}) @ ${GREEN}${port}${NC}"
        ((i++))
    done <<< "$primary_nodes"
    read -r -p "请输入要修改的节点编号 (输入 0 返回): " num
    [[ "$num" =~ ^[0-9]+$ ]] || { _error "请输入有效编号。"; return 1; }
    [ "$num" -ne 0 ] || return
    count=${#tags[@]}; [ "$num" -le "$count" ] || { _error "编号超出范围。"; return 1; }
    index=$((num - 1)); tag=${tags[$index]}; type=${types[$index]}; port=${ports[$index]}; display_name=${names[$index]}
    variant=$(_detect_main_node_variant "$tag")
    proxy_name=$(_find_proxy_name "$port" "$type" "$tag")
    local expected_node expected_metadata choice
    expected_node=$(jq -cS --arg tag "$tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE") || return 1
    expected_metadata=$(jq -cS --arg tag "$tag" '.[$tag] // {}' "$METADATA_FILE") || return 1

    echo ""
    _info "当前节点: ${display_name} (${variant})"
    echo "  1) 修改节点名称"
    echo "  2) 修改客户端连接地址"
    echo "  3) 修改监听端口"
    case "$variant" in
        tuic) echo "  4) 修改 UUID 和密码" ;;
        shadowsocks-shadowtls) echo "  4) 修改 ShadowTLS 与内部 SS 密码" ;;
        socks) echo "  4) 修改用户名和密码" ;;
        *) echo "  4) 修改认证信息" ;;
    esac
    case "$variant" in
        vless-reality|any-reality|shadowsocks-shadowtls) echo "  5) 修改伪装域名/SNI" ;;
        vless-ws-tls|vless-grpc-tls|trojan-ws-tls|anytls|hysteria2|tuic) echo "  5) 修改 SNI 与证书" ;;
    esac
    case "$variant" in
        vless-reality|any-reality) echo "  6) 重新生成 Reality 密钥和 Short ID" ;;
        vless-ws-tls|trojan-ws-tls) echo "  6) 修改 WebSocket 路径" ;;
        vless-grpc-tls) echo "  6) 修改 gRPC serviceName" ;;
        hysteria2) echo "  6) 修改 Salamander 混淆"; echo "  7) 修改端口跳跃"; echo "  8) 修改客户端带宽参数" ;;
    esac
    echo "  0) 返回"
    read -r -p "请选择修改项: " choice

    local value value2 current method cert_choice cert_path key_path skip_verify confirm
    case "$choice" in
        1)
            read -r -p "请输入新节点名称: " value
            [ -n "$value" ] && [[ "$value" != *$'\n'* ]] || { _error "节点名称不能为空或包含换行。"; return 1; }
            _info "节点名称: ${display_name} -> ${value}"
            _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" name "$value"
            ;;
        2)
            current=$(jq -r --arg tag "$tag" '.[$tag].clientServer // empty' "$METADATA_FILE")
            [ -n "$current" ] || current=$(_get_proxy_field "$proxy_name" '.server // ""')
            read -r -p "请输入新的客户端连接地址 (当前: ${current}): " value
            value=$(_normalize_client_server "$value")
            [ -n "$value" ] && [[ "$value" != *[[:space:]]* ]] && [[ "$value" != *"://"* ]] || { _error "连接地址格式无效，请只输入 IP 或域名。"; return 1; }
            _info "客户端连接地址: ${current} -> ${value}"
            _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" address "$value"
            ;;
        3) _modify_port "$tag" ;;
        4)
            case "$variant" in
                vless-*)
                    read -r -p "请输入新 UUID (回车随机生成): " value; value=${value:-$(${SINGBOX_BIN} generate uuid)}
                    [[ "$value" =~ ^[0-9A-Fa-f-]{36}$ ]] || { _error "UUID 格式无效。"; return 1; }
                    ;;
                trojan-ws-tls|hysteria2|anytls|any-reality)
                    read -r -s -p "请输入新密码 (回车随机生成): " value; echo ""; value=${value:-$(${SINGBOX_BIN} generate rand --hex 16)}
                    ;;
                tuic)
                    read -r -p "请输入新 UUID (回车随机生成): " value; value=${value:-$(${SINGBOX_BIN} generate uuid)}
                    [[ "$value" =~ ^[0-9A-Fa-f-]{36}$ ]] || { _error "UUID 格式无效。"; return 1; }
                    read -r -s -p "请输入新密码 (回车随机生成): " value2; echo ""; value2=${value2:-$(${SINGBOX_BIN} generate rand --hex 16)}
                    ;;
                shadowsocks)
                    method=$(printf '%s' "$expected_node" | jq -r '.method')
                    read -r -s -p "请输入新密钥/密码 (回车按当前算法随机生成): " value; echo ""
                    [ -n "$value" ] || value=$(_generate_shadowsocks_password "$method") || return 1
                    ;;
                shadowsocks-shadowtls)
                    read -r -s -p "请输入新 ShadowTLS 密码 (回车随机生成): " value; echo ""; value=${value:-$(${SINGBOX_BIN} generate rand --hex 16)}
                    read -r -s -p "请输入新内部 SS 密钥 (回车随机生成): " value2; echo ""; value2=${value2:-$(${SINGBOX_BIN} generate rand --base64 32)}
                    ;;
                socks)
                    read -r -p "请输入新用户名 (回车随机生成): " value; value=${value:-$(${SINGBOX_BIN} generate rand --hex 8)}
                    read -r -s -p "请输入新密码 (回车随机生成): " value2; echo ""; value2=${value2:-$(${SINGBOX_BIN} generate rand --hex 16)}
                    ;;
            esac
            [ -n "$value" ] || { _error "认证信息不能为空。"; return 1; }
            _info "认证信息将被更新（新凭据不会在确认信息中显示）。"
            _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" auth "$value" "$value2"
            ;;
        5)
            case "$variant" in
                vless-reality|any-reality)
                    current=$(printf '%s' "$expected_node" | jq -r '.tls.reality.handshake.server // .tls.server_name // empty')
                    read -r -p "请输入新伪装域名/SNI (当前: ${current}): " value
                    [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || { _error "域名/SNI 格式无效。"; return 1; }
                    _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" identity "$value"
                    ;;
                shadowsocks-shadowtls)
                    current=$(printf '%s' "$expected_node" | jq -r '.handshake.server // empty')
                    read -r -p "请输入新伪装域名 (当前: ${current}): " value
                    [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || { _error "伪装域名格式无效。"; return 1; }
                    _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" identity "$value"
                    ;;
                vless-ws-tls|vless-grpc-tls|trojan-ws-tls|anytls|hysteria2|tuic)
                    current=$(printf '%s' "$expected_node" | jq -r '.tls.server_name // empty')
                    [ -n "$current" ] || current=$(_get_proxy_field "$proxy_name" '.sni // .servername // ""')
                    read -r -p "请输入新 SNI/证书域名 (当前: ${current}): " value
                    [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || { _error "域名/SNI 格式无效。"; return 1; }
                    echo "  1) 重新生成脚本管理的自签证书"
                    echo "  2) 使用自定义证书和私钥"
                    read -r -p "请选择证书方式 [1-2] (默认: 1): " cert_choice; cert_choice=${cert_choice:-1}
                    if [ "$cert_choice" = "1" ]; then
                        _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" identity "$value" self_signed
                    elif [ "$cert_choice" = "2" ]; then
                        read -r -p "请输入证书完整路径: " cert_path
                        read -r -p "请输入私钥完整路径: " key_path
                        _validate_tls_key_pair "$cert_path" "$key_path" || return 1
                        read -r -p "客户端是否跳过证书链验证？[y/N]: " confirm
                        skip_verify=false; [[ "$confirm" =~ ^[Yy]$ ]] && skip_verify=true
                        _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" identity "$value" custom "$cert_path" "$key_path" "$skip_verify"
                    else
                        _error "无效选择。"; return 1
                    fi
                    ;;
                *) _error "该节点没有 SNI/证书修改项。"; return 1 ;;
            esac
            ;;
        6)
            case "$variant" in
                vless-reality|any-reality)
                    read -r -p "重新生成后旧客户端将立即失效，确认继续？[y/N]: " confirm
                    [[ "$confirm" =~ ^[Yy]$ ]] || return
                    _modify_node_apply "$tag" "$expected_node" "$expected_metadata" "$proxy_name" reality_keys
                    ;;
                vless-ws-tls|trojan-ws-tls)
                    current=$(printf '%s' "$expected_node" | jq -r '.transport.path // "/"')
                    read -r -p "请输入新 WebSocket 路径 (当前: ${current}): " value
                    [ -n "$value" ] || { _error "路径不能为空。"; return 1; }; [[ "$value" == /* ]] || value="/$value"
                    _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" transport "$value"
                    ;;
                vless-grpc-tls)
                    current=$(printf '%s' "$expected_node" | jq -r '.transport.service_name // empty')
                    read -r -p "请输入新 gRPC serviceName (当前: ${current}): " value
                    [ -n "$value" ] && [[ "$value" != *[[:space:]]* ]] || { _error "serviceName 不能为空或包含空白。"; return 1; }
                    _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" transport "$value"
                    ;;
                hysteria2)
                    echo "  1) 开启/重新生成 Salamander 密码"; echo "  2) 关闭混淆"
                    read -r -p "请选择 [1-2]: " value2
                    if [ "$value2" = "1" ]; then read -r -s -p "请输入混淆密码 (回车随机): " value; echo ""; value=${value:-$(${SINGBOX_BIN} generate rand --hex 16)}; elif [ "$value2" = "2" ]; then value=""; else _error "无效选择。"; return 1; fi
                    _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" hy2_obfs "$value"
                    ;;
                *) _error "该节点没有此修改项。"; return 1 ;;
            esac
            ;;
        7)
            [ "$variant" = "hysteria2" ] || { _error "该节点没有端口跳跃。"; return 1; }
            current=$(jq -r --arg tag "$tag" '.[$tag].portHopping // "未启用"' "$METADATA_FILE")
            read -r -p "请输入新跳跃范围 start-end，输入 none 关闭 (当前: ${current}): " value
            if [ "$value" = "none" ]; then value=""; else
                [[ "$value" =~ ^([0-9]+)-([0-9]+)$ ]] || { _error "范围格式无效。"; return 1; }
                [ "${BASH_REMATCH[1]}" -ge 1 ] && [ "${BASH_REMATCH[2]}" -le 65535 ] && [ "${BASH_REMATCH[1]}" -le "${BASH_REMATCH[2]}" ] || { _error "跳跃范围无效。"; return 1; }
            fi
            _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" hy2_hop "$value"
            ;;
        8)
            [ "$variant" = "hysteria2" ] || { _error "该节点没有带宽参数。"; return 1; }
            read -r -p "请输入客户端上行 Mbps: " value
            read -r -p "请输入客户端下行 Mbps: " value2
            [[ "$value" =~ ^[0-9]+$ && "$value2" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value2" -ge 1 ] || { _error "带宽必须是正整数。"; return 1; }
            _confirm_node_change "$tag" "$expected_node" "$expected_metadata" "$proxy_name" hy2_bandwidth "$value" "$value2"
            ;;
        0) return ;;
        *) _error "无效选择。"; return 1 ;;
    esac
}

# --- 更新管理脚本 ---
_download_bash_script_atomic() {
    local url="$1" target="$2" label="${3:-脚本}"
    [[ "$url" == https://* ]] || { _error "拒绝从非 HTTPS 地址下载 ${label}。"; return 1; }
    mkdir -p "$(dirname "$target")" || return 1
    local tmp
    tmp=$(mktemp "$(dirname "$target")/.${label}.new.XXXXXX") || return 1
    if ! wget -qO "$tmp" "$url" || [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        _error "${label} 下载失败或内容为空。"
        return 1
    fi
    if ! head -n 1 "$tmp" | grep -q '^#!/bin/bash' || ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        _error "${label} 未通过 Bash 脚本格式/语法校验，已拒绝覆盖。"
        return 1
    fi
    chmod 755 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$target" || { rm -f "$tmp"; return 1; }
}

_update_script_locked() {
    _info "--- 更新脚本 ---"

    if [ "$SCRIPT_UPDATE_URL" == "YOUR_GITHUB_RAW_URL_HERE/singbox.sh" ]; then
        _error "错误：您尚未在脚本中配置 SCRIPT_UPDATE_URL 变量。"
        _warning "请编辑此脚本，找到 SCRIPT_UPDATE_URL 并填入您正确的 GitHub raw 链接。"
        return 1
    fi

    local cache_bust downloaded_version script_name script_path script_url stage backup i j
    local names=("singbox.sh" "advanced_relay.sh" "parser.sh" "xray_manager.sh")
    local targets=("$SELF_SCRIPT_PATH")
    local urls=()
    local stages=() backups=() had_original=()
    cache_bust=$(date +%s)
    urls+=("${SCRIPT_UPDATE_URL}?v=${cache_bust}")

    for script_name in "${names[@]:1}"; do
        script_path="${SINGBOX_DIR}/${script_name}"
        # 与实际执行路径一致：开发/当前目录存在时优先更新它，否则更新生产副本。
        [ -f "${SCRIPT_DIR}/${script_name}" ] && script_path="${SCRIPT_DIR}/${script_name}"
        targets+=("$script_path")
        urls+=("${GITHUB_RAW_BASE}/${script_name}?v=${cache_bust}")
    done

    _info "正在预下载并校验全部脚本组件..."
    for i in "${!names[@]}"; do
        script_name=${names[$i]}
        script_path=${targets[$i]}
        script_url=${urls[$i]}
        mkdir -p "$(dirname "$script_path")" || return 1
        stage=$(mktemp "$(dirname "$script_path")/.${script_name}.stage.XXXXXX") || return 1
        rm -f -- "$stage"
        if ! _download_bash_script_atomic "$script_url" "$stage" "$script_name"; then
            rm -f -- "$stage" "${stages[@]}"
            _error "脚本组件 ${script_name} 下载或校验失败；本地文件均未修改。"
            return 1
        fi
        stages+=("$stage")
    done

    downloaded_version=$(sed -n 's/^export SCRIPT_VERSION="\([^"]*\)".*/\1/p' "${stages[0]}" | head -n 1)
    if [ -z "$downloaded_version" ]; then
        rm -f -- "${stages[@]}"
        _error "下载的主脚本缺少 SCRIPT_VERSION，已拒绝更新。"
        return 1
    fi
    if [[ "$SCRIPT_VERSION" =~ ^[0-9]+$ && "$downloaded_version" =~ ^[0-9]+$ ]] \
        && [ "$((10#$downloaded_version))" -lt "$((10#$SCRIPT_VERSION))" ]; then
        rm -f -- "${stages[@]}"
        _error "仓库版本 v${downloaded_version} 低于本地 v${SCRIPT_VERSION}，已拒绝自动降级。"
        return 1
    fi

    # 所有组件都验证成功后再建立回滚副本。任何一个替换失败都会恢复整组文件。
    for i in "${!targets[@]}"; do
        script_path=${targets[$i]}
        if [ -e "$script_path" ] || [ -L "$script_path" ]; then
            backup=$(mktemp "$(dirname "$script_path")/.${names[$i]}.rollback.XXXXXX") || {
                rm -f -- "${stages[@]}" "${backups[@]}"
                return 1
            }
            if ! cp -p -- "$script_path" "$backup"; then
                rm -f -- "$backup" "${stages[@]}" "${backups[@]}"
                return 1
            fi
            backups+=("$backup")
            had_original+=(1)
        else
            backups+=("")
            had_original+=(0)
        fi
    done

    local commit_failed=0
    for i in "${!targets[@]}"; do
        if ! chmod 755 "${stages[$i]}" || ! mv -f -- "${stages[$i]}" "${targets[$i]}"; then
            commit_failed=1
            break
        fi
    done
    if [ "$commit_failed" -ne 0 ]; then
        _error "脚本组提交失败，正在恢复更新前的全部组件。"
        for j in "${!targets[@]}"; do
            if [ "${had_original[$j]}" -eq 1 ] && [ -n "${backups[$j]}" ]; then
                mv -f -- "${backups[$j]}" "${targets[$j]}" 2>/dev/null || true
            else
                rm -f -- "${targets[$j]}"
            fi
        done
        rm -f -- "${stages[@]}" "${backups[@]}"
        return 1
    fi

    rm -f -- "${stages[@]}" "${backups[@]}"
    _success "脚本组件已作为一个事务完成更新：v${SCRIPT_VERSION} -> v${downloaded_version}"

    # yq 是独立工具，不参与脚本文件事务；失败时明确提示，不伪报全部成功。
    if ! _install_yq; then
        _warning "脚本已更新，但 yq 检查/更新失败，请检查网络后重试。"
    fi

    _info "请重新运行脚本以应用所有变更："
    echo -e "${YELLOW}bash ${SELF_SCRIPT_PATH}${NC}"
    return 0
}

_update_script() {
    _with_state_lock _update_script_locked
    local rc=$?
    [ "$rc" -eq 0 ] && exit 0
    return "$rc"
}

# 守卫函数：检查 sing-box 核心是否已安装
_require_singbox() {
    if [ ! -f "${SINGBOX_BIN}" ]; then
        _error "此功能需要先安装 Sing-box 核心。请前往主菜单【核心管理】-> [15] 进行安装。"
        return 1
    fi
    return 0
}

# [安装/更新 Sing-box 核心] — 最新稳定版或永久固定 v1.13.21
_install_or_update_singbox() {
    local current_ver="未安装" choice confirm
    if [ -f "${SINGBOX_BIN}" ]; then
        current_ver=$(${SINGBOX_BIN} version 2>/dev/null | head -n1 | awk '{print $3}')
        [ -n "$current_ver" ] || current_ver="未知"
    fi

    clear
    echo -e "${CYAN}"
    echo '  ╔═══════════════════════════════════════╗'
    echo '  ║       安装/更新 Sing-box 核心         ║'
    echo '  ╚═══════════════════════════════════════╝'
    echo -e "${NC}"
    if [ "$current_ver" = "未安装" ]; then
        echo -e "  当前版本: ${YELLOW}未安装${NC}"
    else
        echo -e "  当前版本: ${GREEN}v${current_ver}${NC}"
    fi

    if _singbox_core_is_locked; then
        echo -e "  版本策略: ${YELLOW}固定 v${SINGBOX_FIXED_VERSION}（禁止升级）${NC}"
        if [ "$current_ver" != "$SINGBOX_FIXED_VERSION" ]; then
            _warn "检测到固定锁与当前核心版本不一致，请选择 [2] 恢复固定版。"
        fi
    else
        echo -e "  版本策略: ${GREEN}跟随最新稳定版${NC}"
    fi
    echo ""
    echo -e "    ${GREEN}[1]${NC} 安装/更新最新稳定版"
    echo -e "    ${GREEN}[2]${NC} 安装固定版 v${SINGBOX_FIXED_VERSION}（安装后禁止升级）"
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    read -r -p "  请选择 [0-2]: " choice
    case "$choice" in
        1)
            if _singbox_core_is_locked; then
                _error "当前核心已固定为 v${SINGBOX_FIXED_VERSION}，不允许升级到其他版本。"
                _info "如需修复或重装，请选择 [2] 重新安装固定版。"
                return 1
            fi
            _do_update_singbox latest
            ;;
        2)
            if ! _singbox_core_is_locked; then
                _warn "安装完成后，脚本将永久锁定 v${SINGBOX_FIXED_VERSION}，后续菜单不再允许核心升级。"
                read -r -p "  确认安装并锁定固定版？(y/N): " confirm
                [[ "$confirm" =~ ^[Yy]$ ]] || { _info "已取消固定版安装。"; return 0; }
            fi
            _do_update_singbox "$SINGBOX_FIXED_VERSION"
            ;;
        0) return 0 ;;
        *) _error "无效输入，请选择 [0-2]。"; return 1 ;;
    esac
}

# 执行 sing-box 核心的安装/更新
_do_update_singbox() {
    local install_target="${1:-latest}"
    if [ "$install_target" = "latest" ] && _singbox_core_is_locked; then
        _error "固定版锁已启用，拒绝执行 sing-box 核心升级。"
        return 1
    fi
    case "$install_target" in
        latest|"$SINGBOX_FIXED_VERSION") ;;
        *) _error "无效的 sing-box 安装目标: ${install_target}"; return 1 ;;
    esac

    _info "--- 安装/更新 Sing-box 核心 ---"
    # 更新核心时复用已验证的依赖缓存，避免在 128M 容器中再次触发 apk
    # 的高峰内存占用；缓存缺项时 _install_dependencies 仍会自愈安装。
    _install_dependencies
    if ! _install_sing_box "$install_target"; then
        _error "Sing-box 核心安装/更新失败。"
        return 1
    fi

    _success "sing-box 核心已暂存，正在执行配置和服务验证。"
    if [ ! -f "${CONFIG_FILE}" ] || [ ! -f "${CLASH_YAML_FILE}" ]; then
        _info "检测到主配置文件缺失，正在初始化..."
        _initialize_config_files || { _rollback_singbox_binary; return 1; }
    fi
    _init_relay_config
    _ensure_relay_config || { _rollback_singbox_binary; return 1; }
    _secure_state_permissions

    local check_result
    if ! check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
        _error "新核心未通过 config.json + relay.json 组合校验，正在恢复旧核心："
        echo "$check_result"
        _rollback_singbox_binary
        return 1
    fi

    _create_service_files
    _setup_log_cleanup
    _info "正在启动/重启 [主] 服务 (sing-box)..."
    if ! _manage_service restart; then
        _error "新核心启动失败，正在恢复旧核心。"
        _rollback_singbox_binary
        if [ -x "$SINGBOX_BIN" ]; then _manage_service restart >/dev/null 2>&1 || true; fi
        return 1
    fi

    if [ "$install_target" = "$SINGBOX_FIXED_VERSION" ]; then
        if ! _write_singbox_core_lock; then
            _error "固定版本锁写入失败，正在恢复旧核心。"
            _manage_service stop >/dev/null 2>&1 || true
            _rollback_singbox_binary
            if [ -x "$SINGBOX_BIN" ]; then _manage_service restart >/dev/null 2>&1 || true; fi
            return 1
        fi
        _secure_state_permissions
    fi
    _commit_singbox_binary
    if [ "$install_target" = "$SINGBOX_FIXED_VERSION" ]; then
        _success "[主] 服务已使用固定核心 v${SINGBOX_FIXED_VERSION} 启动，版本升级锁已生效。"
    else
        _success "[主] 服务已使用最新稳定核心 v${SINGBOX_STAGED_VERSION:-未知} 启动，更新已提交。"
    fi
}

# [安装/更新 Xray 核心] — 双模态：未装就装、已装就更新
_install_or_update_xray() {
    local xray_bin="/usr/local/bin/xray"
    if [ -f "$xray_bin" ]; then
        local current_ver=$($xray_bin version 2>/dev/null | head -1 | awk '{print $2}')
        _info "当前 Xray 版本: v${current_ver}，正在检查更新..."
    else
        _info "Xray 核心未安装，正在执行首次安装..."
    fi
    _do_update_xray
}

# 执行 Xray 核心的安装/更新 (内联实现，避免依赖 xray_manager.sh 的 source)
_do_update_xray() {
    _info "--- 安装/更新 Xray 核心 ---"
    local xray_bin="/usr/local/bin/xray"
    local xray_dir="/usr/local/etc/xray"
    local is_first_install=false
    [ ! -f "$xray_bin" ] && is_first_install=true
    command -v unzip &>/dev/null || _pkg_install unzip

    local arch=$(uname -m)
    local xray_arch=""
    case "$arch" in
        x86_64|amd64)  xray_arch="64" ;;
        aarch64|arm64) xray_arch="arm64-v8a" ;;
        armv7l)        xray_arch="arm32-v7a" ;;
        *)             _error "Xray 不支持当前架构: $arch"; return 1 ;;
    esac

    local download_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xray_arch}.zip"
    local digest_url="${download_url}.dgst"
    local tmp_dir
    mkdir -p /var/tmp || return 1
    tmp_dir=$(mktemp -d /var/tmp/.xray-install.XXXXXX) || return 1
    local tmp_zip="${tmp_dir}/xray.zip"

    _info "下载地址: ${download_url}"
    if ! wget -qO "$tmp_zip" "$download_url" || ! wget -qO "${tmp_zip}.dgst" "$digest_url"; then
        _error "Xray 安装包或官方摘要下载失败！"
        rm -rf "$tmp_dir"
        return 1
    fi

    local expected actual
    expected=$(awk -F'= *' 'toupper($1) == "SHA2-256" || toupper($1) == "SHA256" {print $2; exit}' "${tmp_zip}.dgst" | tr -d ' \r\n')
    if command -v sha256sum &>/dev/null; then
        actual=$(sha256sum "$tmp_zip" | awk '{print $1}')
    else
        actual=$(openssl dgst -sha256 "$tmp_zip" 2>/dev/null | awk '{print $NF}')
    fi
    if [ -z "$expected" ] || [ -z "$actual" ] || [ "${expected,,}" != "${actual,,}" ]; then
        _error "Xray 安装包 SHA-256 校验失败，已拒绝替换核心。"
        rm -rf "$tmp_dir"
        return 1
    fi

    # 只提取运行所需的三个文件，避免完整展开后再复制核心产生双份页缓存。
    # 这对 128MB 一类低内存容器尤为重要。
    if ! unzip -tq "$tmp_zip" >/dev/null 2>&1 || ! unzip -p "$tmp_zip" xray > "${tmp_dir}/xray"; then
        _error "Xray 解压失败！"
        rm -rf "$tmp_dir"
        return 1
    fi
    local geodata_file
    for geodata_file in geoip.dat geosite.dat; do
        if unzip -p "$tmp_zip" "$geodata_file" > "${tmp_dir}/${geodata_file}" 2>/dev/null; then
            chmod 600 "${tmp_dir}/${geodata_file}" 2>/dev/null || true
        else
            rm -f -- "${tmp_dir}/${geodata_file}"
        fi
    done
    local new_xray="${tmp_dir}/xray"
    [ -f "$new_xray" ] || { _error "压缩包中没有 Xray 可执行文件。"; rm -rf "$tmp_dir"; return 1; }
    chmod 755 "$new_xray" || { rm -rf "$tmp_dir"; return 1; }
    "$new_xray" version >/dev/null 2>&1 || { _error "下载的 Xray 无法执行。"; rm -rf "$tmp_dir"; return 1; }

    mkdir -p "$xray_dir" || { rm -rf "$tmp_dir"; return 1; }
    chmod 700 "$xray_dir" 2>/dev/null || true
    if [ ! -s "${xray_dir}/config.json" ]; then
        printf '%s\n' '{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[]}}' > "${xray_dir}/config.json"
    fi
    [ -s "${xray_dir}/metadata.json" ] || printf '%s\n' '{}' > "${xray_dir}/metadata.json"
    chmod 600 "${xray_dir}/config.json" "${xray_dir}/metadata.json" 2>/dev/null || true
    if ! "$new_xray" run -test -config "${xray_dir}/config.json" >/dev/null 2>&1; then
        _error "新 Xray 核心无法加载现有配置，已取消更新。"
        rm -rf "$tmp_dir"
        return 1
    fi

    local staged_xray backup_xray="" had_old="false"
    staged_xray=$(mktemp "$(dirname "$xray_bin")/.xray.new.XXXXXX") || { rm -rf "$tmp_dir"; return 1; }
    rm -f -- "$staged_xray"
    mv -f -- "$new_xray" "$staged_xray" && chmod 755 "$staged_xray" || { rm -f "$staged_xray"; rm -rf "$tmp_dir"; return 1; }
    if [ -f "$xray_bin" ]; then
        had_old="true"
        backup_xray="$(dirname "$xray_bin")/.xray.rollback.$$"
        cp -p "$xray_bin" "$backup_xray" || { rm -f "$staged_xray"; rm -rf "$tmp_dir"; return 1; }
    fi
    mv -f "$staged_xray" "$xray_bin" || { rm -f "$staged_xray" "$backup_xray"; rm -rf "$tmp_dir"; return 1; }
    [ -f "${tmp_dir}/geoip.dat" ] && mv -f "${tmp_dir}/geoip.dat" "$xray_dir/"
    [ -f "${tmp_dir}/geosite.dat" ] && mv -f "${tmp_dir}/geosite.dat" "$xray_dir/"

    _create_xray_service_from_main
    local service_ok="true"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        if [ "$is_first_install" = true ] || systemctl is-active xray >/dev/null 2>&1; then systemctl reset-failed xray >/dev/null 2>&1 || true; systemctl restart xray 8>&- 9>&- 219>&- || service_ok="false"; fi
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        if [ "$is_first_install" = true ] || rc-service xray status >/dev/null 2>&1; then rc-service xray restart 8>&- 9>&- 219>&- || service_ok="false"; fi
    elif [ "$INIT_SYSTEM" == "direct" ]; then
        mkdir -p "$XRAY_RUNTIME_DIR" && chmod 700 "$XRAY_RUNTIME_DIR" || service_ok="false"
        if [ "$service_ok" = "true" ]; then
            if [ -s "$XRAY_PID_FILE" ]; then
                local xray_pid
                xray_pid=$(cat "$XRAY_PID_FILE" 2>/dev/null)
                _is_pid_running_cmd "$xray_pid" "$xray_bin" && kill "$xray_pid" 2>/dev/null
            fi
            rm -f "$XRAY_PID_FILE"
            nohup "$xray_bin" run -c "${xray_dir}/config.json" >> /var/log/xray.log 2>&1 8>&- 9>&- 219>&- &
            echo $! > "$XRAY_PID_FILE"
            chmod 600 "$XRAY_PID_FILE" 2>/dev/null || true
            sleep 1
            _is_pid_file_running_cmd "$XRAY_PID_FILE" "$xray_bin" || service_ok="false"
        fi
    fi

    if [ "$service_ok" != "true" ]; then
        _error "Xray 新核心启动失败，正在恢复旧核心。"
        if [ "$had_old" = "true" ] && [ -s "$backup_xray" ]; then mv -f "$backup_xray" "$xray_bin"; else rm -f "$xray_bin"; fi
        rm -f "$XRAY_PID_FILE"
        if [ "$had_old" = "true" ] && [ "$INIT_SYSTEM" = "systemd" ]; then systemctl restart xray >/dev/null 2>&1 || true; fi
        if [ "$had_old" = "true" ] && [ "$INIT_SYSTEM" = "openrc" ]; then rc-service xray restart >/dev/null 2>&1 || true; fi
        if [ "$had_old" = "true" ] && [ "$INIT_SYSTEM" = "direct" ]; then
            mkdir -p "$XRAY_RUNTIME_DIR" && chmod 700 "$XRAY_RUNTIME_DIR" 2>/dev/null || true
            nohup "$xray_bin" run -c "${xray_dir}/config.json" >> /var/log/xray.log 2>&1 8>&- 9>&- 219>&- &
            echo $! > "$XRAY_PID_FILE"
            chmod 600 "$XRAY_PID_FILE" 2>/dev/null || true
            sleep 1
            if ! _is_pid_file_running_cmd "$XRAY_PID_FILE" "$xray_bin"; then
                _error "旧 Xray 核心已恢复，但 direct 模式重新启动失败，请检查 /var/log/xray.log。"
                rm -f "$XRAY_PID_FILE"
            fi
        fi
        rm -rf "$tmp_dir"
        return 1
    fi

    rm -f "$backup_xray"
    local version
    version=$($xray_bin version 2>/dev/null | head -1 | awk '{print $2}')
    rm -rf "$tmp_dir"
    _release_install_cache
    _success "Xray-core v${version} 已校验、替换并成功启动。"
}

# 从主脚本创建 Xray 服务文件 (内联实现)
_create_xray_service_from_main() {
    local xray_bin="/usr/local/bin/xray"
    local xray_dir="/usr/local/etc/xray"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        if [ ! -f "/etc/systemd/system/xray.service" ]; then
            cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=${xray_bin} run -c ${xray_dir}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable xray
        fi
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        local openrc_service="/etc/init.d/xray"
        local rewrite_openrc="false"
        if [ ! -f "$openrc_service" ]; then
            rewrite_openrc="true"
        elif grep -Fqx 'pidfile="/run/xray.pid"' "$openrc_service" 2>/dev/null; then
            # 仅迁移本项目旧模板，避免覆盖用户自定义的其他 OpenRC 服务。
            rewrite_openrc="true"
        fi
        if [ "$rewrite_openrc" = "true" ]; then
            local openrc_tmp
            openrc_tmp=$(mktemp /etc/init.d/.xray.XXXXXX) || return 1
            cat > "$openrc_tmp" << 'EOF'
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="run -c /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/singboxlite/xray.pid"

start_pre() {
    checkpath -d -m 0700 /run/singboxlite
}
EOF
            chmod 755 "$openrc_tmp" && mv -f "$openrc_tmp" "$openrc_service" || { rm -f "$openrc_tmp"; return 1; }
            rc-update add xray default 2>/dev/null
        fi
        mkdir -p "$XRAY_RUNTIME_DIR" && chmod 700 "$XRAY_RUNTIME_DIR" 2>/dev/null || true
    fi
}

# --- 进阶功能 (子脚本) ---
_advanced_features() {
    local script_name="advanced_relay.sh"
    local script_path="${SINGBOX_DIR}/${script_name}"
    
    # 优先检测当前目录 (开发者/测试点优先)
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        script_path="$SCRIPT_DIR/$script_name"
    fi

    # 如果都不存在，则下载
    if [ ! -f "$script_path" ]; then
        _info "本地未检测到进阶脚本，正在尝试下载..."
        local download_url="${GITHUB_RAW_BASE}/${script_name}"
        
        if _download_bash_script_atomic "$download_url" "$script_path" "$script_name"; then
            _success "下载成功！"
        else
            _error "下载失败！请检查网络或确认 GitHub 仓库地址。"
            # 清理可能的空文件
            rm -f "$script_path"
            return 1
        fi
    fi

    # 执行脚本
    if [ -f "$script_path" ]; then
        if ! bash -n "$script_path" 2>/dev/null; then
            _error "进阶脚本未通过 Bash 语法检查，已拒绝执行: ${script_path}"
            return 1
        fi
        # 赋予权限并执行
        chmod 755 "$script_path"
        bash "$script_path"
    else
        _error "找不到进阶脚本文件: ${script_path}"
    fi
}

# --- Xray 节点管理 (子脚本) ---
_xray_features() {
    # 前置检查：Xray 核心必须已安装
    if [ ! -f "/usr/local/bin/xray" ]; then
        _error "Xray 核心未安装！请先通过主菜单【核心管理】-> [16] 进行安装。"
        return 1
    fi

    local script_name="xray_manager.sh"
    local script_path="${SINGBOX_DIR}/${script_name}"
    
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        script_path="$SCRIPT_DIR/$script_name"
    fi
    
    if [ ! -f "$script_path" ]; then
        _info "本地未检测到 Xray 管理脚本，正在尝试下载..."
        local download_url="${GITHUB_RAW_BASE}/${script_name}"
        if _download_bash_script_atomic "$download_url" "$script_path" "$script_name"; then
            _success "下载成功！"
        else
            _error "下载失败！请检查网络或确认 GitHub 仓库地址。"
            rm -f "$script_path"
            return 1
        fi
    fi
    
    if [ -f "$script_path" ]; then
        if ! bash -n "$script_path" 2>/dev/null; then
            _error "Xray 管理脚本未通过 Bash 语法检查，已拒绝执行: ${script_path}"
            return 1
        fi
        chmod 755 "$script_path"
        bash "$script_path"
    else
        _error "找不到 Xray 管理脚本: ${script_path}"
    fi
}

_main_menu() {
    while true; do
        clear
        # ASCII Logo
        echo -e "${CYAN}"
        echo '  ____  _             ____            '
        echo ' / ___|(_)_ __   __ _| __ )  _____  __'
        echo ' \___ \| | '\''_ \ / _` |  _ \ / _ \ \/ /'
        echo '  ___) | | | | | (_| | |_) | (_) >  < '
        echo ' |____/|_|_| |_|\__, |____/ \___/_/\_\'
        echo '                |___/    Lite Manager '
        echo -e "${NC}"
        
        # 版本标题
        echo -e "${CYAN}"
        echo "  ╔═══════════════════════════════════════╗"
        echo "  ║         sing-box 管理脚本 v${SCRIPT_VERSION}         ║"
        echo "  ╚═══════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        
        # 获取系统信息
        local os_info="未知"
        if [ -f /etc/os-release ]; then
            os_info=$(grep -E "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -1)
            [ -z "$os_info" ] && os_info=$(grep -E "^NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -1)
        fi
        [ -z "$os_info" ] && os_info=$(uname -s)
        
        # 获取 Sing-box 版本和状态
        local sb_version=""
        local service_status="○ 未知"
        if [ -f "$SINGBOX_BIN" ]; then
            sb_version=" v$($SINGBOX_BIN version 2>/dev/null | head -n1 | awk '{print $3}')"
            if _singbox_core_is_locked; then
                sb_version="${sb_version} [固定]"
            fi
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                if systemctl is-active --quiet sing-box 2>/dev/null; then
                    service_status="${GREEN}● 运行中${NC}"
                else
                    service_status="${RED}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                if rc-service sing-box status 2>/dev/null | grep -q "started"; then
                    service_status="${GREEN}● 运行中${NC}"
                else
                    service_status="${RED}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "direct" ]; then
                if _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                    service_status="${GREEN}● 运行中${NC}"
                else
                    service_status="${RED}○ 已停止${NC}"
                fi
            fi
        else
            service_status="${RED}○ 未安装${NC}"
        fi
        
        # 获取 Argo 状态 (修复 Alpine/BusyBox 的 ps 截断问题：优先使用 PID 文件检测)
        local argo_status="${RED}○ 未安装${NC}"
        if [ -f "$CLOUDFLARED_BIN" ]; then
            local argo_running=false
            # 先迁移元数据中记录的旧 /tmp PID，再遍历受保护运行目录。
            if [ -s "$ARGO_METADATA_FILE" ]; then
                local argo_port
                while IFS= read -r argo_port; do
                    [[ "$argo_port" =~ ^[0-9]+$ ]] || continue
                    _migrate_legacy_argo_state "$argo_port" >/dev/null 2>&1 || true
                done < <(jq -r '.[].local_port // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
            fi
            # 方式1 (精准): 遍历 PID 文件，与守护进程 _argo_keepalive 使用相同的检测方式
            for pid_file in "$RUNTIME_DIR"/argo-*.pid; do
                [ -f "$pid_file" ] || continue
                local pid=$(cat "$pid_file" 2>/dev/null)
                if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
                    argo_running=true
                    break
                fi
            done
            # 方式2 (兜底): PID 文件不存在时，尝试 pgrep 或 ps 匹配进程名
            if [ "$argo_running" = false ]; then
                if command -v pgrep &>/dev/null; then
                    pgrep -x cloudflared &>/dev/null && argo_running=true
                elif ps w 2>/dev/null | grep -v "grep" | grep -q "cloudflared"; then
                    argo_running=true
                fi
            fi
            if [ "$argo_running" = true ]; then
                argo_status="${GREEN}● 运行中${NC}"
            else
                argo_status="${YELLOW}○ 已安装 (未运行)${NC}"
            fi
        fi
        
        # 获取 Xray 版本和状态
        local xray_version=""
        local xray_status="${RED}○ 未安装${NC}"
        if [ -f "/usr/local/bin/xray" ]; then
            xray_version=" v$(/usr/local/bin/xray version 2>/dev/null | head -1 | awk '{print $2}')"
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                if systemctl is-active --quiet xray 2>/dev/null; then
                    xray_status="${GREEN}● 运行中${NC}"
                else
                    xray_status="${YELLOW}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                if rc-service xray status 2>/dev/null | grep -q "started"; then
                    xray_status="${GREEN}● 运行中${NC}"
                else
                    xray_status="${YELLOW}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "direct" ]; then
                if _is_pid_file_running_cmd "$XRAY_PID_FILE" /usr/local/bin/xray; then
                    xray_status="${GREEN}● 运行中${NC}"
                else
                    xray_status="${YELLOW}○ 已停止${NC}"
                fi
            fi
            local xray_nodes=$(jq '.inbounds | length' /usr/local/etc/xray/config.json 2>/dev/null || echo "0")
            xray_status="${xray_status} (${xray_nodes}节点)"
        fi
        
        echo -e "  系统: ${CYAN}${os_info}${NC}  |  模式: ${CYAN}${INIT_SYSTEM}${NC}"
        echo -e "  Sing-box${CYAN}${sb_version}${NC}: ${service_status}  |  Argo: ${argo_status}"
        echo -e "  Xray${CYAN}${xray_version}${NC}: ${xray_status}"
        echo ""
        
        # 节点管理
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${GREEN}[1]${NC} 添加节点          ${GREEN}[2]${NC} Argo 隧道节点"
        echo -e "    ${GREEN}[3]${NC} 查看节点链接      ${GREEN}[4]${NC} 删除节点"
        echo -e "    ${GREEN}[5]${NC} 修改节点"
        echo ""
        
        # 服务控制
        echo -e "  ${CYAN}【服务控制】${NC}"
        echo -e "    ${GREEN}[6]${NC} 重启服务          ${GREEN}[7]${NC} 停止服务"
        echo -e "    ${GREEN}[8]${NC} 查看运行状态      ${GREEN}[9]${NC} 查看实时日志"
        echo -e "    ${GREEN}[10]${NC} 定时重启设置"
        echo -e "    ${GREEN}[11]${NC} 同步系统时间"
        echo ""
        
        # 配置与更新
        echo -e "  ${CYAN}【配置与更新】${NC}"
        echo -e "    ${GREEN}[12]${NC} 检查配置文件    ${GREEN}[13]${NC} 更新脚本"
        echo -e "    ${GREEN}[14]${NC} DNS 设置"
        echo ""
        
        # 核心管理
        echo -e "  ${CYAN}【核心管理】${NC}"
        echo -e "    ${GREEN}[15]${NC} 安装/更新 Sing-box 核心"
        echo -e "    ${GREEN}[16]${NC} 安装/更新 Xray 核心"
        echo -e "    ${RED}[17]${NC} 卸载脚本"
        echo ""
        
        # 进阶功能
        echo -e "  ${CYAN}【进阶功能】${NC}"
        echo -e "    ${GREEN}[18]${NC} 落地/中转/第三方节点导入"
        echo -e "    ${GREEN}[19]${NC} Xray 节点管理"
        echo ""
        
        echo -e "  ─────────────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 退出脚本"
        echo ""
        
        read -p "  请输入选项 [0-19]: " choice
 
        case $choice in
            1) _require_singbox && _show_add_node_menu ;;
            2) _require_singbox && _argo_menu ;;
            3) _require_singbox && _view_nodes ;;
            4) _require_singbox && _delete_node ;;
            5) _require_singbox && _modify_node ;;
            6) _require_singbox && _manage_service "restart" ;;
            7) _require_singbox && _manage_service "stop" ;;
            8) _require_singbox && _manage_service "status" ;;
            9) _require_singbox && _view_log ;;
            10) _require_singbox && _scheduled_restart_menu ;;
            11) _sync_system_time ;;
            12) _require_singbox && _check_config ;;
            13) _update_script ;;
            14) _require_singbox && _dns_config_menu ;;
            15) _install_or_update_singbox ;;
            16) _install_or_update_xray ;;
            17) _uninstall ;; 
            18) _require_singbox && _advanced_features ;;
            19) _xray_features ;;
            0) exit 0 ;;
            *) _error "无效输入，请重试。" ;;
        esac
        echo
        read -n 1 -s -r -p "按任意键返回主菜单..."
    done
}

    # 定时重启功能 - 零依赖版本 (Systemd Timer & OpenRC Logic)
    _scheduled_restart_menu() {
        clear
        echo -e "${CYAN}"
        echo '  ╔═══════════════════════════════════════╗'
        echo '  ║         定时重启 sing-box             ║'
        echo '  ╚═══════════════════════════════════════╝'
        echo -e "${NC}"
        echo ""
        
        # [!] 零依赖策略：不再安装 cron
        # 仅简单的环境预判
        if [ "$INIT_SYSTEM" == "direct" ]; then
            _error "未能识别系统初始化环境 (systemd/openrc)，定时重启功能暂不可用。"
            read -n 1 -s -r -p "按任意键返回..."
            return
        fi

    
    # 获取服务器时间信息
    local server_time=$(date '+%Y-%m-%d %H:%M:%S')
    local server_tz_offset=$(date +%z)  # 如: +0800, +0000, -0500
    local server_tz_name=$(date +%Z 2>/dev/null || echo "Unknown")  # 如: CST, UTC
    
    # 解析时区偏移 (格式: +0800 或 -0500)
    local offset_sign="${server_tz_offset:0:1}"
    local offset_hours="${server_tz_offset:1:2}"
    local offset_mins="${server_tz_offset:3:2}"
    
    # 去除前导零
    offset_hours=$((10#$offset_hours))
    offset_mins=$((10#$offset_mins))
    
    # 计算总偏移分钟数
    local server_offset_mins=$((offset_hours * 60 + offset_mins))
    if [ "$offset_sign" == "-" ]; then
        server_offset_mins=$((-server_offset_mins))
    fi
    
    # 北京时间 = UTC+8 = +480 分钟
    local beijing_offset_mins=480
    local diff_mins=$((beijing_offset_mins - server_offset_mins))
    local diff_hours=$((diff_mins / 60))
    local diff_remaining_mins=$((diff_mins % 60))
    
    # 格式化显示
    local diff_display=""
    if [ $diff_mins -gt 0 ]; then
        diff_display="北京时间比服务器快 ${diff_hours} 小时"
        if [ $diff_remaining_mins -ne 0 ]; then
            diff_display="${diff_display} ${diff_remaining_mins} 分钟"
        fi
    elif [ $diff_mins -lt 0 ]; then
        diff_display="北京时间比服务器慢 $((-diff_hours)) 小时"
        if [ $diff_remaining_mins -ne 0 ]; then
            diff_display="${diff_display} $((-diff_remaining_mins)) 分钟"
        fi
    else
        diff_display="服务器与北京时间同步"
    fi
    
    # 检查当前定时任务状态
    local cron_status="未设置"
    local cron_time=""
    
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        if [ -f "/etc/systemd/system/sing-box-restart.timer" ]; then
            cron_time=$(grep "OnCalendar" /etc/systemd/system/sing-box-restart.timer | cut -d' ' -f2 | cut -d: -f1,2)
            cron_status="已启用 (每天 ${cron_time} 重启 - Systemd)"
        fi
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        if [ -f "/etc/init.d/sing-box-timer" ] && rc-service sing-box-timer status &>/dev/null; then
            cron_time=$(grep "RESTART_TIME=" /etc/init.d/sing-box-timer | cut -d'"' -f2)
            cron_status="已启用 (每天 ${cron_time} 重启 - OpenRC)"
        fi
    fi
    
    echo -e "  ${CYAN}【服务器时间信息】${NC}"
    echo -e "    当前时间: ${GREEN}${server_time}${NC}"
    echo -e "    时区: ${GREEN}${server_tz_name} (UTC${server_tz_offset})${NC}"
    echo -e "    与北京时间: ${YELLOW}${diff_display}${NC}"
    echo ""
    echo -e "  ${CYAN}【定时重启状态】${NC}"
    if [ "$cron_status" != "未设置" ]; then
        echo -e "    状态: ${GREEN}${cron_status}${NC}"
    else
        echo -e "    状态: ${YELLOW}${cron_status}${NC}"
    fi
    echo ""
    echo -e "  ─────────────────────────────────────────"
    echo -e "    ${GREEN}[1]${NC} 设置定时重启"
    echo -e "    ${GREEN}[2]${NC} 查看当前设置"
    echo -e "    ${RED}[3]${NC} 取消定时重启"
    echo ""
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    
    read -p "  请输入选项 [0-3]: " choice
    
    case $choice in
        1)
            echo ""
            echo -e "  ${CYAN}设置定时重启时间${NC}"
            echo -e "  提示: 输入服务器时区的时间 (24小时制)"
            echo ""
            read -p "  请输入重启时间 (格式 HH:MM, 如 04:30): " restart_time
            
            # 验证时间格式
            if [[ ! "$restart_time" =~ ^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$ ]]; then
                _error "时间格式错误！请使用 HH:MM 格式 (如 04:30)"
                return
            fi
            
            local hour=$(echo "$restart_time" | cut -d: -f1)
            local min=$(echo "$restart_time" | cut -d: -f2)
            local time_str=$(printf "%02d:%02d" "$((10#$hour))" "$((10#$min))")

            if [ "$INIT_SYSTEM" == "systemd" ]; then
                # Systemd Timer 方案
                cat > /etc/systemd/system/sing-box-restart.service <<EOF
[Unit]
Description=Sing-box Scheduled Restart
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart sing-box
EOF
                cat > /etc/systemd/system/sing-box-restart.timer <<EOF
[Unit]
Description=Sing-box Scheduled Restart Timer
[Timer]
OnCalendar=*-*-* ${time_str}:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
                systemctl daemon-reload
                systemctl enable --now sing-box-restart.timer
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                # OpenRC 调度服务方案
                cat > /usr/local/bin/sb-timer.sh <<EOF
#!/bin/bash
TARGET_TIME="\$1"
while true; do
    [ "\$(date +%H:%M)" == "\$TARGET_TIME" ] && rc-service sing-box restart && sleep 61
    sleep 30
done
EOF
                chmod +x /usr/local/bin/sb-timer.sh
                cat > /etc/init.d/sing-box-timer <<EOF
#!/sbin/openrc-run
description="Sing-box Scheduled Restart Timer"
command="/usr/local/bin/sb-timer.sh"
command_args="${time_str}"
pidfile="/run/sing-box-timer.pid"
command_background=true
RESTART_TIME="${time_str}"
EOF
                chmod +x /etc/init.d/sing-box-timer
                rc-service sing-box-timer restart 2>/dev/null
                rc-update add sing-box-timer default 2>/dev/null
            fi
            
            _success "定时重启已通过 ${INIT_SYSTEM} 原生组件设置完成！"
            echo ""
            echo -e "  重启时间: ${GREEN}每天 ${time_str}${NC} (服务器时区)"
                
                # 计算对应的北京时间
                local beijing_hour=$((hour + diff_hours))
                local beijing_min=$((min + diff_remaining_mins))
                
                # 处理分钟溢出
                if [ $beijing_min -ge 60 ]; then
                    beijing_min=$((beijing_min - 60))
                    beijing_hour=$((beijing_hour + 1))
                elif [ $beijing_min -lt 0 ]; then
                    beijing_min=$((beijing_min + 60))
                    beijing_hour=$((beijing_hour - 1))
                fi
                
                # 处理小时溢出
                if [ $beijing_hour -ge 24 ]; then
                    beijing_hour=$((beijing_hour - 24))
                elif [ $beijing_hour -lt 0 ]; then
                    beijing_hour=$((beijing_hour + 24))
                fi
                
                echo -e "  对应北京时间: ${YELLOW}$(printf "%02d:%02d" "$beijing_hour" "$beijing_min")${NC}"
            ;;
        2)
            echo ""
            echo -e "  ${CYAN}当前定时任务详情:${NC}"
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                systemctl list-timers sing-box-restart.timer --no-pager
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                rc-service sing-box-timer status
            fi
            ;;
        3)
            echo ""
            if [ "$cron_status" == "未设置" ]; then
                _warning "当前没有设置定时重启"
            else
                read -p "$(echo -e ${YELLOW}"  确定取消定时重启? (y/N): "${NC})" confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    _remove_scheduled_restart_components
                    _success "定时重启已取消，相关系统组件已清理。"
                else
                    _info "已取消操作"
                fi
            fi
            ;;
        0)
            return
            ;;
        *)
            _error "无效输入"
            ;;
    esac
    
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
}

# 主节点创建必须作为一个整体提交：协议生成器会依次修改 JSON、YAML、
# 凭据和 nftables；任一步失败都恢复创建前状态，且只在组合校验通过后重启一次。
_main_create_tx_snapshot_file() {
    local tx_dir="$1" label="$2" source_file="$3"
    if [ -e "$source_file" ] || [ -L "$source_file" ]; then
        [ -f "$source_file" ] || { _error "事务快照目标不是普通文件: $source_file"; return 1; }
        cp -p "$source_file" "${tx_dir}/${label}" || return 1
        : > "${tx_dir}/${label}.present" || return 1
    fi
}

_main_create_tx_restore_file() {
    local tx_dir="$1" label="$2" target_file="$3"
    if [ -f "${tx_dir}/${label}.present" ]; then
        mkdir -p "$(dirname "$target_file")" || return 1
        cp -p "${tx_dir}/${label}" "$target_file" || return 1
    else
        rm -f -- "$target_file" || return 1
    fi
}

_main_create_tx_snapshot() {
    local tx_dir="$1" credential credential_name nft_tables
    mkdir -p "${tx_dir}/credentials" || return 1

    _main_create_tx_snapshot_file "$tx_dir" config.json "$CONFIG_FILE" || return 1
    _main_create_tx_snapshot_file "$tx_dir" metadata.json "$METADATA_FILE" || return 1
    _main_create_tx_snapshot_file "$tx_dir" clash.yaml "$CLASH_YAML_FILE" || return 1
    _main_create_tx_snapshot_file "$tx_dir" argo_metadata.json "$ARGO_METADATA_FILE" || return 1
    _main_create_tx_snapshot_file "$tx_dir" relay.json "$RELAY_CONFIG_FILE" || return 1
    _main_create_tx_snapshot_file "$tx_dir" nft-persist.nft "$NFT_PERSIST_FILE" || return 1
    _main_create_tx_snapshot_file "$tx_dir" nftables.conf /etc/nftables.conf || return 1

    for credential in "$SINGBOX_DIR"/*.pem "$SINGBOX_DIR"/*.key; do
        [ -f "$credential" ] && [ ! -L "$credential" ] || continue
        credential_name="${credential##*/}"
        cp -p "$credential" "${tx_dir}/credentials/${credential_name}" || return 1
    done

    # 该表只归 singboxlite 使用。能够枚举 nftables 时保存完整可回放快照；
    # 不支持 nftables 的容器会由 HY2 自身安全降级为原生多监听。
    if command -v nft >/dev/null 2>&1 && nft_tables=$(nft list tables 2>/dev/null); then
        : > "${tx_dir}/nft.available" || return 1
        if printf '%s\n' "$nft_tables" | grep -Eq "^[[:space:]]*table[[:space:]]+inet[[:space:]]+${NFT_TABLE}[[:space:]]*$"; then
            nft list table inet "$NFT_TABLE" > "${tx_dir}/nft-table.nft" 2>/dev/null || return 1
            : > "${tx_dir}/nft.present" || return 1
        fi
    else
        : > "${tx_dir}/nft.unavailable" || return 1
    fi
}

_main_create_tx_restore_credentials() {
    local tx_dir="$1" credential credential_name restore_failed=0
    while IFS= read -r -d '' credential; do
        credential_name="${credential##*/}"
        if [ ! -f "${tx_dir}/credentials/${credential_name}" ]; then
            rm -f -- "$credential" || restore_failed=1
        fi
    done < <(find "$SINGBOX_DIR" -maxdepth 1 -type f \( -name '*.pem' -o -name '*.key' \) -print0 2>/dev/null)

    for credential in "${tx_dir}/credentials"/*.pem "${tx_dir}/credentials"/*.key; do
        [ -f "$credential" ] || continue
        cp -p "$credential" "${SINGBOX_DIR}/${credential##*/}" || restore_failed=1
    done
    [ "$restore_failed" -eq 0 ]
}

_main_create_tx_remove_new_nft_comments() {
    local tx_dir="$1" tag cleanup_failed=0
    [ -s "$CONFIG_FILE" ] || return 0

    if [ -f "${tx_dir}/config.json.present" ]; then
        while IFS= read -r tag; do
            [ -n "$tag" ] || continue
            _nft_delete_rules_by_comment "singboxlite-hy2-hop-${tag}" || cleanup_failed=1
        done < <(jq -r --slurpfile before "${tx_dir}/config.json" '
            ($before[0].inbounds // [] | map(.tag // "")) as $old
            | .inbounds[]? | (.tag // "") as $tag
            | select($tag != "" and (($old | index($tag)) == null)) | $tag
        ' "$CONFIG_FILE" 2>/dev/null)
    else
        while IFS= read -r tag; do
            [ -n "$tag" ] || continue
            _nft_delete_rules_by_comment "singboxlite-hy2-hop-${tag}" || cleanup_failed=1
        done < <(jq -r '.inbounds[]?.tag // empty' "$CONFIG_FILE" 2>/dev/null)
    fi
    [ "$cleanup_failed" -eq 0 ]
}

_main_create_tx_restore() {
    local tx_dir="$1" restart_required="$2" restore_failed=0

    # nft 可枚举时以整表快照恢复；否则按新增 tag 精确清理可能创建的 HY2 规则。
    if [ -f "${tx_dir}/nft.available" ]; then
        if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            nft delete table inet "$NFT_TABLE" >/dev/null 2>&1 || restore_failed=1
        fi
        if [ -f "${tx_dir}/nft.present" ]; then
            nft -f "${tx_dir}/nft-table.nft" >/dev/null 2>&1 || restore_failed=1
        fi
    elif [ ! -f "${tx_dir}/nft.unavailable" ]; then
        _main_create_tx_remove_new_nft_comments "$tx_dir" || restore_failed=1
    fi

    _main_create_tx_restore_file "$tx_dir" config.json "$CONFIG_FILE" || restore_failed=1
    _main_create_tx_restore_file "$tx_dir" metadata.json "$METADATA_FILE" || restore_failed=1
    _main_create_tx_restore_file "$tx_dir" clash.yaml "$CLASH_YAML_FILE" || restore_failed=1
    _main_create_tx_restore_file "$tx_dir" argo_metadata.json "$ARGO_METADATA_FILE" || restore_failed=1
    _main_create_tx_restore_file "$tx_dir" relay.json "$RELAY_CONFIG_FILE" || restore_failed=1
    _main_create_tx_restore_file "$tx_dir" nft-persist.nft "$NFT_PERSIST_FILE" || restore_failed=1
    _main_create_tx_restore_file "$tx_dir" nftables.conf /etc/nftables.conf || restore_failed=1
    _main_create_tx_restore_credentials "$tx_dir" || restore_failed=1
    _secure_state_permissions

    if [ "$restart_required" -eq 1 ]; then
        _manage_service restart >/dev/null 2>&1 || restore_failed=1
    fi
    [ "$restore_failed" -eq 0 ]
}

_run_main_create_transaction_locked() (
    local tx_dir committed=0 restart_attempted=0 target_rc=0 check_result
    tx_dir=$(mktemp -d /tmp/.singbox-create.XXXXXX) || return 1
    if ! _main_create_tx_snapshot "$tx_dir"; then
        _error "无法完整创建主节点事务快照，操作尚未开始。"
        rm -rf -- "$tx_dir"
        return 1
    fi

    export MAIN_CREATE_TX_ACTIVE=1
    if [ -f "${tx_dir}/nft.available" ]; then
        export MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE=1
    else
        export MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE=0
    fi
    trap 'tx_exit_rc=$?; trap - EXIT INT TERM; if [ "$committed" -ne 1 ]; then if _main_create_tx_restore "$tx_dir" "$restart_attempted"; then _error "主节点创建未提交，已恢复创建前状态。"; rm -rf -- "$tx_dir" || _warn "创建事务已恢复，但快照目录清理失败: $tx_dir"; else _error "主节点创建失败且回滚不完整，请立即检查配置、凭据与 nftables。"; _error "为便于人工恢复，事务快照已保留: $tx_dir"; tx_exit_rc=1; fi; fi; exit "$tx_exit_rc"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    "$@"
    target_rc=$?
    if [ "$target_rc" -ne 0 ]; then
        _error "节点生成步骤失败，正在回滚本次创建事务。"
        return "$target_rc"
    fi

    _ensure_relay_config || return 1
    if ! check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$CONFIG_FILE" "$RELAY_CONFIG_FILE" 2>&1); then
        _error "新节点未通过 config.json + relay.json 组合校验："
        echo "$check_result"
        return 1
    fi

    restart_attempted=1
    if ! _manage_service restart; then
        _error "新节点配置重启失败，正在恢复创建前运行状态。"
        return 1
    fi

    committed=1
    trap - EXIT INT TERM
    rm -rf -- "$tx_dir"
    unset MAIN_CREATE_TX_ACTIVE MAIN_CREATE_TX_NFT_SNAPSHOT_AVAILABLE
    _success "主节点创建事务已通过组合校验并提交。"
    return 0
)

_run_main_create_transaction() {
    _with_state_lock _run_main_create_transaction_locked "$@"
}

# 批量创建节点 (v11.3 深度向导版)
_batch_create_nodes() {
    local input_str="$1"
    if [ -z "$input_str" ]; then
        _info "请输入协议编号 (空格或逗号分隔，如: 1,6,9)"
        _warn "注：批量部署不支持含有 CDN 的协议 (2, 3, 4)"
        read -p "协议列表: " input_str
    fi
    [ -z "$input_str" ] && return 1

    # 1. 解析协议列表
    local proto_ids
    proto_ids=$(printf '%s' "$input_str" | tr ',' ' ' | xargs)
    local proto_count=0
    local has_complex=false 
    local has_sni_req=false 
    local has_hy2=false     
    local has_ss=false      
    local ss_occurences=0

    for pid in $proto_ids; do
        if [[ ! "$pid" =~ ^(1|2|3|4|5|6|7|8|9|10)$ ]]; then
            _error "协议 ID $pid 无效，请输入 1-10 范围内的协议编号。"
            return 1
        fi
        if [[ "$pid" =~ ^(2|3|4)$ ]]; then
            _error "协议 ID $pid (WebSocket/gRPC+TLS) 不支持批量创建，请使用单节点模式单独创建以开启高级 CDN 优化。"
            return 1
        fi
        ((proto_count++))
        if [[ "$pid" == "8" ]]; then
            has_ss=true
            ((ss_occurences++))
        fi
        [[ "$pid" =~ ^(6|8)$ ]] && has_complex=true
        [[ "$pid" =~ ^(1|4|5|6|7)$ ]] && has_sni_req=true
        [[ "$pid" == "6" ]] && has_hy2=true
    done

    [ $proto_count -eq 0 ] && { _error "未选择任何协议"; return 1; }

    # 2. 引导向导
    _info "--- 批量部署引导向导 ---"
    
    # [修复] 强制初始化服务器 IP，防止各协议函数因变量未定义生成空配置
    [ -z "$server_ip" ] && server_ip=$(_get_ip)
    local batch_ip="${server_ip}"
    read -p "请输入批量节点绑定的IP地址 (回车默认: ${server_ip}): " custom_batch_ip
    batch_ip=${custom_batch_ip:-$server_ip}
    export BATCH_IP="$batch_ip"
    
    # 2.1 SNI 收集 (强制净化处理)
    export BATCH_SNI="$DEFAULT_SNI"
    if [ "$has_sni_req" = true ]; then
        read -p "请输入统一伪装域名 (SNI) [默认: $BATCH_SNI]: " input_sni
        input_sni=$(echo "$input_sni" | xargs)
        [ -n "$input_sni" ] && BATCH_SNI="$input_sni"
    fi

    # 2.2 Hy2 专项
    local hy2_obfs="none"
    local hy2_hop="false"
    local hy2_hop_range=""
    if [ "$has_hy2" = true ]; then
        read -p "是否开启 Hysteria2 QUIC 混淆? (y/N): " hy2_q_choice
        [[ "$hy2_q_choice" == "y" ]] && hy2_obfs="salamander"
        read -p "是否开启 Hysteria2 端口跳跃? (y/N): " hy2_h_choice
        if [[ "$hy2_h_choice" == "y" ]]; then
            hy2_hop="true"
            read -p "请输入端口跳跃范围 (如 20000-30000): " hy2_hop_range
        fi
    fi

    # 2.4 SS 专项 (支持多选)
    local ss_variant="1"
    if [ "$has_ss" = true ]; then
        echo "选择 Shadowsocks 批量加密方式 (支持多选，如 1,2,5,6):"
        echo " 1) aes-128-gcm"
        echo " 2) aes-256-gcm"
        echo " 3) chacha20-ietf-poly1305"
        echo " 4) xchacha20-ietf-poly1305"
        echo " 5) 2022-blake3-aes-128-gcm"
        echo " 6) 2022-blake3-aes-256-gcm"
        echo " 7) 2022-blake3-chacha20-poly1305"
        echo " 8) 2022-blake3-aes-256-gcm (带 Padding)"
        read -r -p "选择 [1-8] (默认1): " ss_choice
        ss_variant=${ss_choice:-1}
        local normalized_ss variant
        normalized_ss=$(printf '%s' "$ss_variant" | tr ',' ' ' | xargs)
        for variant in $normalized_ss; do
            [[ "$variant" =~ ^[1-8]$ ]] || { _error "Shadowsocks 加密方式无效，请选择 1-8。"; return 1; }
        done
        [ -n "$normalized_ss" ] || { _error "未选择 Shadowsocks 加密方式。"; return 1; }
        ss_variant=$(printf '%s' "$normalized_ss" | tr ' ' ',')
        # 计算 SS 实际需要的端口数
        local ss_needed
        ss_needed=$(printf '%s' "$normalized_ss" | wc -w)
        # 每个 Shadowsocks 协议 ID (8) 额外需要 (ss_needed - 1) 个端口
        proto_count=$((proto_count + (ss_needed - 1) * ss_occurences))
    fi

    # 与实际创建顺序一一对应，避免此前把 HY2/TUIC 误按 TCP 检查。
    local planned_protocols=()
    local planned_pid planned_variant
    for planned_pid in $proto_ids; do
        case "$planned_pid" in
            6|7) planned_protocols+=("udp") ;;
            8)
                for planned_variant in $(echo "$ss_variant" | tr ',' ' '); do
                    planned_protocols+=("tcp+udp")
                done
                ;;
            *) planned_protocols+=("tcp") ;;
        esac
    done

    # 3. 端口规划
    local ports_list=()
    _info "共需规划 $proto_count 个批量监听端口。"
    while true; do
        read -p "请输入端口号 (范围如 10001-10010 或空格分隔): " p_input
        local current_p_list=()
        local invalid_port=false
        local duplicate_port=false
        local occupied_port=false
        local seen_ports=" "
        p_input=$(printf '%s' "$p_input" | tr ',' ' ' | xargs)
        [ -z "$p_input" ] && { _error "端口不能为空，请重新输入。"; continue; }
        if [[ "$p_input" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start_p=$((10#${BASH_REMATCH[1]}))
            local end_p=$((10#${BASH_REMATCH[2]}))
            if [ "$start_p" -lt 1 ] || [ "$end_p" -gt 65535 ] || [ "$start_p" -gt "$end_p" ]; then
                _error "端口范围无效，应为 1-65535 内的 start-end。"
                continue
            fi
            for ((p=start_p; p<=end_p; p++)); do current_p_list+=("$p"); done
        elif [[ "$p_input" == *"-"* ]]; then
            _error "端口范围格式无效，应使用单一的 start-end。"
            continue
        else
            read -r -a current_p_list <<< "$p_input"
        fi

        local p port_index=0
        for p in "${current_p_list[@]}"; do
            if [[ ! "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
                _error "端口 ${p} 无效，应为 1-65535。"
                invalid_port=true
                break
            fi
            if [[ "$seen_ports" == *" $p "* ]]; then
                _error "端口 ${p} 重复，请重新输入。"
                duplicate_port=true
                break
            fi
            seen_ports="${seen_ports}${p} "
            # 多余端口不会被使用；仅按计划中的协议检查前 proto_count 个。
            if [ "$port_index" -ge "$proto_count" ]; then break; fi
            local planned_proto="${planned_protocols[$port_index]:-tcp}"
            if _check_port_conflict "$p" "$planned_proto" "true"; then
                _error "端口 ${p} 已被占用，请重新输入。"
                occupied_port=true
                break
            fi
            ((port_index++))
        done
        if [ "$invalid_port" = true ] || [ "$duplicate_port" = true ] || [ "$occupied_port" = true ]; then
            continue
        fi
        
        if [ "${#current_p_list[@]}" -lt "$proto_count" ]; then
            _error "输入端口数量不足（仅 ${#current_p_list[@]} 个），请重新输入。"
        else
            ports_list=("${current_p_list[@]}")
            break
        fi
    done

    # 4. 执行安装循环
    local bulk_idx=0
    local proto_array=()
    read -r -a proto_array <<< "$proto_ids"
    local batch_failed=false
    for i in "${!proto_array[@]}"; do
        local pid=${proto_array[$i]}
        
        if [ "$pid" == "8" ]; then
            local ss_variants=$(echo "$ss_variant" | tr ',' ' ')
            for v in $ss_variants; do
                local current_port=${ports_list[$bulk_idx]}
                _info "正在安装 Shadowsocks (变体 $v) 到端口 $current_port..."
                export BATCH_MODE="true"
                export BATCH_PORT="$current_port"
                export BATCH_SS_VARIANT="$v"
                if ! _add_shadowsocks_menu; then
                    batch_failed=true
                    break
                fi
                ((bulk_idx++))
            done
            [ "$batch_failed" = false ] || break
        else
            local current_port=${ports_list[$bulk_idx]}
            _info "正在安装协议 [$pid] 到端口 $current_port..."
            
            export BATCH_MODE="true"
            export BATCH_PORT="$current_port"
            export BATCH_HY2_OBFS="$hy2_obfs"
            export BATCH_HY2_HOP="$hy2_hop_range"

            case $pid in
                1) _add_vless_reality || batch_failed=true ;;
                2) _add_vless_ws_tls || batch_failed=true ;;
                3) _add_trojan_ws_tls || batch_failed=true ;;
                4) _add_vless_grpc_tls || batch_failed=true ;;
                5) _add_anytls || batch_failed=true ;;
                6) _add_hysteria2 || batch_failed=true ;;
                7) _add_tuic || batch_failed=true ;;
                9) _add_vless_tcp || batch_failed=true ;;
                10) _add_socks || batch_failed=true ;;
            esac
            [ "$batch_failed" = false ] || break
            ((bulk_idx++))
        fi
    done

    unset BATCH_MODE BATCH_PORT BATCH_SNI BATCH_HY2_OBFS BATCH_HY2_HOP BATCH_SS_VARIANT BATCH_ANYTLS_MODE BATCH_IP BATCH_GRPC_TLS_DOMAIN BATCH_GRPC_SERVICE_NAME

    if [ "$batch_failed" != false ]; then
        _error "批量创建在第 $((bulk_idx + 1)) 个节点失败，整批操作将回滚。"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}══════════════════ 批量创建完成提示 ══════════════════${NC}"
    _success "所有节点已按直连模式部署完毕。"
    _info "所有批量节点已就绪，您可以运行 sb 查看具体配置。"
    echo -e "${YELLOW}══════════════════════════════════════════════════════${NC}"

    _success "批量创建任务已全部完成。"
    return 0
}

_show_add_node_menu() {
    [ -z "$server_ip" ] && _init_server_ip
    clear
    echo -e "${CYAN}"
    echo '  ╔═══════════════════════════════════════╗'
    echo '  ║          sing-box 添加节点            ║'
    echo '  ╚═══════════════════════════════════════╝'
    echo -e "${NC}"
    echo ""
    
    echo -e "  ${CYAN}【协议选择】${NC}"
    echo -e "    ${GREEN}[1]${NC} VLESS + TCP + Reality + Vision"
    echo -e "    ${GREEN}[2]${NC} VLESS (WebSocket+TLS)"
    echo -e "    ${GREEN}[3]${NC} Trojan (WebSocket+TLS)"
    echo -e "    ${GREEN}[4]${NC} VLESS (gRPC+TLS)"
    echo -e "    ${GREEN}[5]${NC} AnyTLS"
    echo -e "    ${GREEN}[6]${NC} Hysteria2"
    echo -e "    ${GREEN}[7]${NC} TUICv5"
    echo -e "    ${GREEN}[8]${NC} Shadowsocks"
    echo -e "    ${GREEN}[9]${NC} VLESS (TCP)"
    echo -e "    ${GREEN}[10]${NC} SOCKS5"
    echo ""
    
    echo -e "  ${CYAN}【快捷功能】${NC}"
    echo -e "   ${GREEN}[11]${NC} 批量创建节点"
    echo ""
    
    echo -e "  ─────────────────────────────────────────"
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    
    read -p "  请输入选项 [0-11]: " choice

    # 如果输入包含逗号或空格，自动进入批量处理模式
    if [[ "$choice" == *","* ]] || [[ "$choice" == *" "* ]]; then
        _run_main_create_transaction _batch_create_nodes "$choice"
        return $?
    fi

    case $choice in
        1) _run_main_create_transaction _add_vless_reality ;;
        2) _run_main_create_transaction _add_vless_ws_tls ;;
        3) _run_main_create_transaction _add_trojan_ws_tls ;;
        4) _run_main_create_transaction _add_vless_grpc_tls ;;
        5) _run_main_create_transaction _add_anytls ;;
        6) _run_main_create_transaction _add_hysteria2 ;;
        7) _run_main_create_transaction _add_tuic ;;
        8) _run_main_create_transaction _add_shadowsocks_menu ;;
        9) _run_main_create_transaction _add_vless_tcp ;;
        10) _run_main_create_transaction _add_socks ;;
        11) _run_main_create_transaction _batch_create_nodes ;;
        0) return ;;
        *) _error "无效输入，请重试。"; return 1 ;;
    esac
}

# --- 脚本入口 ---

main() {
    _check_root
    _detect_init_system
    
    # 强制预创建目录，防止后续 cp/mv 因路径不存在报错 (保底机制)
    mkdir -p "${SINGBOX_DIR}" 2>/dev/null
    chmod 700 "${SINGBOX_DIR}" 2>/dev/null || true
    
    # 1. 首次安装或依赖状态失效时才完整检查，避免每次 sb 进入菜单都触发包管理器
    _install_dependencies
    
    # 2. 根据核心安装状态决定初始化路径
    if [ -f "${SINGBOX_BIN}" ]; then
        # --- sing-box 已安装：执行完整的初始化与自愈检测 ---
        
        # 3. 检查配置文件
        if [ ! -f "${CONFIG_FILE}" ] || [ ! -f "${CLASH_YAML_FILE}" ]; then
             _info "检测到主配置文件缺失，正在初始化..."
             _initialize_config_files
        fi

        # 3.1 初始化中转配置 (配置隔离)
        _init_relay_config
        _ensure_relay_config || { _error "无法初始化 relay.json。"; return 1; }
        
        # 3.2 [关键修复] 清理主配置文件中的旧版残留
        local config_updated=false
        if _cleanup_legacy_config; then
            config_updated=true
        fi
        
        # 3.3 [热修复] 检测并补充 DNS 模块
        if _check_and_fix_dns; then
            config_updated=true
        fi
        
        if [ "$config_updated" = true ]; then
            _manage_service restart
        fi
        
        # [BUG FIX] 检查并修复旧版服务文件
        if [ -f "$SERVICE_FILE" ]; then
            local need_update=false
            if grep -q "\-C " "$SERVICE_FILE"; then
                _warn "检测到旧版服务配置(目录加载模式导致冲突)，正在修复..."
                need_update=true
            fi
            if grep -q "ENABLE_DEPRECATED_" "$SERVICE_FILE"; then
                _warn "检测到 sing-box 1.14 已移除功能的旧兼容环境变量，正在清理..."
                need_update=true
            fi
            if [ "$INIT_SYSTEM" == "openrc" ] && ! grep -q "supervisor=" "$SERVICE_FILE"; then
                _warn "检测到旧版 OpenRC 服务配置，正在修复以兼容 Alpine..."
                need_update=true
            fi
            if [ "$INIT_SYSTEM" == "openrc" ] && { ! grep -Fq "pidfile=\"${PID_FILE}\"" "$SERVICE_FILE" || ! grep -Fq "checkpath -d -m 0700 ${RUNTIME_DIR}" "$SERVICE_FILE"; }; then
                _warn "检测到旧版 OpenRC PID 路径，正在迁移到 ${PID_FILE}..."
                need_update=true
            fi
            if [ "$need_update" = true ]; then
                if [ "$INIT_SYSTEM" == "systemd" ]; then
                     _create_systemd_service
                     systemctl daemon-reload
                elif [ "$INIT_SYSTEM" == "openrc" ]; then
                     _create_openrc_service
                fi
                if { [ "$INIT_SYSTEM" == "systemd" ] && systemctl is-active sing-box >/dev/null 2>&1; } || { [ "$INIT_SYSTEM" == "openrc" ] && rc-service sing-box status >/dev/null 2>&1; }; then
                    _manage_service restart
                fi
                _success "服务配置修复完成。"
            fi
        fi

        # 4. 首次安装或服务文件缺失时才创建，避免每次进入菜单都重写服务文件
        if [ -n "$SERVICE_FILE" ] && [ ! -f "$SERVICE_FILE" ]; then
            _create_service_files
        elif [ "$INIT_SYSTEM" == "direct" ] && [ ! -f "$LOG_FILE" ]; then
            touch "$LOG_FILE"
        fi
        _setup_log_cleanup
        _secure_state_permissions
    else
        # --- sing-box 未安装：仅显示提示，不自动安装 ---
        _warn "sing-box 核心未安装。请通过主菜单【核心管理】进行安装。"
    fi
    
    _main_menu
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        keepalive)
            _argo_keepalive
            exit 0
            ;;
        cleanup-logs)
            _cleanup_runtime_logs
            exit $?
            ;;
        *)
            shift
            ;;
    esac
done

main

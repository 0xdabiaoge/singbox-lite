#!/bin/bash

# 本脚本会写入节点密码、私钥和分享链接；禁止新文件继承宽松权限。
umask 077

# 核心环境定义
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
SINGBOX_DIR="/usr/local/etc/sing-box"
SINGBOX_BIN="/usr/local/bin/sing-box"
GITHUB_RAW_BASE="https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main"

# [整合方案] 检测父进程导出的工具函数
# 如果独立运行且函数缺失，可在此定义最简兜底逻辑 (可选)
# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 核心工具函数
_url_encode() {
    # [修复] 使用 jq 内建 @uri 过滤器，完美处理 UTF-8 多字节字符
    printf '%s' "$1" | jq -sRr @uri
}

if ! declare -f _cert_sha256_hex >/dev/null 2>&1; then
    _cert_sha256_hex() {
        local cert_path="$1"
        [ -f "$cert_path" ] || return 1
        openssl x509 -in "$cert_path" -noout -fingerprint -sha256 2>/dev/null | \
            awk -F= 'NR==1 { gsub(":", "", $2); print tolower($2) }'
    }
fi

# 打印消息函数 (强制重定向到 stderr，防止干扰变量捕获)
if ! declare -f _info >/dev/null; then
    _info() { echo -e "${CYAN}[信息] $1${NC}" >&2; }
    _error() { echo -e "${RED}[错误] $1${NC}" >&2; }
    _success() { echo -e "${GREEN}[成功] $1${NC}" >&2; }
    _warn() { echo -e "${YELLOW}[注意] $1${NC}" >&2; }
fi

# --- 全局变量 ---
# 工具路径
YQ_BINARY="/usr/local/bin/yq"

# 配置文件路径
MAIN_CONFIG_FILE="${SINGBOX_DIR}/config.json"
MAIN_METADATA_FILE="${SINGBOX_DIR}/metadata.json"
RELAY_AUX_DIR="${SINGBOX_DIR}"
RELAY_CLASH_YAML="${RELAY_AUX_DIR}/clash.yaml"
RELAY_CONFIG_FILE="${RELAY_AUX_DIR}/relay.json"
STATE_LOCK_FILE="${SINGBOX_DIR}/.singboxlite.lock"
RUN_DIR="/run/singboxlite"
SINGBOX_PID_FILE="${RUN_DIR}/sing-box.pid"
STATE_LOCK_FD=""
STATE_LOCK_OWNED="false"

_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

_valid_ipv4_literal() {
    local addr="$1" octet
    local -a octets
    IFS='.' read -r -a octets <<< "$addr"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        [ "${#octet}" -eq 1 ] || [[ "$octet" != 0* ]] || return 1
        [ "$octet" -le 255 ] || return 1
    done
}

_ipv6_side_count() {
    local side="$1" group count=0 index=0
    local -a groups
    [ -z "$side" ] && { echo 0; return 0; }
    IFS=':' read -r -a groups <<< "$side"
    for group in "${groups[@]}"; do
        [ -n "$group" ] || return 1
        if [[ "$group" == *.* ]]; then
            [ "$index" -eq $((${#groups[@]} - 1)) ] || return 1
            _valid_ipv4_literal "$group" || return 1
            count=$((count + 2))
        else
            [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
            count=$((count + 1))
        fi
        index=$((index + 1))
    done
    echo "$count"
}

_valid_ipv6_literal() {
    local addr="$1" prefix suffix prefix_count suffix_count total
    [[ "$addr" == *:* && "$addr" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    if [[ "$addr" == *::* ]]; then
        prefix="${addr%%::*}"
        suffix="${addr#*::}"
        [[ "$suffix" != *::* ]] || return 1
        [[ "$prefix" != *.* ]] || return 1
        prefix_count=$(_ipv6_side_count "$prefix") || return 1
        suffix_count=$(_ipv6_side_count "$suffix") || return 1
        total=$((prefix_count + suffix_count))
        [ "$total" -lt 8 ]
    else
        total=$(_ipv6_side_count "$addr") || return 1
        [ "$total" -eq 8 ]
    fi
}

_valid_hostname() {
    local host="$1" label
    local -a labels
    host="${host%.}"
    [ -n "$host" ] && [ "${#host}" -le 253 ] || return 1
    [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    IFS='.' read -r -a labels <<< "$host"
    for label in "${labels[@]}"; do
        [ -n "$label" ] && [ "${#label}" -le 63 ] || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

_valid_server_address() {
    if [[ "$1" =~ ^[0-9.]+$ ]]; then
        _valid_ipv4_literal "$1"
    elif [[ "$1" == *:* ]]; then
        _valid_ipv6_literal "$1"
    else
        _valid_hostname "$1"
    fi
}

if ! declare -f _flock_wait >/dev/null 2>&1; then
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
fi

# 所有脚本共用同一把状态锁。父脚本持锁调用时通过环境变量避免二次加锁。
_state_lock_acquire() {
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" = "1" ]; then
        return 0
    fi
    if ! command -v flock >/dev/null 2>&1; then
        _error "缺少 flock，无法安全修改共享配置"
        return 1
    fi
    mkdir -p "$SINGBOX_DIR" || return 1
    chmod 700 "$SINGBOX_DIR" 2>/dev/null || true
    exec {STATE_LOCK_FD}>"$STATE_LOCK_FILE" || return 1
    if ! _flock_wait "$STATE_LOCK_FD" 30; then
        exec {STATE_LOCK_FD}>&-
        STATE_LOCK_FD=""
        _error "等待共享配置锁超时（30 秒），请稍后重试"
        return 1
    fi
    export SINGBOXLITE_LOCK_HELD=1
    STATE_LOCK_OWNED="true"
}

_state_lock_release() {
    [ "$STATE_LOCK_OWNED" = "true" ] || return 0
    flock -u "$STATE_LOCK_FD" 2>/dev/null || true
    exec {STATE_LOCK_FD}>&-
    STATE_LOCK_FD=""
    STATE_LOCK_OWNED="false"
    unset SINGBOXLITE_LOCK_HELD
}

trap '_state_lock_release' EXIT
trap '_state_lock_release; exit 130' INT TERM

_secure_state_file() {
    [ -e "$1" ] && chmod 600 "$1" 2>/dev/null || true
}

_make_same_dir_tmp() {
    local file="$1"
    mktemp "${file}.tmp.XXXXXX"
}

_prepare_run_dir() {
    if [ -L "$RUN_DIR" ]; then
        _error "运行目录不能是符号链接: $RUN_DIR"
        return 1
    fi
    mkdir -p "$RUN_DIR" || return 1
    chmod 700 "$RUN_DIR" || return 1
}

# [修复] 独立定义 _install_yq，确保子脚本可独立运行
_install_yq() {
    if [ ! -x "$YQ_BINARY" ] || ! "$YQ_BINARY" --version >/dev/null 2>&1; then
        _info "安装 yq..."
        local arch tmp checksums_tmp order_tmp release_json release_tag asset expected_sha actual_sha sha_line sha_field
        arch=$(uname -m)
        case $arch in
            x86_64|amd64) arch='amd64' ;;
            aarch64|arm64) arch='arm64' ;;
            armv7l|armv7|armhf) arch='arm' ;;
            *) _error "yq 不支持当前架构: $arch"; return 1 ;;
        esac
        asset="yq_linux_${arch}"
        tmp=$(mktemp /tmp/singboxlite-yq.XXXXXX) || return 1
        checksums_tmp=$(mktemp /tmp/singboxlite-yq-checksums.XXXXXX) || { rm -f -- "$tmp"; return 1; }
        order_tmp=$(mktemp /tmp/singboxlite-yq-order.XXXXXX) || { rm -f -- "$tmp" "$checksums_tmp"; return 1; }
        release_json=$(curl -fsSL --max-time 15 https://api.github.com/repos/mikefarah/yq/releases/latest 2>/dev/null) || true
        release_tag=$(printf '%s' "$release_json" | jq -r '.tag_name // empty' 2>/dev/null)
        if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            rm -f -- "$tmp" "$checksums_tmp" "$order_tmp"
            _error "无法解析 yq 官方 release tag"
            return 1
        fi
        local release_base="https://github.com/mikefarah/yq/releases/download/${release_tag}"
        if ! wget -qO "$tmp" "${release_base}/${asset}" \
            || ! wget -qO "$checksums_tmp" "${release_base}/checksums" \
            || ! wget -qO "$order_tmp" "${release_base}/checksums_hashes_order"; then
            rm -f -- "$tmp" "$checksums_tmp" "$order_tmp"
            _error "yq 或官方校验文件下载失败"
            return 1
        fi
        sha_line=$(grep -n -x -m 1 'SHA-256' "$order_tmp" | cut -d: -f1)
        if ! [[ "$sha_line" =~ ^[0-9]+$ ]]; then
            rm -f -- "$tmp" "$checksums_tmp" "$order_tmp"
            _error "yq 官方校验文件缺少 SHA-256 定义"
            return 1
        fi
        sha_field=$((sha_line + 1))
        expected_sha=$(awk -v name="$asset" -v field="$sha_field" '
            $1 == name { count++; value=$field }
            END { if (count == 1) print tolower(value) }
        ' "$checksums_tmp")
        actual_sha=$(openssl dgst -sha256 "$tmp" 2>/dev/null | awk '{print tolower($NF)}')
        if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || [ "$actual_sha" != "$expected_sha" ]; then
            rm -f -- "$tmp" "$checksums_tmp" "$order_tmp"
            _error "yq SHA-256 校验失败，拒绝安装"
            return 1
        fi
        rm -f -- "$checksums_tmp" "$order_tmp"
        if ! chmod 755 "$tmp" || ! "$tmp" --version >/dev/null 2>&1 \
            || ! mv -f "$tmp" "$YQ_BINARY"; then
            rm -f -- "$tmp"
            _error "yq 下载或完整性自检失败"
            return 1
        fi
    fi
}

# 核心环境检测 (与主脚本 singbox.sh 保持一致)
_detect_init_system() {
    if [ -f /sbin/openrc-run ] || command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    elif command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        INIT_SYSTEM="systemd"
    else
        INIT_SYSTEM="direct"
    fi
}
[ -z "$INIT_SYSTEM" ] && _detect_init_system

# 公网 IP 获取 (带全局缓存)
server_ip=""
_get_public_ip() {
    [ -n "$server_ip" ] && [ "$server_ip" != "null" ] && { echo "$server_ip"; return; }
    local ip=$(timeout 5 curl -fsS4 --max-time 2 https://icanhazip.com 2>/dev/null || timeout 5 curl -fsS4 --max-time 2 https://ipinfo.io/ip 2>/dev/null)
    [ -z "$ip" ] && ip=$(timeout 5 curl -fsS6 --max-time 2 https://icanhazip.com 2>/dev/null || timeout 5 curl -fsS6 --max-time 2 https://ipinfo.io/ip 2>/dev/null)
    ip="${ip//$'\r'/}"
    ip="${ip//$'\n'/}"
    if [[ ! "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ && ! "$ip" =~ ^[0-9A-Fa-f:]+$ ]]; then
        ip=""
    fi
    server_ip="$ip"
    echo "$ip"
}

# 端口冲突检测 (与主脚本 singbox.sh 保持一致，区分 TCP/UDP)
_check_port_occupied() {
    local port=$1
    local proto=${2:-tcp}
    _valid_port "$port" || return 1
    if [[ "$proto" == "tcp" ]]; then
        if command -v ss &>/dev/null; then
            ss -lnpt | grep -q ":${port} " && return 0
        elif command -v netstat &>/dev/null; then
            netstat -lnpt | grep -q ":${port} " && return 0
        fi
    else
        if command -v ss &>/dev/null; then
            ss -lnpu | grep -q ":${port} " && return 0
        elif command -v netstat &>/dev/null; then
            netstat -lnpu | grep -q ":${port} " && return 0
        fi
    fi
    return 1
}

_json_config_port_conflict() {
    local file="$1" port="$2" proto="$3" exclude_tag="${4:-}"
    [ -s "$file" ] || return 1
    jq -e --argjson port "$port" --arg proto "$proto" --arg exclude "$exclude_tag" '
        def uses_tcp:
            if (.network? == "udp" or .type == "hysteria2" or .type == "tuic") then false else true end;
        def uses_udp:
            if .network? == "tcp" then false
            elif (.type == "hysteria2" or .type == "tuic" or .type == "shadowsocks" or .type == "socks" or .type == "direct") then true
            else false end;
        any(.inbounds[]?;
            (.tag // "") != $exclude
            and (.listen_port? == $port)
            and (if $proto == "tcp" then uses_tcp else uses_udp end)
        )
    ' "$file" >/dev/null 2>&1
}

_metadata_port_conflict() {
    local port="$1" proto="$2"
    local pf_meta="${RELAY_AUX_DIR}/relay_pf.json"
    [ -s "$pf_meta" ] || return 1
    jq -e --arg p "$port" --arg proto "$proto" '
        .[$p] as $rule
        | $rule != null
        and ($rule.network == $proto or $rule.network == "tcp+udp")
    ' "$pf_meta" >/dev/null 2>&1
}

_port_conflict() {
    local port="$1" proto="$2" exclude_tag="${3:-}"
    _valid_port "$port" || return 0
    _check_port_occupied "$port" "$proto" && return 0
    _json_config_port_conflict "$MAIN_CONFIG_FILE" "$port" "$proto" "$exclude_tag" && return 0
    _json_config_port_conflict "$RELAY_CONFIG_FILE" "$port" "$proto" "$exclude_tag" && return 0
    _json_config_port_conflict "/usr/local/etc/xray/config.json" "$port" "$proto" "$exclude_tag" && return 0
    _metadata_port_conflict "$port" "$proto" && return 0
    return 1
}

_network_port_conflict() {
    local port="$1" network="$2" exclude_tag="${3:-}"
    case "$network" in
        tcp) _port_conflict "$port" tcp "$exclude_tag" ;;
        udp) _port_conflict "$port" udp "$exclude_tag" ;;
        tcp+udp)
            _port_conflict "$port" tcp "$exclude_tag" || _port_conflict "$port" udp "$exclude_tag"
            ;;
        *) return 0 ;;
    esac
}

_is_pid_running_cmd() {
    local pid="$1"
    local pattern="$2"
    [ -n "$pid" ] || return 1
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

# nftables 规则管理 (独立表，避免污染系统其他防火墙规则)
NFT_TABLE="${NFT_TABLE:-singboxlite}"
NFT_PERSIST_FILE="${NFT_PERSIST_FILE:-/etc/nftables.d/singboxlite.nft}"

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
    local entries chain handle delete_failed=0
    command -v nft &>/dev/null || return 0
    entries=$(nft -a list table inet "$NFT_TABLE" 2>/dev/null | awk -v c="comment \"$comment\"" '
        /^[[:space:]]*chain / { chain=$2 }
        index($0, c) && /# handle / { print chain, $NF }
    ')
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
    if [ "$action" = "delete" ]; then
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

_find_pf_udp_conflict_in_range() {
    local start="$1" end="$2"
    local pf_meta="${RELAY_AUX_DIR}/relay_pf.json"
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
    if [ -f "$MAIN_METADATA_FILE" ]; then
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
        ' "$MAIN_METADATA_FILE" 2>/dev/null | head -n 1)
        [ -n "$conflict" ] && { echo "$conflict"; return 0; }
    fi

    local relay_links="${RELAY_AUX_DIR}/relay_links.json"
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

_save_nftables_rules() {
    command -v nft &>/dev/null || return 0
    mkdir -p /etc/nftables.d
    local nft_tmp
    nft_tmp=$(mktemp "${NFT_PERSIST_FILE}.tmp.XXXXXX") || return 1
    if nft list table inet "$NFT_TABLE" > "$nft_tmp" 2>/dev/null \
        && chmod 600 "$nft_tmp" && mv -f "$nft_tmp" "$NFT_PERSIST_FILE"; then
        if [ ! -f /etc/nftables.conf ]; then
            {
                echo '#!/usr/sbin/nft -f'
                echo 'include "/etc/nftables.d/*.nft"'
            } > /etc/nftables.conf
        elif ! grep -q 'singboxlite\.nft\|/etc/nftables\.d/\*\.nft' /etc/nftables.conf 2>/dev/null; then
            echo 'include "/etc/nftables.d/singboxlite.nft"' >> /etc/nftables.conf
        fi
        if command -v systemctl &>/dev/null; then
            systemctl enable nftables >/dev/null 2>&1 || true
        fi
        if command -v rc-update &>/dev/null; then
            rc-update add nftables default >/dev/null 2>&1 || true
        fi
    else
        rm -f -- "$nft_tmp"
        return 1
    fi
}

# 原子修改 JSON (与主脚本 singbox.sh 保持一致，不静默吞掉 jq 错误)
_atomic_modify_json() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local acquired="false" tmp rc=0
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" != "1" ]; then
        _state_lock_acquire || return 1
        acquired="true"
    fi
    tmp=$(_make_same_dir_tmp "$file") || rc=1
    if [ "$rc" -eq 0 ] && jq "$filter" "$file" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$file"; then
        :
    else
        _error "修改JSON失败: $file"
        [ -n "$tmp" ] && rm -f -- "$tmp"
        rc=1
    fi
    [ "$acquired" = "true" ] && _state_lock_release
    return "$rc"
}

_atomic_write_json() {
    local file="$1" payload="$2"
    local acquired="false" tmp rc=0
    printf '%s' "$payload" | jq -e . >/dev/null 2>&1 || return 1
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" != "1" ]; then
        _state_lock_acquire || return 1
        acquired="true"
    fi
    tmp=$(_make_same_dir_tmp "$file") || rc=1
    if [ "$rc" -eq 0 ] && printf '%s\n' "$payload" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$file"; then
        :
    else
        [ -n "$tmp" ] && rm -f -- "$tmp"
        rc=1
    fi
    [ "$acquired" = "true" ] && _state_lock_release
    return "$rc"
}

# 单个原子修改 YAML
_atomic_modify_yaml() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local acquired="false" tmp rc=0
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" != "1" ]; then
        _state_lock_acquire || return 1
        acquired="true"
    fi
    tmp=$(_make_same_dir_tmp "$file") || rc=1
    if [ "$rc" -eq 0 ] && cp -p "$file" "$tmp" && "$YQ_BINARY" eval "$filter" -i "$tmp" 2>/dev/null \
        && chmod 600 "$tmp" && mv -f "$tmp" "$file"; then
        :
    else
        _error "修改 YAML 失败: $file"
        [ -n "$tmp" ] && rm -f -- "$tmp"
        rc=1
    fi
    [ "$acquired" = "true" ] && _state_lock_release
    return "$rc"
}

_check_combined_config() {
    if [ ! -x "$SINGBOX_BIN" ]; then
        _error "sing-box 不存在或不可执行: $SINGBOX_BIN"
        return 1
    fi
    if [ ! -s "$MAIN_CONFIG_FILE" ] || [ ! -s "$RELAY_CONFIG_FILE" ]; then
        _error "主配置或中转配置不存在，无法执行组合校验"
        return 1
    fi
    ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true \
    ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true \
    ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true \
        "$SINGBOX_BIN" check -c "$MAIN_CONFIG_FILE" -c "$RELAY_CONFIG_FILE" >/dev/null
}

_txn_begin() {
    mktemp -d /tmp/singboxlite-relay-txn.XXXXXX
}

_txn_snapshot_file() {
    local dir="$1" key="$2" file="$3"
    if [ -e "$file" ]; then
        cp -p "$file" "$dir/$key"
    else
        : > "$dir/${key}.absent"
    fi
}

_txn_restore_file() {
    local dir="$1" key="$2" file="$3"
    if [ -e "$dir/${key}.absent" ]; then
        rm -f -- "$file"
    elif [ -e "$dir/$key" ]; then
        cp -p "$dir/$key" "$file"
        _secure_state_file "$file"
    fi
}

_txn_cleanup() {
    local dir="$1"
    case "$dir" in
        /tmp/singboxlite-relay-txn.*)
            rm -f -- \
                "$dir/relay" "$dir/relay.absent" \
                "$dir/links" "$dir/links.absent" \
                "$dir/clash" "$dir/clash.absent" \
                "$dir/pf" "$dir/pf.absent" 2>/dev/null || true
            rmdir -- "$dir" 2>/dev/null || true
            ;;
    esac
}

_restart_checked() {
    if ! _check_combined_config; then
        _error "sing-box 组合配置校验失败"
        return 1
    fi
    if ! _manage_service restart; then
        _error "sing-box 服务重启失败"
        return 1
    fi
}

# 服务管理
_manage_service() {
    local action="$1"
    # 中转脚本可能使用独立服务或主服务，此处保持与主脚本一致的逻辑
    local service_pkg="sing-box"
    # 如果检测到中转专用服务文件，则使用单机中转模式
    [ -f "/etc/systemd/system/sing-box-relay.service" ] && service_pkg="sing-box-relay"

    _info "执行服务操作: $action ($service_pkg)..."
    case "$INIT_SYSTEM" in
        systemd) systemctl "$action" "$service_pkg" ;;
        openrc) rc-service "$service_pkg" "$action" ;;
        direct)
            _prepare_run_dir || return 1
            local pid_file="$SINGBOX_PID_FILE"
            local log_file="/var/log/sing-box.log"
            case "$action" in
                start)
                    if _is_pid_file_running_cmd "$pid_file" "$SINGBOX_BIN"; then
                        return 0
                    fi
                    rm -f -- "$pid_file"
                    if [ ! -s "$RELAY_CONFIG_FILE" ]; then
                        _atomic_write_json "$RELAY_CONFIG_FILE" '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' || return 1
                    fi
                    nohup env ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true \
                        ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true \
                        ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true \
                        "$SINGBOX_BIN" run -c "$MAIN_CONFIG_FILE" -c "$RELAY_CONFIG_FILE" \
                        >> "$log_file" 2>&1 &
                    printf '%s\n' "$!" > "$pid_file"
                    chmod 600 "$pid_file" 2>/dev/null || true
                    sleep 1
                    _is_pid_file_running_cmd "$pid_file" "$SINGBOX_BIN"
                    ;;
                stop)
                    if [ -s "$pid_file" ]; then
                        local pid
                        pid=$(cat "$pid_file" 2>/dev/null)
                        if _is_pid_running_cmd "$pid" "$SINGBOX_BIN"; then
                            kill "$pid" 2>/dev/null
                        fi
                    fi
                    rm -f -- "$pid_file"
                    ;;
                restart)
                    _manage_service stop || return 1
                    sleep 1
                    _manage_service start
                    ;;
                status)
                    _is_pid_file_running_cmd "$pid_file" "$SINGBOX_BIN"
                    ;;
            esac
            ;;
        *) _warn "不支持的服务管理系统: ${INIT_SYSTEM}"; return 1 ;;
    esac
}

# 日志记录函数
_log_operation() {
    local operation="$1"
    local details="$2"
    local LOG_FILE="${RELAY_AUX_DIR}/relay_operations.log"
    if [ -d "$RELAY_AUX_DIR" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $operation: $details" >> "$LOG_FILE"
        chmod 600 "$LOG_FILE" 2>/dev/null || true
    fi
}

# YAML 操作辅助函数
_ensure_relay_yaml_groups() {
    [ -x "$YQ_BINARY" ] || return 1
    [ -s "$RELAY_CLASH_YAML" ] || return 1

    _atomic_modify_yaml "$RELAY_CLASH_YAML" \
        '.proxies = (.proxies // []) | .proxy-groups = (.proxy-groups // []) | .rules = (.rules // [])' || return 1

    if ! "$YQ_BINARY" eval -e '.proxy-groups[] | select(.name == "中转节点")' "$RELAY_CLASH_YAML" >/dev/null 2>&1; then
        export RELAY_GROUP_JSON='{"name":"中转节点","type":"select","proxies":["DIRECT"]}'
        _atomic_modify_yaml "$RELAY_CLASH_YAML" '.proxy-groups += [env(RELAY_GROUP_JSON)]' || return 1
    fi
    _atomic_modify_yaml "$RELAY_CLASH_YAML" \
        '(.proxy-groups[] | select(.name == "中转节点") | .proxies) |= (. // [])' || return 1
    if ! "$YQ_BINARY" eval -e '.proxy-groups[] | select(.name == "中转节点") | .proxies[] | select(. == "DIRECT")' "$RELAY_CLASH_YAML" >/dev/null 2>&1; then
        _atomic_modify_yaml "$RELAY_CLASH_YAML" \
            '(.proxy-groups[] | select(.name == "中转节点") | .proxies) += ["DIRECT"]' || return 1
    fi

    if ! "$YQ_BINARY" eval -e '.proxy-groups[] | select(.name == "节点选择")' "$RELAY_CLASH_YAML" >/dev/null 2>&1; then
        export MAIN_GROUP_JSON='{"name":"节点选择","type":"select","proxies":["中转节点","DIRECT"]}'
        _atomic_modify_yaml "$RELAY_CLASH_YAML" '.proxy-groups += [env(MAIN_GROUP_JSON)]' || return 1
    else
        _atomic_modify_yaml "$RELAY_CLASH_YAML" \
            '(.proxy-groups[] | select(.name == "节点选择") | .proxies) |= (. // [])' || return 1
        if ! "$YQ_BINARY" eval -e '.proxy-groups[] | select(.name == "节点选择") | .proxies[] | select(. == "中转节点")' "$RELAY_CLASH_YAML" >/dev/null 2>&1; then
            _atomic_modify_yaml "$RELAY_CLASH_YAML" \
                '(.proxy-groups[] | select(.name == "节点选择") | .proxies) += ["中转节点"]' || return 1
        fi
    fi
    _secure_state_file "$RELAY_CLASH_YAML"
}

_add_node_to_relay_yaml() {
    local proxy_json="$1"
    local proxy_name
    proxy_name=$(echo "$proxy_json" | jq -r .name)
    
    # 使用本地定义的全局 YQ_BINARY
    if [ ! -f "$YQ_BINARY" ]; then
        _warn "未找到 yq 工具，跳过 YAML 配置生成"
        return
    fi
    
    # 检查 YAML 文件是否存在
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        _warn "YAML 配置文件不存在，跳过添加"
        return
    fi
    
    _ensure_relay_yaml_groups || return 1

    # 不允许使用名称覆盖主节点或 Xray 节点；名称是 Clash 分组的引用键。
    export PROXY_NAME="$proxy_name"
    if "$YQ_BINARY" eval -e '.proxies[] | select(.name == strenv(PROXY_NAME))' "$RELAY_CLASH_YAML" >/dev/null 2>&1; then
        _error "Clash 节点名称已存在: ${proxy_name}"
        return 1
    fi

    # 使用环境变量传递 JSON 字符串，确保安全性
    export NODE_JSON="$proxy_json"
    _atomic_modify_yaml "$RELAY_CLASH_YAML" '.proxies += [env(NODE_JSON)]' || return 1
    
    # 使用环境变量避免名称中特殊字符问题
    export PROXY_NAME="$proxy_name"
    _atomic_modify_yaml "$RELAY_CLASH_YAML" '(.proxy-groups[] | select(.name == "中转节点") | .proxies) += [strenv(PROXY_NAME)]' || return 1
    
    _info "已添加节点到 YAML 配置: ${proxy_name}"
}

_remove_node_from_relay_yaml() {
    local proxy_name="$1"
    local proxy_port="${2:-}"
    # 使用本地定义的全局 YQ_BINARY
    
    if [ ! -f "$YQ_BINARY" ]; then
        return
    fi
    
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        return
    fi
    
    # 只删除 metadata 指向的中转节点；同名但不同端口的主/Xray 节点不受影响。
    export PROXY_NAME="$proxy_name"
    export RELAY_PROXY_PORT="$proxy_port"
    _atomic_modify_yaml "$RELAY_CLASH_YAML" '(.proxy-groups[] | select(.name == "中转节点") | .proxies) |= map(select(. != strenv(PROXY_NAME)))' || return 1
    if _valid_port "$proxy_port"; then
        _atomic_modify_yaml "$RELAY_CLASH_YAML" 'del(.proxies[] | select(.name == strenv(PROXY_NAME) and .port == (env(RELAY_PROXY_PORT) | tonumber)))' || return 1
    else
        _warn "缺少中转节点端口，已保留 Clash proxy 以避免误删同名的其他模块节点"
    fi
    
    _info "已从 YAML 配置中删除节点: ${proxy_name}"
}


# 初始化辅助目录
_init_relay_dirs() {
    local acquired="false"
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" != "1" ]; then
        _state_lock_acquire || return 1
        acquired="true"
    fi
    # 确保辅助目录存在
    if [ ! -d "$RELAY_AUX_DIR" ]; then
        mkdir -p "$RELAY_AUX_DIR" || { [ "$acquired" = "true" ] && _state_lock_release; return 1; }
        _info "已创建辅助目录: $RELAY_AUX_DIR"
    fi
    chmod 700 "$RELAY_AUX_DIR" 2>/dev/null || true
    
    # 确保 relay_links.json 存在
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    if [ ! -f "$LINKS_FILE" ]; then
        echo '{}' > "$LINKS_FILE"
        _info "已初始化链接存储文件: $LINKS_FILE"
    fi
    
    # 确保 clash.yaml 存在
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        cat > "$RELAY_CLASH_YAML" << 'EOF'
proxies: []
proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - 中转节点
      - DIRECT
  - name: 中转节点
    type: select
    proxies:
      - DIRECT
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
EOF
        _info "已初始化 YAML 配置文件: $RELAY_CLASH_YAML"
    fi

    # 确保 relay.json 存在
    if [ ! -f "$RELAY_CONFIG_FILE" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE"
        _info "已初始化中转配置文件: $RELAY_CONFIG_FILE"
    fi
    _ensure_relay_yaml_groups || { [ "$acquired" = "true" ] && _state_lock_release; return 1; }
    _secure_state_file "$LINKS_FILE"
    _secure_state_file "$RELAY_CLASH_YAML"
    _secure_state_file "$RELAY_CONFIG_FILE"
    [ -e "${RELAY_AUX_DIR}/relay_pf.json" ] && _secure_state_file "${RELAY_AUX_DIR}/relay_pf.json"
    [ "$acquired" = "true" ] && _state_lock_release
}

# 检查并下载解析脚本
_check_parser() {
    local PARSER_NAME="parser.sh"
    local local_parser="${SCRIPT_DIR}/${PARSER_NAME}"
    local prod_parser="${SINGBOX_DIR}/${PARSER_NAME}"
    local PARSER_BIN=""

    if [ -f "$local_parser" ]; then
        PARSER_BIN="$local_parser"
    elif [ -f "$prod_parser" ]; then
        PARSER_BIN="$prod_parser"
    else
        _info "正在下载解析脚本 (${PARSER_NAME})..."
        local PARSER_URL="${GITHUB_RAW_BASE}/${PARSER_NAME}"
        local parser_tmp
        parser_tmp=$(_make_same_dir_tmp "$prod_parser") || return 1
        if ! timeout 10 wget -qO "$parser_tmp" "$PARSER_URL" \
            || [ ! -s "$parser_tmp" ] || ! bash -n "$parser_tmp" \
            || ! chmod 700 "$parser_tmp" || ! mv -f "$parser_tmp" "$prod_parser"; then
             rm -f -- "$parser_tmp"
             _error "解析脚本下载失败，请检查网络！"
             return 1
        fi
        PARSER_BIN="$prod_parser"
        _success "解析脚本下载成功。"
    fi
    
    if [ ! -s "$PARSER_BIN" ] || ! bash -n "$PARSER_BIN"; then
        _error "解析脚本为空或语法校验失败: $PARSER_BIN"
        return 1
    fi
    # 确保有执行权限
    chmod +x "$PARSER_BIN"
    # 更新全局或局部变量以便后续使用
    _PARSER_PATH="$PARSER_BIN"
}

# 第三方导入只接受明确约定的最小 schema，禁止解析器静默降级传输方式。
_validate_imported_outbound() {
    local mode="$1" payload="$2"
    printf '%s' "$payload" | jq -e --arg mode "$mode" '
        def only_keys($allowed): ((keys_unsorted - $allowed) | length) == 0;
        def base:
            type == "object"
            and (.error? == null)
            and (.server | type == "string" and length > 0)
            and (.server | test("[[:space:]]") | not)
            and (.server_port | type == "number" and floor == . and . >= 1 and . <= 65535)
            and (.tag? == null or (.tag | type == "string"));
        base and
        if $mode == "vless-reality-vision" then
            only_keys(["type","tag","server","server_port","uuid","flow","tls"])
            and .type == "vless"
            and (.uuid | type == "string" and test("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"))
            and .flow == "xtls-rprx-vision"
            and (.tls | only_keys(["enabled","server_name","reality","utls"]))
            and (.tls.enabled == true)
            and (.tls.reality.enabled == true)
            and (.tls.reality | only_keys(["enabled","public_key","short_id"]))
            and (.tls.utls | only_keys(["enabled","fingerprint"]))
            and (.tls.utls.enabled == true)
            and (.tls.utls.fingerprint as $fp | ($fp | type == "string") and (["chrome","firefox","edge","safari","360","qq","ios","android","random","randomized"] | index($fp) != null))
            and (.tls.server_name | type == "string" and length > 0)
            and (.tls.reality.public_key | type == "string" and test("^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"))
            and (.tls.reality.short_id | type == "string" and test("^([0-9A-Fa-f]{2}){0,8}$"))
            and (.transport? == null)
        elif $mode == "vless-tcp" then
            only_keys(["type","tag","server","server_port","uuid"])
            and .type == "vless"
            and (.uuid | type == "string" and test("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"))
            and ((.flow? // "") == "")
            and ((.tls.enabled? // false) == false)
            and (.transport? == null)
        elif $mode == "ss-aes-128-gcm" then
            only_keys(["type","tag","server","server_port","method","password"])
            and .type == "shadowsocks"
            and .method == "aes-128-gcm"
            and (.password | type == "string" and length > 0)
        elif $mode == "ss-aes-256-gcm" then
            only_keys(["type","tag","server","server_port","method","password"])
            and .type == "shadowsocks"
            and .method == "aes-256-gcm"
            and (.password | type == "string" and length > 0)
        elif $mode == "socks5-none" then
            only_keys(["type","tag","server","server_port","version"])
            and .type == "socks" and .version == "5" and (.username? == null) and (.password? == null)
        elif $mode == "socks5-auth" then
            only_keys(["type","tag","server","server_port","version","username","password"])
            and .type == "socks" and .version == "5"
            and (.username | type == "string" and length > 0)
            and (.password | type == "string" and length > 0)
        else false end
    ' >/dev/null 2>&1
}

_manual_socks_outbound() {
    local auth_mode="$1" server port username password
    read -r -p "  SOCKS5 服务器地址（IP 或域名）: " server
    if [[ "$server" =~ ^\[(.*)\]$ ]]; then
        server="${BASH_REMATCH[1]}"
    fi
    if [ -z "$server" ] || [[ "$server" =~ [[:space:]/?\#@] ]] || ! _valid_server_address "$server"; then
        _error "服务器地址无效"
        return 1
    fi
    read -r -p "  SOCKS5 服务器端口 [1-65535]: " port
    if ! _valid_port "$port"; then
        _error "服务器端口无效"
        return 1
    fi
    if [ "$auth_mode" = "auth" ]; then
        read -r -p "  SOCKS5 用户名: " username
        read -r -s -p "  SOCKS5 密码: " password
        echo ""
        if [ -z "$username" ] || [ -z "$password" ]; then
            _error "用户名和密码不能为空"
            return 1
        fi
        jq -n --arg server "$server" --argjson port "$port" --arg username "$username" --arg password "$password" \
            '{type:"socks",tag:"TEMP_TAG",server:$server,server_port:$port,version:"5",username:$username,password:$password}'
    else
        jq -n --arg server "$server" --argjson port "$port" \
            '{type:"socks",tag:"TEMP_TAG",server:$server,server_port:$port,version:"5"}'
    fi
}

# --- 2.1 导入第三方节点 ---
_import_link_config() {
    echo -e "${CYAN}"
    echo '  ╔═══════════════════════════════════════╗'
    echo '  ║     中转机：导入第三方落地节点        ║'
    echo '  ╚═══════════════════════════════════════╝'
    echo -e "${NC}"
    echo -e "    ${YELLOW}[0]${NC} 返回"
    echo -e "    ${GREEN}[1]${NC} VLESS + TCP + Vision + Reality（链接）"
    echo -e "    ${GREEN}[2]${NC} 纯 VLESS + TCP（链接）"
    echo -e "    ${GREEN}[3]${NC} Shadowsocks aes-128-gcm（链接）"
    echo -e "    ${GREEN}[4]${NC} Shadowsocks aes-256-gcm（链接）"
    echo -e "    ${GREEN}[5]${NC} SOCKS5 无认证（手动输入）"
    echo -e "    ${GREEN}[6]${NC} SOCKS5 用户名密码认证（手动输入）"
    echo ""

    local choice parser_mode validation_mode outbound_json parser_status share_link
    read -r -p "  请选择第三方节点类型 [0-6]: " choice
    case "$choice" in
        0) return ;;
        1) parser_mode="vless-reality-vision" ;;
        2) parser_mode="vless-tcp" ;;
        3) parser_mode="ss-aes-128-gcm" ;;
        4) parser_mode="ss-aes-256-gcm" ;;
        5)
            validation_mode="socks5-none"
            outbound_json=$(_manual_socks_outbound none) || return
            ;;
        6)
            validation_mode="socks5-auth"
            outbound_json=$(_manual_socks_outbound auth) || return
            ;;
        *) _error "无效选项"; return ;;
    esac

    if [ -n "$parser_mode" ]; then
        _check_parser || return
        local PARSER_BIN="$_PARSER_PATH"
        read -r -p "  请输入对应类型的节点分享链接: " share_link
        [ -n "$share_link" ] || { _error "节点链接不能为空"; return; }
        _info "正在按 ${parser_mode} 严格解析链接..."
        outbound_json=$(printf '%s\n' "$share_link" | bash "$PARSER_BIN" "$parser_mode")
        parser_status=$?
        if [ "$parser_status" -ne 0 ]; then
            local parser_error
            parser_error=$(printf '%s' "$outbound_json" | jq -r '.error // empty' 2>/dev/null)
            _error "链接解析失败（解析器退出码: ${parser_status}）"
            [ -n "$parser_error" ] && _error "$parser_error"
            return
        fi
        validation_mode="$parser_mode"
    fi

    if ! _validate_imported_outbound "$validation_mode" "$outbound_json"; then
        _error "解析结果不符合所选协议的严格 schema，已拒绝导入"
        return
    fi

    outbound_json=$(printf '%s' "$outbound_json" | jq -c '.tag = "TEMP_TAG"') || {
        _error "解析结果不是有效 JSON"
        return
    }
    local dest_type dest_addr dest_port
    IFS=$'\t' read -r dest_type dest_addr dest_port <<< "$(printf '%s' "$outbound_json" | jq -r '[.type,.server,(.server_port|tostring)] | @tsv')"
    if ! _valid_server_address "$dest_addr"; then
        _error "解析结果中的服务器地址无效"
        return 1
    fi
    _finalize_relay_setup "$dest_type" "$dest_addr" "$dest_port" "$outbound_json"
}

# 检查依赖 (主脚本已预装绝大部分，此处仅做快速校验)
_check_deps() {
    # [修复] 移除 Bash 数组语法，防止在部分环境（如 Ash/Dash）下闪退
    for cmd in jq openssl wget curl flock; do
        if ! command -v "$cmd" &>/dev/null; then
            _error "缺少关键依赖: $cmd"
            _warn "请先运行主脚本 [1) 安装环境]。"
            return 1
        fi
    done
}

_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        _error "此脚本必须使用 root 权限运行"
        return 1
    fi
}

# --- 1. 落地机配置 (生成 Token) ---
_landing_config() {
    echo -e "\n  ${CYAN}【落地机：生成全协议 Token】${NC}"
    _info "正在加载本地落地节点..."
    
    if [ ! -f "$MAIN_CONFIG_FILE" ]; then
        _error "配置文件不存在: $MAIN_CONFIG_FILE"
        _warn "请先在主菜单中添加节点。"
        return
    fi
    
    # 获取本机IP，作为备选
    local server_ip=$(_get_public_ip)
    # 使用主脚本中定义的全局 YQ_BINARY 和路径常量
    local MAIN_CLASH_YAML="/usr/local/etc/sing-box/clash.yaml"
    local METADATA_FILE="/usr/local/etc/sing-box/metadata.json"

    # 获取所有有效的落地节点 (排除 tag 为 direct 的 outbound，获取所有 inbounds)
    local nodes=$(jq -c '.inbounds[] | select(.tag != "direct")' "$MAIN_CONFIG_FILE")

    if [ -z "$nodes" ]; then
        _error "未找到任何落地节点。"
        _warn "请先去主菜单 [1) 添加节点] 创建节点。"
        return
    fi

    echo -e "  ─────────────────────────────────────────"
    local i=1
    local node_list=()
    local has_ss2022=false
    
    while IFS= read -r node; do
        [ -z "$node" ] && continue
        # [资源优化] 合并3次jq为1次
        local _node_fields
        _node_fields=$(echo "$node" | jq -r '[.tag, .type, (.listen_port|tostring), (.method // "")] | @tsv')
        local tag type port method
        IFS=$'\t' read -r tag type port method <<< "$_node_fields"
        
        # [屏蔽逻辑] 屏蔽 SS-2022 节点
        if [ "$type" == "shadowsocks" ] && [[ "$method" == *"2022"* ]]; then
            has_ss2022=true
            continue
        fi
        
        # 尝试从 metadata 中获取自定义名称
        local display_name="$tag"
        if [ -f "$METADATA_FILE" ]; then
            # [资源优化] 合并3次meta jq为1次
            local _meta_fields
            _meta_fields=$(jq -r --arg t "$tag" '.[$t] // {} | [(.type // ""), (.adapter_name // ""), (.adapter_type // "")] | @tsv' "$METADATA_FILE" 2>/dev/null)
            local node_type adapter_name adapter_type
            IFS=$'\t' read -r node_type adapter_name adapter_type <<< "$_meta_fields"
            if [ "$node_type" == "third-party-adapter" ] && [ -n "$adapter_name" ]; then
                display_name="${adapter_name} [${adapter_type}适配层]"
            fi
        fi
        
        echo -e "    ${GREEN}[$i]${NC} ${display_name} (${type}:${port})"
        node_list+=("$node")
        ((i++))
    done <<< "$nodes"
    echo -e "  ─────────────────────────────────────────"
    
    if [ "$has_ss2022" == "true" ]; then
        echo -e "${YELLOW}[注意] 已自动隐藏 Shadowsocks-2022 节点 (因需要同步时间，屏蔽SS2022加密)${NC}"
    fi
    
    read -p "  请选择落地节点编号: " choice
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        return
    fi
    
    local selected_node=${node_list[$((choice-1))]}
    # [资源优化] 合并3次jq为1次 (重复提取tag/type/port)
    local _sel_fields
    _sel_fields=$(echo "$selected_node" | jq -r '[.tag, .type, (.listen_port|tostring)] | @tsv')
    IFS=$'\t' read -r tag type port <<< "$_sel_fields"
    
    # 自动检测地址
    local token_addr="$server_ip"
    local use_auto_detect=false
    if [ -f "$MAIN_CLASH_YAML" ] && [ -f "$YQ_BINARY" ]; then
        local detected_addr=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}') | .server' "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
        if [ -n "$detected_addr" ] && [ "$detected_addr" != "null" ]; then
            token_addr="$detected_addr"
            use_auto_detect=true
            _info "自动检测到连接地址: ${CYAN}${token_addr}${NC}"
        fi
    fi
    
    # 检测落地机监听地址 (适配层强制 127.0.0.1)
    local listen_addr=$(echo "$selected_node" | jq -r '.listen // "::"')
    if [[ "$listen_addr" == "127.0.0.1" || "$listen_addr" == "localhost" ]]; then
        token_addr="127.0.0.1"
    fi
    if [ -z "$token_addr" ]; then
        _error "无法获取有效的落地连接地址"
        return 1
    fi

    # --- 核心改造：全协议出站(Outbound)构造器 ---
    _info "正在构造全协议中转 Token..."
    
    local outbound_json=""
    case "$type" in
        "vless")
            # [资源优化] 合并vless基础字段2次jq为1次
            local uuid flow
            IFS=$'\t' read -r uuid flow <<< "$(echo "$selected_node" | jq -r '[.users[0].uuid, (.users[0].flow // "")] | @tsv')"
            outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg u "$uuid" --arg f "$flow" \
                '{"type":"vless","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"uuid":$u,"flow":$f}')
            
            # [资源优化] 合并TLS字段提取3次jq为1次
            local _tls_fields
            _tls_fields=$(echo "$selected_node" | jq -r '[(.tls.enabled // false | tostring), (.tls.server_name // ""), (.tls.reality.enabled // false | tostring)] | @tsv')
            local tls_enabled sni reality_enabled
            IFS=$'\t' read -r tls_enabled sni reality_enabled <<< "$_tls_fields"
            
            if [ "$tls_enabled" == "true" ]; then
                # 尝试从 clash.yaml 获取 SNI (如果 inbound 里没存)
                if [ -z "$sni" ] && [ -f "$MAIN_CLASH_YAML" ]; then
                    sni=$(${YQ_BINARY} eval ".proxies[] | select(.port == $port) | .servername // .sni" "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
                fi
                [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.amd.com" # 极简保底

                local utls_json='{"enabled":true,"fingerprint":"chrome"}'
                
                if [ "$reality_enabled" == "true" ]; then
                    # Reality 需要从 metadata 读取 publicKey
                    local pbk="" sid=""
                    if [ -f "$MAIN_METADATA_FILE" ]; then
                        # [资源优化] 合并2次meta jq为1次
                        IFS=$'\t' read -r pbk sid <<< "$(jq -r --arg t "$tag" '.[$t] | [(.publicKey // ""), (.shortId // "")] | @tsv' "$MAIN_METADATA_FILE")"
                    fi
                    [ -z "$pbk" ] && _warn "Reality 节点未在 metadata 中找到公钥，可能无法连接。"
                    outbound_json=$(echo "$outbound_json" | jq --arg sni "$sni" --arg pbk "$pbk" --arg sid "$sid" --argjson utls "$utls_json" \
                        '.tls = {enabled:true, server_name:$sni, utls:$utls, reality:{enabled:true, public_key:$pbk, short_id:$sid}}')
                else
                    outbound_json=$(echo "$outbound_json" | jq --arg sni "$sni" --argjson utls "$utls_json" \
                        '.tls = {enabled:true, server_name:$sni, utls:$utls, insecure:true}')
                fi
            fi
            
            # 处理 Transport (WS) - 合并多次jq为1次
            local _ws_fields
            _ws_fields=$(echo "$selected_node" | jq -r '[(.transport.type // ""), (.transport.path // "/"), (.transport.headers.Host // "")] | @tsv')
            local trans_type path host
            IFS=$'\t' read -r trans_type path host <<< "$_ws_fields"
            if [ "$trans_type" == "ws" ]; then
                # 尝试从 clash.yaml 获取 Host
                if [ -z "$host" ] && [ -f "$MAIN_CLASH_YAML" ]; then
                    host=$(${YQ_BINARY} eval ".proxies[] | select(.port == $port) | .\"ws-opts\".headers.Host" "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
                fi
                [ -z "$host" ] || [ "$host" == "null" ] && host="$sni" # 兜底使用 SNI
                
                outbound_json=$(echo "$outbound_json" | jq --arg path "$path" --arg host "$host" \
                    '.transport = {type:"ws", path:$path, headers:{Host:$host}}')
            fi
            ;;
            
        "shadowsocks")
            # [修复] 放弃对密码字段使用 @tsv
            local method=$(echo "$selected_node" | jq -r '.method')
            local password=$(echo "$selected_node" | jq -r '.password')
            outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg m "$method" --arg pw "$password" \
                '{"type":"shadowsocks","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
            ;;
            
        "trojan")
            local password=$(echo "$selected_node" | jq -r '.users[0].password')
            outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg pw "$password" \
                '{"type":"trojan","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"password":$pw}')
            
            # [资源优化] 合并TLS字段提取2次jq为1次
            local _trojan_tls_fields
            _trojan_tls_fields=$(echo "$selected_node" | jq -r '[(.tls.enabled // false | tostring), (.tls.server_name // "")] | @tsv')
            local tls_enabled sni
            IFS=$'\t' read -r tls_enabled sni <<< "$_trojan_tls_fields"
            
            if [ "$tls_enabled" == "true" ]; then
                if [ -z "$sni" ] && [ -f "$MAIN_CLASH_YAML" ]; then
                    sni=$(${YQ_BINARY} eval ".proxies[] | select(.port == $port) | .sni // .servername" "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
                fi
                [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.amd.com"
                outbound_json=$(echo "$outbound_json" | jq --arg sni "$sni" '.tls = {enabled:true, server_name:$sni, insecure:true}')
            fi
            
            # [资源优化] 合并transport字段提取3次jq为1次
            local _trojan_ws_fields
            _trojan_ws_fields=$(echo "$selected_node" | jq -r '[(.transport.type // ""), (.transport.path // "/"), (.transport.headers.Host // "")] | @tsv')
            local trans_type path host
            IFS=$'\t' read -r trans_type path host <<< "$_trojan_ws_fields"
            if [ "$trans_type" == "ws" ]; then
                if [ -z "$host" ] && [ -f "$MAIN_CLASH_YAML" ]; then
                    host=$(${YQ_BINARY} eval ".proxies[] | select(.port == $port) | .\"ws-opts\".headers.Host" "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
                fi
                [ -z "$host" ] || [ "$host" == "null" ] && host="$sni"
                outbound_json=$(echo "$outbound_json" | jq --arg path "$path" --arg host "$host" \
                    '.transport = {type:"ws", path:$path, headers:{Host:$host}}')
            fi
            ;;

        "hysteria2")
            # [修复] 放弃对密钥字段使用 @tsv
            local password=$(echo "$selected_node" | jq -r '.users[0].password')
            local sni=$(echo "$selected_node" | jq -r '.tls.server_name // ""')
            local obfs_type=$(echo "$selected_node" | jq -r '.obfs.type // ""')
            local obfs_pw=$(echo "$selected_node" | jq -r '.obfs.password // ""')
            if [ -z "$sni" ] && [ -f "$MAIN_CLASH_YAML" ]; then
                sni=$(${YQ_BINARY} eval ".proxies[] | select(.port == $port) | .sni" "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
            fi
            [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.amd.com"

            outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg pw "$password" --arg sni "$sni" \
                '{"type":"hysteria2","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"password":$pw,"tls":{"enabled":true,"server_name":$sni,"insecure":true,"alpn":["h3"]}}')
            
            if [ -n "$obfs_type" ] && [ -n "$obfs_pw" ]; then
                outbound_json=$(echo "$outbound_json" | jq --arg ot "$obfs_type" --arg op "$obfs_pw" '.obfs = {type:$ot, password:$op}')
            fi
            ;;

        "tuic")
            # [修复] 放弃对 UUID/Password 使用 @tsv
            local uuid=$(echo "$selected_node" | jq -r '.users[0].uuid')
            local password=$(echo "$selected_node" | jq -r '.users[0].password')
            local sni=$(echo "$selected_node" | jq -r '.tls.server_name // ""')
            local cc=$(echo "$selected_node" | jq -r '.congestion_control // "bbr"')
            
            if [ -z "$sni" ] && [ -f "$MAIN_CLASH_YAML" ]; then
                sni=$(${YQ_BINARY} eval ".proxies[] | select(.port == $port) | .sni" "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
            fi
            [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.amd.com"

            outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sni "$sni" --arg cc "$cc" \
                '{"type":"tuic","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"uuid":$u,"password":$pw,"congestion_control":$cc,"tls":{"enabled":true,"server_name":$sni,"insecure":true,"alpn":["h3"]}}')
            ;;

        "anytls")
            # [资源优化] 合并2次jq为1次
            local password sni
            IFS=$'\t' read -r password sni <<< "$(echo "$selected_node" | jq -r '[.users[0].password, (.tls.server_name // "")] | @tsv')"
            if [ -z "$sni" ] && [ -f "$MAIN_CLASH_YAML" ]; then
                sni=$(${YQ_BINARY} eval ".proxies[] | select(.port == $port) | .sni" "$MAIN_CLASH_YAML" 2>/dev/null | head -n 1)
            fi
            [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.amd.com"
            outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg pw "$password" --arg sni "$sni" \
                '{"type":"anytls","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"password":$pw,"tls":{"enabled":true,"server_name":$sni,"insecure":true}}')
            ;;
            
        *)
            _error "暂不支持对协议 [$type] 自动生成 Token。"
            return
            ;;
    esac
    
    if [ -n "$outbound_json" ]; then
        # 密文与解密口令分开展示，避免旧版 ENC:<口令>:<密文> 的伪加密。
        local passphrase encrypted_token
        passphrase=$(openssl rand -hex 32) || { _error "生成 Token 口令失败"; return; }
        encrypted_token=$(printf '%s' "$outbound_json" | openssl enc -aes-256-cbc -pbkdf2 -salt -a -A -pass fd:3 3<<<"$passphrase" 2>/dev/null)
        if [ -n "$encrypted_token" ]; then
            local token_final="ENC2:${encrypted_token}"
            echo -e "\n  ${GREEN}成功！全协议加密 Token 已生成:${NC}"
            echo -e "  Token: ${YELLOW}${token_final}${NC}"
            echo -e "  解密口令: ${YELLOW}${passphrase}${NC}\n"
            _warn "请通过不同渠道传递 Token 与解密口令；二者同时泄露等同于节点凭据泄露。"
        else
            _error "Token 加密失败；为避免明文泄露，本次不再回退到 Base64"
            return
        fi
        _info "使用说明: 请在中转机上使用 [2] 导入此 Token。"
    else
        _error "Token 生成失败。"
    fi
    
    read -p "  按回车继续..."
}

# 清理由尚未提交的中转创建流程产生的精确资产，不触碰其他模块证书或 PF。
_cleanup_pending_relay_assets() {
    local inbound_tag="$1" listen_port="$2" port_range="$3" cert_path="$4" key_path="$5"
    rm -f -- "$cert_path" "$key_path"
    if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        _nft_apply_redirect_rule delete "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$listen_port" "singboxlite-relay-hop-${inbound_tag}"
        _save_nftables_rules
    fi
}

# --- 通用：完成中转配置 (Inbound + Outbound写入) ---
# 参数: $1=dest_type, $2=dest_addr, $3=dest_port, $4=outbound_json
_finalize_relay_setup() {
    local dest_type="$1"
    local dest_addr="$2"
    local dest_port="$3"
    local outbound_json="$4"
    
    if ! _valid_port "$dest_port" || ! _valid_server_address "$dest_addr"; then
        _error "落地节点服务器地址或端口无效"
        return 1
    fi
    if ! printf '%s' "$outbound_json" | jq -e '
        type == "object"
        and (.type | type == "string" and length > 0)
        and (.server | type == "string" and length > 0)
        and (.server_port | type == "number" and floor == . and . >= 1 and . <= 65535)
    ' >/dev/null 2>&1; then
        _error "落地 outbound JSON 不完整或端口越界"
        return 1
    fi

    _success "已解析落地节点: ${dest_type} -> ${dest_addr}:${dest_port}"
    
    # --- 选择中转入口协议 ---
    echo -e "\n  ${CYAN}【请选择本机的 [中转入口] 协议】${NC}"
    echo -e "    ${GREEN}[1]${NC} VLESS-Reality"
    echo -e "    ${GREEN}[2]${NC} Hysteria2"
    echo -e "    ${GREEN}[3]${NC} TUICv5"
    echo -e "    ${GREEN}[4]${NC} AnyTLS"
    echo ""
    read -p "  请输入选项 [1-4]: " relay_choice
    
    local relay_type=""
    local listen_network="tcp"
    case "$relay_choice" in
        1) relay_type="vless-reality" ;;
        2) relay_type="hysteria2"; listen_network="udp" ;;
        3) relay_type="tuic"; listen_network="udp" ;;
        4) relay_type="anytls" ;;
        *) _error "无效选项"; return ;;
    esac
    
    # --- 配置入口详细信息 ---
    while true; do
        read -p "  请输入本机监听端口 (回车随机): " listen_port
        [[ -z "$listen_port" ]] && listen_port=$(( $(od -An -tu2 -N2 /dev/urandom | tr -d ' ') % 40001 + 10000 ))

        if ! _valid_port "$listen_port"; then
            _error "端口必须是 1-65535 之间的整数"
            continue
        fi
        if _network_port_conflict "$listen_port" "$listen_network"; then
            _error "${listen_network^^} 端口 $listen_port 已被系统或已有配置占用，请重新输入！"
        elif [ "$listen_network" = "udp" ]; then
            hop_conflict=$(_pf_find_hy2_hop_conflict "$listen_port")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                _error "UDP 入口端口 ${listen_port} 落在已有 HY2 端口跳跃范围 ${c_range} 内。"
                _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请换端口。"
                continue
            fi
            _info "端口 $listen_port 可用。"
            break
        else
            _info "端口 $listen_port 可用。"
            break
        fi
    done
    
    read -p "  请输入中转机入口 SNI (回车默认 www.amd.com): " entrance_sni
    [[ -z "$entrance_sni" ]] && entrance_sni="www.amd.com"
    
    local default_name="${dest_type}-Relay-${listen_port}"
    read -p "  请输入节点名称 (回车: ${default_name}): " node_name
    [[ -z "$node_name" ]] && node_name="$default_name"
    if [ -s "$RELAY_CLASH_YAML" ] && [ -x "$YQ_BINARY" ]; then
        export PROXY_NAME="$node_name"
        if "$YQ_BINARY" eval -e '.proxies[] | select(.name == strenv(PROXY_NAME))' "$RELAY_CLASH_YAML" >/dev/null 2>&1; then
            _error "节点名称已存在，请使用唯一名称: $node_name"
            return 1
        fi
    fi
    
    # --- 生成配置 ---
    local tag_suffix="${listen_port}"
    local inbound_tag="${relay_type}-in-${tag_suffix}"
    local outbound_tag="relay-out-${tag_suffix}"
    
    # 更新 outbound_json 中的 tag
    outbound_json=$(echo "$outbound_json" | jq --arg t "$outbound_tag" '.tag = $t')

    # 1. 生成 Inbound (本机入口)
    local inbound_json=""
    local link=""
    local keypair=""
    local pbk=""
    
    # 证书处理 (仅中转入口使用)
    local cert_path="${RELAY_AUX_DIR}/${inbound_tag}.pem"
    local key_path="${RELAY_AUX_DIR}/${inbound_tag}.key"
    if [[ "$relay_type" == "hysteria2" || "$relay_type" == "tuic" || "$relay_type" == "anytls" ]]; then
        _info "正在生成中转入口自签名证书..."
        if ! openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1 \
            || ! openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${entrance_sni}" >/dev/null 2>&1; then
            rm -f -- "$cert_path" "$key_path"
            _error "生成中转入口证书失败"
            return 1
        fi
        chmod 600 "$cert_path" "$key_path" 2>/dev/null || true
    fi

    # 构造路由规则内容 (修复：定义被误删的变量)
    local rule_json=$(jq -n --arg it "$inbound_tag" --arg ot "$outbound_tag" '{"inbound": $it, "outbound": $ot}')
    
    # [作用域修复] 统一获取公网IP，避免在每个分支中重复声明 local server_ip
    local relay_server_ip=$(_get_public_ip)
    if [ -z "$relay_server_ip" ]; then
        rm -f -- "$cert_path" "$key_path"
        _error "无法获取有效公网 IP，已取消创建中转"
        return 1
    fi
    local link_ip="$relay_server_ip"; [[ "$relay_server_ip" == *":"* ]] && link_ip="[$relay_server_ip]"
    
    if [ "$relay_type" == "vless-reality" ]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        keypair=$($SINGBOX_BIN generate reality-keypair)
        local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
        pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
        local sid=$($SINGBOX_BIN generate rand --hex 8)
        
        # 默认开启 XTLS-Vision 流控
        local flow="xtls-rprx-vision"

        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg f "$flow" --arg sn "$entrance_sni" --arg pk "$pk" --arg sid "$sid" \
            '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":$f}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
             
        link="vless://${uuid}@${link_ip}:${listen_port}?encryption=none&flow=${flow}&security=reality&sni=${entrance_sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#$(_url_encode "${node_name}")"
        
    elif [ "$relay_type" == "hysteria2" ]; then
        local password=$($SINGBOX_BIN generate rand --hex 16)
        
        local hop_str=""
        local port_range=""
        read -p "是否为本 Hysteria2 中转入口开启跳跃端口? (y/N): " hop_choice
        if [[ "$hop_choice" == "y" || "$hop_choice" == "Y" ]]; then
            read -p "请输入接收跳转端口范围 (例如 40000-45000): " port_range
            if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                local hop_start="${BASH_REMATCH[1]}"
                local hop_end="${BASH_REMATCH[2]}"
                if [ "$hop_start" -lt 1 ] || [ "$hop_end" -gt 65535 ] || [ "$hop_start" -gt "$hop_end" ]; then
                    _warn "跳跃端口范围无效，已取消该功能。"
                    port_range=""
                else
                    local pf_conflict
                    pf_conflict=$(_find_pf_udp_conflict_in_range "$hop_start" "$hop_end")
                    if [ -n "$pf_conflict" ]; then
                        local c_port c_name c_net c_target
                        IFS=$'\t' read -r c_port c_name c_net c_target <<< "$pf_conflict"
                        _warn "跳跃端口范围 ${port_range} 覆盖已有 ${c_net} 端口转发入口 ${c_port}（${c_name} -> ${c_target}），已取消该功能。"
                        port_range=""
                    fi
                    if [ -n "$port_range" ]; then
                        local hop_conflict
                        hop_conflict=$(_find_udp_hop_conflict_in_range "$hop_start" "$hop_end" "$inbound_tag")
                        if [ -n "$hop_conflict" ]; then
                            local c_tag c_name c_range c_mode
                            IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                            _warn "跳跃端口范围 ${port_range} 与已有跳跃范围 ${c_range} 重叠（${c_name}, ${c_tag}, ${c_mode}），已取消该功能。"
                            port_range=""
                        fi
                    fi
                fi
                
                if [ -n "$port_range" ]; then
                    local nft_comment="singboxlite-relay-hop-${inbound_tag}"
                    if _nft_apply_redirect_rule add "$hop_start" "$hop_end" "$listen_port" "$nft_comment"; then
                        hop_str="&mport=${port_range}"
                        _save_nftables_rules
                        _info "已注入底层 nftables 高效端口映射: UDP ${port_range} -> ${listen_port}"
                    else
                        _warn "环境受限：原生容器 (LXC/Docker) 缺失必需的系统级 nftables NAT 操作权限。"
                        _warn "高级中转为了节点本身的绝对稳定，不支持易崩溃的 JSON 多实例监听平替，现已安全截停并取消本次跳跃设定。"
                        port_range=""
                    fi
                fi
            else
                _warn "跳跃端口格式错误，已取消该功能。"
                port_range=""
            fi
        fi
        
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg sn "$entrance_sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"server_name":$sn,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')

        local cert_pcs=$(_cert_sha256_hex "$cert_path")
        local pin_param=""
        [ -n "$cert_pcs" ] && pin_param="&pinSHA256=${cert_pcs}"
        link="hysteria2://${password}@${link_ip}:${listen_port}?sni=${entrance_sni}&insecure=1&up=10000&down=10000${hop_str}${pin_param}#$(_url_encode "${node_name}")"
        
    elif [ "$relay_type" == "tuic" ]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        local password=$($SINGBOX_BIN generate rand --hex 16)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg pw "$password" --arg sn "$entrance_sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"server_name":$sn,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
            
        link="tuic://${uuid}:${password}@${link_ip}:${listen_port}?sni=${entrance_sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "${node_name}")"
        
    elif [ "$relay_type" == "anytls" ]; then
        local password=$($SINGBOX_BIN generate uuid)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg sn "$entrance_sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"anytls","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"name":"default","password":$pw}],"padding_scheme":["stop=2","0=100-200","1=100-200"],"tls":{"enabled":true,"server_name":$sn,"certificate_path":$cert,"key_path":$key}}')
            
        local cert_pcs=$(_cert_sha256_hex "$cert_path")
        local pin_param=""
        [ -n "$cert_pcs" ] && pin_param="&pcs=${cert_pcs}"
        link="anytls://${password}@${link_ip}:${listen_port}?security=tls&sni=${entrance_sni}&insecure=1&type=tcp${pin_param}#$(_url_encode "${node_name}")"
    fi
    
    # 构造 Clash 客户端节点，随后与 config/metadata 一起事务提交。
    local proxy_json=""
    if [ "$relay_type" == "vless-reality" ]; then
        local uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        local flow=$(echo "$inbound_json" | jq -r '.users[0].flow')
        local pk=$(echo "$inbound_json" | jq -r '.tls.reality.private_key')
        local sid=$(echo "$inbound_json" | jq -r '.tls.reality.short_id[0]')
        local pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$relay_server_ip" --arg p "$listen_port" --arg u "$uuid" --arg sn "$sn" --arg pbk "$pbk" --arg sid "$sid" --arg flow "$flow" \
            '{name:$n,type:"vless",server:$s,port:($p|tonumber),uuid:$u,tls:true,udp:true,network:"tcp",flow:$flow,servername:$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    elif [ "$relay_type" == "hysteria2" ]; then
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$relay_server_ip" --arg p "$listen_port" --arg pw "$password" --arg sn "$sn" \
            '{name:$n,type:"hysteria2",server:$s,port:($p|tonumber),password:$pw,sni:$sn,"skip-cert-verify":true,alpn:["h3"]}')
    elif [ "$relay_type" == "tuic" ]; then
        local uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid')
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$relay_server_ip" --arg p "$listen_port" --arg u "$uuid" --arg pw "$password" --arg sn "$sn" \
            '{name:$n,type:"tuic",server:$s,port:($p|tonumber),uuid:$u,password:$pw,sni:$sn,"skip-cert-verify":true,alpn:["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    elif [ "$relay_type" == "anytls" ]; then
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$relay_server_ip" --arg p "$listen_port" --arg pw "$password" --arg sn "$sn" \
            '{name:$n,type:"anytls",server:$s,port:($p|tonumber),password:$pw,"client-fingerprint":"chrome",udp:true,sni:$sn,alpn:["h2","http/1.1"],"skip-cert-verify":true}')
    fi
    if [ -z "$proxy_json" ]; then
        _error "无法生成中转客户端配置"
        _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"
        return 1
    fi

    _info "正在事务写入中转配置..."
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local txn_dir tmp metadata combined_filter
    _state_lock_acquire || { _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"; return 1; }
    txn_dir=$(_txn_begin) || { _state_lock_release; _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"; return 1; }
    if ! _txn_snapshot_file "$txn_dir" relay "$CONFIG_FILE" \
        || ! _txn_snapshot_file "$txn_dir" links "$LINKS_FILE" \
        || ! _txn_snapshot_file "$txn_dir" clash "$RELAY_CLASH_YAML"; then
        _error "无法创建中转状态快照"
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"
        return 1
    fi

    if _network_port_conflict "$listen_port" "$listen_network"; then
        _error "提交前发现 ${listen_network^^} 端口 ${listen_port} 已被占用"
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"
        return 1
    fi
    export PROXY_NAME="$node_name"
    if "$YQ_BINARY" eval -e '.proxies[] | select(.name == strenv(PROXY_NAME))' "$RELAY_CLASH_YAML" >/dev/null 2>&1; then
        _error "提交前发现 Clash 节点名称已存在: $node_name"
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"
        return 1
    fi

    if jq -e --arg tag "$inbound_tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "中转入口 tag 已存在: $inbound_tag"
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"
        return 1
    fi

    combined_filter=".inbounds = (.inbounds // []) + [$inbound_json] | .outbounds = [$outbound_json] + (.outbounds // []) | .route = (.route // {\"rules\":[]}) | .route.rules = (.route.rules // []) + [$rule_json]"
    if ! _atomic_modify_json "$CONFIG_FILE" "$combined_filter"; then
        _txn_restore_file "$txn_dir" relay "$CONFIG_FILE"
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"
        return 1
    fi

    metadata=$(jq -n --arg link "$link" --arg created "$(date '+%Y-%m-%d %H:%M:%S')" --arg relay_type "$relay_type" \
        --arg landing_type "$dest_type" --arg landing_addr "${dest_addr}:${dest_port}" --arg node_name "$node_name" \
        --argjson listen_port "$listen_port" --arg hop "${port_range:-}" \
        '{link:$link,created_at:$created,relay_type:$relay_type,landing_type:$landing_type,landing_addr:$landing_addr,node_name:$node_name,listen_port:$listen_port} | if $hop != "" then .port_hopping=$hop else . end') || true
    tmp=$(_make_same_dir_tmp "$LINKS_FILE") || true
    if [ -z "$metadata" ] || [ -z "$tmp" ] || ! jq --arg tag "$inbound_tag" --argjson meta "$metadata" '.[$tag] = $meta' "$LINKS_FILE" > "$tmp" \
        || ! chmod 600 "$tmp" || ! mv -f "$tmp" "$LINKS_FILE" || ! _add_node_to_relay_yaml "$proxy_json" \
        || ! _restart_checked; then
        [ -n "$tmp" ] && rm -f -- "$tmp"
        _txn_restore_file "$txn_dir" relay "$CONFIG_FILE"
        _txn_restore_file "$txn_dir" links "$LINKS_FILE"
        _txn_restore_file "$txn_dir" clash "$RELAY_CLASH_YAML"
        _manage_service restart >/dev/null 2>&1 || true
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _cleanup_pending_relay_assets "$inbound_tag" "$listen_port" "${port_range:-}" "$cert_path" "$key_path"
        _error "中转配置提交失败，已恢复原配置"
        return 1
    fi
    _secure_state_file "$CONFIG_FILE"
    _secure_state_file "$LINKS_FILE"
    _secure_state_file "$RELAY_CLASH_YAML"
    _secure_state_file "$cert_path"
    _secure_state_file "$key_path"
    _txn_cleanup "$txn_dir"
    _state_lock_release
    _save_nftables_rules
    _log_operation "CREATE_RELAY" "Type: $relay_type, Port: $listen_port, Landing: ${dest_type}@${dest_addr}:${dest_port}"
    
    echo -e "${YELLOW}═══════════════════ 配置成功 ═══════════════════${NC}"
    _success "中转配置已生效！"
    echo -e "  节点名称: ${GREEN}$node_name${NC}"
    echo -e "  中转协议: ${CYAN}$relay_type${NC}"
    echo -e "  落地地址: ${CYAN}${dest_addr}:${dest_port}${NC}"
    echo -e "  本地监听: ${CYAN}$listen_port${NC}"
    echo -e "分享链接:"
    echo -e "${CYAN}$link${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════════${NC}"
    read -p "  按回车键返回..."
}

# --- 2. 中转机配置 (导入 Token) ---
_relay_config() {
    echo -e "\n  ${CYAN}【配置为 [中转机] (导入 Token)】${NC}"
    echo -e "  请输入来自 [落地机] 的 Token 字符串:"
    echo ""
    read -r token_input
    
    if [ -z "$token_input" ]; then _error "输入为空。"; return; fi
    
    local decoded_json
    
    if [[ "$token_input" == ENC2:* ]]; then
        _info "检测到新版分离式加密 Token。"
        local passphrase encrypted_data
        encrypted_data="${token_input#ENC2:}"
        read -r -s -p "  请输入单独收到的解密口令: " passphrase
        echo ""
        decoded_json=$(printf '%s' "$encrypted_data" | openssl enc -aes-256-cbc -pbkdf2 -d -a -A -pass fd:3 3<<<"$passphrase" 2>/dev/null)
        if [ -z "$decoded_json" ] || ! echo "$decoded_json" | jq . >/dev/null 2>&1; then
            _error "Token 解密失败！密钥可能不正确。"
            return
        fi
        _success "Token 解密成功。"
    elif [[ "$token_input" == ENC:* ]]; then
        _warn "检测到旧版 Token：它把密钥与密文放在一起，不具备有效保密性。"
        _warn "本次仍兼容导入，之后请重新生成 ENC2 Token。"
        local legacy_passphrase legacy_encrypted_data
        legacy_passphrase=$(echo "$token_input" | cut -d':' -f2)
        legacy_encrypted_data=$(echo "$token_input" | cut -d':' -f3-)
        decoded_json=$(printf '%s' "$legacy_encrypted_data" | openssl enc -aes-256-cbc -pbkdf2 -d -a -A -pass fd:3 3<<<"$legacy_passphrase" 2>/dev/null)
        if [ -z "$decoded_json" ] || ! printf '%s' "$decoded_json" | jq . >/dev/null 2>&1; then
            _error "旧版 Token 解密失败"
            return
        fi
    else
        # 向后兼容: 尝试旧版 Base64 解码
        decoded_json=$(echo "$token_input" | base64 -d 2>/dev/null)
        local decode_status=$?
        if [ $decode_status -ne 0 ] || [ -z "$decoded_json" ] || ! echo "$decoded_json" | jq . >/dev/null 2>&1; then
            _error "Token 无效或无法解码！"
            return
        fi
        _warn "检测到旧版未加密 Token，建议在落地机重新生成加密版本。"
    fi
    
    local dest_type=$(echo "$decoded_json" | jq -r '.type')
    local dest_addr=$(echo "$decoded_json" | jq -r '.server // .addr')
    local dest_port=$(echo "$decoded_json" | jq -r '.server_port // .port')
    
    # 构造 outbound
    local outbound_json=""
    
    # 智能检查 Token 类型
    if echo "$decoded_json" | jq -e '.server_port' >/dev/null 2>&1; then
        _info "检测到全协议增强型 Token..."
        outbound_json="$decoded_json"
    else
        _info "检测到旧版基础型 Token，正在转换..."
        if [ "$dest_type" == "vless" ]; then
            local uuid=$(echo "$decoded_json" | jq -r '.uuid')
            outbound_json=$(jq -n --arg ip "$dest_addr" --arg p "$dest_port" --arg u "$uuid" \
                '{"type":"vless","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"uuid":$u,"tls":{"enabled":false}}')
        elif [ "$dest_type" == "shadowsocks" ]; then
            local method=$(echo "$decoded_json" | jq -r '.method')
            local password=$(echo "$decoded_json" | jq -r '.password')
            outbound_json=$(jq -n --arg ip "$dest_addr" --arg p "$dest_port" --arg m "$method" --arg pw "$password" \
                '{"type":"shadowsocks","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
        fi
    fi
    
    if [ -z "$outbound_json" ]; then _error "Token 解析失败"; return; fi
    _finalize_relay_setup "$dest_type" "$dest_addr" "$dest_port" "$outbound_json"
}

# --- 3. 查看中转路由 ---
_view_relays() {
    clear
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║         当前中转链路列表              ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
    
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    if [ ! -f "$CONFIG_FILE" ]; then _error "配置文件不存在。"; return; fi
    
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null and (.outbound | startswith("relay-out-")))' "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$rules" ]; then
        echo -e "\n    ${YELLOW}暂无活跃中转链路${NC}"
        echo ""
        read -p "  按回车键继续..."
        return
    fi
    
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local i=1
    
    while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local metadata=""
        local link=""
        local landing_info="--"
        local node_name="未知节点"
        local relay_type="--"
        
        if [ -f "$LINKS_FILE" ]; then
            metadata=$(jq -r --arg t "$in_tag" '.[$t] // empty' "$LINKS_FILE")
            if [ -n "$metadata" ]; then
                if echo "$metadata" | jq -e '.link' >/dev/null 2>&1; then
                    link=$(echo "$metadata" | jq -r '.link')
                    landing_info=$(echo "$metadata" | jq -r '.landing_addr // "未知"')
                    node_name=$(echo "$metadata" | jq -r '.node_name // "未知节点"')
                    relay_type=$(echo "$metadata" | jq -r '.relay_type // "--"')
                else
                    link="$metadata"
                fi
            fi
        fi

        echo -e "  ${GREEN}[$i]${NC} ${YELLOW}${node_name}${NC}"
        echo -e "      入口索引: ${CYAN}${in_tag}${NC}"
        echo -e "      中转方式: ${relay_type}"
        echo -e "      落地目标: ${landing_info}"
        [ -n "$link" ] && echo -e "      分享链接: ${CYAN}${link}${NC}"
        echo "  -------------------------------------------------"
        ((i++))
    done <<< "$rules"
    
    echo ""
    read -p "  按回车键继续..."
}

# --- 4. 删除中转路由 ---
_clear_all_relays() {
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local txn_dir cleanup_rows relay_tags failed="false"

    _state_lock_acquire || return 1
    txn_dir=$(_txn_begin) || { _state_lock_release; return 1; }
    if ! _txn_snapshot_file "$txn_dir" relay "$CONFIG_FILE" \
        || ! _txn_snapshot_file "$txn_dir" links "$LINKS_FILE" \
        || ! _txn_snapshot_file "$txn_dir" clash "$RELAY_CLASH_YAML"; then
        _error "无法创建中转状态快照，已取消清空"
        _txn_cleanup "$txn_dir"
        _state_lock_release
        return 1
    fi

    cleanup_rows=$(jq -r --slurpfile config "$CONFIG_FILE" '
        to_entries[]
        | .key as $tag
        | [
            $tag,
            (.value.node_name // ""),
            (.value.port_hopping // ""),
            ((.value.listen_port // ([ $config[0].inbounds[]? | select(.tag == $tag) | .listen_port ][0] // "")) | tostring)
          ]
        | @tsv
    ' "$LINKS_FILE" 2>/dev/null || true)

    while IFS=$'\t' read -r tag node_name hop port; do
        [ -z "$tag" ] && continue
        if [ -n "$node_name" ] && ! _remove_node_from_relay_yaml "$node_name" "$port"; then
            failed="true"
            break
        fi
    done <<< "$cleanup_rows"

    relay_tags=$(jq -c '[
        (.route.rules[]? | select(((.outbound? // "") | startswith("relay-out-"))) | .inbound),
        (.inbounds[]? | select((.tag? // "") | test("^(vless-reality|hysteria2|tuic|anytls)-in-[0-9]+$")) | .tag)
    ] | unique' "$CONFIG_FILE" 2>/dev/null)
    [ -n "$relay_tags" ] || relay_tags='[]'

    if [ "$failed" != "true" ]; then
        local clear_filter
        clear_filter="$relay_tags as \$relay_in | [.route.rules[]? | select(((.outbound? // \"\") | startswith(\"relay-out-\"))) | .outbound] as \$relay_out | .inbounds = [(.inbounds // [])[] | select((.tag as \$tag | (\$relay_in | index(\$tag))) == null)] | .outbounds = [(.outbounds // [])[] | select((.tag as \$tag | (\$relay_out | index(\$tag))) == null and ((.tag? // \"\") | startswith(\"relay-out-\") | not))] | .route.rules = [(.route.rules // [])[] | select((.inbound as \$tag | (\$relay_in | index(\$tag))) == null and (((.outbound? // \"\") | startswith(\"relay-out-\")) | not))]"
        _atomic_modify_json "$CONFIG_FILE" "$clear_filter" || failed="true"
        _atomic_modify_json "$LINKS_FILE" '{}' || failed="true"
    fi

    if [ "$failed" = "true" ] || ! _restart_checked; then
        _txn_restore_file "$txn_dir" relay "$CONFIG_FILE"
        _txn_restore_file "$txn_dir" links "$LINKS_FILE"
        _txn_restore_file "$txn_dir" clash "$RELAY_CLASH_YAML"
        _manage_service restart >/dev/null 2>&1 || true
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "清空中转失败，已恢复原配置"
        return 1
    fi

    # 服务已接受新配置后，再精确删除中转自己的证书与 HY2 跳跃规则。
    while IFS=$'\t' read -r tag node_name hop port; do
        [ -z "$tag" ] && continue
        rm -f -- "${RELAY_AUX_DIR}/${tag}.pem" "${RELAY_AUX_DIR}/${tag}.key"
        if [[ "$hop" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            _nft_apply_redirect_rule delete "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$port" "singboxlite-relay-hop-${tag}"
        fi
    done <<< "$cleanup_rows"
    while IFS= read -r tag; do
        [ -n "$tag" ] || continue
        rm -f -- "${RELAY_AUX_DIR}/${tag}.pem" "${RELAY_AUX_DIR}/${tag}.key"
    done < <(printf '%s' "$relay_tags" | jq -r '.[]' 2>/dev/null)
    _save_nftables_rules
    _txn_cleanup "$txn_dir"
    _state_lock_release
    _success "全部中转已清空；主节点、Xray 与端口转发配置均已保留"
}

_delete_relay() {
    echo -e "\n  ${RED}【删除中转路由】${NC}"
    
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    if [ ! -f "$CONFIG_FILE" ]; then _error "配置文件不存在。"; return; fi
    
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null and (.outbound | startswith("relay-out-")))' "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$rules" ]; then
        echo -e "    ${YELLOW}暂无活跃中转链路${NC}"
        read -p "  按回车键继续..."
        return
    fi
    
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local i=1
    local rules_list=()
    
    # 构建列表
    while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local metadata=""
        local landing_info="--"
        local node_name="未知节点"
        
        if [ -f "$LINKS_FILE" ]; then
            metadata=$(jq -r --arg t "$in_tag" '.[$t] // empty' "$LINKS_FILE")
            if [ -n "$metadata" ]; then
                if echo "$metadata" | jq -e '.link' >/dev/null 2>&1; then
                    landing_info=$(echo "$metadata" | jq -r '.landing_addr // "未知"')
                    node_name=$(echo "$metadata" | jq -r '.node_name // "未知节点"')
                fi
            fi
        fi
        
        echo -e "  ${GREEN}[$i]${NC} ${YELLOW}${node_name}${NC} (${landing_info})"
        rules_list+=("$rule")
        ((i++))
    done <<< "$rules"
    
    echo ""
    echo -e "    ${YELLOW}[0]${NC} 取消"
    echo -e "    ${RED}[A]${NC} 删除全部"
    echo ""
    read -p "  请输入要删除的序号 [1-$((i-1))]: " choice
    
    # 处理 "0" 或空输入
    if [[ "$choice" == "0" || -z "$choice" ]]; then return; fi
    
    # 处理全部删除
    if [[ "$choice" == "A" || "$choice" == "a" ]]; then
        _warn "即将删除所有 $((i-1)) 个中转路由！"
        read -p "  确认删除所有? (yes/N): " confirm_all
        if [[ "$confirm_all" == "yes" ]]; then
            _info "正在批量删除中转自有对象..."
            _clear_all_relays
        fi
        return
    fi

    # 验证输入
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        _error "无效序号"
        return
    fi
    
    local selected_rule="${rules_list[$((choice-1))]}"
    local in_tag out_tag relay_port
    in_tag=$(echo "$selected_rule" | jq -r '.inbound')
    out_tag=$(echo "$selected_rule" | jq -r '.outbound')
    relay_port=$(jq -r --arg tag "$in_tag" '.inbounds[]? | select(.tag == $tag) | .listen_port' "$CONFIG_FILE" | head -n 1)
    if ! _valid_port "$relay_port"; then
        _error "无法确认该中转入口端口，已取消删除以避免误操作"
        return 1
    fi

    local node_name_yaml="" port_hopping=""
    if [ -f "$LINKS_FILE" ]; then
        node_name_yaml=$(jq -r --arg t "$in_tag" '.[$t].node_name // empty' "$LINKS_FILE")
        port_hopping=$(jq -r --arg t "$in_tag" '.[$t].port_hopping // empty' "$LINKS_FILE")
    fi

    _info "正在事务删除中转链路: $in_tag -> $out_tag ..."
    local txn_dir failed="false"
    _state_lock_acquire || return 1
    txn_dir=$(_txn_begin) || { _state_lock_release; return 1; }
    if ! _txn_snapshot_file "$txn_dir" relay "$CONFIG_FILE" \
        || ! _txn_snapshot_file "$txn_dir" links "$LINKS_FILE" \
        || ! _txn_snapshot_file "$txn_dir" clash "$RELAY_CLASH_YAML"; then
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "无法创建删除前快照"
        return 1
    fi

    _atomic_modify_json "$CONFIG_FILE" \
        ".inbounds = [(.inbounds // [])[] | select(.tag != \"$in_tag\")] | .outbounds = [(.outbounds // [])[] | select(.tag != \"$out_tag\")] | .route.rules = [(.route.rules // [])[] | select(.inbound != \"$in_tag\" and .outbound != \"$out_tag\")]" || failed="true"
    if [ "$failed" != "true" ] && [ -n "$node_name_yaml" ]; then
        _remove_node_from_relay_yaml "$node_name_yaml" "$relay_port" || failed="true"
    fi
    if [ "$failed" != "true" ] && [ -f "$LINKS_FILE" ]; then
        _atomic_modify_json "$LINKS_FILE" "del(.\"$in_tag\")" || failed="true"
    fi

    if [ "$failed" = "true" ] || ! _restart_checked; then
        _txn_restore_file "$txn_dir" relay "$CONFIG_FILE"
        _txn_restore_file "$txn_dir" links "$LINKS_FILE"
        _txn_restore_file "$txn_dir" clash "$RELAY_CLASH_YAML"
        _manage_service restart >/dev/null 2>&1 || true
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "删除失败，已恢复原配置"
        return 1
    fi

    rm -f -- "${RELAY_AUX_DIR}/${in_tag}.pem" "${RELAY_AUX_DIR}/${in_tag}.key"
    if [[ "$port_hopping" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        _nft_apply_redirect_rule delete "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$relay_port" "singboxlite-relay-hop-${in_tag}"
        _save_nftables_rules
        _info "已卸载绑定的 nftables UDP 端口跳跃范围转发规则 (${port_hopping})"
    fi
    _txn_cleanup "$txn_dir"
    _state_lock_release
    _success "已移除中转链路 [$in_tag]。"
}

# --- 5. 修改中转路由端口 (功能恢复) ---
_modify_relay_port() {
    echo -e "\n  ${CYAN}【修改中转路由端口】${NC}"
    
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    local rules=$(jq -c '.route.rules[]? | select(.inbound != null and .outbound != null and ((.outbound | type) == "string") and (.outbound | startswith("relay-out-")))' "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$rules" ]; then
        _warn "没有可修改的中转路由。"
        return
    fi
    
    local i=1; local rule_list=()
    while IFS= read -r rule; do
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local inbound=$(jq -c --arg t "$in_tag" '.inbounds[] | select(.tag == $t)' "$CONFIG_FILE")
        local port=$(echo "$inbound" | jq -r '.listen_port')
        echo -e "    ${GREEN}[$i]${NC} 端口: ${port} [${in_tag}]"
        rule_list+=("$rule")
        ((i++))
    done <<< "$rules"
    
    echo ""
    read -p "  请输入要修改端口的序号: " choice
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then return; fi
    
    local selected_rule=${rule_list[$((choice-1))]}
    local in_tag=$(echo "$selected_rule" | jq -r '.inbound')
    local old_port=$(jq -r --arg t "$in_tag" '.inbounds[] | select(.tag == $t) | .listen_port' "$CONFIG_FILE")
    local inbound_type listen_network="tcp"
    inbound_type=$(jq -r --arg t "$in_tag" '.inbounds[] | select(.tag == $t) | .type' "$CONFIG_FILE")
    [[ "$inbound_type" == "hysteria2" || "$inbound_type" == "tuic" ]] && listen_network="udp"
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    
    while true; do
        read -p "  请输入新的端口号: " new_port
        if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
             _error "无效端口"; continue
        fi
        
        if _network_port_conflict "$new_port" "$listen_network" "$in_tag"; then
             _error "${listen_network^^} 端口 $new_port 已被系统或已有配置占用，请重试！"
             continue
        fi

        if [ "$listen_network" = "udp" ]; then
            local hop_conflict
            hop_conflict=$(_pf_find_hy2_hop_conflict "$new_port")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                if [ "$c_tag" != "$in_tag" ]; then
                    _error "新端口 ${new_port} 落在已有 HY2 端口跳跃范围 ${c_range} 内。"
                    _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请换端口。"
                    continue
                fi
            fi
        fi
        break
    done
    
    _info "正在修改端口..."
    local old_node_name="" current_link="" new_link="" hop_info=""
    if [ -f "$LINKS_FILE" ]; then
        old_node_name=$(jq -r --arg tag "$in_tag" '.[$tag].node_name // empty' "$LINKS_FILE")
        current_link=$(jq -r --arg tag "$in_tag" '.[$tag].link // empty' "$LINKS_FILE")
        hop_info=$(jq -r --arg tag "$in_tag" '.[$tag].port_hopping // empty' "$LINKS_FILE")
    fi
    if [ -n "$current_link" ]; then
        new_link=$(printf '%s' "$current_link" | sed -E "s/(:${old_port})([?&#\/]|$)/:${new_port}\2/g")
    fi

    local txn_dir tmp failed="false"
    _state_lock_acquire || return 1
    txn_dir=$(_txn_begin) || { _state_lock_release; return 1; }
    if ! _txn_snapshot_file "$txn_dir" relay "$CONFIG_FILE" \
        || ! _txn_snapshot_file "$txn_dir" links "$LINKS_FILE" \
        || ! _txn_snapshot_file "$txn_dir" clash "$RELAY_CLASH_YAML"; then
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "无法创建修改前快照"
        return 1
    fi

    if _network_port_conflict "$new_port" "$listen_network" "$in_tag"; then
        failed="true"
        _error "提交前发现 ${listen_network^^} 端口 ${new_port} 已被占用"
    fi
    if [ "$failed" != "true" ]; then
        _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$in_tag\") | .listen_port) = ($new_port|tonumber)" || failed="true"
    fi
    if [ "$failed" != "true" ] && [ -f "$LINKS_FILE" ]; then
        tmp=$(_make_same_dir_tmp "$LINKS_FILE") || failed="true"
        if [ "$failed" != "true" ]; then
            if ! jq --arg tag "$in_tag" --arg link "$new_link" --argjson port "$new_port" \
                '.[$tag].listen_port = $port | if $link != "" then .[$tag].link = $link else . end' \
                "$LINKS_FILE" > "$tmp" || ! chmod 600 "$tmp" || ! mv -f "$tmp" "$LINKS_FILE"; then
                rm -f -- "$tmp"
                failed="true"
            fi
        fi
    fi
    if [ "$failed" != "true" ] && [ -n "$old_node_name" ]; then
        export OLD_RELAY_NAME="$old_node_name"
        export OLD_RELAY_PORT="$old_port"
        export NEW_RELAY_PORT="$new_port"
        _atomic_modify_yaml "$RELAY_CLASH_YAML" \
            '(.proxies[] | select(.name == strenv(OLD_RELAY_NAME) and .port == (env(OLD_RELAY_PORT) | tonumber)) | .port) = (env(NEW_RELAY_PORT) | tonumber)' || failed="true"
    fi

    if [ "$failed" = "true" ] || ! _restart_checked; then
        _txn_restore_file "$txn_dir" relay "$CONFIG_FILE"
        _txn_restore_file "$txn_dir" links "$LINKS_FILE"
        _txn_restore_file "$txn_dir" clash "$RELAY_CLASH_YAML"
        _manage_service restart >/dev/null 2>&1 || true
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "端口修改失败，已恢复原配置"
        return 1
    fi

    if [[ "$hop_info" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        local hop_start="${BASH_REMATCH[1]}" hop_end="${BASH_REMATCH[2]}"
        if ! _nft_apply_redirect_rule add "$hop_start" "$hop_end" "$new_port" "singboxlite-relay-hop-${in_tag}"; then
            _txn_restore_file "$txn_dir" relay "$CONFIG_FILE"
            _txn_restore_file "$txn_dir" links "$LINKS_FILE"
            _txn_restore_file "$txn_dir" clash "$RELAY_CLASH_YAML"
            _nft_apply_redirect_rule add "$hop_start" "$hop_end" "$old_port" "singboxlite-relay-hop-${in_tag}" >/dev/null 2>&1 || true
            _manage_service restart >/dev/null 2>&1 || true
            _save_nftables_rules
            _txn_cleanup "$txn_dir"
            _state_lock_release
            _error "端口跳跃规则更新失败，已恢复原端口"
            return 1
        fi
        _save_nftables_rules
        _info "已将端口跳跃映射从 ${old_port} 联动更新到 ${new_port}"
    fi

    _txn_cleanup "$txn_dir"
    _state_lock_release
    _log_operation "MODIFY_RELAY_PORT" "Tag: $in_tag, Old Port: $old_port, New Port: $new_port"
    _success "中转端口已修改并通过组合配置校验"
    read -p "  按回车键继续..."
}


# ============================================================
# --- 端口转发管理模块 (Port Forwarding) ---
# 智能双引擎方案:
#   引擎A (nftables DNAT): 内核级转发, TCP+UDP 全通, KVM/特权LXC 优先
#   引擎B (sing-box direct): 用户态转发, TCP+UDP 可用, 无特权环境降级
# 元数据统一存储于 relay_pf.json
# ============================================================

PF_METADATA_FILE="${RELAY_AUX_DIR}/relay_pf.json"
PF_ENGINE="singbox"
PF_ENV_KIND="unknown"
PF_ACCESS_HINT=""
PF_PUBLISH_HINT="false"

_pf_normalize_target_addr() {
    local addr="$1"
    if [[ "$addr" =~ ^\[(.*)\]$ ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "$addr"
    fi
}

_pf_is_ipv4_literal() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

_pf_is_ipv6_literal() {
    local addr="$(_pf_normalize_target_addr "$1")"
    [[ "$addr" == *:* ]]
}

_pf_nft_addr_key() {
    if [ "$1" == "ipv6" ]; then
        echo "ip6"
    else
        echo "ip"
    fi
}

_pf_nft_dnat_target() {
    local family="$1" ip="$2" port="$3"
    if [ "$family" == "ipv6" ]; then
        echo "[${ip}]:${port}"
    else
        echo "${ip}:${port}"
    fi
}

_pf_delete_nft_rule_set() {
    local listen_port="$1"
    local proto chain
    for proto in tcp udp; do
        for chain in prerouting output; do
            _nft_delete_rules_by_comment "singboxlite-pf-${listen_port}-${proto}-${chain}"
        done
        _nft_delete_rules_by_comment "singboxlite-pf-${listen_port}-${proto}-fwd-in"
        _nft_delete_rules_by_comment "singboxlite-pf-${listen_port}-${proto}-fwd-out"
    done
    _nft_delete_rules_by_comment "singboxlite-pf-${listen_port}-masq"
}

_pf_find_hy2_hop_conflict() {
    local listen_port="$1"
    local conflict=""
    if [ -f "$MAIN_METADATA_FILE" ]; then
        conflict=$(jq -r --argjson port "$listen_port" '
            to_entries[]
            | select(.value.portHopping)
            | (.value.portHopping | capture("^(?<start>[0-9]+)-(?<end>[0-9]+)$")?) as $range
            | select($range != null)
            | ($range.start | tonumber) as $start
            | ($range.end | tonumber) as $end
            | select($port >= $start and $port <= $end)
            | [
                .key,
                (.value.name // .key),
                .value.portHopping,
                ("主HY2/" + (.value.portHoppingMode // "unknown"))
              ]
            | @tsv
        ' "$MAIN_METADATA_FILE" 2>/dev/null | head -n 1)
        [ -n "$conflict" ] && { echo "$conflict"; return 0; }
    fi

    local relay_links="${RELAY_AUX_DIR}/relay_links.json"
    if [ -f "$relay_links" ]; then
        conflict=$(jq -r --argjson port "$listen_port" '
            to_entries[]
            | select(.value.port_hopping)
            | (.value.port_hopping | capture("^(?<start>[0-9]+)-(?<end>[0-9]+)$")?) as $range
            | select($range != null)
            | ($range.start | tonumber) as $start
            | ($range.end | tonumber) as $end
            | select($port >= $start and $port <= $end)
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

_pf_can_write_nft_rules() {
    local comment="singboxlite-pf-test-$$"
    command -v nft &>/dev/null || return 1
    _nft_ensure_base || return 1
    nft add rule inet "$NFT_TABLE" prerouting tcp dport 65535 dnat ip to 127.0.0.1:65535 comment "$comment" >/dev/null 2>&1 || return 1
    _nft_delete_rules_by_comment "$comment"
}

# 确保元数据文件存在
_pf_ensure_metadata() {
    [ -f "$PF_METADATA_FILE" ] || _atomic_write_json "$PF_METADATA_FILE" '{}' || return 1
    _secure_state_file "$PF_METADATA_FILE"
}

# 统计端口转发规则数量 (基于元数据)
_pf_count() {
    _pf_ensure_metadata
    jq 'length' "$PF_METADATA_FILE" 2>/dev/null || echo 0
}

# 启用内核 IP 转发 (nftables DNAT 的前提条件)
_pf_enable_forwarding() {
    # IPv4 转发
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
        if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null; then
            echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        else
            sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
        fi
        _info "已启用 IPv4 转发 (ip_forward=1)"
    fi
    # IPv6 转发
    if [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
        if [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]; then
            echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null
            if ! grep -q "^net.ipv6.conf.all.forwarding" /etc/sysctl.conf 2>/dev/null; then
                echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
            else
                sed -i 's/^net.ipv6.conf.all.forwarding.*/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
            fi
        fi
    fi
}

# 查看当前转发规则
_pf_view() {
    echo ""
    _info "=== 当前端口转发规则 ==="
    echo ""
    _pf_ensure_metadata
    
    local count=$(_pf_count)
    if [ "$count" -eq 0 ]; then
        _warn "暂无转发规则"; read -p "  按回车继续..."; return
    fi
    
    local i=1
    while IFS=$'\t' read -r port name engine addr tport net_display; do
        [ -z "$port" ] && continue
        local engine_label=""
        if [ "$engine" == "nftables" ]; then
            engine_label="${GREEN}nftables${NC}"
        else
            engine_label="${YELLOW}sing-box${NC}"
        fi
        echo -e "  ${GREEN}[$i]${NC} 【${name}】 本机 :${CYAN}${port}${NC} → ${CYAN}${addr}:${tport}${NC}  [${YELLOW}${net_display}${NC}]  引擎: ${engine_label}"
        i=$((i+1))
    done < <(jq -r 'to_entries[] | [.key, .value.name, .value.engine, .value.target_addr, (.value.target_port|tostring), .value.network_display] | @tsv' "$PF_METADATA_FILE" 2>/dev/null)
    
    echo ""
    echo -e "  共 ${GREEN}${count}${NC} 条转发规则"
    echo ""
    read -p "  按回车继续..."
}

# 安装/卸载 DNS 定时刷新 cron 任务
_pf_setup_dns_cron() {
    local SCRIPT_PATH="$(readlink -f "$0")"
    local CRON_CMD="* * * * * /bin/bash \"${SCRIPT_PATH}\" pf-dns-refresh >/dev/null 2>&1"
    local CRON_TAG="# pf-dns-auto-refresh"

    # 始终替换带标签的旧任务，确保检查周期和脚本绝对路径保持最新。
    # 旧实现检测到标签后直接返回，导致 */5 的旧任务或失效路径永远不会被修复。
    if ! (crontab -l 2>/dev/null | grep -vF "$CRON_TAG"; echo "${CRON_CMD} ${CRON_TAG}") | crontab -; then
        _warning "安装域名动态刷新定时任务失败，请检查 cron/crond 服务"
        return 1
    fi
    _info "已安装域名动态刷新定时任务 (每 1 分钟检查一次)"
}

_pf_remove_dns_cron() {
    local CRON_TAG="# pf-dns-auto-refresh"
    if crontab -l 2>/dev/null | grep -qF "$CRON_TAG"; then
        crontab -l 2>/dev/null | grep -vF "$CRON_TAG" | crontab -
        _info "已卸载域名动态刷新定时任务"
    fi
}

# 端口转发子菜单
_pf_detect_engine() {
    PF_ENGINE="singbox"
    PF_ENV_KIND="unknown"
    PF_ACCESS_HINT=""
    PF_PUBLISH_HINT="false"

    if command -v systemd-detect-virt &>/dev/null; then
        local svirt
        svirt=$(systemd-detect-virt 2>/dev/null)
        case "$svirt" in
            lxc|lxc-libvirt|systemd-nspawn) PF_ENV_KIND="lxc" ;;
            docker) PF_ENV_KIND="docker" ;;
            podman) PF_ENV_KIND="podman" ;;
            wsl) PF_ENV_KIND="container" ;;
            kvm|qemu|vmware|oracle|microsoft|xen|zvm) PF_ENV_KIND="kvm" ;;
            none) PF_ENV_KIND="host" ;;
        esac
    fi

    if [ "$PF_ENV_KIND" == "unknown" ]; then
        if [ -f /.dockerenv ] || grep -qa 'docker' /proc/1/cgroup 2>/dev/null; then
            PF_ENV_KIND="docker"
        elif grep -qa 'libpod' /proc/1/cgroup 2>/dev/null || grep -qa 'podman' /proc/1/environ 2>/dev/null; then
            PF_ENV_KIND="podman"
        elif grep -qa 'container=lxc' /proc/1/environ 2>/dev/null || grep -qa 'lxc' /proc/1/cgroup 2>/dev/null || grep -qa 'lxd' /proc/1/cgroup 2>/dev/null || [ -e /dev/lxd ]; then
            PF_ENV_KIND="lxc"
        elif dmesg 2>/dev/null | grep -qi 'kvm\|qemu\|vmware\|virtualbox'; then
            PF_ENV_KIND="kvm"
        elif [ -f /sys/class/dmi/id/product_name ] && grep -qi 'kvm\|qemu\|vmware\|bochs' /sys/class/dmi/id/product_name 2>/dev/null; then
            PF_ENV_KIND="kvm"
        else
            PF_ENV_KIND="host"
        fi
    fi

    if _pf_can_write_nft_rules; then
        PF_ENGINE="nftables"
    fi

    case "$PF_ENV_KIND" in
        host|kvm)
            if [ "$PF_ENGINE" == "nftables" ]; then
                PF_ACCESS_HINT="当前环境具备完整 netfilter 权限，将使用内核级 nftables 转发。"
            else
                PF_ACCESS_HINT="当前环境缺少完整 netfilter 权限，将回退到 sing-box 用户态转发。"
            fi
            ;;
        lxc)
            if [ "$PF_ENGINE" == "nftables" ]; then
                PF_ACCESS_HINT="当前 LXC 具备 NET_ADMIN/nftables 能力，将使用内核级 nftables 转发。"
            else
                PF_ACCESS_HINT="当前 LXC 权限受限，将使用 sing-box 用户态转发；TCP/UDP 都可创建。"
            fi
            ;;
        docker|podman)
            PF_PUBLISH_HINT="true"
            if [ "$PF_ENGINE" == "nftables" ]; then
                PF_ACCESS_HINT="当前容器具备宿主级 netfilter 能力，将使用 nftables 转发。"
            else
                PF_ACCESS_HINT="当前容器将使用 sing-box 用户态转发；若未使用 host 网络，请确保宿主机已预先发布对应的 TCP/UDP 端口。"
            fi
            ;;
        *)
            PF_ACCESS_HINT="当前环境将使用 ${PF_ENGINE} 转发路径。"
            ;;
    esac
}

_pf_resolve_domain_family() {
    local raw_addr="$1"
    local family="${2:-ipv4}"
    local addr="$(_pf_normalize_target_addr "$raw_addr")"
    local resolved=""

    if [ "$family" == "ipv6" ]; then
        if command -v getent &>/dev/null; then
            resolved=$(getent ahostsv6 "$addr" 2>/dev/null | awk '{print $1}' | head -1)
        fi
        if [ -z "$resolved" ] && command -v dig &>/dev/null; then
            resolved=$(dig +short AAAA "$addr" 2>/dev/null | grep ':' | head -1)
        fi
        if [ -z "$resolved" ] && command -v nslookup &>/dev/null; then
            resolved=$(nslookup -query=AAAA "$addr" 2>/dev/null | awk '/^Address: / {print $2}' | grep ':' | head -1)
        fi
    else
        if command -v getent &>/dev/null; then
            resolved=$(getent ahostsv4 "$addr" 2>/dev/null | awk '{print $1}' | head -1)
        fi
        if [ -z "$resolved" ] && command -v dig &>/dev/null; then
            resolved=$(dig +short A "$addr" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        fi
        if [ -z "$resolved" ] && command -v nslookup &>/dev/null; then
            resolved=$(nslookup "$addr" 2>/dev/null | awk '/^Address: / && !/127\.0\.0\.|#/ {print $2}' | grep -E '^[0-9]+\.' | head -1)
        fi
    fi

    [ -n "$resolved" ] && echo "$resolved"
}

_pf_prepare_nft_target() {
    local raw_addr="$1"
    local addr="$(_pf_normalize_target_addr "$raw_addr")"

    if _pf_is_ipv4_literal "$addr"; then
        printf 'ipv4\t%s\tfalse\n' "$addr"
        return 0
    fi
    if _pf_is_ipv6_literal "$addr"; then
        printf 'ipv6\t%s\tfalse\n' "$addr"
        return 0
    fi

    local resolved=""
    local family=""
    resolved=$(_pf_resolve_domain_family "$addr" "ipv4")
    if [ -n "$resolved" ]; then
        family="ipv4"
    else
        resolved=$(_pf_resolve_domain_family "$addr" "ipv6")
        [ -n "$resolved" ] && family="ipv6"
    fi

    [ -z "$resolved" ] && return 1
    printf '%s\t%s\ttrue\n' "$family" "$resolved"
}

_pf_apply_nft_rules() {
    local action="$1"
    local listen_port="$2"
    local target_ip="$3"
    local target_port="$4"
    local network="$5"
    local family="$6"
    local rc=0
    local addr_key
    addr_key=$(_pf_nft_addr_key "$family")

    if [ "$action" == "delete" ]; then
        _pf_delete_nft_rule_set "$listen_port"
        return 0
    fi

    _nft_ensure_base || return 1
    _pf_delete_nft_rule_set "$listen_port"

    local to_dest
    to_dest=$(_pf_nft_dnat_target "$family" "$target_ip" "$target_port")
    local proto
    for proto in tcp udp; do
        if [[ "$network" != "$proto" && "$network" != "tcp+udp" ]]; then
            continue
        fi
        if ! nft add rule inet "$NFT_TABLE" prerouting "$proto" dport "$listen_port" dnat "$addr_key" to "$to_dest" comment "singboxlite-pf-${listen_port}-${proto}-prerouting" >/dev/null 2>&1; then
            rc=1
        fi
        # 不在 output 链按“仅目标端口”做 DNAT：该规则会误改本机访问任意远端同端口的连接。
        # 外部进入本机的转发流量只需要 prerouting；删除函数仍会清理历史 output 规则。
        nft add rule inet "$NFT_TABLE" forward "$proto" dport "$target_port" "$addr_key" daddr "$target_ip" ct state new,established,related accept comment "singboxlite-pf-${listen_port}-${proto}-fwd-in" >/dev/null 2>&1 || true
        nft add rule inet "$NFT_TABLE" forward "$proto" sport "$target_port" "$addr_key" saddr "$target_ip" ct state established,related accept comment "singboxlite-pf-${listen_port}-${proto}-fwd-out" >/dev/null 2>&1 || true
    done

    nft add rule inet "$NFT_TABLE" postrouting "$addr_key" daddr "$target_ip" masquerade comment "singboxlite-pf-${listen_port}-masq" >/dev/null 2>&1 || true
    if [ "$rc" -ne 0 ]; then
        _pf_delete_nft_rule_set "$listen_port"
    fi
    return "$rc"
}

_pf_build_inbound_json() {
    local tag="$1"
    local listen_port="$2"
    local network="$3"

    if [ "$network" == "tcp+udp" ]; then
        jq -n --arg t "$tag" --argjson p "$listen_port" \
            '{"type":"direct","tag":$t,"listen":"::","listen_port":$p}'
    else
        jq -n --arg t "$tag" --argjson p "$listen_port" --arg net "$network" \
            '{"type":"direct","tag":$t,"listen":"::","listen_port":$p,"network":$net}'
    fi
}

_pf_build_rule_json() {
    local inbound_tag="$1"
    local outbound_tag="$2"
    local target_addr="$3"
    local target_port="$4"
    local network="$5"

    jq -n --arg it "$inbound_tag" --arg ot "$outbound_tag" --arg addr "$target_addr" --argjson port "$target_port" --arg net "$network" '
        {
            inbound: $it,
            outbound: $ot,
            action: "route",
            override_address: $addr,
            override_port: $port
        }
        | if ($net == "udp" or $net == "tcp+udp") then .udp_connect = true | .udp_timeout = "5m" else . end
    '
}

_pf_apply_singbox_rules() {
    local action="$1"
    local listen_port="$2"
    local target_addr="$3"
    local target_port="$4"
    local network="$5"
    local in_tag="pf-in-${listen_port}"
    local out_tag="pf-out-${listen_port}"

    [ ! -f "$RELAY_CONFIG_FILE" ] && _atomic_write_json "$RELAY_CONFIG_FILE" '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}'

    if [ "$action" == "delete" ]; then
        local del_filter="del(.inbounds[] | select(.tag == \"$in_tag\"))"
        del_filter="${del_filter} | del(.outbounds[] | select(.tag == \"$out_tag\"))"
        del_filter="${del_filter} | .route.rules = [.route.rules[] | select(.inbound != \"$in_tag\")]"
        _atomic_modify_json "$RELAY_CONFIG_FILE" "$del_filter"
        return $?
    fi

    local inbound_json
    inbound_json=$(_pf_build_inbound_json "$in_tag" "$listen_port" "$network")
    local outbound_json
    outbound_json=$(jq -n --arg t "$out_tag" '{"type":"direct","tag":$t}')
    local rule_json
    rule_json=$(_pf_build_rule_json "$in_tag" "$out_tag" "$target_addr" "$target_port" "$network")

    local combined_filter=".inbounds += [$inbound_json] | .outbounds += [$outbound_json]"
    if ! jq -e '.route' "$RELAY_CONFIG_FILE" >/dev/null 2>&1; then
        combined_filter="${combined_filter} | . + {\"route\":{\"rules\":[]}}"
    fi
    combined_filter="${combined_filter} | .route.rules += [$rule_json]"
    _atomic_modify_json "$RELAY_CONFIG_FILE" "$combined_filter"
}

_pf_store_metadata() {
    local listen_port="$1"
    local engine="$2"
    local custom_name="$3"
    local target_addr="$4"
    local target_port="$5"
    local network="$6"
    local network_display="$7"
    local target_family="${8:-}"
    local resolved_ip="${9:-}"
    local is_domain="${10:-false}"
    local publish_hint_json="false"
    [ "$PF_PUBLISH_HINT" == "true" ] && publish_hint_json="true"

    local meta
    meta=$(jq -n \
        --arg engine "$engine" \
        --arg env_kind "$PF_ENV_KIND" \
        --arg access_hint "$PF_ACCESS_HINT" \
        --argjson publish_hint "$publish_hint_json" \
        --arg name "$custom_name" \
        --arg addr "$target_addr" \
        --argjson tport "$target_port" \
        --arg net "$network" \
        --arg net_display "$network_display" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        '{
            engine: $engine,
            env_kind: $env_kind,
            access_hint: $access_hint,
            publish_hint: $publish_hint,
            name: $name,
            target_addr: $addr,
            target_port: $tport,
            network: $net,
            network_display: $net_display,
            created_at: $created
        }')

    if [ -n "$target_family" ]; then
        meta=$(echo "$meta" | jq --arg fam "$target_family" '. + {target_family: $fam}')
    fi
    if [ -n "$resolved_ip" ]; then
        meta=$(echo "$meta" | jq --arg ip "$resolved_ip" '. + {resolved_ip: $ip}')
    fi
    if [ "$is_domain" == "true" ]; then
        meta=$(echo "$meta" | jq '. + {target_is_domain: true}')
    fi

    local updated
    updated=$(jq --arg port "$listen_port" --argjson meta "$meta" '.[$port] = $meta' "$PF_METADATA_FILE") || return 1
    _atomic_write_json "$PF_METADATA_FILE" "$updated"
}

_pf_guess_target_family() {
    local addr="$1"
    if _pf_is_ipv6_literal "$addr"; then
        echo "ipv6"
    else
        echo "ipv4"
    fi
}

_pf_add() {
    echo ""
    _pf_detect_engine
    _pf_ensure_metadata

    if [ "$PF_ENGINE" == "nftables" ]; then
        _info "=== 添加端口转发规则 (引擎: nftables DNAT) ==="
    else
        _warn "=== 添加端口转发规则 (引擎: sing-box 用户态转发) ==="
    fi
    [ -n "$PF_ACCESS_HINT" ] && _info "$PF_ACCESS_HINT"
    echo ""

    local listen_port
    while true; do
        read -p "  请输入本机监听端口: " listen_port
        if [[ ! "$listen_port" =~ ^[0-9]+$ ]] || [ "$listen_port" -lt 1 ] || [ "$listen_port" -gt 65535 ]; then
            _error "无效端口，请输入 1-65535 之间的数字"
            continue
        fi
        if jq -e ".\"$listen_port\"" "$PF_METADATA_FILE" >/dev/null 2>&1; then
            _error "端口 $listen_port 已存在转发规则，请换一个"
            continue
        fi
        break
    done

    local target_addr
    read -p "  请输入目标地址 (IP 或域名): " target_addr
    if [ -z "$target_addr" ]; then
        _error "目标地址不能为空"; read -p "  按回车继续..."; return
    fi

    local target_port
    read -p "  请输入目标端口: " target_port
    if [[ ! "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        _error "无效端口"; read -p "  按回车继续..."; return
    fi

    echo ""
    local proto_choice
    local network="tcp"
    local network_display="TCP"
    if [ "$PF_ENGINE" == "nftables" ]; then
        echo -e "  ${CYAN}【信息】已启用内核级 nftables 转发${NC}"
    else
        echo -e "  ${YELLOW}【提示】当前将使用 sing-box 用户态转发${NC}"
    fi
    echo -e "  ${CYAN}请选择转发协议：${NC}"
    echo -e "    ${GREEN}[1]${NC} 仅 TCP"
    echo -e "    ${GREEN}[2]${NC} 仅 UDP"
    echo -e "    ${GREEN}[3]${NC} TCP+UDP"
    echo ""
    read -p "  请选择 [1-3] (默认 1): " proto_choice
    case "$proto_choice" in
        2) network="udp"; network_display="UDP" ;;
        3) network="tcp+udp"; network_display="TCP+UDP" ;;
        *) ;;
    esac

    if _network_port_conflict "$listen_port" "$network"; then
        _error "${network_display} 端口 ${listen_port} 已被系统或已有配置占用"
        read -p "  按回车继续..."
        return
    fi

    if [[ "$network" == "udp" || "$network" == "tcp+udp" ]]; then
        local hop_conflict
        hop_conflict=$(_pf_find_hy2_hop_conflict "$listen_port")
        if [ -n "$hop_conflict" ]; then
            local c_tag c_name c_range c_mode
            IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
            _error "UDP 转发入口端口 ${listen_port} 落在已有 HY2 端口跳跃范围 ${c_range} 内。"
            _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请换端口或先调整该 HY2 跳跃范围。"
            read -p "  按回车继续..."; return
        fi
    fi

    echo ""
    local custom_name
    read -p "  请输入备注名称 (直接回车默认: 转发规则-${listen_port}): " custom_name
    [ -z "$custom_name" ] && custom_name="转发规则-${listen_port}"
    custom_name="${custom_name//\"/}"
    custom_name="${custom_name//\\/}"
    custom_name="${custom_name//#/}"

    local target_family=""
    local resolved_ip=""
    local target_is_domain="false"
    local txn_dir apply_ok="false"
    _state_lock_acquire || return 1
    txn_dir=$(_txn_begin) || { _state_lock_release; return 1; }
    if ! _txn_snapshot_file "$txn_dir" relay "$RELAY_CONFIG_FILE" \
        || ! _txn_snapshot_file "$txn_dir" pf "$PF_METADATA_FILE"; then
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "无法创建端口转发状态快照"
        return 1
    fi
    if _network_port_conflict "$listen_port" "$network"; then
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "提交前发现 ${network_display} 端口 ${listen_port} 已被占用"
        return 1
    fi
    if [ "$PF_ENGINE" == "nftables" ]; then
        local resolved_payload=""
        resolved_payload=$(_pf_prepare_nft_target "$target_addr")
        if [ $? -ne 0 ] || [ -z "$resolved_payload" ]; then
            _error "目标地址无法解析为可用的 IPv4/IPv6，无法创建 nftables 转发规则"
            _txn_cleanup "$txn_dir"
            _state_lock_release
            read -p "  按回车继续..."; return
        fi
        IFS=$'\t' read -r target_family resolved_ip target_is_domain <<< "$resolved_payload"
        [ "$target_is_domain" == "true" ] && _success "域名已解析: $target_addr -> $resolved_ip (${target_family})"
        _pf_enable_forwarding
        if ! _pf_apply_nft_rules "add" "$listen_port" "$resolved_ip" "$target_port" "$network" "$target_family"; then
            _error "nftables 规则写入失败"
            _txn_cleanup "$txn_dir"
            _state_lock_release
            read -p "  按回车继续..."; return
        fi
        _save_nftables_rules
        apply_ok="true"
    else
        if ! _pf_apply_singbox_rules "add" "$listen_port" "$target_addr" "$target_port" "$network"; then
            _error "配置写入失败"
            _txn_cleanup "$txn_dir"
            _state_lock_release
            read -p "  按回车继续..."; return
        fi
        if _restart_checked; then
            apply_ok="true"
        fi
    fi

    if [ "$apply_ok" != "true" ] || ! _pf_store_metadata "$listen_port" "$PF_ENGINE" "$custom_name" "$target_addr" "$target_port" "$network" "$network_display" "$target_family" "$resolved_ip" "$target_is_domain"; then
        _txn_restore_file "$txn_dir" relay "$RELAY_CONFIG_FILE"
        _txn_restore_file "$txn_dir" pf "$PF_METADATA_FILE"
        if [ "$PF_ENGINE" == "nftables" ]; then
            _pf_apply_nft_rules "delete" "$listen_port" "$resolved_ip" "$target_port" "$network" "$target_family"
            _save_nftables_rules
        else
            _manage_service restart >/dev/null 2>&1 || true
        fi
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "端口转发创建失败，已恢复原配置"
        read -p "  按回车继续..."
        return 1
    fi
    _txn_cleanup "$txn_dir"
    _state_lock_release

    echo ""
    _success "端口转发规则已添加并生效！"
    echo -e "  引擎: ${CYAN}${PF_ENGINE}${NC}"
    echo -e "  环境: ${CYAN}${PF_ENV_KIND}${NC}"
    echo -e "  转发模式: ${CYAN}${network_display}${NC}"
    echo -e "  本机端口: ${GREEN}${listen_port}${NC} -> 目标: ${GREEN}${target_addr}:${target_port}${NC}"
    if [ "$PF_PUBLISH_HINT" == "true" ]; then
        echo -e "  ${YELLOW}提示: 如果当前是 Docker/Podman 非 host 网络，请确保宿主机已发布 ${listen_port}/${network}${NC}"
    fi
    echo ""
    _pf_auto_manage_dns_cron
    read -p "  按回车继续..."
}

_pf_delete() {
    echo ""
    _info "=== 删除端口转发规则 ==="
    echo ""
    _pf_ensure_metadata

    local count=$(_pf_count)
    if [ "$count" -eq 0 ]; then
        _warn "暂无转发规则"; read -p "  按回车继续..."; return
    fi

    local ports=()
    local i=1
    while IFS=$'\t' read -r port name engine addr tport net_display; do
        [ -z "$port" ] && continue
        ports+=("$port")
        echo -e "  ${GREEN}[$i]${NC} 【${name}】:${CYAN}${port}${NC} -> ${CYAN}${addr}:${tport}${NC}  [${YELLOW}${net_display}${NC}]"
        i=$((i+1))
    done < <(jq -r 'to_entries[] | [.key, .value.name, .value.engine, .value.target_addr, (.value.target_port|tostring), .value.network_display] | @tsv' "$PF_METADATA_FILE" 2>/dev/null)

    echo ""
    read -p "  请输入要删除的序号 (0 取消): " sel
    if [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "${#ports[@]}" ]; then
        [ "$sel" != "0" ] && _error "无效选择"
        return
    fi

    local selected_port="${ports[$((sel-1))]}"
    local sel_engine=$(jq -r ".\"$selected_port\".engine" "$PF_METADATA_FILE")
    local sel_addr=$(jq -r ".\"$selected_port\".target_addr" "$PF_METADATA_FILE")
    local sel_tport=$(jq -r ".\"$selected_port\".target_port" "$PF_METADATA_FILE")
    local sel_net=$(jq -r ".\"$selected_port\".network" "$PF_METADATA_FILE")
    local sel_resolved=$(jq -r ".\"$selected_port\".resolved_ip // empty" "$PF_METADATA_FILE")
    local sel_family=$(jq -r ".\"$selected_port\".target_family // empty" "$PF_METADATA_FILE")
    local del_dest="${sel_resolved:-$sel_addr}"
    [ -z "$sel_family" ] && sel_family=$(_pf_guess_target_family "$del_dest")

    local txn_dir delete_ok="false" updated_meta
    _state_lock_acquire || return 1
    txn_dir=$(_txn_begin) || { _state_lock_release; return 1; }
    if ! _txn_snapshot_file "$txn_dir" relay "$RELAY_CONFIG_FILE" \
        || ! _txn_snapshot_file "$txn_dir" pf "$PF_METADATA_FILE"; then
        _txn_cleanup "$txn_dir"
        _state_lock_release
        return 1
    fi
    if [ "$sel_engine" == "nftables" ]; then
        _pf_apply_nft_rules "delete" "$selected_port" "$del_dest" "$sel_tport" "$sel_net" "$sel_family"
        _save_nftables_rules
        delete_ok="true"
    else
        if _pf_apply_singbox_rules "delete" "$selected_port" && _restart_checked; then
            delete_ok="true"
        fi
    fi

    updated_meta=$(jq --arg p "$selected_port" 'del(.[$p])' "$PF_METADATA_FILE") || delete_ok="false"
    if [ "$delete_ok" != "true" ] || ! _atomic_write_json "$PF_METADATA_FILE" "$updated_meta"; then
        _txn_restore_file "$txn_dir" relay "$RELAY_CONFIG_FILE"
        _txn_restore_file "$txn_dir" pf "$PF_METADATA_FILE"
        if [ "$sel_engine" == "nftables" ]; then
            _pf_apply_nft_rules "add" "$selected_port" "$del_dest" "$sel_tport" "$sel_net" "$sel_family" >/dev/null 2>&1 || true
            _save_nftables_rules
        else
            _manage_service restart >/dev/null 2>&1 || true
        fi
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "端口转发删除失败，已恢复原规则"
        return 1
    fi
    _txn_cleanup "$txn_dir"
    _state_lock_release

    _success "已删除端口 ${selected_port} 的转发规则"
    _pf_auto_manage_dns_cron
    read -p "  按回车继续..."
}

_pf_modify() {
    echo ""
    _info "=== 修改端口转发规则 ==="
    echo ""
    _pf_ensure_metadata

    local count=$(_pf_count)
    if [ "$count" -eq 0 ]; then
        _warn "暂无转发规则"; read -p "  按回车继续..."; return
    fi

    local ports=()
    local i=1
    while IFS=$'\t' read -r port name engine addr tport net_display; do
        [ -z "$port" ] && continue
        ports+=("$port")
        echo -e "  ${GREEN}[$i]${NC} 【${name}】:${CYAN}${port}${NC} -> ${CYAN}${addr}:${tport}${NC}  [${YELLOW}${net_display}${NC}]"
        i=$((i+1))
    done < <(jq -r 'to_entries[] | [.key, .value.name, .value.engine, .value.target_addr, (.value.target_port|tostring), .value.network_display] | @tsv' "$PF_METADATA_FILE" 2>/dev/null)

    echo ""
    read -p "  请输入要修改的序号 (0 取消): " sel
    if [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "${#ports[@]}" ]; then
        [ "$sel" != "0" ] && _error "无效选择"
        return
    fi

    local selected_port="${ports[$((sel-1))]}"
    local old_engine=$(jq -r ".\"$selected_port\".engine" "$PF_METADATA_FILE")
    local old_name=$(jq -r ".\"$selected_port\".name" "$PF_METADATA_FILE")
    local old_addr=$(jq -r ".\"$selected_port\".target_addr" "$PF_METADATA_FILE")
    local old_tport=$(jq -r ".\"$selected_port\".target_port" "$PF_METADATA_FILE")
    local old_net=$(jq -r ".\"$selected_port\".network" "$PF_METADATA_FILE")

    echo ""
    echo -e "  当前规则: 【${old_name}】:${CYAN}${selected_port}${NC} -> ${CYAN}${old_addr}:${old_tport}${NC}"
    echo ""

    read -p "  新备注名称 (回车保持 ${old_name}): " new_name
    [ -z "$new_name" ] && new_name="$old_name"
    new_name="${new_name//\"/}"
    new_name="${new_name//\\/}"
    new_name="${new_name//#/}"

    read -p "  新目标地址 (回车保持 ${old_addr}): " new_addr
    [ -z "$new_addr" ] && new_addr="$old_addr"

    read -p "  新目标端口 (回车保持 ${old_tport}): " new_tport
    if [ -n "$new_tport" ]; then
        if [[ ! "$new_tport" =~ ^[0-9]+$ ]] || [ "$new_tport" -lt 1 ] || [ "$new_tport" -gt 65535 ]; then
            _error "无效端口，保持原值"; new_tport="$old_tport"
        fi
    else
        new_tport="$old_tport"
    fi

    local old_net_display=$(echo "$old_net" | tr '[:lower:]' '[:upper:]')
    [ "$old_net" == "tcp+udp" ] && old_net_display="TCP+UDP"

    _pf_detect_engine
    [ -n "$PF_ACCESS_HINT" ] && _info "$PF_ACCESS_HINT"
    echo ""
    echo -e "  当前协议: ${YELLOW}${old_net_display}${NC}"
    local new_net="$old_net"
    echo -e "    ${GREEN}[1]${NC} 仅 TCP  ${GREEN}[2]${NC} 仅 UDP  ${GREEN}[3]${NC} TCP+UDP  ${GREEN}[0]${NC} 不改"
    read -p "  请选择 [0-3] (默认不改): " proto_choice
    case "$proto_choice" in
        1) new_net="tcp" ;;
        2) new_net="udp" ;;
        3) new_net="tcp+udp" ;;
        *) ;;
    esac

    local new_net_display=$(echo "$new_net" | tr '[:lower:]' '[:upper:]')
    [ "$new_net" == "tcp+udp" ] && new_net_display="TCP+UDP"

    if [[ "$new_net" == "udp" || "$new_net" == "tcp+udp" ]]; then
        local hop_conflict
        hop_conflict=$(_pf_find_hy2_hop_conflict "$selected_port")
        if [ -n "$hop_conflict" ]; then
            local c_tag c_name c_range c_mode
            IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
            _error "UDP 转发入口端口 ${selected_port} 落在已有 HY2 端口跳跃范围 ${c_range} 内。"
            _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请换端口或先调整该 HY2 跳跃范围。"
            read -p "  按回车继续..."; return
        fi
    fi

    local old_resolved=$(jq -r ".\"$selected_port\".resolved_ip // empty" "$PF_METADATA_FILE")
    local old_del_dest="${old_resolved:-$old_addr}"
    local old_family=$(jq -r ".\"$selected_port\".target_family // empty" "$PF_METADATA_FILE")
    [ -z "$old_family" ] && old_family=$(_pf_guess_target_family "$old_del_dest")

    local delete_ok="true"
    if [ "$old_engine" == "nftables" ]; then
        _pf_apply_nft_rules "delete" "$selected_port" "$old_del_dest" "$old_tport" "$old_net" "$old_family"
    else
        if ! _pf_apply_singbox_rules "delete" "$selected_port"; then
            delete_ok="false"
        fi
    fi

    if [ "$delete_ok" != "true" ]; then
        _error "旧规则删除失败，已取消修改"
        read -p "  按回车继续..."; return
    fi

    local target_family=""
    local resolved_ip=""
    local target_is_domain="false"
    local apply_ok="false"
    if [ "$PF_ENGINE" == "nftables" ]; then
        local resolved_payload=""
        resolved_payload=$(_pf_prepare_nft_target "$new_addr")
        if [ $? -ne 0 ] || [ -z "$resolved_payload" ]; then
            _error "目标地址无法解析为可用的 IPv4/IPv6，正在恢复旧规则..."
            if [ "$old_engine" == "nftables" ]; then
                _pf_apply_nft_rules "add" "$selected_port" "$old_del_dest" "$old_tport" "$old_net" "$old_family" >/dev/null 2>&1
                _save_nftables_rules
            else
                _pf_apply_singbox_rules "add" "$selected_port" "$old_addr" "$old_tport" "$old_net" >/dev/null 2>&1 && _manage_service restart >/dev/null 2>&1
            fi
            _error "修改失败，已恢复旧规则"
            read -p "  按回车继续..."; return
        fi
        IFS=$'\t' read -r target_family resolved_ip target_is_domain <<< "$resolved_payload"
        [ "$target_is_domain" == "true" ] && _success "域名已解析: $new_addr -> $resolved_ip (${target_family})"
        if _pf_apply_nft_rules "add" "$selected_port" "$resolved_ip" "$new_tport" "$new_net" "$target_family"; then
            apply_ok="true"
            _save_nftables_rules
        fi
    else
        if _pf_apply_singbox_rules "add" "$selected_port" "$new_addr" "$new_tport" "$new_net"; then
            if _restart_checked; then
                apply_ok="true"
            else
                _pf_apply_singbox_rules "delete" "$selected_port" >/dev/null 2>&1
            fi
        fi
    fi

    if [ "$apply_ok" != "true" ]; then
        _error "新规则创建失败，正在恢复旧规则..."
        if [ "$old_engine" == "nftables" ]; then
            _pf_apply_nft_rules "add" "$selected_port" "$old_del_dest" "$old_tport" "$old_net" "$old_family" >/dev/null 2>&1
            _save_nftables_rules
        else
            _pf_apply_singbox_rules "add" "$selected_port" "$old_addr" "$old_tport" "$old_net" >/dev/null 2>&1 && _manage_service restart >/dev/null 2>&1
        fi
        _error "修改失败，已恢复旧规则"
        read -p "  按回车继续..."; return
    fi

    if ! _pf_store_metadata "$selected_port" "$PF_ENGINE" "$new_name" "$new_addr" "$new_tport" "$new_net" "$new_net_display" "$target_family" "$resolved_ip" "$target_is_domain"; then
        _error "metadata 更新失败，正在恢复原规则..."
        if [ "$PF_ENGINE" == "nftables" ]; then
            _pf_apply_nft_rules "delete" "$selected_port" "$resolved_ip" "$new_tport" "$new_net" "$target_family" >/dev/null 2>&1 || true
        else
            _pf_apply_singbox_rules "delete" "$selected_port" >/dev/null 2>&1 || true
        fi
        if [ "$old_engine" == "nftables" ]; then
            _pf_apply_nft_rules "add" "$selected_port" "$old_del_dest" "$old_tport" "$old_net" "$old_family" >/dev/null 2>&1 || true
            _save_nftables_rules
        else
            _pf_apply_singbox_rules "add" "$selected_port" "$old_addr" "$old_tport" "$old_net" >/dev/null 2>&1 || true
            _manage_service restart >/dev/null 2>&1 || true
        fi
        _error "修改失败，已恢复原规则"
        read -p "  按回车继续..."
        return 1
    fi

    _success "转发规则已修改并生效！"
    echo -e "  【${new_name}】本机端口: ${GREEN}${selected_port}${NC} -> 目标: ${GREEN}${new_addr}:${new_tport}${NC}  [${new_net_display}]"
    [ "$PF_PUBLISH_HINT" == "true" ] && echo -e "  ${YELLOW}提示: Docker/Podman 桥接网络下，请确保宿主机已发布 ${selected_port}/${new_net}${NC}"
    _pf_auto_manage_dns_cron
    read -p "  按回车继续..."
}

_pf_clear() {
    local count=$(_pf_count)
    if [ "$count" -eq 0 ]; then
        _warn "暂无转发规则"; read -p "  按回车继续..."; return
    fi

    echo ""
    _warn "确认清空全部 ${count} 条端口转发规则？（中转规则不受影响）"
    read -p "  (y/N): " confirm
    if [ "$confirm" != "y" ]; then return; fi

    local need_singbox_restart=false failed="false" txn_dir
    _state_lock_acquire || return 1
    txn_dir=$(_txn_begin) || { _state_lock_release; return 1; }
    if ! _txn_snapshot_file "$txn_dir" relay "$RELAY_CONFIG_FILE" \
        || ! _txn_snapshot_file "$txn_dir" pf "$PF_METADATA_FILE"; then
        _txn_cleanup "$txn_dir"
        _state_lock_release
        return 1
    fi
    while IFS=$'\t' read -r port engine addr tport net resolved family; do
        [ -z "$port" ] && continue
        local del_dest="${resolved:-$addr}"
        [ "$del_dest" == "null" ] && del_dest="$addr"
        if [ -z "$family" ] || [ "$family" == "null" ]; then
            family=$(_pf_guess_target_family "$del_dest")
        fi

        if [ "$engine" == "nftables" ]; then
            _pf_apply_nft_rules "delete" "$port" "$del_dest" "$tport" "$net" "$family"
        else
            _pf_apply_singbox_rules "delete" "$port" || failed="true"
            need_singbox_restart=true
        fi
    done < <(jq -r 'to_entries[] | [.key, .value.engine, .value.target_addr, (.value.target_port|tostring), .value.network, (.value.resolved_ip // "null"), (.value.target_family // "null")] | @tsv' "$PF_METADATA_FILE" 2>/dev/null)

    _atomic_write_json "$PF_METADATA_FILE" '{}' || failed="true"
    _save_nftables_rules
    if [ "$need_singbox_restart" = true ]; then
        _restart_checked || failed="true"
    fi

    if [ "$failed" = "true" ]; then
        _txn_restore_file "$txn_dir" relay "$RELAY_CONFIG_FILE"
        _txn_restore_file "$txn_dir" pf "$PF_METADATA_FILE"
        while IFS=$'\t' read -r port engine addr tport net resolved family; do
            [ "$engine" = "nftables" ] || continue
            local restore_dest="${resolved:-$addr}"
            [ "$restore_dest" = "null" ] && restore_dest="$addr"
            if [ -z "$family" ] || [ "$family" = "null" ]; then
                family=$(_pf_guess_target_family "$restore_dest")
            fi
            _pf_apply_nft_rules "add" "$port" "$restore_dest" "$tport" "$net" "$family" >/dev/null 2>&1 || true
        done < <(jq -r 'to_entries[] | [.key, .value.engine, .value.target_addr, (.value.target_port|tostring), .value.network, (.value.resolved_ip // "null"), (.value.target_family // "null")] | @tsv' "$txn_dir/pf" 2>/dev/null)
        _save_nftables_rules
        _manage_service restart >/dev/null 2>&1 || true
        _txn_cleanup "$txn_dir"
        _state_lock_release
        _error "清空端口转发失败，已恢复原规则"
        return 1
    fi

    _txn_cleanup "$txn_dir"
    _state_lock_release

    _success "所有端口转发规则已清空"
    _pf_auto_manage_dns_cron
    read -p "  按回车继续..."
}

_pf_dns_refresh() {
    [ ! -f "$PF_METADATA_FILE" ] && return 0
    local updated=false
    local refresh_list=""

    # 不使用“jq | while”管道，避免循环在子 Shell 中运行后丢失 updated 状态。
    refresh_list=$(mktemp /tmp/singboxlite-pf-dns.XXXXXX) || return 1
    if ! jq -r 'to_entries[] | select(.value.engine == "nftables" and .value.target_is_domain == true and .value.resolved_ip != null) | [.key, .value.target_addr, .value.resolved_ip, (.value.target_port|tostring), .value.network, (.value.target_family // "ipv4")] | @tsv' \
        "$PF_METADATA_FILE" > "$refresh_list" 2>/dev/null; then
        logger -t "pf-dns-refresh" "读取端口转发元数据失败"
        rm -f "$refresh_list"
        return 1
    fi

    while IFS=$'\t' read -r port addr old_ip tport network family; do
        [ -z "$port" ] && continue
        [ -z "$old_ip" ] || [ "$old_ip" == "null" ] && continue
        if [ -z "$family" ] || [ "$family" == "null" ]; then
            family="ipv4"
        fi

        local new_ip=""
        new_ip=$(_pf_resolve_domain_family "$addr" "$family")
        [ -z "$new_ip" ] && continue
        [ "$new_ip" == "$old_ip" ] && continue

        logger -t "pf-dns-refresh" "域名 $addr 的 IP 已变化: $old_ip -> $new_ip (端口 $port)"
        if ! _pf_apply_nft_rules "add" "$port" "$new_ip" "$tport" "$network" "$family"; then
            logger -t "pf-dns-refresh" "更新端口 $port 的 nftables 规则失败，尝试恢复旧地址 $old_ip"
            _pf_apply_nft_rules "add" "$port" "$old_ip" "$tport" "$network" "$family" >/dev/null 2>&1
            continue
        fi

        local refreshed_meta
        refreshed_meta=$(jq --arg p "$port" --arg ip "$new_ip" '.[$p].resolved_ip = $ip' "$PF_METADATA_FILE")
        if [ -z "$refreshed_meta" ] || ! _atomic_write_json "$PF_METADATA_FILE" "$refreshed_meta"; then
            logger -t "pf-dns-refresh" "更新端口 $port 的元数据失败，尝试恢复旧地址 $old_ip"
            _pf_apply_nft_rules "add" "$port" "$old_ip" "$tport" "$network" "$family" >/dev/null 2>&1
            continue
        fi

        updated=true
    done < "$refresh_list"

    if [ "$updated" = true ]; then
        _save_nftables_rules
        logger -t "pf-dns-refresh" "nftables 规则已自动更新"
    fi
    rm -f "$refresh_list"
}

_pf_auto_manage_dns_cron() {
    [ ! -f "$PF_METADATA_FILE" ] && return 0

    local domain_count
    domain_count=$(jq '[to_entries[] | select(.value.engine == "nftables" and .value.target_is_domain == true and .value.resolved_ip != null)] | length' "$PF_METADATA_FILE" 2>/dev/null || echo 0)
    if [ "$domain_count" -gt 0 ]; then
        _pf_setup_dns_cron
    else
        _pf_remove_dns_cron
    fi
}

_pf_switch_engine() {
    echo ""
    _info "=== 切换转发引擎 ==="
    echo ""
    _pf_ensure_metadata

    local count=$(_pf_count)
    if [ "$count" -eq 0 ]; then
        _warn "暂无转发规则"; read -p "  按回车继续..."; return
    fi

    local ports=()
    local i=1
    while IFS=$'\t' read -r port name engine addr tport net_display; do
        [ -z "$port" ] && continue
        ports+=("$port")
        if [ "$engine" == "nftables" ]; then
            echo -e "  ${GREEN}[$i]${NC} 【${name}】:${CYAN}${port}${NC} -> ${CYAN}${addr}:${tport}${NC}  [${YELLOW}${net_display}${NC}]  引擎: ${GREEN}nftables${NC}"
        else
            echo -e "  ${GREEN}[$i]${NC} 【${name}】:${CYAN}${port}${NC} -> ${CYAN}${addr}:${tport}${NC}  [${YELLOW}${net_display}${NC}]  引擎: ${YELLOW}singbox${NC}"
        fi
        i=$((i+1))
    done < <(jq -r 'to_entries[] | [.key, .value.name, .value.engine, .value.target_addr, (.value.target_port|tostring), .value.network_display] | @tsv' "$PF_METADATA_FILE" 2>/dev/null)

    echo ""
    read -p "  请输入要切换引擎的规则序号 (0 取消): " sel
    if [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "${#ports[@]}" ]; then
        [ "$sel" != "0" ] && _error "无效选择"
        return
    fi

    local selected_port="${ports[$((sel-1))]}"
    local cur_engine=$(jq -r ".\"$selected_port\".engine" "$PF_METADATA_FILE")
    local cur_name=$(jq -r ".\"$selected_port\".name" "$PF_METADATA_FILE")
    local cur_addr=$(jq -r ".\"$selected_port\".target_addr" "$PF_METADATA_FILE")
    local cur_tport=$(jq -r ".\"$selected_port\".target_port" "$PF_METADATA_FILE")
    local cur_net=$(jq -r ".\"$selected_port\".network" "$PF_METADATA_FILE")
    local cur_net_display=$(jq -r ".\"$selected_port\".network_display" "$PF_METADATA_FILE")
    local cur_resolved=$(jq -r ".\"$selected_port\".resolved_ip // empty" "$PF_METADATA_FILE")
    local cur_family=$(jq -r ".\"$selected_port\".target_family // empty" "$PF_METADATA_FILE")
    local cur_del_dest="${cur_resolved:-$cur_addr}"

    echo ""
    if [ "$cur_engine" == "nftables" ]; then
        echo -e "  当前引擎: ${GREEN}nftables${NC}  ->  切换目标: ${YELLOW}singbox${NC}"
        echo -e "  ${YELLOW}规则: 【${cur_name}】:${selected_port} -> ${cur_addr}:${cur_tport} [${cur_net_display}]${NC}"
        echo ""
        read -p "  确认将此规则从 nftables 切换到 singbox 用户态转发？(y/N): " confirm
        [ "$confirm" != "y" ] && return

        # 删除旧 nftables 规则
        [ -z "$cur_family" ] && cur_family=$(_pf_guess_target_family "$cur_del_dest")
        _pf_apply_nft_rules "delete" "$selected_port" "$cur_del_dest" "$cur_tport" "$cur_net" "$cur_family"
        _save_nftables_rules

        # 用原始域名/IP 建 singbox 规则（singbox 自己做 DNS 解析）
        if ! _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net"; then
            _pf_apply_nft_rules "add" "$selected_port" "$cur_del_dest" "$cur_tport" "$cur_net" "$cur_family" >/dev/null 2>&1
            _save_nftables_rules
            _error "切换失败，已恢复旧的 nftables 规则"
            read -p "  按回车继续..."; return
        fi
        if ! _restart_checked; then
            _pf_apply_singbox_rules "delete" "$selected_port" >/dev/null 2>&1
            _pf_apply_nft_rules "add" "$selected_port" "$cur_del_dest" "$cur_tport" "$cur_net" "$cur_family" >/dev/null 2>&1
            _save_nftables_rules
            _error "切换失败，已恢复旧的 nftables 规则"
            read -p "  按回车继续..."; return
        fi

        # 更新 metadata：引擎改为 singbox，清除 nftables 专用字段
        local switched_meta
        switched_meta=$(jq --arg p "$selected_port" \
            '.[$p].engine = "singbox" | del(.[$p].resolved_ip) | del(.[$p].target_family) | del(.[$p].target_is_domain)' \
            "$PF_METADATA_FILE")
        _atomic_write_json "$PF_METADATA_FILE" "$switched_meta" || {
            _error "端口转发 metadata 更新失败"
            return 1
        }

        _success "已切换到 singbox 引擎，规则生效！"
        echo -e "  ${YELLOW}注意: singbox 用户态转发 UDP 性能低于 nftables，但兼容性更好（如 QUIC/Hysteria2）${NC}"

    else
        # singbox -> nftables
        echo -e "  当前引擎: ${YELLOW}singbox${NC}  ->  切换目标: ${GREEN}nftables${NC}"
        echo -e "  ${YELLOW}规则: 【${cur_name}】:${selected_port} -> ${cur_addr}:${cur_tport} [${cur_net_display}]${NC}"
        echo ""

        # 先检测 nftables 是否可用
        _pf_detect_engine
        if [ "$PF_ENGINE" != "nftables" ]; then
            _error "当前环境无法使用 nftables 引擎（缺少 netfilter 权限），无法切换"
            read -p "  按回车继续..."; return
        fi

        if [[ "$cur_net" == "udp" || "$cur_net" == "tcp+udp" ]]; then
            local hop_conflict
            hop_conflict=$(_pf_find_hy2_hop_conflict "$selected_port")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                _error "UDP 转发入口端口 ${selected_port} 落在已有 HY2 端口跳跃范围 ${c_range} 内。"
                _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请换端口或先调整该 HY2 跳跃范围。"
                read -p "  按回车继续..."; return
            fi
        fi

        read -p "  确认将此规则从 singbox 切换到 nftables 内核转发？(y/N): " confirm
        [ "$confirm" != "y" ] && return

        # 删除旧 singbox 规则
        if ! _pf_apply_singbox_rules "delete" "$selected_port"; then
            _error "旧的 singbox 规则删除失败，无法切换"
            read -p "  按回车继续..."; return
        fi
        if ! _restart_checked; then
            _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net" >/dev/null 2>&1
            _manage_service restart >/dev/null 2>&1
            _error "切换失败，已恢复旧的 singbox 规则"
            read -p "  按回车继续..."; return
        fi

        # nftables 需要解析域名拿到 IP
        local new_family=""
        local new_resolved=""
        local new_is_domain="false"
        local resolved_payload=""
        resolved_payload=$(_pf_prepare_nft_target "$cur_addr")
        if [ $? -ne 0 ] || [ -z "$resolved_payload" ]; then
            _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net" >/dev/null 2>&1
            _manage_service restart >/dev/null 2>&1
            _error "目标地址无法解析为可用的 IPv4/IPv6，已恢复旧的 singbox 规则"
            read -p "  按回车继续..."; return
        fi
        IFS=$'\t' read -r new_family new_resolved new_is_domain <<< "$resolved_payload"
        [ "$new_is_domain" == "true" ] && _success "域名已解析: $cur_addr -> $new_resolved (${new_family})"

        _pf_enable_forwarding
        if ! _pf_apply_nft_rules "add" "$selected_port" "$new_resolved" "$cur_tport" "$cur_net" "$new_family"; then
            _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net" >/dev/null 2>&1
            _manage_service restart >/dev/null 2>&1
            _error "切换失败，已恢复旧的 singbox 规则"
            read -p "  按回车继续..."; return
        fi
        _save_nftables_rules

        # 更新 metadata：引擎改为 nftables，补充 nftables 专用字段
        local updated_meta
        updated_meta=$(jq --arg p "$selected_port" --arg fam "$new_family" --arg ip "$new_resolved" \
            '.[$p].engine = "nftables" | .[$p].target_family = $fam | .[$p].resolved_ip = $ip' \
            "$PF_METADATA_FILE")
        if [ "$new_is_domain" == "true" ]; then
            updated_meta=$(echo "$updated_meta" | jq --arg p "$selected_port" '.[$p].target_is_domain = true')
        fi
        _atomic_write_json "$PF_METADATA_FILE" "$updated_meta" || {
            _error "端口转发 metadata 更新失败"
            return 1
        }

        _success "已切换到 nftables 引擎，规则生效！"
    fi

    _pf_auto_manage_dns_cron
    read -p "  按回车继续..."
}

_port_forward_menu() {
    # 进入菜单时同步修复已有 DDNS 规则的 cron 周期和脚本路径。
    _pf_auto_manage_dns_cron
    while true; do
        clear
        local count=$(_pf_count)
        echo -e "${CYAN}"
        echo "  ╔═══════════════════════════════════════╗"
        echo -e "  ║    端口转发管理 (当前规则: ${GREEN}${count}${CYAN} 条)      ║"
        echo "  ╠═══════════════════════════════════════╣"
        echo -e "  ║  ${GREEN}[1]${CYAN} 添加转发规则                     ║"
        echo -e "  ║  ${GREEN}[2]${CYAN} 查看当前转发规则                 ║"
        echo -e "  ║  ${GREEN}[3]${CYAN} 修改转发规则                     ║"
        echo -e "  ║  ${GREEN}[4]${CYAN} 删除转发规则                     ║"
        echo -e "  ║  ${GREEN}[5]${CYAN} 切换转发引擎                     ║"
        echo -e "  ║  ${RED}[6]${CYAN} 清空所有转发规则                 ║"
        echo -e "  ║  ${YELLOW}[0]${CYAN} 返回上级菜单                     ║"
        echo "  ╚═══════════════════════════════════════╝"
        echo -e "${NC}"
        
        read -p "  请输入选项 [0-6]: " pf_choice
        case "$pf_choice" in
            1) _pf_add ;;
            2) _pf_view ;;
            3) _pf_modify ;;
            4) _pf_delete ;;
            5) _pf_switch_engine ;;
            6) _pf_clear ;;
            0) return ;;
            *) _error "无效输入"; sleep 1 ;;
        esac
    done
}


_menu() {
    _check_root || return 1
    _check_deps || return 1
    _install_yq || return 1
    _init_relay_dirs || return 1

    while true; do
        clear
        # ASCII Logo (对齐主脚本)
        echo -e "${CYAN}"
        echo '  ____  _             ____            '
        echo ' / ___|(_)_ __   __ _| __ )  _____  __'
        echo ' \___ \| | '\''_ \ / _` |  _ \ / _ \ \/ /'
        echo '  ___) | | | | | (_| | |_) | (_) >  < '
        echo ' |____/|_|_| |_|\__, |____/ \___/_/\_\'
        echo '                |___/    Lite Manager '
        echo -e "${NC}"

        # 标题框
        echo -e "${CYAN}"
        echo "  ╔═══════════════════════════════════════╗"
        echo "  ║       singbox-lite 进阶转发管理       ║"
        echo "  ║                (v17)                  ║"
        echo "  ╚═══════════════════════════════════════╝"
        echo -e "${NC}"

        # 获取系统信息与服务状态
        local os_info="Linux"
        [ -f /etc/os-release ] && os_info=$(grep -E "^NAME=" /etc/os-release | cut -d'"' -f2 | head -1)
        
        local service_status="${RED}○ 已停止${NC}"
        local service_name="sing-box"
        [ -f "/etc/systemd/system/sing-box-relay.service" ] && service_name="sing-box-relay"
        
        if [ "$INIT_SYSTEM" == "systemd" ]; then
            systemctl is-active --quiet "$service_name" && service_status="${GREEN}● 运行中${NC}"
        elif [ "$INIT_SYSTEM" == "openrc" ]; then
            rc-service "$service_name" status 2>/dev/null | grep -q "started" && service_status="${GREEN}● 运行中${NC}"
        else
            _is_pid_file_running_cmd "$SINGBOX_PID_FILE" "$SINGBOX_BIN" && service_status="${GREEN}● 运行中${NC}"
        fi

        echo -e "  系统版本: ${CYAN}${os_info}${NC}"
        echo -e "  中转服务: ${service_status} (${service_name})"
        echo ""
        echo -e "  ${CYAN}【基础配置】${NC}"
        echo -e "    ${GREEN}[1]${NC} 落地机：生成全协议 Token"
        echo -e "    ${GREEN}[2]${NC} 中转机：通过 Token 导入规则"
        echo -e "    ${GREEN}[3]${NC} 中转机：导入第三方节点"
        echo ""
        echo -e "  ${CYAN}【链路管理】${NC}"
        echo -e "    ${GREEN}[4]${NC} 查看当前中转链路"
        echo -e "    ${GREEN}[5]${NC} 删除指定中转路由"
        echo -e "    ${GREEN}[6]${NC} 修改中转监听端口"
        echo -e "    ${RED}[7]${NC} 清空所有中转配置"
        echo ""
        echo -e "  ${CYAN}【端口转发】${NC}"
        echo -e "    ${GREEN}[8]${NC} 端口转发管理"
        echo ""
        echo -e "  ─────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        read -p "  请输入选项 [0-8]: " choice
        case $choice in
            1) _landing_config ;;
            2) _relay_config ;;
            3) _import_link_config ;;
            4) _view_relays ;;
            5) _delete_relay ;;
            6) _modify_relay_port ;;
            7) echo ""; _warn "确认清空所有中转配置?"; read -p "  (y/N): " cn;
               if [ "$cn" == "y" ]; then
                   _clear_all_relays
               fi ;;
            0) break ;;
            8) _port_forward_menu ;;
            *) _error "无效输入"; sleep 1 ;;
        esac
    done
}
# 命令行参数解析：支持 cron 定时任务直接调用刷新函数
case "${1:-}" in
    pf-dns-refresh)
        _check_root || exit 1
        _check_deps || exit 1
        _state_lock_acquire || exit 1
        _pf_dns_refresh
        refresh_status=$?
        _state_lock_release
        exit "$refresh_status"
        ;;
esac

_menu

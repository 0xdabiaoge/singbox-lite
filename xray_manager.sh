#!/bin/bash
umask 077
# ============================================================
# xray_manager.sh — Xray-core 节点管理子脚本
# 与 singbox.sh 共存，共享 clash.yaml
# ============================================================
XRAY_SCRIPT_VERSION="3.1.2"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# --- 路径定义 ---
XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
XRAY_CONFIG="${XRAY_DIR}/config.json"
XRAY_METADATA="${XRAY_DIR}/metadata.json"
XRAY_RUN_DIR="/run/singboxlite"
XRAY_PID_FILE="${XRAY_RUN_DIR}/xray.pid"

# 共享路径 (继承自 singbox.sh 或使用默认值)
SINGBOX_DIR="${SINGBOX_DIR:-/usr/local/etc/sing-box}"
CLASH_YAML_FILE="${CLASH_YAML_FILE:-${SINGBOX_DIR}/clash.yaml}"
YQ_BINARY="${YQ_BINARY:-/usr/local/bin/yq}"
SINGBOXLITE_LOCK_FILE="${SINGBOX_DIR}/.singboxlite.lock"
XRAY_STATE_LOCK_OWNED=0

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 打印函数 (如未从父进程继承则定义本地版本) ---
if ! declare -f _info >/dev/null 2>&1; then
    _info()    { echo -e "${CYAN}[信息] $1${NC}" >&2; }
    _error()   { echo -e "${RED}[错误] $1${NC}" >&2; }
    _success() { echo -e "${GREEN}[成功] $1${NC}" >&2; }
    _warn()    { echo -e "${YELLOW}[注意] $1${NC}" >&2; }
    _warning() { _warn "$1"; }
fi

_xray_flock_wait() {
    local fd="$1" timeout="${2:-30}" attempts i
    [[ "$fd" =~ ^[0-9]+$ && "$timeout" =~ ^[0-9]+$ ]] || return 1
    attempts=$((timeout * 10))
    for ((i = 0; i <= attempts; i++)); do
        flock -n "$fd" 2>/dev/null && return 0
        ((i < attempts)) && sleep 0.1
    done
    return 1
}

_acquire_singboxlite_lock() {
    [ "${SINGBOXLITE_LOCK_HELD:-0}" = "1" ] && return 0
    mkdir -p "$SINGBOX_DIR"
    if ! command -v flock >/dev/null 2>&1; then
        _pkg_install util-linux >/dev/null 2>&1 || true
    fi
    if ! command -v flock >/dev/null 2>&1; then
        _error "系统缺少 flock，无法安全修改共享配置。"
        return 1
    fi
    exec 219>"$SINGBOXLITE_LOCK_FILE" || return 1
    if ! _xray_flock_wait 219 30; then
        _error "等待 singboxlite 共享状态锁超时，请稍后重试。"
        exec 219>&-
        return 1
    fi
    export SINGBOXLITE_LOCK_HELD=1
    XRAY_STATE_LOCK_OWNED=1
}

_release_singboxlite_lock() {
    [ "$XRAY_STATE_LOCK_OWNED" -eq 1 ] || return 0
    flock -u 219 2>/dev/null || true
    exec 219>&-
    XRAY_STATE_LOCK_OWNED=0
    unset SINGBOXLITE_LOCK_HELD
}

_with_singboxlite_lock() {
    local release_after=0 rc
    if [ "${SINGBOXLITE_LOCK_HELD:-0}" != "1" ]; then
        _acquire_singboxlite_lock || return 1
        release_after=1
    fi
    "$@"
    rc=$?
    [ "$release_after" -eq 1 ] && _release_singboxlite_lock
    return "$rc"
}

trap '_release_singboxlite_lock' EXIT
trap '_release_singboxlite_lock; exit 130' INT TERM

# --- URL 编码 ---
if ! declare -f _url_encode >/dev/null 2>&1; then
    _url_encode() {
        printf '%s' "$1" | jq -sRr @uri
    }
fi

if ! declare -f _cert_sha256_hex >/dev/null 2>&1; then
    _cert_sha256_hex() {
        local cert_path="$1"
        [ -f "$cert_path" ] || return 1
        openssl x509 -in "$cert_path" -noout -fingerprint -sha256 2>/dev/null | \
            awk -F= 'NR==1 { gsub(":", "", $2); print tolower($2) }'
    }
fi

if ! declare -f _release_install_cache >/dev/null 2>&1; then
    _release_install_cache() {
        sync 2>/dev/null || true
        return 0
    }
fi

if ! declare -f _ss_base64_encode >/dev/null 2>&1; then
    _ss_base64_encode() {
        # SS 标准 Base64 (无 Padding)
        printf '%s' "$1" | base64 | tr -d '\n\r ' | sed 's/=//g'
    }
fi
# --- 环境检测 ---
if ! declare -f _detect_init_system >/dev/null 2>&1; then
    _detect_init_system() {
        if [ -f /sbin/openrc-run ] || command -v rc-service >/dev/null; then
            INIT_SYSTEM="openrc"
        elif command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
            INIT_SYSTEM="systemd"
        else
            INIT_SYSTEM="direct"
        fi
    }
fi
[ -z "$INIT_SYSTEM" ] && _detect_init_system

# 与主脚本使用相同的 Go 运行时软内存限制。独立运行 Xray 管理器时，
# 本地计算有效内存；由 singbox.sh 调用时直接复用主脚本实现。
_xray_get_mem_limit() {
    if declare -f _get_mem_limit >/dev/null 2>&1; then
        _get_mem_limit
        return $?
    fi

    local total_mem_mb=0 cgroup_limit="" candidate_mb=0
    local limit limit_file
    total_mem_mb=$(awk '/^MemTotal:/{print int($2 / 1024); exit}' /proc/meminfo 2>/dev/null)
    [[ "$total_mem_mb" =~ ^[0-9]+$ ]] || total_mem_mb=0

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

# --- 包管理 ---
if ! declare -f _pkg_install >/dev/null 2>&1; then
    _pkg_install() {
        local pkgs="$*"
        [ -z "$pkgs" ] && return 0
        if command -v apk >/dev/null; then
            apk add --no-cache $pkgs >/dev/null 2>&1
        elif command -v apt-get >/dev/null; then
            if [ ! -d "/var/lib/apt/lists" ] || [ "$(ls -A /var/lib/apt/lists/ 2>/dev/null | wc -l)" -le 1 ]; then
                apt-get update -qq >/dev/null 2>&1
            fi
            if [ -f /run/.containerenv ] || grep -qaE 'libpod|podman' /proc/1/cgroup /proc/1/environ 2>/dev/null; then
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
                    apt-get update -qq >/dev/null 2>&1
                    DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >/dev/null 2>&1
                }
            fi
        elif command -v yum >/dev/null; then yum install -y $pkgs >/dev/null 2>&1
        elif command -v dnf >/dev/null; then dnf install -y $pkgs >/dev/null 2>&1
        fi
    }
fi

_ensure_xray_dependencies() {
    local cmd missing="" lock_pkg="util-linux"
    for cmd in jq openssl wget unzip flock; do
        command -v "$cmd" >/dev/null 2>&1 || missing="${missing} ${cmd}"
    done
    if [ -n "$missing" ]; then
        _info "正在补齐 Xray 管理依赖:${missing}"
        command -v apk >/dev/null 2>&1 && lock_pkg="util-linux-misc"
        _pkg_install jq openssl wget unzip ca-certificates "$lock_pkg" >/dev/null 2>&1 || true
        command -v flock >/dev/null 2>&1 || _pkg_install util-linux >/dev/null 2>&1 || true
    fi
    for cmd in jq openssl wget unzip flock; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            _error "缺少 Xray 管理依赖: $cmd"
            return 1
        fi
    done
}

# --- Xray 专用原子 JSON 修改 ---
_xray_atomic_modify_json() {
        local file="$1" filter="$2"
        [ ! -f "$file" ] && return 1
        local tmp tmp_stub
        # Xray 新版本会按文件扩展名识别配置格式；候选配置必须保留 .json
        # 后缀。但 BusyBox mktemp 要求模板以 XXXXXX 结尾，不支持 GNU
        # mktemp 的任意后缀写法。先在同一受保护目录中占用随机文件名，
        # 再原子改名为 .json，兼顾 Alpine 与 Debian。
        tmp_stub=$(mktemp "${file}.tmp.XXXXXX") || return 1
        tmp="${tmp_stub}.json"
        if ! mv -f -- "$tmp_stub" "$tmp"; then
            rm -f -- "$tmp_stub"
            return 1
        fi
        if ! jq "$filter" "$file" > "$tmp" || ! jq empty "$tmp" >/dev/null 2>&1; then
            _error "修改JSON失败: $file"
            rm -f -- "$tmp"
            return 1
        fi
        if [ "$file" = "$XRAY_CONFIG" ] && [ -x "$XRAY_BIN" ] && \
           ! "$XRAY_BIN" run -test -config "$tmp" >/dev/null 2>&1; then
            _error "Xray 配置校验失败，原配置保持不变。"
            rm -f -- "$tmp"
            return 1
        fi
        chmod 600 "$tmp"
        mv -f -- "$tmp" "$file"
}

# --- Xray 专用原子 YAML 修改 ---
_xray_atomic_modify_yaml() {
        local file="$1" filter="$2"
        [ ! -f "$file" ] && return 1
        local tmp
        tmp=$(mktemp "${file}.tmp.XXXXXX") || return 1
        if ${YQ_BINARY} eval "$filter" "$file" > "$tmp" 2>/dev/null; then
            chmod 600 "$tmp"
            mv -f -- "$tmp" "$file"
        else
            _error "修改YAML失败: $file"
            rm -f -- "$tmp"
            return 1
        fi
}

# --- Clash YAML 节点操作（使用 Xray 专用实现，避免继承父脚本的宽泛删除） ---
_xray_add_node_to_yaml() {
        local proxy_json="$1"
        local name proxy_file
        name=$(echo "$proxy_json" | jq -er '.name | select(type == "string" and length > 0)') || return 1
        [ -f "$CLASH_YAML_FILE" ] || { _error "共享 clash.yaml 不存在。"; return 1; }
        export XRAY_NODE_NAME="$name"
        if ${YQ_BINARY} eval -e '.proxies[]? | select(.name == env(XRAY_NODE_NAME))' "$CLASH_YAML_FILE" >/dev/null 2>&1; then
            _error "节点名称 [$name] 已存在，请使用唯一名称。"
            return 1
        fi
        proxy_file=$(mktemp "${XRAY_DIR}/.proxy.XXXXXX") || return 1
        if ! printf '%s\n' "$proxy_json" | ${YQ_BINARY} -P > "$proxy_file"; then
            rm -f -- "$proxy_file"
            return 1
        fi
        export XRAY_PROXY_FILE="$proxy_file"
        if ! ${YQ_BINARY} eval -e '.proxy-groups[]? | select(.name == "节点选择")' "$CLASH_YAML_FILE" >/dev/null 2>&1; then
            _xray_atomic_modify_yaml "$CLASH_YAML_FILE" \
                '.proxy-groups = ((.proxy-groups // []) + [{"name":"节点选择","type":"select","proxies":[]}])' || {
                rm -f -- "$proxy_file"
                return 1
            }
        fi
        if ! _xray_atomic_modify_yaml "$CLASH_YAML_FILE" '
            .proxies = ((.proxies // []) + [load(env(XRAY_PROXY_FILE))]) |
            (.proxy-groups[] | select(.name == "节点选择") | .proxies) =
              (((.proxy-groups[] | select(.name == "节点选择") | .proxies) // []) + [env(XRAY_NODE_NAME)] | unique)'; then
            rm -f -- "$proxy_file"
            return 1
        fi
        rm -f -- "$proxy_file"
}

_xray_remove_node_from_yaml() {
        local name="$1" port="${2:-}"
        [ -f "$CLASH_YAML_FILE" ] || return 0
        export DEL_NAME="$name"
        export DEL_PORT="$port"
        if [ -n "$port" ]; then
            _xray_atomic_modify_yaml "$CLASH_YAML_FILE" \
                'del(.proxies[]? | select(.name == env(DEL_NAME) and ((.port | tostring) == env(DEL_PORT))))' || return 1
        else
            _xray_atomic_modify_yaml "$CLASH_YAML_FILE" \
                'del(.proxies[]? | select(.name == env(DEL_NAME)))' || return 1
        fi
        if ! ${YQ_BINARY} eval -e '.proxies[]? | select(.name == env(DEL_NAME))' "$CLASH_YAML_FILE" >/dev/null 2>&1; then
            _xray_atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxy-groups[]?.proxies) -= [env(DEL_NAME)]' || return 1
        fi
}

if ! declare -f _find_proxy_name >/dev/null 2>&1; then
    _find_proxy_name() {
        local port="$1" type="$2"
        ${YQ_BINARY} eval ".proxies[] | select(.port == ${port}) | .name" "$CLASH_YAML_FILE" 2>/dev/null | head -1
    }
fi

# --- 端口冲突检测 (跨双核心) ---
_xray_check_port_occupied() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep -q ":${port} " && return 0
        ss -ulnp 2>/dev/null | grep -q ":${port} " && return 0
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep -q ":${port} " && return 0
    fi
    return 1
}

_xray_is_pid_running_cmd() {
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

_xray_is_pid_file_running_cmd() {
    local pid_file="$1"
    local pattern="$2"
    local pid
    [ -s "$pid_file" ] || return 1
    pid=$(cat "$pid_file" 2>/dev/null)
    _xray_is_pid_running_cmd "$pid" "$pattern"
}

_check_xray_port_conflict() {
    local port="$1" protocol="${2:-tcp}"
    # 检查系统端口
    if _xray_check_port_occupied "$port"; then
        _error "端口 $port 已被系统占用！"
        return 0
    fi
    # 检查 Xray 配置
    if [ -f "$XRAY_CONFIG" ] && jq -e ".inbounds[] | select(.port == $port)" "$XRAY_CONFIG" >/dev/null 2>&1; then
        _error "端口 $port 已被 Xray 节点使用！"
        return 0
    fi
    # 检查 sing-box 配置
    local sb_config="${SINGBOX_DIR}/config.json"
    if [ -f "$sb_config" ] && jq -e ".inbounds[] | select(.listen_port == $port)" "$sb_config" >/dev/null 2>&1; then
        _error "端口 $port 已被 sing-box 节点使用！"
        return 0
    fi
    local relay_config="${SINGBOX_DIR}/relay.json"
    if [ -f "$relay_config" ] && jq -e ".inbounds[]? | select(.listen_port == $port)" "$relay_config" >/dev/null 2>&1; then
        _error "端口 $port 已被中转或 sing-box 端口转发使用！"
        return 0
    fi
    local pf_meta="${SINGBOX_DIR}/relay_pf.json"
    if [ -f "$pf_meta" ] && jq -e --arg p "$port" 'has($p)' "$pf_meta" >/dev/null 2>&1; then
        _error "端口 $port 已被端口转发规则使用！"
        return 0
    fi
    local relay_links="${SINGBOX_DIR}/relay_links.json"
    if [ -f "$relay_links" ] && jq -e --argjson p "$port" '
        to_entries[]? | .value.port_hopping? as $r |
        select(($r // "") | test("^[0-9]+-[0-9]+$")) |
        ($r | split("-") | map(tonumber)) as $b |
        select($p >= $b[0] and $p <= $b[1])' "$relay_links" >/dev/null 2>&1; then
        _error "端口 $port 落在已有 Hysteria2 跳跃范围内！"
        return 0
    fi
    return 1
}

# --- 公网 IP 获取 ---
if ! declare -f _get_public_ip >/dev/null 2>&1; then
    _get_public_ip() {
        [ -n "$server_ip" ] && [ "$server_ip" != "null" ] && { echo "$server_ip"; return; }
        local ip=$(timeout 5 curl -fsS4 --max-time 2 https://icanhazip.com 2>/dev/null || timeout 5 curl -fsS4 --max-time 2 https://ipinfo.io/ip 2>/dev/null)
        [ -z "$ip" ] && ip=$(timeout 5 curl -fsS6 --max-time 2 https://icanhazip.com 2>/dev/null)
        server_ip="$ip"
        echo "$ip"
    }
fi

# --- 自签证书生成 (Hysteria2 专用) ---
_generate_xray_cert() {
    local domain="$1" cert_path="$2" key_path="$3"
    _info "正在生成自签证书 (${domain})..."
    openssl req -x509 -newkey rsa:2048 -keyout "$key_path" -out "$cert_path" \
        -days 3650 -nodes -subj "/CN=${domain}" \
        -addext "subjectAltName=DNS:${domain}" 2>/dev/null
    if [ $? -ne 0 ]; then
        _error "证书生成失败！"
        return 1
    fi
    chmod 644 "$cert_path"
    chmod 600 "$key_path"
    _success "证书已生成。"
}

# ============================================================
#                   Xray 核心安装与管理
# ============================================================

_install_xray() {
    _info "正在安装/更新 Xray-core..."
    
    # 确保 unzip 可用
    command -v unzip &>/dev/null || _pkg_install unzip
    
    local arch=$(uname -m)
    local xray_arch=""
    case "$arch" in
        x86_64|amd64)  xray_arch="64" ;;
        aarch64|arm64) xray_arch="arm64-v8a" ;;
        armv7l)        xray_arch="arm32-v7a" ;;
        *)
            _error "不支持的 CPU 架构: $arch"
            return 1
            ;;
    esac
    
    local zip_name="Xray-linux-${xray_arch}.zip"
    local download_url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    local tmp_dir
    mkdir -p /var/tmp || { _error "无法创建安装临时目录。"; return 1; }
    tmp_dir=$(mktemp -d /var/tmp/.xray-install.XXXXXX) || { _error "无法创建安装临时目录。"; return 1; }
    local tmp_zip="${tmp_dir}/xray.zip"
    local tmp_digest="${tmp_dir}/xray.zip.dgst"
    
    _info "下载地址: ${download_url}"
    if ! wget -qO "$tmp_zip" "$download_url"; then
        _error "Xray 下载失败！"
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! wget -qO "$tmp_digest" "${download_url}.dgst"; then
        _error "Xray 官方摘要下载失败，拒绝安装未经校验的核心。"
        rm -rf -- "$tmp_dir"
        return 1
    fi
    local expected_sha256 actual_sha256
    expected_sha256=$(awk 'tolower($0) ~ /sha.*256/ {print tolower($NF); exit}' "$tmp_digest" | tr -cd '0-9a-f')
    if command -v sha256sum >/dev/null 2>&1; then
        actual_sha256=$(sha256sum "$tmp_zip" | awk '{print tolower($1)}')
    else
        actual_sha256=$(openssl dgst -sha256 "$tmp_zip" | awk '{print tolower($NF)}')
    fi
    if [ "${#expected_sha256}" -ne 64 ] || [ "$actual_sha256" != "$expected_sha256" ]; then
        _error "Xray 下载包 SHA-256 校验失败，拒绝安装。"
        rm -rf -- "$tmp_dir"
        return 1
    fi

    # 只提取运行所需的三个文件，避免完整展开压缩包中的额外资产。
    # 尤其在 128MB 容器中，完整解压后再复制核心会造成明显的页缓存峰值。
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
    
    if [ ! -f "${tmp_dir}/xray" ]; then
        _error "下载包中缺少 Xray 二进制。"
        rm -rf -- "$tmp_dir"
        return 1
    fi
    chmod 755 "${tmp_dir}/xray"
    if ! "${tmp_dir}/xray" version >/dev/null 2>&1; then
        _error "下载的 Xray 二进制无法执行，拒绝替换。"
        rm -rf -- "$tmp_dir"
        return 1
    fi

    # 验证成功后再原子替换，并保留可回滚副本。
    local previous_bin="${tmp_dir}/xray.previous"
    [ -f "$XRAY_BIN" ] && cp -p "$XRAY_BIN" "$previous_bin"
    local staged_bin="${XRAY_BIN}.new.$$"
    rm -f -- "$staged_bin"
    mv -f -- "${tmp_dir}/xray" "$staged_bin" && chmod 755 "$staged_bin" || { rm -f -- "$staged_bin"; rm -rf -- "$tmp_dir"; return 1; }
    mv -f -- "$staged_bin" "$XRAY_BIN"
    if ! "$XRAY_BIN" version >/dev/null 2>&1; then
        _error "新核心验证失败，正在恢复旧版本。"
        if [ -f "$previous_bin" ]; then
            install -m 755 "$previous_bin" "$XRAY_BIN"
        else
            rm -f -- "$XRAY_BIN"
        fi
        rm -rf -- "$tmp_dir"
        return 1
    fi
    
    # 安装 geodata
    mkdir -p "$XRAY_DIR"
    [ -f "${tmp_dir}/geoip.dat" ] && mv "${tmp_dir}/geoip.dat" "$XRAY_DIR/"
    [ -f "${tmp_dir}/geosite.dat" ] && mv "${tmp_dir}/geosite.dat" "$XRAY_DIR/"
    
    rm -rf "$tmp_dir"
    _release_install_cache
    
    local version=$($XRAY_BIN version 2>/dev/null | head -1 | awk '{print $2}')
    _success "Xray-core v${version} 安装成功！"
}

_create_xray_systemd_service() {
    local mem_limit_mb
    mem_limit_mb=$(_xray_get_mem_limit) || return 1
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
Environment="GOMEMLIMIT=${mem_limit_mb}MiB"
ExecStart=${XRAY_BIN} run -c ${XRAY_CONFIG}
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray 2>/dev/null
}

_create_xray_openrc_service() {
    local mem_limit_mb
    mem_limit_mb=$(_xray_get_mem_limit) || return 1
    cat > /etc/init.d/xray <<EOF
#!/sbin/openrc-run
description="Xray Service"
export GOMEMLIMIT="${mem_limit_mb}MiB"
command="${XRAY_BIN}"
command_args="run -c ${XRAY_CONFIG}"
pidfile="${XRAY_PID_FILE}"
command_background=true
supervisor=supervise-daemon

start_pre() {
    checkpath --directory --mode 0700 "${XRAY_RUN_DIR}"
}
EOF
    chmod +x /etc/init.d/xray
    rc-update add xray default 2>/dev/null
}

_create_xray_service() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _create_xray_systemd_service
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        _create_xray_openrc_service
    elif [ "$INIT_SYSTEM" == "direct" ]; then
        mkdir -p "$XRAY_RUN_DIR"
        chmod 700 "$XRAY_RUN_DIR"
        touch /var/log/xray.log 2>/dev/null || true
        chmod 600 /var/log/xray.log 2>/dev/null || true
    fi
}

_validate_xray_config() {
    [ -f "$XRAY_CONFIG" ] || { _error "Xray 配置不存在。"; return 1; }
    jq empty "$XRAY_CONFIG" >/dev/null 2>&1 || { _error "Xray 配置不是有效 JSON。"; return 1; }
    [ -x "$XRAY_BIN" ] || return 0
    "$XRAY_BIN" run -test -config "$XRAY_CONFIG" >/dev/null 2>&1 || {
        _error "Xray 配置校验失败。"
        return 1
    }
}

_manage_xray_service() {
    local action="$1"
    if [[ "$action" == "start" || "$action" == "restart" ]]; then
        _validate_xray_config || return 1
    fi
    local rc=0
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        if [[ "$action" == "start" || "$action" == "restart" ]]; then
            systemctl reset-failed xray >/dev/null 2>&1 || true
        fi
        systemctl "$action" xray 2>/dev/null 8>&- 9>&- 219>&- || rc=$?
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-service xray "$action" 2>/dev/null 8>&- 9>&- 219>&- || rc=$?
    elif [ "$INIT_SYSTEM" == "direct" ]; then
        local pid_file="$XRAY_PID_FILE"
        local log_file="/var/log/xray.log"
        case "$action" in
            start)
                if _xray_is_pid_file_running_cmd "$pid_file" "$XRAY_BIN"; then
                    :
                else
                    rm -f "$pid_file"
                    nohup env GOMEMLIMIT="$(_xray_get_mem_limit)MiB" \
                        "$XRAY_BIN" run -c "$XRAY_CONFIG" >> "$log_file" 2>&1 8>&- 9>&- 219>&- &
                    echo $! > "$pid_file"
                    sleep 1
                    _xray_is_pid_file_running_cmd "$pid_file" "$XRAY_BIN" || rc=1
                fi
                ;;
            stop)
                if [ -s "$pid_file" ]; then
                    local pid
                    pid=$(cat "$pid_file" 2>/dev/null)
                    if _xray_is_pid_running_cmd "$pid" "$XRAY_BIN"; then
                        kill "$pid" 2>/dev/null
                    fi
                fi
                rm -f "$pid_file"
                ;;
            restart)
                _manage_xray_service stop
                sleep 1
                _manage_xray_service start || rc=$?
                ;;
            status)
                if _xray_is_pid_file_running_cmd "$pid_file" "$XRAY_BIN"; then
                    _success "Xray direct 后台模式运行中 (PID: $(cat "$pid_file"))"
                    return 0
                fi
                rm -f "$pid_file"
                _warn "Xray direct 后台模式未运行。"
                return 1
                ;;
        esac
    fi
    if [ "$rc" -ne 0 ]; then
        _error "Xray 服务操作失败: $action"
        return "$rc"
    fi
    case "$action" in
        start)   _success "Xray 服务已启动。" ;;
        stop)    _success "Xray 服务已停止。" ;;
        restart) _success "Xray 服务已重启。" ;;
        status)
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                systemctl status xray --no-pager
            else
                rc-service xray status
            fi
            ;;
    esac
}

_init_xray_config() {
    mkdir -p "$XRAY_DIR"
    if [ ! -f "$XRAY_CONFIG" ]; then
        cat > "$XRAY_CONFIG" <<'EOF'
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "rules": []
  }
}
EOF
        _success "Xray 配置文件已初始化。"
    fi
    [ -f "$XRAY_METADATA" ] || echo '{}' > "$XRAY_METADATA"
    chmod 700 "$XRAY_DIR"
    chmod 600 "$XRAY_CONFIG" "$XRAY_METADATA" 2>/dev/null || true
    local sensitive_file
    for sensitive_file in "$XRAY_DIR"/*.key; do [ -f "$sensitive_file" ] && chmod 600 "$sensitive_file"; done
    for sensitive_file in "$XRAY_DIR"/*.pem; do [ -f "$sensitive_file" ] && chmod 644 "$sensitive_file"; done
    return 0
}

_check_and_fix_xray_listen() {
    [ -f "$XRAY_CONFIG" ] || return 1
    if jq -e '.inbounds[]? | select(.listen == "0.0.0.0")' "$XRAY_CONFIG" >/dev/null 2>&1; then
        if _xray_atomic_modify_json "$XRAY_CONFIG" '(.inbounds[]? | select(.listen == "0.0.0.0") | .listen) = "::"'; then
            _success "已将既有 Xray 入站监听从 0.0.0.0 升级为 ::，支持 IPv4/IPv6 双栈。"
            return 0
        fi
        return 2
    fi
    return 1
}

XRAY_TX_DIR=""
_xray_snapshot_state() {
    XRAY_TX_DIR=$(mktemp -d "${TMPDIR:-/tmp}/singboxlite-xray.XXXXXX") || return 1
    mkdir -p "$XRAY_TX_DIR/certs"
    if [ -f "$XRAY_CONFIG" ]; then cp -p "$XRAY_CONFIG" "$XRAY_TX_DIR/config.json" && : > "$XRAY_TX_DIR/config.present"; fi
    if [ -f "$XRAY_METADATA" ]; then cp -p "$XRAY_METADATA" "$XRAY_TX_DIR/metadata.json" && : > "$XRAY_TX_DIR/metadata.present"; fi
    if [ -f "$CLASH_YAML_FILE" ]; then cp -p "$CLASH_YAML_FILE" "$XRAY_TX_DIR/clash.yaml" && : > "$XRAY_TX_DIR/clash.present"; fi
    local file
    for file in "$XRAY_DIR"/*.pem "$XRAY_DIR"/*.key; do
        [ -f "$file" ] && cp -p "$file" "$XRAY_TX_DIR/certs/"
    done
    return 0
}

_xray_restore_state() {
    local snapshot="$1" file
    [ -d "$snapshot" ] || return 1
    if [ -f "$snapshot/config.present" ]; then cp -p "$snapshot/config.json" "$XRAY_CONFIG"; else rm -f -- "$XRAY_CONFIG"; fi
    if [ -f "$snapshot/metadata.present" ]; then cp -p "$snapshot/metadata.json" "$XRAY_METADATA"; else rm -f -- "$XRAY_METADATA"; fi
    if [ -f "$snapshot/clash.present" ]; then cp -p "$snapshot/clash.yaml" "$CLASH_YAML_FILE"; fi
    for file in "$XRAY_DIR"/*.pem "$XRAY_DIR"/*.key; do
        [ -f "$file" ] && rm -f -- "$file"
    done
    for file in "$snapshot/certs"/*.pem "$snapshot/certs"/*.key; do
        [ -f "$file" ] && cp -p "$file" "$XRAY_DIR/"
    done
    chmod 600 "$XRAY_CONFIG" "$XRAY_METADATA" "$CLASH_YAML_FILE" 2>/dev/null || true
    return 0
}

_xray_drop_snapshot() {
    local snapshot="$1"
    case "$snapshot" in
        "${TMPDIR:-/tmp}"/singboxlite-xray.*) [ -d "$snapshot" ] && rm -rf -- "$snapshot" ;;
    esac
}

_run_xray_transaction() {
    local operation="$1"
    shift
    _xray_snapshot_state || { _error "无法创建变更快照。"; return 1; }
    local snapshot="$XRAY_TX_DIR"
    if "$operation" "$@" && _validate_xray_config && _manage_xray_service restart; then
        _xray_drop_snapshot "$snapshot"
        return 0
    fi
    _error "Xray 变更失败，正在恢复配置、元数据、证书和 Clash 条目。"
    _xray_restore_state "$snapshot"
    _manage_xray_service restart >/dev/null 2>&1 || true
    _xray_drop_snapshot "$snapshot"
    return 1
}

_view_xray_log() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        journalctl -u xray -n 50 --no-pager -f
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        _warn "OpenRC 环境下请查看 /var/log/messages"
        tail -f /var/log/messages 2>/dev/null | grep -i xray
    else
        tail -n 50 -f /var/log/xray.log 2>/dev/null
    fi
}

_uninstall_xray() {
    echo ""
    _warn "即将卸载 Xray 核心及其所有配置！"
    read -p "$(echo -e ${RED}"确定要卸载吗? (输入 yes 确认): "${NC})" confirm
    if [ "$confirm" != "yes" ]; then
        _info "卸载已取消。"
        return
    fi
    
    # 停止服务
    _manage_xray_service "stop"
    
    # 从 clash.yaml 中清理节点
    if [ -f "$XRAY_METADATA" ] && [ -f "$CLASH_YAML_FILE" ]; then
        local tags=$(jq -r 'keys[]' "$XRAY_METADATA" 2>/dev/null)
        for tag in $tags; do
            local node_name=$(jq -r ".\"$tag\".name // empty" "$XRAY_METADATA" 2>/dev/null)
            local node_port=$(jq -r --arg t "$tag" '.inbounds[]? | select(.tag == $t) | .port' "$XRAY_CONFIG" 2>/dev/null)
            [ -n "$node_name" ] && [ "$node_name" != "null" ] && _xray_remove_node_from_yaml "$node_name" "$node_port"
        done
    fi
    
    # 删除服务文件
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl disable xray 2>/dev/null
        rm -f /etc/systemd/system/xray.service
        systemctl daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-update del xray default 2>/dev/null
        rm -f /etc/init.d/xray
    fi
    
    # 删除文件
    rm -f "$XRAY_BIN"
    rm -rf "$XRAY_DIR"
    
    _success "Xray 核心已完全卸载！"
}

# ============================================================
#                   共享 Reality 配置辅助
# ============================================================

# 生成 Reality 密钥对和 shortId
_generate_reality_keys() {
    local keypair=$($XRAY_BIN x25519 2>&1)
    # 按行号提取：第1行=私钥，第2行=公钥 (不依赖字段名)
    REALITY_PRIVATE_KEY=$(echo "$keypair" | awk 'NR==1 {print $NF}')
    REALITY_PUBLIC_KEY=$(echo "$keypair" | awk 'NR==2 {print $NF}')
    REALITY_SHORT_ID=$(openssl rand -hex 8)
    # 验证密钥是否为空
    if [ -z "$REALITY_PRIVATE_KEY" ] || [ -z "$REALITY_PUBLIC_KEY" ]; then
        _error "Reality 密钥生成失败！xray x25519 输出:"
        echo "$keypair" >&2
        return 1
    fi
    _info "PrivateKey: ${REALITY_PRIVATE_KEY:0:8}... PublicKey: ${REALITY_PUBLIC_KEY:0:8}..."
}

# 通用的 Reality streamSettings JSON 生成
_build_reality_stream() {
    local network="$1" sni="$2" private_key="$3" short_id="$4"
    local extra_settings="$5"
    jq -n --arg net "$network" --arg sni "$sni" --arg pk "$private_key" --arg sid "$short_id" \
        '{
            "network": $net,
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": ($sni + ":443"),
                "xver": 0,
                "serverNames": [$sni],
                "privateKey": $pk,
                "shortIds": [$sid]
            }
        }'
}

# 通用端口输入循环
_input_port() {
    local port=""
    while true; do
        read -p "请输入监听端口: " port
        [[ -z "$port" ]] && _error "端口不能为空" && continue
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            _error "无效端口号！"
            continue
        fi
        _check_xray_port_conflict "$port" && continue
        break
    done
    echo "$port"
}

# 保存分享链接到元数据 (参数: tag name link [key1=val1 key2=val2 ...])
_save_xray_meta() {
    local tag="$1" name="$2" link="$3"
    shift 3
    
    # 先构建基础 JSON
    local tmp
    tmp=$(mktemp "${XRAY_METADATA}.tmp.XXXXXX") || return 1
    if ! jq --arg t "$tag" --arg n "$name" --arg l "$link" \
        '. + {($t): {name: $n, share_link: $l}}' "$XRAY_METADATA" > "$tmp" 2>/dev/null; then
        rm -f -- "$tmp"
        return 1
    fi
    chmod 600 "$tmp"
    mv -f -- "$tmp" "$XRAY_METADATA"
    
    # 追加额外的键值对
    for pair in "$@"; do
        local key="${pair%%=*}"
        local val="${pair#*=}"
        if [ -n "$key" ] && [ -n "$val" ]; then
            local tmp2
            tmp2=$(mktemp "${XRAY_METADATA}.tmp.XXXXXX") || return 1
            if jq --arg t "$tag" --arg k "$key" --arg v "$val" \
                '.[$t][$k] = $v' "$XRAY_METADATA" > "$tmp2" 2>/dev/null; then
                chmod 600 "$tmp2"
                mv -f -- "$tmp2" "$XRAY_METADATA"
            else
                rm -f -- "$tmp2"
                return 1
            fi
        fi
    done
}

# ============================================================
#              1. VLESS + TCP + Reality + Vision
# ============================================================

_add_vless_reality_vision() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    local sni="www.amd.com"
    read -p "请输入伪装域名 SNI (默认: www.amd.com): " custom_sni
    sni=${custom_sni:-www.amd.com}
    
    local default_name="X-VLESS-TCP-REALITY-VISION-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    # 生成凭证
    local uuid=$($XRAY_BIN uuid)
    local flow="xtls-rprx-vision"
    _generate_reality_keys || return 1
    local tag="xray-vless-reality-${port}"
    
    # IPv6 处理
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    # 构建 inbound JSON
    local stream=$(_build_reality_stream "tcp" "$sni" "$REALITY_PRIVATE_KEY" "$REALITY_SHORT_ID")
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg flow "$flow" --argjson stream "$stream" \
        '{
            "tag": $tag,
            "listen": "::",
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": $uuid, "flow": $flow}],
                "decryption": "none"
            },
            "streamSettings": $stream
        }')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    # Clash YAML
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg u "$uuid" \
        --arg sn "$sni" --arg pk "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg f "$flow" \
        '{name:$n, type:"vless", server:$s, port:$p, uuid:$u, flow:$f, tls:true, servername:$sn,
          "reality-opts":{"public-key":$pk, "short-id":$sid}, "client-fingerprint":"chrome", network:"tcp"}')
    _xray_add_node_to_yaml "$proxy_json" || return 1
    
    # 分享链接
    local link="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&type=tcp&flow=${flow}&sni=${sni}&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID" || return 1
    
    _success "VLESS+TCP+Reality+Vision 节点 [${name}] 添加成功！"
    echo -e "  ${YELLOW}分享链接:${NC} ${link}"
}

# ============================================================
#              2. VLESS + gRPC + Reality
# ============================================================

_add_vless_grpc_reality() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    local sni="www.amd.com"
    read -p "请输入伪装域名 SNI (默认: www.amd.com): " custom_sni
    sni=${custom_sni:-www.amd.com}
    
    local service_name="grpc"
    read -p "请输入 gRPC serviceName (默认: grpc): " custom_svc
    service_name=${custom_svc:-grpc}
    
    local default_name="X-gRPC-Reality-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local uuid=$($XRAY_BIN uuid)
    _generate_reality_keys || return 1
    local tag="xray-vless-grpc-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    # 构建 streamSettings (gRPC + Reality)
    local stream=$(_build_reality_stream "grpc" "$sni" "$REALITY_PRIVATE_KEY" "$REALITY_SHORT_ID")
    stream=$(echo "$stream" | jq --arg svc "$service_name" '. + {grpcSettings: {serviceName: $svc}}')
    
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --argjson stream "$stream" \
        '{tag:$tag, listen:"::", port:$port, protocol:"vless",
          settings:{clients:[{id:$uuid, flow:""}], decryption:"none"},
          streamSettings:$stream}')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg u "$uuid" \
        --arg sn "$sni" --arg pk "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg svc "$service_name" \
        '{name:$n, type:"vless", server:$s, port:$p, uuid:$u, tls:true, servername:$sn,
          "reality-opts":{"public-key":$pk, "short-id":$sid}, "client-fingerprint":"chrome",
          network:"grpc", "grpc-opts":{"grpc-service-name":$svc}}')
    _xray_add_node_to_yaml "$proxy_json" || return 1
    
    local link="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&type=grpc&serviceName=${service_name}&authority=${sni}&sni=${sni}&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID" || return 1
    
    _success "VLESS+gRPC+Reality 节点 [${name}] 添加成功！"
    echo -e "  ${YELLOW}分享链接:${NC} ${link}"
}

# ============================================================
#          3. Trojan + XHTTP + Reality
# ============================================================

_add_trojan_xhttp_reality() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    local sni="www.amd.com"
    read -p "请输入伪装域名 SNI (默认: www.amd.com): " custom_sni
    sni=${custom_sni:-www.amd.com}
    
    local path="/$(openssl rand -hex 6)"
    read -p "请输入 XHTTP 路径 (默认: ${path}): " custom_path
    path=${custom_path:-$path}
    
    local default_name="X-Trojan-XHTTP-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local password=$(openssl rand -hex 16)
    _generate_reality_keys || return 1
    local tag="xray-trojan-xhttp-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local stream=$(_build_reality_stream "xhttp" "$sni" "$REALITY_PRIVATE_KEY" "$REALITY_SHORT_ID")
    stream=$(echo "$stream" | jq --arg p "$path" '. + {xhttpSettings: {path: $p}}')
    
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$password" --argjson stream "$stream" \
        '{tag:$tag, listen:"::", port:$port, protocol:"trojan",
          settings:{clients:[{password:$pw}]},
          streamSettings:$stream}')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    # Clash YAML - mihomo 不支持 xhttp 传输层，跳过写入
    _warn "mihomo/Clash 不支持 XHTTP 传输层，此节点仅支持 V2rayN/Xray 客户端"
    
    local link="trojan://${password}@${link_ip}:${port}?security=reality&type=xhttp&path=$(_url_encode "$path")&sni=${sni}&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID" || return 1
    
    _success "Trojan+XHTTP+Reality 节点 [${name}] 添加成功！"
    echo -e "  ${YELLOW}分享链接:${NC} ${link}"
}

# ============================================================
#            4. Trojan + gRPC + Reality
# ============================================================

_add_trojan_grpc_reality() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    local sni="www.amd.com"
    read -p "请输入伪装域名 SNI (默认: www.amd.com): " custom_sni
    sni=${custom_sni:-www.amd.com}
    
    local service_name="trojan-grpc"
    read -p "请输入 gRPC serviceName (默认: trojan-grpc): " custom_svc
    service_name=${custom_svc:-trojan-grpc}
    
    local default_name="X-Trojan-gRPC-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local password=$(openssl rand -hex 16)
    _generate_reality_keys || return 1
    local tag="xray-trojan-grpc-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local stream=$(_build_reality_stream "grpc" "$sni" "$REALITY_PRIVATE_KEY" "$REALITY_SHORT_ID")
    stream=$(echo "$stream" | jq --arg svc "$service_name" '. + {grpcSettings: {serviceName: $svc}}')
    
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$password" --argjson stream "$stream" \
        '{tag:$tag, listen:"::", port:$port, protocol:"trojan",
          settings:{clients:[{password:$pw}]},
          streamSettings:$stream}')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg pw "$password" \
        --arg sn "$sni" --arg pk "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg svc "$service_name" \
        '{name:$n, type:"trojan", server:$s, port:$p, password:$pw, udp:true,
          sni:$sn, "skip-cert-verify":false,
          "reality-opts":{"public-key":$pk, "short-id":$sid}, "client-fingerprint":"chrome",
          network:"grpc", "grpc-opts":{"grpc-service-name":$svc}}')
    _xray_add_node_to_yaml "$proxy_json" || return 1
    
    local link="trojan://${password}@${link_ip}:${port}?security=reality&type=grpc&serviceName=${service_name}&authority=${sni}&sni=${sni}&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID" || return 1
    
    _success "Trojan+gRPC+Reality 节点 [${name}] 添加成功！"
    echo -e "  ${YELLOW}分享链接:${NC} ${link}"
}

# ============================================================
#                   5. Shadowsocks
# ============================================================

_add_shadowsocks_xray() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    clear
    echo "========================================"
    _info "      Xray Shadowsocks 加密方式"
    echo "========================================"
    echo " [经典 SS]"
    echo " 1) aes-256-gcm"
    echo " 2) chacha20-ietf-poly1305"
    echo " [SS-2022 (强抗重放保护)]"
    echo " 3) 2022-blake3-aes-256-gcm"
    echo " 4) 2022-blake3-aes-256-gcm (带 Padding)"
    echo " 0) 返回"
    echo "========================================"
    read -p "请选择 [0-4]: " choice
    
    local method="" password="" name_prefix="" use_multiplex="false"
    case $choice in
        1) 
            method="aes-256-gcm"
            password=$(openssl rand -hex 16)
            name_prefix="X-SS-aes256"
            ;;
        2) 
            method="chacha20-ietf-poly1305"
            password=$(openssl rand -hex 16)
            name_prefix="X-SS-chacha20"
            ;;
        3) 
            method="2022-blake3-aes-256-gcm"
            password=$(openssl rand -base64 32)
            name_prefix="X-SS-2022"
            ;;
        4) 
            method="2022-blake3-aes-256-gcm"
            password=$(openssl rand -base64 32)
            name_prefix="X-SS-2022-Padding"
            use_multiplex="true"
            _info "已配置 Multiplex + Padding 选项"
            ;;
        0) return 1 ;;
        *) _error "无效输入"; return 1 ;;
    esac
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    
    local default_name="${name_prefix}-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local tag="xray-ss-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    # 修复：listen 监听地址改为 "::" 支持 IPv4+IPv6 双栈
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg m "$method" --arg pw "$password" \
        '{
            tag: $tag,
            listen: "::",
            port: $port,
            protocol: "shadowsocks",
            settings: {
                method: $m,
                password: $pw,
                network: "tcp,udp"
            }
        }')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=""
    if [ "$use_multiplex" == "true" ]; then
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg m "$method" --arg pw "$password" \
            '{name:$n, type:"ss", server:$s, port:$p, cipher:$m, password:$pw, smux: {enabled: true, padding: true}}')
    else
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg m "$method" --arg pw "$password" \
            '{name:$n, type:"ss", server:$s, port:$p, cipher:$m, password:$pw}')
    fi
    _xray_add_node_to_yaml "$proxy_json" || return 1
    
    local ss_user_info=$(_ss_base64_encode "${method}:${password}")
    local link="ss://${ss_user_info}@${link_ip}:${port}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" || return 1
    
    _success "Shadowsocks (${method}) 节点 [${name}] 添加成功！"
    echo -e "  ${YELLOW}分享链接:${NC} ${link}"
}

# ============================================================
#                 自签证书生成 (CF回源用)
# ============================================================
# 注意: CF回源协议复用上方第160行定义的 _generate_xray_cert，不再重复定义

# ============================================================
#         6. VLESS + HTTP/2 + TLS (支持CF回源)
# ============================================================

_add_vless_h2_tls() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    local sni="www.amd.com"
    read -p "请输入域名 (CF回源填绑定域名, 直连回车默认: www.amd.com): " custom_sni
    sni=${custom_sni:-www.amd.com}
    
    local path="/$(openssl rand -hex 6)"
    read -p "请输入 H2 路径 (默认: ${path}): " custom_path
    path=${custom_path:-$path}
    
    local default_name="X-VLESS-H2-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local uuid=$($XRAY_BIN uuid)
    local tag="xray-vless-h2-${port}"
    local cert_path="${XRAY_DIR}/${tag}.pem"
    local key_path="${XRAY_DIR}/${tag}.key"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    # 生成自签证书
    _generate_xray_cert "$sni" "$cert_path" "$key_path" || return 1
    
    # 构建 inbound (Xray v26+ 旧h2已迁移至 XHTTP stream-one)
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" \
        --arg cert "$cert_path" --arg key "$key_path" --arg sn "$sni" --arg pa "$path" \
        '{
            tag: $tag,
            listen: "::",
            port: $port,
            protocol: "vless",
            settings: {
                clients: [{id: $uuid, flow: ""}],
                decryption: "none"
            },
            streamSettings: {
                network: "xhttp",
                security: "tls",
                tlsSettings: {
                    certificates: [{certificateFile: $cert, keyFile: $key}],
                    alpn: ["h2"]
                },
                xhttpSettings: {
                    mode: "stream-one",
                    host: $sn,
                    path: $pa
                }
            }
        }')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    # Clash YAML - mihomo 不支持 XHTTP，跳过写入
    _warn "mihomo/Clash 不支持 XHTTP 传输层，此节点仅支持 V2rayN/Xray 客户端"
    
    local cert_pcs=$(_cert_sha256_hex "$cert_path")
    local insecure_param="&insecure=1"
    # Xray 2026-06-01 起移除了 allowInsecure；同时输出 insecure=1 与
    # pcs 会令新核心拒绝客户端配置。可固定证书时只输出 pcs。
    [ -n "$cert_pcs" ] && insecure_param="&pcs=${cert_pcs}"
    local link="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&sni=${sni}&alpn=h2&type=xhttp&mode=stream-one&path=$(_url_encode "$path")&host=${sni}${insecure_param}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" || return 1
    
    _info "此节点支持 CF CDN 回源 (SSL模式设为 Full)"
    _success "VLESS+H2+TLS 节点 [${name}] 添加成功！"
    local clean_link=$(echo "$link" | sed -E 's/&pcs=[a-fA-F0-9]*//g; s/&insecure=1//g')
    if [ "$clean_link" != "$link" ]; then
        echo -e "  ${YELLOW}直连分享链接 (含指纹):${NC} ${link}"
        echo -e "  ${YELLOW}CF优选专用链接 (无指纹):${NC} ${clean_link}"
    else
        echo -e "  ${YELLOW}分享链接:${NC} ${link}"
    fi
}

# ============================================================
#         7. VLESS + gRPC + TLS (支持CF回源)
# ============================================================

_add_xray_vless_grpc_tls() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    local sni="www.amd.com"
    read -p "请输入域名 (CF回源填绑定域名, 直连回车默认: www.amd.com): " custom_sni
    sni=${custom_sni:-www.amd.com}
    
    local service_name="grpc-$(openssl rand -hex 4)"
    read -p "请输入 gRPC serviceName (默认: ${service_name}): " custom_svc
    service_name=${custom_svc:-$service_name}
    
    local default_name="X-VLESS-gRPC-TLS-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local uuid=$($XRAY_BIN uuid)
    local tag="xray-vless-grpc-tls-${port}"
    local cert_path="${XRAY_DIR}/${tag}.pem"
    local key_path="${XRAY_DIR}/${tag}.key"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    _generate_xray_cert "$sni" "$cert_path" "$key_path" || return 1
    
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" \
        --arg cert "$cert_path" --arg key "$key_path" --arg sn "$sni" --arg svc "$service_name" \
        '{
            tag: $tag,
            listen: "::",
            port: $port,
            protocol: "vless",
            settings: {
                clients: [{id: $uuid, flow: ""}],
                decryption: "none"
            },
            streamSettings: {
                network: "grpc",
                security: "tls",
                tlsSettings: {
                    certificates: [{certificateFile: $cert, keyFile: $key}],
                    alpn: ["h2"]
                },
                grpcSettings: {
                    serviceName: $svc
                }
            }
        }')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg u "$uuid" \
        --arg sn "$sni" --arg svc "$service_name" \
        '{name:$n, type:"vless", server:$s, port:$p, uuid:$u, tls:true, servername:$sn,
          "skip-cert-verify":true, network:"grpc",
          "grpc-opts":{"grpc-service-name":$svc}}')
    _xray_add_node_to_yaml "$proxy_json" || return 1
    
    local cert_pcs=$(_cert_sha256_hex "$cert_path")
    local insecure_param="&insecure=1"
    [ -n "$cert_pcs" ] && insecure_param="&pcs=${cert_pcs}"
    local link="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&sni=${sni}&type=grpc&serviceName=${service_name}&authority=${sni}${insecure_param}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" || return 1
    
    _info "此节点支持 CF CDN 回源 (需在CF开启gRPC支持, SSL模式设为 Full)"
    _success "VLESS+gRPC+TLS 节点 [${name}] 添加成功！"
    local clean_link=$(echo "$link" | sed -E 's/&pcs=[a-fA-F0-9]*//g; s/&insecure=1//g')
    if [ "$clean_link" != "$link" ]; then
        echo -e "  ${YELLOW}直连分享链接 (含指纹):${NC} ${link}"
        echo -e "  ${YELLOW}CF优选专用链接 (无指纹):${NC} ${clean_link}"
    else
        echo -e "  ${YELLOW}分享链接:${NC} ${link}"
    fi
}

# ============================================================
#         8. Trojan + gRPC + TLS (支持CF回源)
# ============================================================

_add_trojan_grpc_tls() {
    [ -z "$server_ip" ] && server_ip=$(_get_public_ip)
    local node_ip="$server_ip"
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    local sni="www.amd.com"
    read -p "请输入域名 (CF回源填绑定域名, 直连回车默认: www.amd.com): " custom_sni
    sni=${custom_sni:-www.amd.com}
    
    local service_name="grpc-$(openssl rand -hex 4)"
    read -p "请输入 gRPC serviceName (默认: ${service_name}): " custom_svc
    service_name=${custom_svc:-$service_name}
    
    local default_name="X-Trojan-gRPC-TLS-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local password=$(openssl rand -hex 16)
    local tag="xray-trojan-grpc-tls-${port}"
    local cert_path="${XRAY_DIR}/${tag}.pem"
    local key_path="${XRAY_DIR}/${tag}.key"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    _generate_xray_cert "$sni" "$cert_path" "$key_path" || return 1
    
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$password" \
        --arg cert "$cert_path" --arg key "$key_path" --arg sn "$sni" --arg svc "$service_name" \
        '{
            tag: $tag,
            listen: "::",
            port: $port,
            protocol: "trojan",
            settings: {
                clients: [{password: $pw}]
            },
            streamSettings: {
                network: "grpc",
                security: "tls",
                tlsSettings: {
                    certificates: [{certificateFile: $cert, keyFile: $key}],
                    alpn: ["h2"]
                },
                grpcSettings: {
                    serviceName: $svc
                }
            }
        }')
    
    _xray_atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg pw "$password" \
        --arg sn "$sni" --arg svc "$service_name" \
        '{name:$n, type:"trojan", server:$s, port:$p, password:$pw, udp:true,
          sni:$sn, "skip-cert-verify":true, network:"grpc",
          "grpc-opts":{"grpc-service-name":$svc}}')
    _xray_add_node_to_yaml "$proxy_json" || return 1
    
    local cert_pcs=$(_cert_sha256_hex "$cert_path")
    local insecure_param="&insecure=1"
    [ -n "$cert_pcs" ] && insecure_param="&pcs=${cert_pcs}"
    local link="trojan://${password}@${link_ip}:${port}?security=tls&type=grpc&serviceName=${service_name}&authority=${sni}&sni=${sni}${insecure_param}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" || return 1
    
    _info "此节点支持 CF CDN 回源 (需在CF开启gRPC支持, SSL模式设为 Full)"
    _success "Trojan+gRPC+TLS 节点 [${name}] 添加成功！"
    local clean_link=$(echo "$link" | sed -E 's/&pcs=[a-fA-F0-9]*//g; s/&insecure=1//g')
    if [ "$clean_link" != "$link" ]; then
        echo -e "  ${YELLOW}直连分享链接 (含指纹):${NC} ${link}"
        echo -e "  ${YELLOW}CF优选专用链接 (无指纹):${NC} ${clean_link}"
    else
        echo -e "  ${YELLOW}分享链接:${NC} ${link}"
    fi
}

# ============================================================
#                     节点管理
# ============================================================

_view_xray_nodes() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点。"
        return
    fi
    [ -f "$XRAY_METADATA" ] || echo '{}' > "$XRAY_METADATA"
    echo ""
    echo -e "${YELLOW}══════════════════ Xray 节点列表 ══════════════════${NC}"
    local count=0
    while IFS=$'\t' read -r tag protocol port network security name link; do
        [ -z "$tag" ] && continue
        count=$((count + 1))
        local desc="${protocol}"
        [ "$network" != "null" ] && [ "$network" != "tcp" ] && desc="${desc}+${network}"
        [ "$security" != "null" ] && [ "$security" != "none" ] && desc="${desc}+${security}"
        echo ""
        echo -e "  ${GREEN}[${count}]${NC} ${CYAN}${name}${NC}"
        echo -e "      协议: ${YELLOW}${desc}${NC}  |  端口: ${GREEN}${port}${NC}  |  标签: ${CYAN}${tag}${NC}"
        [ -n "$link" ] && echo -e "      ${YELLOW}分享链接:${NC} ${link}"
    done < <(jq -r --slurpfile meta "$XRAY_METADATA" '
        .inbounds[] |
        . as $in |
        ($meta[0][$in.tag] // {}) as $m |
        [
            $in.tag,
            $in.protocol,
            ($in.port|tostring),
            ($in.streamSettings.network // "tcp"),
            ($in.streamSettings.security // "none"),
            ($m.name // $in.tag),
            ($m.share_link // "")
        ] | @tsv
    ' "$XRAY_CONFIG" 2>/dev/null)
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════════${NC}"
    echo -e "  共 ${GREEN}${count}${NC} 个 Xray 节点"
}

_delete_xray_node() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点可删除。"; return
    fi
    [ -f "$XRAY_METADATA" ] || echo '{}' > "$XRAY_METADATA"
    local tags=()
    local names=()
    local ports=()
    echo ""
    echo -e "${YELLOW}══════════ 选择要删除的节点 ══════════${NC}"
    while IFS=$'\t' read -r tag port name; do
        [ -z "$tag" ] && continue
        tags+=("$tag")
        ports+=("$port")
        names+=("$name")
        local i=${#tags[@]}
        echo -e "  ${GREEN}[${i}]${NC} ${name} (端口: ${port})"
    done < <(jq -r --slurpfile meta "$XRAY_METADATA" '
        .inbounds[] |
        . as $in |
        ($meta[0][$in.tag] // {}) as $m |
        [$in.tag, ($in.port|tostring), ($m.name // $in.tag)] | @tsv
    ' "$XRAY_CONFIG" 2>/dev/null)
    echo -e "  ${RED}[99]${NC} 删除全部节点"
    echo -e "  ${RED}[0]${NC} 返回"
    echo ""
    read -p "请选择: " choice
    [ "$choice" == "0" ] && return
    if [ "$choice" == "99" ]; then _delete_all_xray_nodes; return; fi
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#tags[@]}" ]; then
        _error "无效选择！"; return
    fi
    local target_tag="${tags[$((choice-1))]}"
    local target_name="${names[$((choice-1))]}"
    local target_port="${ports[$((choice-1))]}"
    read -p "$(echo -e ${RED}"确定删除 [$target_name]? (y/N): "${NC})" confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { _info "已取消。"; return; }
    _xray_snapshot_state || { _error "无法创建变更快照。"; return 1; }
    local snapshot="$XRAY_TX_DIR"
    if { [ -z "$target_name" ] || [ "$target_name" = "null" ] || _xray_remove_node_from_yaml "$target_name" "$target_port"; } && \
       _xray_atomic_modify_json "$XRAY_CONFIG" "del(.inbounds[] | select(.tag == \"$target_tag\"))" && \
       _xray_atomic_modify_json "$XRAY_METADATA" "del(.\"$target_tag\")" && \
       _manage_xray_service restart; then
        rm -f -- "${XRAY_DIR}/${target_tag}.pem" "${XRAY_DIR}/${target_tag}.key"
        _xray_drop_snapshot "$snapshot"
    else
        _error "删除失败，正在恢复原状态。"
        _xray_restore_state "$snapshot"
        _manage_xray_service restart >/dev/null 2>&1 || true
        _xray_drop_snapshot "$snapshot"
        return 1
    fi
    _success "节点 [$target_name] 已删除！"
}

_delete_all_xray_nodes() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点。"; return
    fi
    local count=$(jq '.inbounds | length' "$XRAY_CONFIG")
    read -p "$(echo -e ${RED}"确定删除全部 ${count} 个节点? (y/N): "${NC})" confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { _info "已取消。"; return; }
    _xray_snapshot_state || { _error "无法创建变更快照。"; return 1; }
    local snapshot="$XRAY_TX_DIR" cleanup_ok=1 tag name port
    while IFS=$'\t' read -r tag port name; do
        if [ -n "$name" ] && ! _xray_remove_node_from_yaml "$name" "$port"; then cleanup_ok=0; fi
    done < <(jq -r --slurpfile meta "$XRAY_METADATA" '
        .inbounds[] | [.tag, (.port|tostring), ($meta[0][.tag].name // .tag)] | @tsv' "$XRAY_CONFIG" 2>/dev/null)
    if [ "$cleanup_ok" -eq 1 ] && \
       _xray_atomic_modify_json "$XRAY_CONFIG" '.inbounds = []' && \
       _xray_atomic_modify_json "$XRAY_METADATA" '{} ' && \
       _manage_xray_service restart; then
        for tag in $(jq -r '.inbounds[].tag' "$snapshot/config.json" 2>/dev/null); do
            rm -f -- "${XRAY_DIR}/${tag}.pem" "${XRAY_DIR}/${tag}.key"
        done
        _xray_drop_snapshot "$snapshot"
    else
        _error "批量删除失败，正在恢复原状态。"
        _xray_restore_state "$snapshot"
        _manage_xray_service restart >/dev/null 2>&1 || true
        _xray_drop_snapshot "$snapshot"
        return 1
    fi
    _success "全部 ${count} 个节点已删除！"
}

_modify_xray_port() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点。"; return
    fi
    [ -f "$XRAY_METADATA" ] || echo '{}' > "$XRAY_METADATA"
    local tags=()
    local names=()
    local ports=()
    echo ""
    echo -e "${YELLOW}══════════ 选择要修改端口的节点 ══════════${NC}"
    while IFS=$'\t' read -r tag port name; do
        [ -z "$tag" ] && continue
        tags+=("$tag")
        ports+=("$port")
        names+=("$name")
        local i=${#tags[@]}
        echo -e "  ${GREEN}[${i}]${NC} ${name} (端口: ${port})"
    done < <(jq -r --slurpfile meta "$XRAY_METADATA" '
        .inbounds[] |
        . as $in |
        ($meta[0][$in.tag] // {}) as $m |
        [$in.tag, ($in.port|tostring), ($m.name // $in.tag)] | @tsv
    ' "$XRAY_CONFIG" 2>/dev/null)
    echo -e "  ${RED}[0]${NC} 返回"
    echo ""
    read -p "请选择 [0-${#tags[@]}]: " choice
    [ "$choice" == "0" ] && return
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#tags[@]}" ]; then
        _error "无效选择！"; return
    fi
    local target_tag="${tags[$((choice-1))]}"
    local old_port="${ports[$((choice-1))]}"
    local target_name="${names[$((choice-1))]}"
    _info "当前端口: ${old_port}"
    local new_port=$(_input_port)
    
    # tag 保持稳定，避免证书路径与元数据键随端口改名后失配。
    local new_name=$(echo "$target_name" | sed "s/${old_port}/${new_port}/g")
    local old_link=$(jq -r --arg t "$target_tag" '.[$t].share_link // empty' "$XRAY_METADATA" 2>/dev/null)
    local new_link=""
    if [ -n "$old_link" ]; then
        new_link=$(echo "$old_link" | sed -E "s/(:${old_port})([?&#\/]|$)/:${new_port}\2/g; s/(-${old_port})([?&#\/]|$)/-${new_port}\2/g; s/#[^#]*$/#$(_url_encode "$new_name")/g")
    fi
    _xray_snapshot_state || { _error "无法创建变更快照。"; return 1; }
    local snapshot="$XRAY_TX_DIR" change_ok=1
    _xray_atomic_modify_json "$XRAY_CONFIG" "(.inbounds[] | select(.tag == \"$target_tag\") | .port) = $new_port" || change_ok=0
    if [ "$change_ok" -eq 1 ] && [ -n "$target_name" ] && [ "$target_name" != "null" ] && [ -f "$CLASH_YAML_FILE" ]; then
        export MOD_NAME="$target_name" MOD_PORT="$old_port" NEW_NAME="$new_name" NEW_PORT="$new_port"
        _xray_atomic_modify_yaml "$CLASH_YAML_FILE" '
            (.proxies[]? | select(.name == env(MOD_NAME) and ((.port | tostring) == env(MOD_PORT))) | .port) = (env(NEW_PORT) | tonumber) |
            (.proxies[]? | select(.name == env(MOD_NAME) and ((.port | tostring) == env(NEW_PORT))) | .name) = env(NEW_NAME) |
            (.proxy-groups[]?.proxies[] | select(. == env(MOD_NAME))) = env(NEW_NAME)' || change_ok=0
    fi
    if [ "$change_ok" -eq 1 ]; then
        local meta_tmp
        meta_tmp=$(mktemp "${XRAY_METADATA}.tmp.XXXXXX") || change_ok=0
        if [ "$change_ok" -eq 1 ]; then
            jq --arg t "$target_tag" --arg n "$new_name" --arg l "$new_link" \
                '.[$t].name = $n | if $l != "" then .[$t].share_link = $l else . end' \
                "$XRAY_METADATA" > "$meta_tmp" 2>/dev/null || change_ok=0
            if [ "$change_ok" -eq 1 ]; then chmod 600 "$meta_tmp"; mv -f -- "$meta_tmp" "$XRAY_METADATA"; else rm -f -- "$meta_tmp"; fi
        fi
    fi
    if [ "$change_ok" -ne 1 ] || ! _manage_xray_service restart; then
        _error "修改端口失败，正在恢复原状态。"
        _xray_restore_state "$snapshot"
        _manage_xray_service restart >/dev/null 2>&1 || true
        _xray_drop_snapshot "$snapshot"
        return 1
    fi
    _xray_drop_snapshot "$snapshot"
    _success "节点 [$new_name] 端口已改为 ${new_port}！"
}

# ============================================================
#                       菜单系统
# ============================================================

_xray_add_node_menu() {
    while true; do
        clear
        echo ""
        echo -e "  ${GREEN}Xray 添加节点${NC}"
        echo "  ==============================="
        echo -e "  ${CYAN}  ── Reality 协议 ──${NC}"
        echo -e "  ${YELLOW}[1]${NC} VLESS+TCP+Reality+Vision"
        echo -e "  ${YELLOW}[2]${NC} VLESS+gRPC+Reality"
        echo -e "  ${YELLOW}[3]${NC} Trojan+XHTTP+Reality"
        echo -e "  ${YELLOW}[4]${NC} Trojan+gRPC+Reality"
        echo -e "  ${CYAN}  ── TLS 协议 (支持CF回源) ──${NC}"
        echo -e "  ${YELLOW}[5]${NC} VLESS+XHTTP+TLS (H2回源)"
        echo -e "  ${YELLOW}[6]${NC} VLESS+gRPC+TLS"
        echo -e "  ${YELLOW}[7]${NC} Trojan+gRPC+TLS"
        echo -e "  ${CYAN}  ── 其他 ──${NC}"
        echo -e "  ${YELLOW}[8]${NC} Shadowsocks"
        echo -e "  ${RED}[0]${NC} 返回"
        echo "  ==============================="
        read -p "请选择 [0-8]: " choice
        if [ "$choice" != "0" ] && [ ! -f "$XRAY_BIN" ]; then
            _error "Xray 尚未安装！请先安装 Xray 核心。"
            read -p "按回车键返回..."; continue
        fi
        case $choice in
            1) _with_singboxlite_lock _run_xray_transaction _add_vless_reality_vision ;;
            2) _with_singboxlite_lock _run_xray_transaction _add_vless_grpc_reality ;;
            3) _with_singboxlite_lock _run_xray_transaction _add_trojan_xhttp_reality ;;
            4) _with_singboxlite_lock _run_xray_transaction _add_trojan_grpc_reality ;;
            5) _with_singboxlite_lock _run_xray_transaction _add_vless_h2_tls ;;
            6) _with_singboxlite_lock _run_xray_transaction _add_xray_vless_grpc_tls ;;
            7) _with_singboxlite_lock _run_xray_transaction _add_trojan_grpc_tls ;;
            8) _with_singboxlite_lock _run_xray_transaction _add_shadowsocks_xray ;;
            0) return ;;
            *) _error "无效输入" ;;
        esac
        echo ""; read -p "按回车键继续..."
    done
}

_initialize_xray_runtime() {
    local listen_fix_status
    _init_xray_config || return 1
    _create_xray_service || return 1
    _check_and_fix_xray_listen
    listen_fix_status=$?
    if [ "$listen_fix_status" -eq 0 ]; then
        _manage_xray_service "restart" || return 1
    elif [ "$listen_fix_status" -gt 1 ]; then
        return 1
    fi
    return 0
}

_xray_menu() {
    if [ "$(id -u)" -ne 0 ]; then
        _error "Xray 管理需要 root 权限。"
        return 1
    fi
    _ensure_xray_dependencies || return 1
    # 独立运行时也允许安装核心，不再依赖主脚本的隐藏入口。
    if [ ! -f "$XRAY_BIN" ]; then
        _warn "Xray 核心尚未安装。"
        read -p "是否现在安装? (y/N): " install_choice
        if [[ "$install_choice" != "y" && "$install_choice" != "Y" ]]; then
            return
        fi
        _with_singboxlite_lock _install_xray || return 1
    fi
    _with_singboxlite_lock _initialize_xray_runtime || return 1

    while true; do
        clear
        echo ""
        echo -e "  ${GREEN}Xray-core 节点管理 v${XRAY_SCRIPT_VERSION}${NC}"
        echo "  =============================="
        local xray_status="${RED}未安装${NC}"
        if [ -f "$XRAY_BIN" ]; then
            local xray_ver=$($XRAY_BIN version 2>/dev/null | head -1 | awk '{print $2}')
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                systemctl is-active xray >/dev/null 2>&1 && xray_status="${GREEN}运行中${NC} (v${xray_ver})" || xray_status="${YELLOW}已停止${NC} (v${xray_ver})"
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                rc-service xray status >/dev/null 2>&1 && xray_status="${GREEN}运行中${NC} (v${xray_ver})" || xray_status="${YELLOW}已停止${NC} (v${xray_ver})"
            else
                _xray_is_pid_file_running_cmd "$XRAY_PID_FILE" "$XRAY_BIN" && xray_status="${GREEN}运行中${NC} (v${xray_ver})" || xray_status="${YELLOW}已停止${NC} (v${xray_ver})"
            fi
        fi
        local node_count=$(jq '.inbounds | length' "$XRAY_CONFIG" 2>/dev/null || echo "0")
        echo -e "  状态: ${xray_status}  节点: ${GREEN}${node_count}${NC} 个"
        echo ""
        echo -e "  ${CYAN}【服务控制】${NC}"
        echo -e "    ${YELLOW}[1]${NC} 启动 Xray"
        echo -e "    ${YELLOW}[2]${NC} 停止 Xray"
        echo -e "    ${YELLOW}[3]${NC} 重启 Xray"
        echo -e "    ${YELLOW}[4]${NC} 查看 Xray 状态"
        echo -e "    ${YELLOW}[5]${NC} 查看 Xray 日志"
        echo ""
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${YELLOW}[6]${NC} 添加节点"
        echo -e "    ${YELLOW}[7]${NC} 查看所有节点"
        echo -e "    ${YELLOW}[8]${NC} 删除节点"
        echo -e "    ${YELLOW}[9]${NC} 修改端口"
        echo ""
        echo -e "    ${RED}[99]${NC} 卸载 Xray"
        echo -e "    ${RED}[0]${NC}  返回主菜单"
        echo "  =============================="
        read -p "请选择 [0-99]: " choice
        case $choice in
            1) _manage_xray_service "start"; read -p "按回车键继续..." ;;
            2) _manage_xray_service "stop"; read -p "按回车键继续..." ;;
            3) _manage_xray_service "restart"; read -p "按回车键继续..." ;;
            4) _manage_xray_service "status"; read -p "按回车键继续..." ;;
            5) _view_xray_log ;;
            6) _xray_add_node_menu ;;
            7) _view_xray_nodes; read -p "按回车键继续..." ;;
            8) _with_singboxlite_lock _delete_xray_node; read -p "按回车键继续..." ;;
            9) _with_singboxlite_lock _modify_xray_port; read -p "按回车键继续..." ;;
            99) _with_singboxlite_lock _uninstall_xray; read -p "按回车键继续..." ;;
            0) return ;;
            *) _error "无效输入"; read -p "按回车键继续..." ;;
        esac
    done
}

# ============================================================
#                       入口
# ============================================================
_xray_menu

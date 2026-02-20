#!/bin/bash
# ============================================================
# xray_manager.sh — Xray-core 节点管理子脚本
# 与 singbox.sh 共存，共享 clash.yaml
# ============================================================
XRAY_SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# --- 路径定义 ---
XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
XRAY_CONFIG="${XRAY_DIR}/config.json"
XRAY_METADATA="${XRAY_DIR}/metadata.json"

# 共享路径 (继承自 singbox.sh 或使用默认值)
SINGBOX_DIR="${SINGBOX_DIR:-/usr/local/etc/sing-box}"
CLASH_YAML_FILE="${CLASH_YAML_FILE:-${SINGBOX_DIR}/clash.yaml}"
YQ_BINARY="${YQ_BINARY:-/usr/local/bin/yq}"

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

# --- URL 编码 ---
if ! declare -f _url_encode >/dev/null 2>&1; then
    _url_encode() {
        printf '%s' "$1" | jq -sRr @uri
    }
fi

# --- 环境检测 ---
if ! declare -f _detect_init_system >/dev/null 2>&1; then
    _detect_init_system() {
        if [ -f /etc/openrc/rc.conf ]; then INIT_SYSTEM="openrc"
        else INIT_SYSTEM="systemd"; fi
    }
fi
[ -z "$INIT_SYSTEM" ] && _detect_init_system

# --- 包管理 ---
if ! declare -f _pkg_install >/dev/null 2>&1; then
    _pkg_install() {
        if command -v apt-get &>/dev/null; then apt-get update -qq && apt-get install -y -qq "$@"
        elif command -v apk &>/dev/null; then apk add --no-cache "$@"
        elif command -v yum &>/dev/null; then yum install -y "$@"
        elif command -v dnf &>/dev/null; then dnf install -y "$@"
        fi
    }
fi

# --- 原子 JSON 修改 ---
if ! declare -f _atomic_modify_json >/dev/null 2>&1; then
    _atomic_modify_json() {
        local file="$1" filter="$2"
        local tmp="${file}.tmp.$$"
        if jq "$filter" "$file" > "$tmp" 2>/dev/null; then
            mv "$tmp" "$file"
        else
            rm -f "$tmp"
            _error "JSON 修改失败: $filter"
            return 1
        fi
    }
fi

# --- 原子 YAML 修改 ---
if ! declare -f _atomic_modify_yaml >/dev/null 2>&1; then
    _atomic_modify_yaml() {
        local file="$1" expression="$2"
        ${YQ_BINARY} eval "$expression" -i "$file" 2>/dev/null
    }
fi

# --- Clash YAML 节点操作 ---
if ! declare -f _add_node_to_yaml >/dev/null 2>&1; then
    _add_node_to_yaml() {
        local proxy_json="$1"
        local name=$(echo "$proxy_json" | jq -r '.name')
        local yaml_entry=$(echo "$proxy_json" | ${YQ_BINARY} -P '.')
        echo "$yaml_entry" | ${YQ_BINARY} eval -i ".proxies += [load(\"/dev/stdin\")]" "$CLASH_YAML_FILE" 2>/dev/null || \
        ${YQ_BINARY} eval -i ".proxies += [$(echo "$proxy_json" | ${YQ_BINARY} -P '.')]" "$CLASH_YAML_FILE" 2>/dev/null
        export NODE_NAME="$name"
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxy-groups[] | select(.name == "节点选择") | .proxies) += [env(NODE_NAME)]'
    }
fi

if ! declare -f _remove_node_from_yaml >/dev/null 2>&1; then
    _remove_node_from_yaml() {
        local name="$1"
        export DEL_NAME="$name"
        _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == env(DEL_NAME)))'
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxy-groups[].proxies) -= [env(DEL_NAME)]'
    }
fi

if ! declare -f _find_proxy_name >/dev/null 2>&1; then
    _find_proxy_name() {
        local port="$1" type="$2"
        ${YQ_BINARY} eval ".proxies[] | select(.port == ${port}) | .name" "$CLASH_YAML_FILE" 2>/dev/null | head -1
    }
fi

# --- 端口冲突检测 (跨双核心) ---
_check_port_occupied() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep -q ":${port} " && return 0
        ss -ulnp 2>/dev/null | grep -q ":${port} " && return 0
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep -q ":${port} " && return 0
    fi
    return 1
}

_check_xray_port_conflict() {
    local port="$1" protocol="${2:-tcp}"
    # 检查系统端口
    if _check_port_occupied "$port"; then
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
    return 1
}

# --- 公网 IP 获取 ---
if ! declare -f _get_public_ip >/dev/null 2>&1; then
    _get_public_ip() {
        [ -n "$server_ip" ] && [ "$server_ip" != "null" ] && { echo "$server_ip"; return; }
        local ip=$(timeout 5 curl -s4 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s4 --max-time 2 ipinfo.io/ip 2>/dev/null)
        [ -z "$ip" ] && ip=$(timeout 5 curl -s6 --max-time 2 icanhazip.com 2>/dev/null)
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
    chmod 644 "$cert_path" "$key_path"
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
        *)             xray_arch="64" ;;
    esac
    
    local download_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xray_arch}.zip"
    local tmp_dir=$(mktemp -d)
    local tmp_zip="${tmp_dir}/xray.zip"
    
    _info "下载地址: ${download_url}"
    if ! wget -qO "$tmp_zip" "$download_url"; then
        _error "Xray 下载失败！"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    if ! unzip -qo "$tmp_zip" -d "$tmp_dir"; then
        _error "Xray 解压失败！"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    # 安装二进制
    mv "${tmp_dir}/xray" "$XRAY_BIN"
    chmod +x "$XRAY_BIN"
    
    # 安装 geodata
    mkdir -p "$XRAY_DIR"
    [ -f "${tmp_dir}/geoip.dat" ] && mv "${tmp_dir}/geoip.dat" "$XRAY_DIR/"
    [ -f "${tmp_dir}/geosite.dat" ] && mv "${tmp_dir}/geosite.dat" "$XRAY_DIR/"
    
    rm -rf "$tmp_dir"
    
    local version=$($XRAY_BIN version 2>/dev/null | head -1 | awk '{print $2}')
    _success "Xray-core v${version} 安装成功！"
}

_create_xray_systemd_service() {
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
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
    cat > /etc/init.d/xray <<EOF
#!/sbin/openrc-run
description="Xray Service"
command="${XRAY_BIN}"
command_args="run -c ${XRAY_CONFIG}"
pidfile="/run/xray.pid"
command_background=true
supervisor=supervise-daemon
EOF
    chmod +x /etc/init.d/xray
    rc-update add xray default 2>/dev/null
}

_create_xray_service() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        [ -f /etc/systemd/system/xray.service ] || _create_xray_systemd_service
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        [ -f /etc/init.d/xray ] || _create_xray_openrc_service
    fi
}

_manage_xray_service() {
    local action="$1"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl "$action" xray 2>/dev/null
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-service xray "$action" 2>/dev/null
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
}

_view_xray_log() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        journalctl -u xray -n 50 --no-pager -f
    else
        _warn "OpenRC 环境下请查看 /var/log/messages"
        tail -f /var/log/messages 2>/dev/null | grep -i xray
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
            [ -n "$node_name" ] && [ "$node_name" != "null" ] && _remove_node_from_yaml "$node_name"
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
    local tmp="${XRAY_METADATA}.tmp.$$"
    jq --arg t "$tag" --arg n "$name" --arg l "$link" \
        '. + {($t): {name: $n, share_link: $l}}' "$XRAY_METADATA" > "$tmp" 2>/dev/null && \
        mv "$tmp" "$XRAY_METADATA" || { rm -f "$tmp"; return 1; }
    
    # 追加额外的键值对
    for pair in "$@"; do
        local key="${pair%%=*}"
        local val="${pair#*=}"
        if [ -n "$key" ] && [ -n "$val" ]; then
            local tmp2="${XRAY_METADATA}.tmp.$$"
            jq --arg t "$tag" --arg k "$key" --arg v "$val" \
                '.[$t][$k] = $v' "$XRAY_METADATA" > "$tmp2" 2>/dev/null && \
                mv "$tmp2" "$XRAY_METADATA" || rm -f "$tmp2"
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
    local sni="www.apple.com"
    read -p "请输入伪装域名 SNI (默认: www.apple.com): " custom_sni
    sni=${custom_sni:-www.apple.com}
    
    local default_name="X-Reality-${port}"
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
            "listen": "0.0.0.0",
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": $uuid, "flow": $flow}],
                "decryption": "none"
            },
            "streamSettings": $stream
        }')
    
    _atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    # Clash YAML
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg u "$uuid" \
        --arg sn "$sni" --arg pk "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg f "$flow" \
        '{name:$n, type:"vless", server:$s, port:$p, uuid:$u, flow:$f, tls:true, servername:$sn,
          "reality-opts":{"public-key":$pk, "short-id":$sid}, "client-fingerprint":"chrome", network:"tcp"}')
    _add_node_to_yaml "$proxy_json"
    
    # 分享链接
    local link="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&type=tcp&flow=${flow}&sni=${sni}&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID"
    
    _success "VLESS+Reality+Vision 节点 [${name}] 添加成功！"
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
    local sni="www.apple.com"
    read -p "请输入伪装域名 SNI (默认: www.apple.com): " custom_sni
    sni=${custom_sni:-www.apple.com}
    
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
        '{tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
          settings:{clients:[{id:$uuid, flow:""}], decryption:"none"},
          streamSettings:$stream}')
    
    _atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg u "$uuid" \
        --arg sn "$sni" --arg pk "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg svc "$service_name" \
        '{name:$n, type:"vless", server:$s, port:$p, uuid:$u, tls:true, servername:$sn,
          "reality-opts":{"public-key":$pk, "short-id":$sid}, "client-fingerprint":"chrome",
          network:"grpc", "grpc-opts":{"grpc-service-name":$svc}}')
    _add_node_to_yaml "$proxy_json"
    
    local link="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&type=grpc&serviceName=${service_name}&sni=${sni}&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID"
    
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
    local sni="www.apple.com"
    read -p "请输入伪装域名 SNI (默认: www.apple.com): " custom_sni
    sni=${custom_sni:-www.apple.com}
    
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
        '{tag:$tag, listen:"0.0.0.0", port:$port, protocol:"trojan",
          settings:{clients:[{password:$pw}]},
          streamSettings:$stream}')
    
    _atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    # Clash YAML - mihomo 不支持 xhttp 传输层，跳过写入
    _warn "mihomo/Clash 不支持 XHTTP 传输层，此节点仅支持 V2rayN/Xray 客户端"
    
    local link="trojan://${password}@${link_ip}:${port}?security=reality&type=xhttp&path=$(_url_encode "$path")&sni=${sni}&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID"
    
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
    local sni="www.apple.com"
    read -p "请输入伪装域名 SNI (默认: www.apple.com): " custom_sni
    sni=${custom_sni:-www.apple.com}
    
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
        '{tag:$tag, listen:"0.0.0.0", port:$port, protocol:"trojan",
          settings:{clients:[{password:$pw}]},
          streamSettings:$stream}')
    
    _atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg pw "$password" \
        --arg sn "$sni" --arg pk "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg svc "$service_name" \
        '{name:$n, type:"trojan", server:$s, port:$p, password:$pw, udp:true,
          sni:$sn, "skip-cert-verify":false,
          "reality-opts":{"public-key":$pk, "short-id":$sid}, "client-fingerprint":"chrome",
          network:"grpc", "grpc-opts":{"grpc-service-name":$svc}}')
    _add_node_to_yaml "$proxy_json"
    
    local link="trojan://${password}@${link_ip}:${port}?security=reality&type=grpc&serviceName=${service_name}&sni=${sni}&pbk=$(_url_encode "$REALITY_PUBLIC_KEY")&fp=chrome&sid=${REALITY_SHORT_ID}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link" "publicKey=$REALITY_PUBLIC_KEY" "shortId=$REALITY_SHORT_ID"
    
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
    echo " 1) chacha20-ietf-poly1305 (推荐)"
    echo " 2) aes-128-gcm"
    echo " 3) aes-256-gcm"
    echo " 0) 返回"
    echo "========================================"
    read -p "请选择 [0-3]: " choice
    
    local method=""
    case $choice in
        1) method="chacha20-ietf-poly1305" ;;
        2) method="aes-128-gcm" ;;
        3) method="aes-256-gcm" ;;
        0) return 1 ;;
        *) _error "无效输入"; return 1 ;;
    esac
    
    read -p "请输入服务器IP (默认: ${server_ip}): " custom_ip
    node_ip=${custom_ip:-$server_ip}
    
    local port=$(_input_port)
    
    local default_name="X-SS-${method}-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local password=$(openssl rand -hex 16)
    local tag="xray-ss-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local inbound=$(jq -n --arg tag "$tag" --argjson port "$port" --arg m "$method" --arg pw "$password" \
        '{
            tag: $tag,
            listen: "0.0.0.0",
            port: $port,
            protocol: "shadowsocks",
            settings: {
                method: $m,
                password: $pw,
                network: "tcp,udp"
            }
        }')
    
    _atomic_modify_json "$XRAY_CONFIG" ".inbounds += [$inbound]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --argjson p "$port" --arg m "$method" --arg pw "$password" \
        '{name:$n, type:"ss", server:$s, port:$p, cipher:$m, password:$pw}')
    _add_node_to_yaml "$proxy_json"
    
    local link="ss://$(_url_encode "${method}:${password}")@${link_ip}:${port}#$(_url_encode "$name")"
    
    _save_xray_meta "$tag" "$name" "$link"
    
    _success "Shadowsocks (${method}) 节点 [${name}] 添加成功！"
    echo -e "  ${YELLOW}分享链接:${NC} ${link}"
}

# ============================================================
#                     节点管理
# ============================================================

_view_xray_nodes() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点。"
        return
    fi
    echo ""
    echo -e "${YELLOW}══════════════════ Xray 节点列表 ══════════════════${NC}"
    local count=0
    local tags=$(jq -r '.inbounds[].tag' "$XRAY_CONFIG" 2>/dev/null)
    for tag in $tags; do
        count=$((count + 1))
        local protocol=$(jq -r ".inbounds[] | select(.tag == \"$tag\") | .protocol" "$XRAY_CONFIG")
        local port=$(jq -r ".inbounds[] | select(.tag == \"$tag\") | .port" "$XRAY_CONFIG")
        local network=$(jq -r ".inbounds[] | select(.tag == \"$tag\") | .streamSettings.network // \"tcp\"" "$XRAY_CONFIG")
        local security=$(jq -r ".inbounds[] | select(.tag == \"$tag\") | .streamSettings.security // \"none\"" "$XRAY_CONFIG")
        local name=$(jq -r ".\"$tag\".name // \"$tag\"" "$XRAY_METADATA" 2>/dev/null)
        local link=$(jq -r ".\"$tag\".share_link // empty" "$XRAY_METADATA" 2>/dev/null)
        local desc="${protocol}"
        [ "$network" != "null" ] && [ "$network" != "tcp" ] && desc="${desc}+${network}"
        [ "$security" != "null" ] && [ "$security" != "none" ] && desc="${desc}+${security}"
        echo ""
        echo -e "  ${GREEN}[${count}]${NC} ${CYAN}${name}${NC}"
        echo -e "      协议: ${YELLOW}${desc}${NC}  |  端口: ${GREEN}${port}${NC}  |  标签: ${CYAN}${tag}${NC}"
        [ -n "$link" ] && echo -e "      ${YELLOW}分享链接:${NC} ${link}"
    done
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════════${NC}"
    echo -e "  共 ${GREEN}${count}${NC} 个 Xray 节点"
}

_delete_xray_node() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点可删除。"; return
    fi
    local tags=($(jq -r '.inbounds[].tag' "$XRAY_CONFIG" 2>/dev/null))
    echo ""
    echo -e "${YELLOW}══════════ 选择要删除的节点 ══════════${NC}"
    for i in "${!tags[@]}"; do
        local tag="${tags[$i]}"
        local port=$(jq -r ".inbounds[] | select(.tag == \"$tag\") | .port" "$XRAY_CONFIG")
        local name=$(jq -r ".\"$tag\".name // \"$tag\"" "$XRAY_METADATA" 2>/dev/null)
        echo -e "  ${GREEN}[$((i+1))]${NC} ${name} (端口: ${port})"
    done
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
    local target_name=$(jq -r ".\"$target_tag\".name // \"$target_tag\"" "$XRAY_METADATA" 2>/dev/null)
    read -p "$(echo -e ${RED}"确定删除 [$target_name]? (y/N): "${NC})" confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { _info "已取消。"; return; }
    [ -n "$target_name" ] && [ "$target_name" != "null" ] && _remove_node_from_yaml "$target_name"
    rm -f "${XRAY_DIR}/${target_tag}.pem" "${XRAY_DIR}/${target_tag}.key" 2>/dev/null
    _atomic_modify_json "$XRAY_CONFIG" "del(.inbounds[] | select(.tag == \"$target_tag\"))"
    _atomic_modify_json "$XRAY_METADATA" "del(.\"$target_tag\")" 2>/dev/null
    _manage_xray_service "restart"
    _success "节点 [$target_name] 已删除！"
}

_delete_all_xray_nodes() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点。"; return
    fi
    local count=$(jq '.inbounds | length' "$XRAY_CONFIG")
    read -p "$(echo -e ${RED}"确定删除全部 ${count} 个节点? (y/N): "${NC})" confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { _info "已取消。"; return; }
    # 从 clash.yaml 中移除所有节点
    local tags=$(jq -r '.inbounds[].tag' "$XRAY_CONFIG" 2>/dev/null)
    for tag in $tags; do
        local name=$(jq -r ".\"$tag\".name // empty" "$XRAY_METADATA" 2>/dev/null)
        [ -n "$name" ] && _remove_node_from_yaml "$name"
        rm -f "${XRAY_DIR}/${tag}.pem" "${XRAY_DIR}/${tag}.key" 2>/dev/null
    done
    _atomic_modify_json "$XRAY_CONFIG" '.inbounds = []'
    echo '{}' > "$XRAY_METADATA"
    _manage_xray_service "restart"
    _success "全部 ${count} 个节点已删除！"
}

_modify_xray_port() {
    if [ ! -f "$XRAY_CONFIG" ] || ! jq -e '.inbounds | length > 0' "$XRAY_CONFIG" >/dev/null 2>&1; then
        _warn "当前没有 Xray 节点。"; return
    fi
    local tags=($(jq -r '.inbounds[].tag' "$XRAY_CONFIG" 2>/dev/null))
    echo ""
    echo -e "${YELLOW}══════════ 选择要修改端口的节点 ══════════${NC}"
    for i in "${!tags[@]}"; do
        local tag="${tags[$i]}"
        local port=$(jq -r ".inbounds[] | select(.tag == \"$tag\") | .port" "$XRAY_CONFIG")
        local name=$(jq -r ".\"$tag\".name // \"$tag\"" "$XRAY_METADATA" 2>/dev/null)
        echo -e "  ${GREEN}[$((i+1))]${NC} ${name} (端口: ${port})"
    done
    echo -e "  ${RED}[0]${NC} 返回"
    echo ""
    read -p "请选择 [0-${#tags[@]}]: " choice
    [ "$choice" == "0" ] && return
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#tags[@]}" ]; then
        _error "无效选择！"; return
    fi
    local target_tag="${tags[$((choice-1))]}"
    local old_port=$(jq -r ".inbounds[] | select(.tag == \"$target_tag\") | .port" "$XRAY_CONFIG")
    local target_name=$(jq -r ".\"$target_tag\".name // \"$target_tag\"" "$XRAY_METADATA" 2>/dev/null)
    _info "当前端口: ${old_port}"
    local new_port=$(_input_port)
    
    # 计算新的 tag 和名称
    local new_tag=$(echo "$target_tag" | sed "s/${old_port}/${new_port}/g")
    local new_name=$(echo "$target_name" | sed "s/${old_port}/${new_port}/g")
    
    # 1. 更新 config.json: 端口 + tag
    _atomic_modify_json "$XRAY_CONFIG" "(.inbounds[] | select(.tag == \"$target_tag\") | .port) = $new_port"
    _atomic_modify_json "$XRAY_CONFIG" "(.inbounds[] | select(.tag == \"$target_tag\") | .tag) = \"$new_tag\""
    
    # 2. 更新 clash.yaml: 端口 + 名称
    if [ -n "$target_name" ] && [ "$target_name" != "null" ]; then
        export MOD_NAME="$target_name"
        _atomic_modify_yaml "$CLASH_YAML_FILE" "(.proxies[] | select(.name == env(MOD_NAME)) | .port) = $new_port"
        if [ "$new_name" != "$target_name" ]; then
            export NEW_NAME="$new_name"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(MOD_NAME)) | .name) = env(NEW_NAME)'
        fi
    fi
    
    # 3. 更新 metadata: tag键名 + 名称 + 分享链接
    local old_link=$(jq -r ".\"$target_tag\".share_link // empty" "$XRAY_METADATA" 2>/dev/null)
    local new_link=""
    if [ -n "$old_link" ]; then
        new_link=$(echo "$old_link" | sed "s/:${old_port}/:${new_port}/g; s/-${old_port}/-${new_port}/g; s/#[^#]*$/#$(_url_encode "$new_name")/g")
    fi
    # 用新 tag 作为 key，删除旧 key
    local tmp="${XRAY_METADATA}.tmp.$$"
    if [ -n "$new_link" ]; then
        jq --arg ot "$target_tag" --arg nt "$new_tag" --arg n "$new_name" --arg l "$new_link" \
            '. + {($nt): (.[$ot] + {name: $n, share_link: $l})} | del(.[$ot])' "$XRAY_METADATA" > "$tmp" 2>/dev/null && \
            mv "$tmp" "$XRAY_METADATA" || rm -f "$tmp"
    else
        jq --arg ot "$target_tag" --arg nt "$new_tag" --arg n "$new_name" \
            '. + {($nt): (.[$ot] + {name: $n})} | del(.[$ot])' "$XRAY_METADATA" > "$tmp" 2>/dev/null && \
            mv "$tmp" "$XRAY_METADATA" || rm -f "$tmp"
    fi
    
    _manage_xray_service "restart"
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
        echo "  =============================="
        echo -e "  ${YELLOW}[1]${NC} VLESS+TCP+Reality+Vision"
        echo -e "  ${YELLOW}[2]${NC} VLESS+gRPC+Reality"
        echo -e "  ${YELLOW}[3]${NC} Trojan+XHTTP+Reality"
        echo -e "  ${YELLOW}[4]${NC} Trojan+gRPC+Reality"
        echo -e "  ${YELLOW}[5]${NC} Shadowsocks"
        echo -e "  ${RED}[0]${NC} 返回"
        echo "  =============================="
        read -p "请选择 [0-5]: " choice
        if [ "$choice" != "0" ] && [ ! -f "$XRAY_BIN" ]; then
            _error "Xray 尚未安装！请先安装 Xray 核心。"
            read -p "按回车键返回..."; continue
        fi
        case $choice in
            1) _add_vless_reality_vision && _manage_xray_service "restart" ;;
            2) _add_vless_grpc_reality && _manage_xray_service "restart" ;;
            3) _add_trojan_xhttp_reality && _manage_xray_service "restart" ;;
            4) _add_trojan_grpc_reality && _manage_xray_service "restart" ;;
            5) _add_shadowsocks_xray && _manage_xray_service "restart" ;;
            0) return ;;
            *) _error "无效输入" ;;
        esac
        echo ""; read -p "按回车键继续..."
    done
}

_xray_menu() {
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
            else
                rc-service xray status >/dev/null 2>&1 && xray_status="${GREEN}运行中${NC} (v${xray_ver})" || xray_status="${YELLOW}已停止${NC} (v${xray_ver})"
            fi
        fi
        local node_count=$(jq '.inbounds | length' "$XRAY_CONFIG" 2>/dev/null || echo "0")
        echo -e "  状态: ${xray_status}  节点: ${GREEN}${node_count}${NC} 个"
        echo ""
        echo -e "  ${CYAN}【核心管理】${NC}"
        echo -e "    ${YELLOW}[1]${NC} 安装/更新 Xray-core"
        echo -e "    ${YELLOW}[2]${NC} 启动 Xray"
        echo -e "    ${YELLOW}[3]${NC} 停止 Xray"
        echo -e "    ${YELLOW}[4]${NC} 重启 Xray"
        echo -e "    ${YELLOW}[5]${NC} 查看 Xray 状态"
        echo -e "    ${YELLOW}[6]${NC} 查看 Xray 日志"
        echo ""
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${YELLOW}[7]${NC} 添加节点"
        echo -e "    ${YELLOW}[8]${NC} 查看所有节点"
        echo -e "    ${YELLOW}[9]${NC} 删除节点"
        echo -e "    ${YELLOW}[10]${NC} 修改端口"
        echo ""
        echo -e "    ${RED}[99]${NC} 卸载 Xray"
        echo -e "    ${RED}[0]${NC}  返回主菜单"
        echo "  =============================="
        read -p "请选择 [0-99]: " choice
        case $choice in
            1) _install_xray; _create_xray_service; _init_xray_config; read -p "按回车键继续..." ;;
            2) _manage_xray_service "start"; read -p "按回车键继续..." ;;
            3) _manage_xray_service "stop"; read -p "按回车键继续..." ;;
            4) _manage_xray_service "restart"; read -p "按回车键继续..." ;;
            5) _manage_xray_service "status"; read -p "按回车键继续..." ;;
            6) _view_xray_log ;;
            7) _xray_add_node_menu ;;
            8) _view_xray_nodes; read -p "按回车键继续..." ;;
            9) _delete_xray_node; read -p "按回车键继续..." ;;
            10) _modify_xray_port; read -p "按回车键继续..." ;;
            99) _uninstall_xray; read -p "按回车键继续..." ;;
            0) return ;;
            *) _error "无效输入"; read -p "按回车键继续..." ;;
        esac
    done
}

# ============================================================
#                       入口
# ============================================================
_xray_menu



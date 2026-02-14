#!/bin/bash

# ==========================================================
# singbox.sh - singbox-lite 核心管理脚本 (优化版)
# ==========================================================

# 引入工具库 (Self-Initialization Logic)
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
GITHUB_RAW_BASE="https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main"

_download_missing_component() {
    local name="$1"
    local target="$SCRIPT_DIR/$name"
    echo "检测到缺失核心组件: $name，正在尝试自动补全..."
    if command -v curl &>/dev/null; then
        curl -LfSs "$GITHUB_RAW_BASE/$name" -o "$target"
    elif command -v wget &>/dev/null; then
        wget -qO "$target" "$GITHUB_RAW_BASE/$name"
    else
        echo "错误: 未找到 curl 或 wget，无法自动补全缺失组件。"
        exit 1
    fi
    [ -f "$target" ] && chmod +x "$target"
}

if [ ! -f "$SCRIPT_DIR/utils.sh" ]; then
    _download_missing_component "utils.sh"
fi

if [ -f "$SCRIPT_DIR/utils.sh" ]; then
    source "$SCRIPT_DIR/utils.sh"
else
    echo "错误: 未找到 utils.sh，且自动补全失败。请确保网络连通或手动上传。"
    exit 1
fi

# 文件路径常量
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_DIR="/usr/local/etc/sing-box"
CONFIG_FILE="${SINGBOX_DIR}/config.json"
CLASH_YAML_FILE="${SINGBOX_DIR}/clash.yaml"
METADATA_FILE="${SINGBOX_DIR}/metadata.json"
YQ_BINARY="/usr/local/bin/yq"
LOG_FILE="/var/log/sing-box.log"

# Argo Tunnel 相关常量
CLOUDFLARED_BIN="/usr/local/bin/cloudflared"
ARGO_METADATA_FILE="${SINGBOX_DIR}/argo_metadata.json"

# 全局状态
server_ip=""
INIT_SYSTEM=""
SERVICE_FILE=""
QUICK_DEPLOY_MODE=false

# 脚本全路径与 PID
SELF_SCRIPT_PATH=$(readlink -f "$0")
PID_FILE="/var/run/singbox_manager.pid"

# 脚本版本
SCRIPT_VERSION="11.3"

# 捕获退出信号
trap 'rm -f ${SINGBOX_DIR}/*.tmp /tmp/singbox_links.tmp' EXIT



# 依赖安装
_install_dependencies() {
    # 集中预装所有脚本可能用到的基础工具 (Argo 除外)
    local pkgs="curl jq openssl wget procps iptables socat tar iproute2"
    local needs_install=false
    
    # 检查是否所有包都已安装
    for pkg in $pkgs; do
        if ! command -v $pkg &>/dev/null && ! dpkg -l $pkg &>/dev/null 2>&1 && ! apk info -e $pkg &>/dev/null 2>&1; then
            needs_install=true
            break
        fi
    done
    
    if [ "$needs_install" = true ]; then
        _info "正在进行全家桶式依赖预装 (Master Installer Strategy)..."
        _pkg_install $pkgs
    fi
    _install_yq
}

# 确保 iptables 已安装
_ensure_iptables() {
    if ! command -v iptables &>/dev/null; then
        _info "未检测到 iptables，尝试安装..."
        _pkg_install iptables
        
        if ! command -v iptables &>/dev/null; then
             _error "iptables 安装失败。"
             return 1
        fi
        _success "iptables 安装成功。"
    fi
    return 0
}

_install_sing_box() {
    _info "正在安装最新稳定版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; exit 1 ;;
    esac
    
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
    if [ -z "$download_url" ]; then _error "无法获取 sing-box 下载链接。"; exit 1; fi
    
    wget -qO sing-box.tar.gz "$download_url" || { _error "下载失败!"; exit 1; }
    
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    mv "$temp_dir/sing-box-"*"/sing-box" ${SINGBOX_BIN}
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x ${SINGBOX_BIN}
    
    _success "sing-box 安装成功, 版本: $(${SINGBOX_BIN} version)"
}

_install_cloudflared() {
    if [ -f "${CLOUDFLARED_BIN}" ]; then
        _info "cloudflared 已安装: $(${CLOUDFLARED_BIN} --version 2>&1 | head -n1)"
        return 0
    fi
    
    _info "正在安装 cloudflared..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='arm' ;;
        *) _error "不支持的架构：$arch"; return 1 ;;
    esac
    
    local download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch_tag}"
    
    wget -qO "${CLOUDFLARED_BIN}" "$download_url" || { _error "cloudflared 下载失败!"; return 1; }
    chmod +x "${CLOUDFLARED_BIN}"
    
    _success "cloudflared 安装成功: $(${CLOUDFLARED_BIN} --version 2>&1 | head -n1)"
}

# --- Argo Tunnel 功能 ---

_start_argo_tunnel() {
    local target_port="$1"
    local protocol="$2"
    local token="$3" # 可选，用于固定隧道
    
    # 基于端口生成独立的 PID 和日志文件路径
    local pid_file="/tmp/singbox_argo_${target_port}.pid"
    local log_file="/tmp/singbox_argo_${target_port}.log"
    
    _info "正在启动 Argo 隧道 (端口: $target_port)..." >&2
    
    # 检查该端口对应的隧道是否已在运行
    if [ -f "$pid_file" ]; then
        local old_pid=$(cat "$pid_file" 2>/dev/null)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            _warning "检测到端口 $target_port 的 Argo 隧道已在运行 (PID: $old_pid)" >&2
            return 0
        fi
    fi
    
    # 清理旧日志
    rm -f "${log_file}"
    
    if [ -n "$token" ]; then
        # --- Token 固定隧道模式 ---
        _info "启动固定隧道 (Token 模式)..." >&2
        
        # 注意: tunnel run --token 不需要 --url 参数
        nohup ${CLOUDFLARED_BIN} tunnel run --token "$token" > "${log_file}" 2>&1 &
            
        local cf_pid=$!
        echo "$cf_pid" > "${pid_file}"
        
        sleep 5
        if ! kill -0 "$cf_pid" 2>/dev/null; then
             _error "cloudflared 进程已退出！" >&2
             _error "Token 可能无效，或者网络连接被拒绝。" >&2
             echo "--- 错误日志 (最后 20 行) ---" >&2
             cat "${log_file}" | tail -20 >&2
             echo "-----------------------------"
             return 1
        fi
        _success "Argo 固定隧道 (端口: $target_port) 启动成功!" >&2
        return 0
    else
        # --- URL 临时隧道模式 ---
        _info "启动临时隧道，指向 localhost:${target_port}..." >&2
        
        # 启动临时隧道
        nohup ${CLOUDFLARED_BIN} tunnel --url "http://localhost:${target_port}" \
            --logfile "${log_file}" \
            > /dev/null 2>&1 &
        
        local cf_pid=$!
        echo "$cf_pid" > "${pid_file}"
        
        # 等待隧道启动并获取域名
        _info "等待隧道建立 (最多30秒)..." >&2
        
        local tunnel_domain=""
        local wait_count=0
        local max_wait=30
        
        while [ $wait_count -lt $max_wait ]; do
            sleep 2
            wait_count=$((wait_count + 2))
            
            # 检查进程是否还在运行
            if ! kill -0 "$cf_pid" 2>/dev/null; then
                _error "cloudflared 进程已退出，请检查日志: ${log_file}" >&2
                cat "${log_file}" 2>/dev/null | tail -20 >&2
                return 1
            fi
            
            # 提取域名
            if [ -f "${log_file}" ]; then
                tunnel_domain=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "${log_file}" 2>/dev/null | tail -1 | sed 's|https://||')
                if [ -n "$tunnel_domain" ]; then
                    break
                fi
            fi
            echo -n "." >&2
        done
        echo "" >&2
        
        if [ -n "$tunnel_domain" ]; then
            _success "Argo 临时隧道建立成功: ${tunnel_domain}" >&2
            echo "$tunnel_domain"
            return 0
        else
            _error "获取临时域名超时。请检查网络。"
            kill "$cf_pid" 2>/dev/null
            rm -f "${pid_file}"
            return 1
        fi
    fi
}

_stop_argo_tunnel() {
    local target_port="$1"
    if [ -z "$target_port" ]; then
        return
    fi
    
    local pid_file="/tmp/singbox_argo_${target_port}.pid"
    local log_file="/tmp/singbox_argo_${target_port}.log"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            _success "Argo 隧道 (端口: $target_port) 已停止"
        fi
        rm -f "$pid_file" "$log_file"
    fi
}

_stop_all_argo_tunnels() {
    _info "正在停止所有 Argo 隧道..."
    for pid_file in /tmp/singbox_argo_*.pid; do
        [ -e "$pid_file" ] || continue
        # 解析端口
        local filename=$(basename "$pid_file")
        local port=${filename#singbox_argo_}
        port=${port%.pid}
        _stop_argo_tunnel "$port"
    done
    # 保底清理
    pkill -f "cloudflared" 2>/dev/null
}

_add_argo_vless_ws() {
    _info "--- 创建 VLESS-WS + Argo 隧道节点 ---"
    
    # 安装 cloudflared
    _install_cloudflared || return 1
    
    # 内部端口分配 (支持自定义或随机)
    read -p "请输入 Argo 内部监听端口 (回车随机生成): " input_port
    local port="$input_port"
    
    if [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ]; then
        if jq -e ".inbounds[] | select(.listen_port == $port)" "$CONFIG_FILE" >/dev/null 2>&1; then
             _warning "端口 $port 已被占用，将切换为随机端口。"
             port=""
        fi
    else
        [ -n "$port" ] && _warning "端口格式无效，将切换为随机端口。"
        port=""
    fi

    if [ -z "$port" ]; then
        port=$(shuf -i 10000-60000 -n 1)
        while jq -e ".inbounds[] | select(.listen_port == $port)" "$CONFIG_FILE" >/dev/null 2>&1; do
             port=$(shuf -i 10000-60000 -n 1)
        done
        _info "已随机分配内部监听端口: ${port}"
    else
        _info "已使用自定义内部监听端口: ${port}"
    fi
    
    # 输入 WebSocket 路径
    read -p "请输入 WebSocket 路径 (回车随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已生成随机路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi
    
    # 自定义名称
    # (节点名称输入已移动到模式选择之后)
    
    # --- 模式选择 ---
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

    # --- 节点名称输入 (移动至此) ---
    local default_prefix="Argo-Temp"
    if [ "$argo_type" == "fixed" ]; then
        default_prefix="Argo-Fixed"
    fi
    local default_name="${default_prefix}-Vless-${port}"
    
    echo ""
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    # 生成配置
    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="argo-vless-ws-${port}"
    
    # 创建 Inbound (监听 localhost，无 TLS，由 cloudflared 处理)
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg wsp "$ws_path" \
        '{
            "type": "vless",
            "tag": $t,
            "listen": "127.0.0.1",
            "listen_port": ($p|tonumber),
            "users": [{"uuid": $u, "flow": ""}],
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    # 重启 sing-box
    _manage_service "restart"
    sleep 2
    
    # 启动 Argo 隧道
    if [ "$argo_type" == "fixed" ]; then
        if ! _start_argo_tunnel "$port" "vless-ws" "$token"; then
             # 回滚
             _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
             _manage_service "restart"
             return 1
        fi
    else
        local real_domain=$(_start_argo_tunnel "$port" "vless-ws")
        if [ -z "$real_domain" ] || [ "$real_domain" == "" ]; then
            _error "隧道启动失败，正在回滚配置..."
            _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
            _manage_service "restart"
            return 1
        fi
        tunnel_domain="$real_domain"
    fi
    
    # 保存 Argo 元数据 (增加 type 和 token 字段)
    local argo_meta=$(jq -n \
        --arg tag "$tag" \
        --arg name "$name" \
        --arg domain "$tunnel_domain" \
        --arg port "$port" \
        --arg uuid "$uuid" \
        --arg path "$ws_path" \
        --arg protocol "vless-ws" \
        --arg type "$argo_type" \
        --arg token "$token" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        '{($tag): {name: $name, domain: $domain, local_port: ($port|tonumber), uuid: $uuid, path: $path, protocol: $protocol, type: $type, token: $token, created_at: $created}}')
    
    if [ ! -f "$ARGO_METADATA_FILE" ]; then
        echo '{}' > "$ARGO_METADATA_FILE"
    fi
    _atomic_modify_json "$ARGO_METADATA_FILE" ". + $argo_meta"
    
    # 生成 Clash 配置
    local proxy_json=$(jq -n \
        --arg n "$name" \
        --arg s "$tunnel_domain" \
        --arg u "$uuid" \
        --arg wsp "$ws_path" \
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
                "headers": {
                    "Host": $s
                }
            }
        }')
    _add_node_to_yaml "$proxy_json"
    
    # 生成分享链接
    local encoded_path=$(_url_encode "$ws_path")
    local share_link="vless://${uuid}@${tunnel_domain}:443?encryption=none&security=tls&type=ws&host=${tunnel_domain}&path=${encoded_path}&sni=${tunnel_domain}#$(_url_encode "$name")"
    
    # 启用守护进程
    _enable_argo_watchdog

    echo ""
    _success "VLESS-WS + Argo 节点创建成功!"
    echo "-------------------------------------------"
    echo -e "节点名称: ${GREEN}${name}${NC}"
    echo -e "隧道类型: ${CYAN}${argo_type}${NC}"
    echo -e "隧道域名: ${CYAN}${tunnel_domain}${NC}"
    echo -e "本地端口: ${port}"
    echo "-------------------------------------------"
    echo -e "${YELLOW}分享链接:${NC}"
    echo "$share_link"
    echo "-------------------------------------------"
    if [ "$argo_type" == "temp" ]; then
        _warning "注意: 临时隧道每次重启域名会变化！"
    fi
}

_add_argo_trojan_ws() {
    _info "--- 创建 Trojan-WS + Argo 隧道节点 ---"
    
    # 安装 cloudflared
    _install_cloudflared || return 1
    
    # 内部端口分配 (支持自定义或随机)
    read -p "请输入 Argo 内部监听端口 (回车随机生成): " input_port
    local port="$input_port"
    
    if [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ]; then
        if jq -e ".inbounds[] | select(.listen_port == $port)" "$CONFIG_FILE" >/dev/null 2>&1; then
             _warning "端口 $port 已被占用，将切换为随机端口。"
             port=""
        fi
    else
        [ -n "$port" ] && _warning "端口格式无效，将切换为随机端口。"
        port=""
    fi

    if [ -z "$port" ]; then
        port=$(shuf -i 10000-60000 -n 1)
        while jq -e ".inbounds[] | select(.listen_port == $port)" "$CONFIG_FILE" >/dev/null 2>&1; do
             port=$(shuf -i 10000-60000 -n 1)
        done
        _info "已随机分配内部监听端口: ${port}"
    else
        _info "已使用自定义内部监听端口: ${port}"
    fi
    
    # 输入 WebSocket 路径
    read -p "请输入 WebSocket 路径 (回车随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已生成随机路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi
    
    # 密码
    read -p "请输入 Trojan 密码 (回车随机生成): " password
    if [ -z "$password" ]; then
        password=$(${SINGBOX_BIN} generate rand --hex 16)
        _info "已生成随机密码: ${password}"
    fi
    
    # 自定义名称
    # (节点名称输入已移动到模式选择之后)
    
    # --- 模式选择 ---
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

    # --- 节点名称输入 (移动至此) ---
    local default_prefix="Argo-Temp"
    if [ "$argo_type" == "fixed" ]; then
        default_prefix="Argo-Fixed"
    fi
    local default_name="${default_prefix}-Trojan-${port}"
    
    echo ""
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local tag="argo-trojan-ws-${port}"
    
    # 创建 Inbound (监听 localhost，无 TLS)
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg wsp "$ws_path" \
        '{
            "type": "trojan",
            "tag": $t,
            "listen": "127.0.0.1",
            "listen_port": ($p|tonumber),
            "users": [{"password": $pw}],
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    # 重启 sing-box
    _manage_service "restart"
    sleep 2
    
    # 启动 Argo 隧道
    if [ "$argo_type" == "fixed" ]; then
        if ! _start_argo_tunnel "$port" "trojan-ws" "$token"; then
             # 回滚
             _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
             _manage_service "restart"
             return 1
        fi
    else
        local real_domain=$(_start_argo_tunnel "$port" "trojan-ws")
        
        if [ -z "$real_domain" ] || [ "$real_domain" == "" ]; then
            _error "隧道启动失败，正在回滚配置..."
            _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
            _manage_service "restart"
            return 1
        fi
        tunnel_domain="$real_domain"
    fi
    
    # 保存 Argo 元数据 (增加 type 和 token)
    local argo_meta=$(jq -n \
        --arg tag "$tag" \
        --arg name "$name" \
        --arg domain "$tunnel_domain" \
        --arg port "$port" \
        --arg password "$password" \
        --arg path "$ws_path" \
        --arg protocol "trojan-ws" \
        --arg type "$argo_type" \
        --arg token "$token" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        '{($tag): {name: $name, domain: $domain, local_port: ($port|tonumber), password: $password, path: $path, protocol: $protocol, type: $type, token: $token, created_at: $created}}')
    
    if [ ! -f "$ARGO_METADATA_FILE" ]; then
        echo '{}' > "$ARGO_METADATA_FILE"
    fi
    _atomic_modify_json "$ARGO_METADATA_FILE" ". + $argo_meta"
    
    # 生成 Clash 配置
    local proxy_json=$(jq -n \
        --arg n "$name" \
        --arg s "$tunnel_domain" \
        --arg pw "$password" \
        --arg wsp "$ws_path" \
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
                "headers": {
                    "Host": $s
                }
            }
        }')
    _add_node_to_yaml "$proxy_json"
    
    # 生成分享链接
    local encoded_path=$(_url_encode "$ws_path")
    local encoded_password=$(_url_encode "$password")
    local share_link="trojan://${encoded_password}@${tunnel_domain}:443?security=tls&type=ws&host=${tunnel_domain}&path=${encoded_path}&sni=${tunnel_domain}#$(_url_encode "$name")"
    
    # 启用守护进程
    _enable_argo_watchdog

    echo ""
    _success "Trojan-WS + Argo 节点创建成功!"
    echo "-------------------------------------------"
    echo -e "节点名称: ${GREEN}${name}${NC}"
    echo -e "隧道类型: ${CYAN}${argo_type}${NC}"
    echo -e "隧道域名: ${CYAN}${tunnel_domain}${NC}"
    echo -e "本地端口: ${port}"
    echo "-------------------------------------------"
    echo -e "${YELLOW}分享链接:${NC}"
    echo "$share_link"
    echo "-------------------------------------------"
    if [ "$argo_type" == "temp" ]; then
        _warning "注意: 临时隧道每次重启域名会变化！"
    fi
}

_view_argo_nodes() {
    _info "--- Argo 隧道节点信息 ---"
    
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE")" -eq 0 ]; then
        _warning "没有 Argo 隧道节点。"
        return
    fi
    
    echo "==================================================="
    # 遍历并显示
    jq -r 'to_entries[] | "\(.value.name)|\(.value.type)|\(.value.protocol)|\(.value.local_port)|\(.value.domain)|\(.value.uuid // "")|\(.value.path // "")|\(.value.password // "")"' "$ARGO_METADATA_FILE" | \
    while IFS='|' read -r name type protocol port domain uuid path password; do
        echo -e "节点: ${GREEN}${name}${NC}"
        echo -e "  协议: ${protocol}"
        echo -e "  端口: ${port}"
        
        # 检查状态
        local pid_file="/tmp/singbox_argo_${port}.pid"
        local state="${RED}已停止${NC}"
        local running_domain=""
        
        if [ -f "$pid_file" ] && kill -0 $(cat "$pid_file") 2>/dev/null; then
             state="${GREEN}运行中${NC} (PID: $(cat $pid_file))"
             # 如果是临时的，尝试从 log 读最新域名
             if [ "$type" == "temp" ] || [ -z "$domain" ] || [ "$domain" == "null" ]; then
                  local log_file="/tmp/singbox_argo_${port}.log"
                  local temp_domain=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "$log_file" 2>/dev/null | tail -1 | sed 's|https://||')
                   [ -n "$temp_domain" ] && domain="$temp_domain"
             fi
             running_domain="$domain"
        fi
        
        echo -e "  状态: ${state}"
        echo -e "  域名: ${CYAN}${domain}${NC}"

        # --- 生成并显示链接 ---
        if [ -n "$domain" ] && [ "$domain" != "null" ]; then
             local safe_name=$(_url_encode "$name")
             local safe_path=$(_url_encode "$path")
             local link=""
             
             if [[ "$protocol" == "vless-ws" ]]; then
                 link="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${safe_path}&sni=${domain}#${safe_name}"
             elif [[ "$protocol" == "trojan-ws" ]]; then
                 local safe_pw=$(_url_encode "$password")
                 link="trojan://${safe_pw}@${domain}:443?security=tls&type=ws&host=${domain}&path=${safe_path}&sni=${domain}#${safe_name}"
             fi

             if [ -n "$link" ]; then
                  echo -e "  ${YELLOW}链接:${NC} $link"
             fi
        fi
        echo "-------------------------------------------"
    done
    
    echo -e "${YELLOW}提示: 请使用 [5] 重启隧道 来刷新所有节点状态或获取新临时域名。${NC}"
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
    jq "del(.\"$selected_key\")" "$ARGO_METADATA_FILE" > "${ARGO_METADATA_FILE}.tmp" && mv "${ARGO_METADATA_FILE}.tmp" "$ARGO_METADATA_FILE"
    
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
    
    local idx_list=()
    if [ "$choice" == "a" ]; then
        # 生成所有索引
        for ((j=0; j<${#keys[@]}; j++)); do idx_list+=($j); done
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -gt 0 ] && [ "$choice" -le "${#keys[@]}" ]; then
        idx_list+=($((choice - 1)))
    else
        if [ "$choice" -ne 0 ]; then _error "无效输入"; fi
        return
    fi
    
    # 执行重启循环
    for idx in "${idx_list[@]}"; do
        local key="${keys[$idx]}" # tag
        local name="${names[$idx]}"
        local port="${ports[$idx]}"
        local proto="${protocols[$idx]}"
        local type="${types[$idx]}"
        local token="${tokens[$idx]}"
        
        _info "正在重启: $name (端口: $port)..."
        
        # 停止
        _stop_argo_tunnel "$port"
        sleep 1
        
        # 启动
        local new_domain=""
        if [ "$type" == "fixed" ]; then
            if _start_argo_tunnel "$port" "$proto" "$token"; then
                 new_domain=$(jq -r ".\"$key\".domain" "$ARGO_METADATA_FILE")
            else
                 _error "固定隧道重启失败: $name"
            fi
        else
            new_domain=$(_start_argo_tunnel "$port" "$proto")
            if [ -n "$new_domain" ]; then
                 # 更新元数据域
                 jq ".\"$key\".domain = \"$new_domain\"" "$ARGO_METADATA_FILE" > "${ARGO_METADATA_FILE}.tmp" && mv "${ARGO_METADATA_FILE}.tmp" "$ARGO_METADATA_FILE"
                 _success "更新临时域名: $new_domain"
            else
                 _error "临时隧道重启失败: $name"
            fi
        fi
    done
    _success "操作完成。"
}

# --- Argo 守护进程逻辑 ---

_argo_keepalive() {
    # --- 性能优化: 互斥锁 ---
    local lock_file="/tmp/singbox_keepalive.lock"
    if [ -f "$lock_file" ]; then
        local pid=$(cat "$lock_file")
        if kill -0 "$pid" 2>/dev/null; then
            # 进程仍在运行，跳过本次执行
            return
        fi
    fi
    echo "$$" > "$lock_file"
    # 确保退出时删除锁
    trap 'rm -f "$lock_file"' RETURN EXIT

    # --- 性能优化: 日志轮转 (10MB) ---
    local max_size=$((10 * 1024 * 1024))
    for log in "$LOG_FILE" "$ARGO_LOG_FILE"; do
        if [ -f "$log" ] && [ $(stat -c%s "$log" 2>/dev/null || echo 0) -ge $max_size ]; then
            tail -n 1000 "$log" > "${log}.tmp" && mv "${log}.tmp" "$log"
        fi
    done

    # 如果元数据文件不存在或为空，不需要守护
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null)" -eq 0 ]; then
        return
    fi

    # 遍历所有节点
    local i=0
    # keys[] 可能会包含空格，虽然 tag 一般不含空格，但为了健壮性...
    local tags=$(jq -r 'keys[]' "$ARGO_METADATA_FILE")
    
    for tag in $tags; do
        local port=$(jq -r ".\"$tag\".local_port" "$ARGO_METADATA_FILE")
        local type=$(jq -r ".\"$tag\".type" "$ARGO_METADATA_FILE")
        local token=$(jq -r ".\"$tag\".token // empty" "$ARGO_METADATA_FILE")
        local protocol=$(jq -r ".\"$tag\".protocol // \"vless-ws\"" "$ARGO_METADATA_FILE")
        
        local pid_file="/tmp/singbox_argo_${port}.pid"
        local is_running=false
        
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file" 2>/dev/null)
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                is_running=true
            fi
        fi
        
        if [ "$is_running" == "false" ]; then
            # 尝试重启
            logger "sing-box-watchdog: Detected dead tunnel for $tag (Port: $port). Restarting..."
            
            if [ "$type" == "fixed" ] && [ -n "$token" ]; then
                 if _start_argo_tunnel "$port" "$type" "$token"; then
                     logger "sing-box-watchdog: Fixed tunnel $tag restarted successfully."
                 else
                     logger "sing-box-watchdog: Failed to restart fixed tunnel $tag."
                 fi
            else
                 # 临时隧道
                 local new_domain=$(_start_argo_tunnel "$port" "temp")
                 if [ -n "$new_domain" ]; then
                      # 更新元数据
                      _atomic_modify_json "$ARGO_METADATA_FILE" ".\"$tag\".domain = \"$new_domain\""
                      logger "sing-box-watchdog: Temp tunnel $tag restarted with new domain: $new_domain"
                 else
                      logger "sing-box-watchdog: Failed to restart temp tunnel $tag."
                 fi
            fi
        fi
    done
}

_enable_argo_watchdog() {
    # 检查 crontab 是否已有任务
    local job="* * * * * bash ${SELF_SCRIPT_PATH} keepalive >/dev/null 2>&1"
    
    if ! crontab -l 2>/dev/null | grep -Fq "$job"; then
        _info "正在添加后台守护进程 (Watchdog)..."
        (crontab -l 2>/dev/null; echo "$job") | crontab -
        if [ $? -eq 0 ]; then
            _success "守护进程已启用！(每分钟检查并自动修复失效隧道)"
        else
            _warning "添加 Crontab 失败，守护进程未生效。"
        fi
    fi
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
         # 同样需要遍历删除逻辑，这里简化为遍历 metadata 删除
         # 为防止 jq 读写竞争，我们先收集所有 tags
        local tags=$(jq -r 'keys[]' "$ARGO_METADATA_FILE" 2>/dev/null)
        for tag in $tags; do
             if [ -n "$tag" ]; then
                _info "正在删除节点配置: ${tag}"
                _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
                
                local node_name=$(jq -r ".\"$tag\".name" "$ARGO_METADATA_FILE" 2>/dev/null)
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
    
    pkill -f "cloudflared" 2>/dev/null
    
    # 删除所有 PID/LOG 文件
    rm -f /tmp/singbox_argo_*.pid /tmp/singbox_argo_*.log
    rm -f "${CLOUDFLARED_BIN}" "${ARGO_METADATA_FILE}"
    rm -rf "/etc/cloudflared"
    
    # 4. 重启 sing-box
    _manage_service "restart"
    
    _success "Argo 服务已完全卸载！"
    _success "已释放 cloudflared 占用的空间。"
}

_argo_menu() {
    while true; do
        clear
        echo -e "${CYAN}"
        echo '  ╔═══════════════════════════════════════╗'
        echo '  ║           Argo 隧道节点管理           ║'
        echo '  ╚═══════════════════════════════════════╝'
        echo -e "${NC}"
        echo ""
        
        echo -e "  ${CYAN}【创建节点】${NC}"
        echo -e "    ${GREEN}[1]${NC} 创建 VLESS-WS + Argo 节点"
        echo -e "    ${GREEN}[2]${NC} 创建 Trojan-WS + Argo 节点"
        echo ""
        
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${GREEN}[3]${NC} 查看 Argo 节点信息"
        echo -e "    ${GREEN}[4]${NC} 删除 Argo 节点"
        echo ""
        
        echo -e "  ${CYAN}【隧道控制】${NC}"
        echo -e "    ${GREEN}[5]${NC} 重启隧道 (获取新域名)"
        echo -e "    ${GREEN}[6]${NC} 停止隧道"
        echo -e "    ${RED}[7]${NC} 卸载 Argo 服务"
        echo ""
        
        echo -e "  ─────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        
        read -p "  请输入选项 [0-7]: " choice
        
        case $choice in
            1) _add_argo_vless_ws ;;
            2) _add_argo_trojan_ws ;;
            3) _view_argo_nodes ;;
            4) _delete_argo_node ;;
            5) _restart_argo_tunnel_menu ;;
            6) _stop_argo_menu ;;
            7) _uninstall_argo ;;
            0) return ;;
            *) _error "无效选项，请重新输入。" ;;
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

depend() {
    need net
    after firewall
}

start_pre() {
    export GOMEMLIMIT="${mem_limit_mb}MiB"
}
EOF
    chmod +x "$SERVICE_FILE"
}

_create_service_files() {
    if [ -f "$SERVICE_FILE" ]; then return; fi
    
    _info "正在创建 ${INIT_SYSTEM} 服务文件..."
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _create_systemd_service
        systemctl daemon-reload
        systemctl enable sing-box
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        touch "$LOG_FILE"
        _create_openrc_service
        rc-update add sing-box default
    fi
    _success "${INIT_SYSTEM} 服务创建并启用成功。"
}


# 此处已由 utils.sh 中的 _manage_service 替代，移除本地定义以防冲突

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

_uninstall() {
    _warning "！！！警告！！！"
    _warning "本操作将停止并禁用 [主脚本] 服务 (sing-box)，"
    _warning "删除所有相关文件 (包括二进制、组件脚本、别名及配置文件)。"
    
    echo ""
    echo "即将删除以下内容："
    echo -e "  ${RED}-${NC} 主配置目录: ${SINGBOX_DIR}"
    echo -e "  ${RED}-${NC} 中转辅助目录: /etc/singbox"
    echo -e "  ${RED}-${NC} sing-box 二进制: ${SINGBOX_BIN}"
    echo -e "  ${RED}-${NC} yq 二进制: ${YQ_BINARY}"
    [ -f "${CLOUDFLARED_BIN}" ] && echo -e "  ${RED}-${NC} cloudflared 二进制: ${CLOUDFLARED_BIN}"
    echo -e "  ${RED}-${NC} 辅助组件: utils.sh, parser.sh, advanced_relay.sh"
    echo -e "  ${RED}-${NC} 系统别名: /usr/local/bin/sb"
    echo -e "  ${RED}-${NC} 管理脚本: ${SELF_SCRIPT_PATH}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm_main
    [[ "$confirm_main" != "y" && "$confirm_main" != "Y" ]] && _info "卸载已取消。" && return

    # 1. 停止服务
    _manage_service "stop"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl disable sing-box >/dev/null 2>&1
        systemctl daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-update del sing-box default >/dev/null 2>&1
    fi

    # 2. 清理配置与日志
    _info "正在清理配置文件与日志..."
    rm -rf "${SINGBOX_DIR}" "${LOG_FILE}" "/etc/singbox"
    
    # 3. 清理 Argo 隧道
    if [ -f "${CLOUDFLARED_BIN}" ]; then
        _info "正在清理 Argo 隧道..."
        pkill -f "cloudflared" 2>/dev/null
        rm -f "${CLOUDFLARED_BIN}"
        rm -rf "/etc/cloudflared"
    fi

    # 4. 清理组件脚本与别名
    _info "正在清理组件脚本与环境配置..."
    rm -f "${SCRIPT_DIR}/utils.sh" "${SCRIPT_DIR}/parser.sh" "${SCRIPT_DIR}/advanced_relay.sh"
    rm -f "/usr/local/bin/sb"
    
    # 5. 复原 MOTD
    if [ -f "/etc/motd" ]; then
        sed -i '/sing-box 节点信息/d' /etc/motd 2>/dev/null
        sed -i '/====/d' /etc/motd 2>/dev/null
        sed -i '/Base64 订阅/d' /etc/motd 2>/dev/null
    fi

    # 6. 处理主程序 (考虑线路机共用)
    local relay_script="/root/relay-install.sh"
    if [ -f "$relay_script" ]; then
        _warn "检测到 [线路机] 脚本存在，为保持其运行，将 [保留] sing-box 主程序。"
    else
        _info "正在删除 sing-box 主程序..."
        rm -f "${SINGBOX_BIN}" "${YQ_BINARY}"
    fi

    _success "清理完成。脚本已自毁。再见！"
    rm -f "${SELF_SCRIPT_PATH}"
    exit 0
}

_initialize_config_files() {
    mkdir -p ${SINGBOX_DIR}
    [ -s "$CONFIG_FILE" ] || echo '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[],"final":"direct"}}' > "$CONFIG_FILE"
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
ipv6: false
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
  ipv6: false
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
    if [ ! -s "${SINGBOX_DIR}/relay.json" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
        _info "已初始化中转配置文件"
    fi
}

_cleanup_legacy_config() {
    # 检查并清理 config.json 中残留的旧版中转配置 (tag 以 relay-out- 开头的 outbound)
    # 这些残留会导致路由冲突，使主脚本节点误走中转线路
    local needs_restart=false
    
    if jq -e '.outbounds[] | select(.tag | startswith("relay-out-"))' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "检测到舊版中转残留配置，正在清理..."
        cp "$CONFIG_FILE" "${CONFIG_FILE}.bak_legacy"
        
        # 删除所有 relay-out- 开头的 outbounds
        jq 'del(.outbounds[] | select(.tag | startswith("relay-out-")))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        
        # 删除所有 relay-out- 开头的路由规则 (如果有)
        if jq -e '.route.rules' "$CONFIG_FILE" >/dev/null 2>&1; then
            jq 'del(.route.rules[] | select(.outbound | startswith("relay-out-")))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        fi
        
        # 确保存在 direct 出站且位于第一位 (如果没有 direct，添加一个)
        if ! jq -e '.outbounds[] | select(.tag == "direct")' "$CONFIG_FILE" >/dev/null 2>&1; then
             jq '.outbounds = [{"type":"direct","tag":"direct"}] + .outbounds' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        fi
        
        _success "配置清理完成。相关中转已被迁移至独立配置文件 (relay.json)。"
        needs_restart=true
    fi
    
    # [关键修复] 确保 route.final 设置为 "direct"
    # 这是核心修复：当 config.json 和 relay.json 合并时，relay-out-* outbound 会被插入到 outbounds 列表前面
    # 如果没有 route.final，sing-box 会使用列表中的第一个 outbound 作为默认出口，导致主节点流量走中转
    if ! jq -e '.route.final == "direct"' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "检测到 route.final 未设置或不正确，正在修复..."
        
        # 确保 route 对象存在
        if ! jq -e '.route' "$CONFIG_FILE" >/dev/null 2>&1; then
            jq '. + {"route":{"rules":[],"final":"direct"}}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        else
            # 设置 route.final = "direct"
            jq '.route.final = "direct"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        fi
        
        _success "route.final 已设置为 direct，主节点流量将走本机 IP。"
        needs_restart=true
    fi
    
    if [ "$needs_restart" = true ]; then
        return 0
    fi
    return 1
}

_generate_self_signed_cert() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"

    _info "正在为 ${domain} 生成自签名证书..."
    # 使用>/dev/null 2>&1以保持界面清洁
    openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${domain}" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        _error "为 ${domain} 生成证书失败！"
        rm -f "$cert_path" "$key_path" # 如果失败，清理不完整的文件
        return 1
    fi
    _success "证书 ${cert_path} 和私钥 ${key_path} 已成功生成。"
    return 0
}

_atomic_modify_json() {
    local file_path="$1"
    local jq_filter="$2"
    cp "$file_path" "${file_path}.tmp"
    if jq "$jq_filter" "${file_path}.tmp" > "$file_path"; then
        rm "${file_path}.tmp"
    else
        _error "修改JSON文件 '$file_path' 失败！配置已回滚。"
        mv "${file_path}.tmp" "$file_path"
        return 1
    fi
}

_atomic_modify_yaml() {
    local file_path="$1"
    local yq_filter="$2"
    cp "$file_path" "${file_path}.tmp"
    if ${YQ_BINARY} eval "$yq_filter" -i "$file_path"; then
        rm "${file_path}.tmp"
    else
        _error "修改YAML文件 '$file_path' 失败！配置已回滚。"
        mv "${file_path}.tmp" "$file_path"
        return 1
    fi
}

# 安全地从 clash.yaml 获取代理字段值（支持中文和特殊字符的节点名称）
_get_proxy_field() {
    local proxy_name="$1"
    local field="$2"
    # 使用 yq 的环境变量功能避免特殊字符问题
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME)) | '"$field" "${CLASH_YAML_FILE}" 2>/dev/null | head -n 1
}

_add_node_to_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    _atomic_modify_yaml "$CLASH_YAML_FILE" ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name)"
    # 使用环境变量避免特殊字符问题
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= . + [env(PROXY_NAME)] | .proxies |= unique)' -i "$CLASH_YAML_FILE"
}

_remove_node_from_yaml() {
    local proxy_name="$1"
    # 使用环境变量避免特殊字符问题
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval 'del(.proxies[] | select(.name == env(PROXY_NAME)))' -i "$CLASH_YAML_FILE"
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= del(.[] | select(. == env(PROXY_NAME))))' -i "$CLASH_YAML_FILE"
}

# 显示节点分享链接（在添加节点后调用）
# 参数: $1=协议类型, $2=节点名称, $3=服务器IP(用于链接), $4=端口, 其他参数根据协议不同
_show_node_link() {
    local type="$1"
    local name="$2"
    local link_ip="$3"
    local port="$4"
    shift 4
    
    local url=""
    
    case "$type" in
        "vless-reality")
            # 参数: uuid, sni, public_key, short_id, flow
            local uuid="$1" sni="$2" pk="$3" sid="$4" flow="${5:-xtls-rprx-vision}"
            url="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=${pk}&fp=chrome&type=tcp&flow=${flow}&sni=${sni}&sid=${sid}#$(_url_encode "$name")"
            ;;
        "vless-ws-tls")
            # 参数: uuid, sni, ws_path, skip_verify
            local uuid="$1" sni="$2" ws_path="$3" skip_verify="$4"
            local insecure_param=""
            [[ "$skip_verify" == "true" ]] && insecure_param="&insecure=1"
            url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=ws&host=${sni}&path=$(_url_encode "$ws_path")&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "vless-tcp")
            # 参数: uuid
            local uuid="$1"
            url="vless://${uuid}@${link_ip}:${port}?encryption=none&type=tcp#$(_url_encode "$name")"
            ;;
        "trojan-ws-tls")
            # 参数: password, sni, ws_path, skip_verify
            local password="$1" sni="$2" ws_path="$3" skip_verify="$4"
            local insecure_param=""
            [[ "$skip_verify" == "true" ]] && insecure_param="&allowInsecure=1"
            url="trojan://${password}@${link_ip}:${port}?security=tls&type=ws&host=${sni}&path=$(_url_encode "$ws_path")&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "hysteria2")
            # 参数: password, sni, obfs_password(可选), port_hopping(可选)
            local password="$1" sni="$2" obfs_password="$3" port_hopping="$4"
            local obfs_param=""; [[ -n "$obfs_password" ]] && obfs_param="&obfs=salamander&obfs-password=${obfs_password}"
            local hop_param=""; [[ -n "$port_hopping" ]] && hop_param="&mport=${port_hopping}"
            url="hysteria2://${password}@${link_ip}:${port}?sni=${sni}&insecure=1${obfs_param}${hop_param}#$(_url_encode "$name")"
            ;;
        "tuic")
            # 参数: uuid, password, sni
            local uuid="$1" password="$2" sni="$3"
            url="tuic://${uuid}:${password}@${link_ip}:${port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$name")"
            ;;
        "anytls")
            # 参数: password, sni, skip_verify
            local password="$1" sni="$2" skip_verify="$3"
            local insecure_param=""
            if [ "$skip_verify" == "true" ]; then
                insecure_param="&insecure=1&allowInsecure=1"
            fi
            url="anytls://${password}@${link_ip}:${port}?security=tls&sni=${sni}${insecure_param}&type=tcp#$(_url_encode "$name")"
            ;;
        "shadowsocks")
            # 参数: method, password
            local method="$1" password="$2"
            url="ss://$(_url_encode "${method}:${password}")@${link_ip}:${port}#$(_url_encode "$name")"
            ;;
        "socks")
            # 参数: username, password
            local username="$1" password="$2"
            echo ""
            _info "节点信息: 服务器: ${link_ip}, 端口: ${port}, 用户名: ${username}, 密码: ${password}"
            return
            ;;
    esac
    
    if [ -n "$url" ]; then
        echo ""
        echo -e "${YELLOW}═══════════════════ 分享链接 ═══════════════════${NC}"
        echo -e "${CYAN}${url}${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════════${NC}"
    fi
}

_add_vless_ws_tls() {
    local camouflage_domain=""
    local port=""
    local is_cdn_mode=false
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_WS_TLS_DOMAIN:-$BATCH_SNI}"
        [ "$BATCH_WS_MODE" = "cdn" ] && is_cdn_mode=true
        if [ "$is_cdn_mode" = true ]; then
            client_server_addr="www.visa.com.sg"
        fi
    else
        _info "--- VLESS (WebSocket+TLS) 设置向导 ---"
        echo "请选择连接模式："
        echo "  1. 直连模式 (回车默认, 适合直连使用)"
        echo "  2. 优选域名/IP模式 (适合IP被墙或者需要优选加速)"
        read -p "请输入选项 [1/2]: " mode_choice
        if [ "$mode_choice" == "2" ]; then
            is_cdn_mode=true
            _info "您选择了 [优选域名/IP模式]。"
            _info "请输入优选域名或优选IP"
            read -p "请输入 (回车默认 www.visa.com.sg): " cdn_input
            client_server_addr=${cdn_input:-"www.visa.com.sg"}
        else
            _info "您选择了 [直连模式]。"
            _info "请输入客户端用于“连接”的地址:"
            _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
            _info "  - (其他)   您也可以手动输入一个IP或域名"
            read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
            client_server_addr=${connection_address:-$server_ip}
        fi
        
        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi

        _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
        _info " (例如: xxx.987654.xyz)"
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

        read -p "请输入监听端口 (直连模式下填写已经映射的端口，优选模式下填写CF回源设置的端口): " port
        [[ -z "$port" ]] && _error "端口不能为空" && return 1
    fi

    # 确定客户端连接端口
    local client_port="$port"
    if [ "$is_cdn_mode" == "true" ]; then
        client_port="443"
        _info "检测到 优选域名/IP模式 ，客户端连接端口已自动设置为: 443"
    fi

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
    
    # [!] 自定义名称 (核心修改点)
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-VLESS-WS-${port}"
    else
        local default_name="VLESS-WS-${port}"
        if [ "$is_cdn_mode" == "true" ]; then 
            default_name="VLESS-CDN-443" 
        fi
        
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    # tag 已在证书选择步骤提前定义
    
    # Inbound (服务器端) 配置: 使用 $port
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg wsp "$ws_path" \
        '{
            "type": "vless",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"uuid": $u, "flow": ""}],
            "tls": {
                "enabled": true,
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # Proxy (客户端) 配置: 使用 $client_port (CDN模式为443)
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
                "tls": true,
                "udp": true,
                "skip-cert-verify": ($skip_verify_bool == "true"),
                "network": "ws",
                "servername": $sn,
                "ws-opts": {
                    "path": $wsp,
                    "headers": {
                        "Host": $host_header
                    }
                }
            }')
            
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (WebSocket+TLS) 节点 [${name}] 添加成功!"
    _success "客户端连接地址 (server): ${client_server_addr}"
    _success "客户端连接端口 (port): ${client_port}"
    _success "客户端伪装域名 (servername/Host): ${camouflage_domain}"
    if [ "$is_cdn_mode" == "true" ]; then
        _success "优选域名/IP模式已应用。请确保 Cloudflare 回源规则将流量指向本机端口: ${port}"
    fi
    
    # IPv6 处理用于链接
    local link_ip="$client_server_addr"
    _show_node_link "vless-ws-tls" "$name" "$link_ip" "$client_port" "$uuid" "$camouflage_domain" "$ws_path" "$skip_verify"
}

_add_trojan_ws_tls() {
    local camouflage_domain=""
    local port=""
    local is_cdn_mode=false
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_WS_TLS_DOMAIN:-$BATCH_SNI}"
        [ "$BATCH_WS_MODE" = "cdn" ] && is_cdn_mode=true
        if [ "$is_cdn_mode" = true ]; then
            client_server_addr="www.visa.com.sg"
        fi
    else
        _info "--- Trojan (WebSocket+TLS) 设置向导 ---"
        echo "请选择连接模式："
        echo "  1. 直连模式 (回车默认)"
        echo "  2. 优选域名/IP模式"
        read -p "请输入选项 [1/2]: " mode_choice
        if [ "$mode_choice" == "2" ]; then
            is_cdn_mode=true
            read -p "请输入优选域名或优选IP (默认 www.visa.com.sg): " cdn_input
            client_server_addr=${cdn_input:-"www.visa.com.sg"}
        else
            read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
            client_server_addr=${connection_address:-$server_ip}
        fi
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1
        read -p "请输入监听端口: " port
        [[ -z "$port" ]] && _error "端口不能为空" && return 1
    fi

    # 确定客户端连接端口
    local client_port="$port"
    if [ "$is_cdn_mode" == "true" ]; then
        client_port="443"
    fi

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

    # [!] 自定义名称 (核心修改点)
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-Trojan-WS-${port}"
    else
        local default_name="Trojan-WS-${port}"
        if [ "$is_cdn_mode" == "true" ]; then 
            default_name="Trojan-CDN-443" 
        fi
        
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    # tag 已在证书选择步骤提前定义
    
    # Inbound (服务器端) 配置: 使用 $port
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg wsp "$ws_path" \
        '{
            "type": "trojan",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"password": $pw}],
            "tls": {
                "enabled": true,
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # Proxy (客户端) 配置: 使用 $client_port
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
            
    _add_node_to_yaml "$proxy_json"
    _success "Trojan (WebSocket+TLS) 节点 [${name}] 添加成功!"
    _success "客户端连接地址 (server): ${client_server_addr}"
    _success "客户端连接端口 (port): ${client_port}"
    _success "客户端伪装域名 (sni/Host): ${camouflage_domain}"
    if [ "$is_cdn_mode" == "true" ]; then
        _success "优选域名/IP模式已应用。请确保 Cloudflare 回源规则将流量指向本机端口: ${port}"
    fi
    
    # IPv6 处理用于链接
    local link_ip="$client_server_addr"
    _show_node_link "trojan-ws-tls" "$name" "$link_ip" "$client_port" "$password" "$camouflage_domain" "$ws_path" "$skip_verify"
}

_add_anytls() {
    local node_ip="${server_ip}"
    local port=""
    local server_name="www.apple.com"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="$BATCH_SNI"
    else
        _info "--- 添加 AnyTLS 节点 ---"
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入监听端口: " port
        [[ -z "$port" ]] && _error "端口不能为空" && return 1
        read -p "请输入伪装域名/SNI (默认: www.apple.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.apple.com"}
    fi
    
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
    
    # --- 步骤 5: 密码 (UUID 格式) ---
    local password=""
    if [ "$BATCH_MODE" = "true" ]; then
        password=$(${SINGBOX_BIN} generate uuid)
    else
        read -p "请输入密码/UUID (回车则随机生成): " input_pw
        password=${input_pw:-$(${SINGBOX_BIN} generate uuid)}
    fi
    
    # --- 步骤 6: 自定义名称 ---
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-AnyTLS-${port}"
    else
        local default_name="AnyTLS-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
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
                "server_name": $sn,
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
    
    _add_node_to_yaml "$proxy_json"
    
    # --- 保存元数据 ---
    local meta_json=$(jq -n \
        --arg sn "$server_name" \
        '{server_name: $sn}')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1
    
    # --- 生成分享链接 ---
    local insecure_param=""
    if [ "$skip_verify" == "true" ]; then
        insecure_param="&insecure=1&allowInsecure=1"
    fi
    local share_link="anytls://${password}@${link_ip}:${port}?security=tls&sni=${server_name}${insecure_param}&type=tcp#$(_url_encode "$name")"
    
    _success "AnyTLS 节点 [${name}] 添加成功!"
    _show_node_link "anytls" "$name" "$link_ip" "$port" "$password" "$server_name" "$skip_verify"
}

_add_vless_reality() {
    local node_ip="${server_ip}"
    local server_name="www.apple.com"
    local port=""
    local name=""

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="$BATCH_SNI"
        name="Batch-Reality-${port}"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入伪装域名 (默认: www.apple.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.apple.com"}
        read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
        local default_name="VLESS-REALITY-${port}"
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
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (REALITY) 节点 [${name}] 添加成功!"
    _show_node_link "vless-reality" "$name" "$link_ip" "$port" "$uuid" "$server_name" "$public_key" "$short_id"
}

_add_vless_tcp() {
    local node_ip="${server_ip}"
    local port=""
    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
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
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (TCP) 节点 [${name}] 添加成功!"
    _show_node_link "vless-tcp" "$name" "$link_ip" "$port" "$uuid"
}

_add_hysteria2() {
    local node_ip="${server_ip}"
    local port=""
    local server_name="www.apple.com"
    local obfs_password=""
    local port_hopping=""
    local use_multiport="false"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="$BATCH_SNI"
        [ "$BATCH_HY2_OBFS" != "none" ] && obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        port_hopping="$BATCH_HY2_HOP"
        if [ -n "$port_hopping" ]; then
            local port_range_start=$(echo $port_hopping | cut -d'-' -f1)
            local port_range_end=$(echo $port_hopping | cut -d'-' -f2)
            local hop_count=$((port_range_end - port_range_start + 1))
            [ "$hop_count" -le 1000 ] && use_multiport="true"
        fi
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
        read -p "请输入伪装域名 (默认: www.apple.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.apple.com"}
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
                port_hopping="$port_range"
                local hop_count=$((port_range_end - port_range_start + 1))
                [ "$hop_count" -le 1000 ] && use_multiport="true"
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

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # [!] 新增：多端口监听模式逻辑
    if [ "$use_multiport" == "true" ] && [ -n "$port_hopping" ]; then
        _info "正在生成多端口监听配置 (${port_range_start}-${port_range_end})..."
        
        # 使用 Bash 循环构建 JSON 数组，避免复杂 jq 语法问题
        local multi_json_array="["
        local first=true
        
        for ((p=port_range_start; p<=port_range_end; p++)); do
            # 跳过主端口
            if [ "$p" -eq "$port" ]; then continue; fi
            
            if [ "$first" = true ]; then first=false; else multi_json_array+=","; fi
            
            local hop_tag="${tag}-hop-${p}"
            # 生成单个端口的配置
            local item_json=$(jq -n --arg t "$hop_tag" --arg p "$p" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
                '{
                    "type": "hysteria2",
                    "tag": $t,
                    "listen": "::",
                    "listen_port": ($p|tonumber),
                    "users": [{"password": $pw}],
                    "tls": {
                        "enabled": true,
                        "alpn": ["h3"],
                        "certificate_path": $cert,
                        "key_path": $key
                    }
                }')
                
            # 如果有混淆，追加混淆配置
            if [ -n "$obfs_password" ]; then
                item_json=$(echo "$item_json" | jq --arg op "$obfs_password" '.obfs={"type":"salamander","password":$op}')
            fi
            
            multi_json_array+="$item_json"
        done
        multi_json_array+="]"
        
        # 追加到配置文件
        _atomic_modify_json "$CONFIG_FILE" ".inbounds += $multi_json_array | .inbounds |= unique_by(.tag)" || return 1
        _success "已添加 $((port_range_end - port_range_start)) 个辅助监听端口"
    fi
    
    # 保存元数据（包含端口跳跃信息）
    local meta_json=$(jq -n --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" --arg hop "$port_hopping" \
        '{ "up": $up, "down": $down } | if $op != "" then .obfsPassword = $op else . end | if $hop != "" then .portHopping = $hop else . end')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    # Clash 配置中的端口（如果有端口跳跃，使用范围格式）
    local clash_ports="$port"
    if [ -n "$port_hopping" ]; then
        clash_ports="$port_hopping"
    fi
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg ports "$clash_ports" --arg pw "$password" --arg sn "$server_name" --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" --arg hop "$port_hopping" \
        '{
            "name": $n,
            "type": "hysteria2",
            "server": $s,
            "port": ($p|tonumber),
            "password": $pw,
            "sni": $sn,
            "skip-cert-verify": true,
            "alpn": ["h3"],
            "up": $up,
            "down": $down
        } | if $op != "" then .obfs = "salamander" | .["obfs-password"] = $op else . end | if $hop != "" then .ports = $hop else . end')
    _add_node_to_yaml "$proxy_json"
    
    _success "Hysteria2 节点 [${name}] 添加成功!"
    
    # 显示端口跳跃信息
    if [ -n "$port_hopping" ]; then
        _info "端口跳跃范围: ${port_hopping}"
    fi
    
    _show_node_link "hysteria2" "$name" "$link_ip" "$port" "$password" "$server_name" "$obfs_password" "$port_hopping"
}

_add_tuic() {
    local node_ip="${server_ip}"
    local port=""
    local server_name="www.apple.com"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="$BATCH_SNI"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
        read -p "请输入伪装域名 (默认: www.apple.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.apple.com"}
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
    _add_node_to_yaml "$proxy_json"
    _success "TUICv5 节点 [${name}] 添加成功!"
    _show_node_link "tuic" "$name" "$link_ip" "$port" "$uuid" "$password" "$server_name"
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
        echo " 1) shadowsocks (aes-256-gcm)"
        echo " 2) shadowsocks-2022"
        echo " 3) shadowsocks-2022 + Padding"
        echo " 0) 返回"
        echo "========================================"
        read -p "请选择加密方式 [0-3]: " choice
    fi

    local method="" password="" name_prefix="" use_multiplex=false
    case $choice in
        1) 
            method="aes-256-gcm"
            password=$(${SINGBOX_BIN} generate rand --hex 16)
            name_prefix="SS-aes-256-gcm"
            ;;
        2)
            method="2022-blake3-aes-128-gcm"
            password=$(${SINGBOX_BIN} generate rand --base64 16)
            name_prefix="SS-2022"
            ;;
        3)
            method="2022-blake3-aes-128-gcm"
            password=$(${SINGBOX_BIN} generate rand --base64 16)
            name_prefix="SS-2022-Padding"
            use_multiplex=true
            _info "已启用 Multiplex + Padding 模式"
            _warning "注意：客户端也必须启用 Multiplex + Padding 才能连接！"
            ;;
        0) return 1 ;;
        *) _error "无效输入"; return 1 ;;
    esac

    local node_ip="${server_ip}"
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

    local tag="${name_prefix}-in-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    # 根据是否启用 Multiplex 生成不同配置
    local inbound_json=""
    if [ "$use_multiplex" == "true" ]; then
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
    fi
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # YAML 配置也需要根据 Multiplex 状态生成
    local proxy_json=""
    if [ "$use_multiplex" == "true" ]; then
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
    _add_node_to_yaml "$proxy_json"

    _success "Shadowsocks (${method}) 节点 [${name}] 添加成功!"
    if [ "$use_multiplex" == "true" ]; then
        _info "Multiplex + Padding 已启用，客户端需配置对应选项"
    fi
    _show_node_link "shadowsocks" "$name" "$link_ip" "$port" "$method" "$password"
    return 0
}

_add_socks() {
    local node_ip="${server_ip}"
    local port=""
    local username=""
    local password=""

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        username=$(${SINGBOX_BIN} generate rand --hex 8)
        password=$(${SINGBOX_BIN} generate rand --hex 16)
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
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
    _add_node_to_yaml "$proxy_json"
    _success "SOCKS5 节点添加成功!"
    _show_node_link "socks" "$name" "$display_ip" "$port" "$username" "$password"
}

_view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    
    # 统计有效节点数量（排除辅助节点）
    local node_count=$(jq '[.inbounds[] | select(.tag | contains("-hop-") | not)] | length' "$CONFIG_FILE")
    _info "--- 当前节点信息 (共 ${node_count} 个) ---"
    
    # [关键修复] 确保在查看前清空之前的临时链接缓存
    rm -f /tmp/singbox_links.tmp
    
    jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') type=$(echo "$node" | jq -r '.type') port=$(echo "$node" | jq -r '.listen_port')
        
        # 过滤掉多端口监听生成的辅助节点（跳过 tag 中包含 -hop- 的节点）
        if [[ "$tag" == *"-hop-"* ]]; then continue; fi
        
        # 优化查找逻辑：优先使用端口匹配，因为tag和name可能不完全对应
        local proxy_name_to_find=""
        local proxy_obj_by_port=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}')' ${CLASH_YAML_FILE} | head -n 1)

        if [ -n "$proxy_obj_by_port" ]; then
             proxy_name_to_find=$(echo "$proxy_obj_by_port" | ${YQ_BINARY} eval '.name' -)
        fi

        # 如果通过端口找不到（比如443端口被复用），则尝试用类型模糊匹配
        if [[ -z "$proxy_name_to_find" ]]; then
            proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | grep -i "${type}" | head -n 1)
        fi
        
        # 再次降级，如果还找不到
        if [[ -z "$proxy_name_to_find" ]]; then
             proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | head -n 1)
        fi

        # [!] 已修改：创建一个显示名称，优先使用clash.yaml中的名称，失败则回退到tag
        local display_name=${proxy_name_to_find:-$tag}

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
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                local flow=$(echo "$node" | jq -r '.users[0].flow // empty')
                local is_reality=$(echo "$node" | jq -r '.tls.reality.enabled // false')
                local transport_type=$(echo "$node" | jq -r '.transport.type // empty')
                
                if [ "$is_reality" == "true" ]; then
                    local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE")
                    local sn=$(echo "$node" | jq -r '.tls.server_name // "www.apple.com"')
                    local pk=$(echo "$meta" | jq -r '.publicKey')
                    local sid=$(echo "$meta" | jq -r '.shortId')
                    local fp="chrome"
                    url="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=${pk}&fp=${fp}&type=tcp&flow=${flow}&sni=${sn}&sid=${sid}#$(_url_encode "$display_name")"
                elif [ "$transport_type" == "ws" ]; then
                    local ws_path=$(echo "$node" | jq -r '.transport.path')
                    local sn=$(_get_proxy_field "$proxy_name_to_find" ".servername")
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=ws&host=${sn}&path=$(_url_encode "$ws_path")&sni=${sn}#$(_url_encode "$display_name")"
                    
                    # [!] 处理 Argo 节点
                    local is_argo=$(jq -r --arg t "$tag" '.[$t].isArgo // false' "$METADATA_FILE")
                    if [ "$is_argo" == "true" ]; then
                        local argo_domain=$(jq -r --arg t "$tag" '.[$t].argoDomain' "$METADATA_FILE")
                        if [ -n "$argo_domain" ] && [ "$argo_domain" != "null" ]; then
                            url="vless://${uuid}@${argo_domain}:443?security=tls&encryption=none&type=ws&host=${argo_domain}&path=$(_url_encode "$ws_path")&sni=${argo_domain}#$(_url_encode "$display_name")"
                        fi
                    fi
                elif [ "$(echo "$node" | jq -r '.tls.enabled // false')" == "true" ]; then
                    local sn=$(echo "$node" | jq -r '.tls.server_name // "www.apple.com"')
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=tcp&sni=${sn}#$(_url_encode "$display_name")"
                else
                    url="vless://${uuid}@${link_ip}:${port}?encryption=none&type=tcp#$(_url_encode "$display_name")"
                fi
                ;;
            "trojan")
                local password=$(echo "$node" | jq -r '.users[0].password')
                local transport_type=$(echo "$node" | jq -r '.transport.type // empty')
                
                if [ "$transport_type" == "ws" ]; then
                    local ws_path=$(echo "$node" | jq -r '.transport.path')
                    local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                    url="trojan://${password}@${link_ip}:${port}?security=tls&type=ws&host=${sn}&path=$(_url_encode "$ws_path")&sni=${sn}#$(_url_encode "$display_name")"
                    
                    # [!] 处理 Argo 节点
                    local is_argo=$(jq -r --arg t "$tag" '.[$t].isArgo // false' "$METADATA_FILE")
                    if [ "$is_argo" == "true" ]; then
                        local argo_domain=$(jq -r --arg t "$tag" '.[$t].argoDomain' "$METADATA_FILE")
                        if [ -n "$argo_domain" ] && [ "$argo_domain" != "null" ]; then
                            url="trojan://${password}@${argo_domain}:443?security=tls&type=ws&host=${argo_domain}&path=$(_url_encode "$ws_path")&sni=${argo_domain}#$(_url_encode "$display_name")"
                        fi
                    fi
                else
                    local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                    url="trojan://${password}@${link_ip}:${port}?security=tls&type=tcp&sni=${sn}#$(_url_encode "$display_name")"
                fi
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password');
                local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE");
                local op=$(echo "$meta" | jq -r '.obfsPassword')
                local obfs_param=""; [[ -n "$op" && "$op" != "null" ]] && obfs_param="&obfs=salamander&obfs-password=${op}"
                # 端口跳跃参数
                local hop=$(echo "$meta" | jq -r '.portHopping // empty')
                local hop_param=""; [[ -n "$hop" && "$hop" != "null" ]] && hop_param="&mport=${hop}"
                url="hysteria2://${pw}@${link_ip}:${port}?sni=${sn}&insecure=1${obfs_param}${hop_param}#$(_url_encode "$display_name")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                url="tuic://${uuid}:${pw}@${link_ip}:${port}?sni=${sn}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$display_name")"
                ;;
            "anytls")
                local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn=$(echo "$node" | jq -r '.tls.server_name')
                local skip_verify=$(_get_proxy_field "$proxy_name_to_find" ".skip-cert-verify")
                local insecure_param=""
                if [ "$skip_verify" == "true" ]; then
                    insecure_param="&insecure=1&allowInsecure=1"
                fi
                url="anytls://${pw}@${link_ip}:${port}?security=tls&sni=${sn}${insecure_param}&type=tcp#$(_url_encode "$display_name")"
                ;;
            "shadowsocks")
                local method=$(echo "$node" | jq -r '.method')
                local password=$(echo "$node" | jq -r '.password')
                url="ss://$(_url_encode "${method}:${password}")@${link_ip}:${port}#$(_url_encode "$display_name")"
                ;;
            "socks")
                local u=$(echo "$node" | jq -r '.users[0].username'); local p=$(echo "$node" | jq -r '.users[0].password')
                _info "  类型: SOCKS5, 地址: $display_server, 端口: $port, 用户: $u, 密码: $p"
                ;;
        esac
        [ -n "$url" ] && echo -e "  ${YELLOW}分享链接:${NC} ${url}"
        # 收集链接到临时文件
        [ -n "$url" ] && echo "$url" >> /tmp/singbox_links.tmp
    done
    echo "-------------------------------------"
    
    # 生成聚合 Base64 选项
    if [ -f /tmp/singbox_links.tmp ]; then
        echo ""
        read -p "是否生成聚合 Base64 订阅? (y/N): " gen_base64
        if [[ "$gen_base64" == "y" || "$gen_base64" == "Y" ]]; then
            echo ""
            _info "=== 聚合 Base64 订阅 ==="
            local base64_result=$(cat /tmp/singbox_links.tmp | base64 -w 0)
            echo -e "${CYAN}${base64_result}${NC}"
            echo ""
            _success "可直接复制上方内容导入 v2rayN 等客户端"
        fi
        rm -f /tmp/singbox_links.tmp
    fi
}

_delete_node() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    _info "--- 节点删除 ---"
    
    # --- [!] 新的列表逻辑 ---
    # 我们需要先构建一个数组，来映射用户输入和节点信息
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local display_names=() # 存储显示名称
    
    local i=1
    # [!] 已修改：使用进程替换 < <(...) 来避免 subshell，确保数组在循环外可用
    local i=1
    # [!] 已修改：使用进程替换 < <(...) 来避免 subshell，确保数组在循环外可用
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') 
        
        # [!] 过滤辅助节点
        if [[ "$tag" == *"-hop-"* ]]; then continue; fi
        
        local type=$(echo "$node" | jq -r '.type') 
        local port=$(echo "$node" | jq -r '.listen_port')
        
        # 存储信息
        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")

        # --- 复用 _view_nodes 中的名称查找逻辑 ---
        local proxy_name_to_find=""
        local proxy_obj_by_port=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}')' ${CLASH_YAML_FILE} | head -n 1)
        if [ -n "$proxy_obj_by_port" ]; then
             proxy_name_to_find=$(echo "$proxy_obj_by_port" | ${YQ_BINARY} eval '.name' -)
        fi
        if [[ -z "$proxy_name_to_find" ]]; then
            proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | grep -i "${type}" | head -n 1)
        fi
        if [[ -z "$proxy_name_to_find" ]]; then
             proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | head -n 1)
        fi
        # --- 结束名称查找逻辑 ---
        
        local display_name=${proxy_name_to_find:-$tag} # 回退到 tag
        display_names+=("$display_name") # 存储显示名称
        
        # [!] 已修改：显示自定义名称、类型和端口
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${port}"
        ((i++))
    done < <(jq -c '.inbounds[]' "$CONFIG_FILE") # [!] 已修改：使用 < <(...) 
    # --- 列表逻辑结束 ---
    
    # 添加删除所有选项
    local count=${#inbound_tags[@]}
    echo ""
    echo -e "  ${RED}99)${NC} 删除所有节点"

    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    
    # 处理删除所有节点
    if [ "$num" -eq 99 ]; then
        read -p "$(echo -e ${RED}"确定要删除所有节点吗? 此操作不可恢复! (输入 yes 确认): "${NC})" confirm_all
        if [ "$confirm_all" != "yes" ]; then
            _info "删除已取消。"
            return
        fi
        
        _info "正在删除所有节点..."
        
        # 清空配置
        _atomic_modify_json "$CONFIG_FILE" '.inbounds = []'
        _atomic_modify_json "$METADATA_FILE" '{}'
        
        # 清空 clash.yaml 中的代理
        ${YQ_BINARY} eval '.proxies = []' -i "$CLASH_YAML_FILE"
        ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "节点选择") | .proxies = ["DIRECT"])' -i "$CLASH_YAML_FILE"
        
        # 删除所有证书文件
        rm -f ${SINGBOX_DIR}/*.pem ${SINGBOX_DIR}/*.key 2>/dev/null
        
        # 清空 iptables NAT PREROUTING 规则 (清除端口跳跃规则)
        if command -v iptables &>/dev/null; then
            _info "正在清理 iptables NAT PREROUTING 规则..."
            iptables -t nat -F PREROUTING 2>/dev/null
            _save_iptables_rules
        fi
        
        _success "所有节点已删除！"
        _manage_service "restart"
        return
    fi
    
    # [!] 已修改：现在 count 会在循环外被正确计算
    if [ "$num" -gt "$count" ]; then _error "编号超出范围。"; return; fi

    local index=$((num - 1))
    # [!] 已修改：从数组中获取正确的信息
    local tag_to_del=${inbound_tags[$index]}
    local type_to_del=${inbound_types[$index]}
    local port_to_del=${inbound_ports[$index]}
    local display_name_to_del=${display_names[$index]}

    # --- [!] 新的删除逻辑 ---
    # 我们需要再次运行查找逻辑，来确定 clash.yaml 中的确切名称
    # (这一步是必须的，因为 display_names 可能会回退到 tag，但 clash.yaml 中是有自定义名称的)
    local proxy_name_to_del=""
    local proxy_obj_by_port_del=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port_to_del}')' ${CLASH_YAML_FILE} | head -n 1)
    if [ -n "$proxy_obj_by_port_del" ]; then
         proxy_name_to_del=$(echo "$proxy_obj_by_port_del" | ${YQ_BINARY} eval '.name' -)
    fi
    if [[ -z "$proxy_name_to_del" ]]; then
        proxy_name_to_del=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port_to_del}' or .port == 443) | .name' ${CLASH_YAML_FILE} | grep -i "${type_to_del}" | head -n 1)
    fi
    if [[ -z "$proxy_name_to_del" ]]; then
         proxy_name_to_del=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port_to_del}' or .port == 443) | .name' ${CLASH_YAML_FILE} | head -n 1)
    fi

    # [!] 已修改：使用显示名称进行确认
    read -p "$(echo -e ${YELLOW}"确定要删除节点 ${display_name_to_del} 吗? (y/N): "${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "删除已取消。"
        return
    fi
    
    # === 关键修复：必须先读取 metadata 判断节点类型，再删除！===
    local node_metadata=$(jq -r --arg tag "$tag_to_del" '.[$tag] // empty' "$METADATA_FILE" 2>/dev/null)
    local node_type=""
    if [ -n "$node_metadata" ]; then
        node_type=$(echo "$node_metadata" | jq -r '.type // empty')
    fi
    
    # [!] 重要修正：不使用索引删除（因为列表已过滤），改为使用 Tag 精确匹配删除
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag_to_del\"))" || return
    
    # [!] 新增：级联删除关联的辅助端口监听节点 (格式: tag-hop-xxx)
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag | startswith(\"$tag_to_del-hop-\")))"
    
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_del\")" || return
    
    # [!] 已修改：使用找到的 proxy_name_to_del 从 clash.yaml 中删除
    if [ -n "$proxy_name_to_del" ]; then
        _remove_node_from_yaml "$proxy_name_to_del"
    fi

    # 证书清理逻辑 - 包含 hysteria2, tuic, anytls (基于 tag)
    if [ "$type_to_del" == "hysteria2" ] || [ "$type_to_del" == "tuic" ] || [ "$type_to_del" == "anytls" ]; then
        local cert_to_del="${SINGBOX_DIR}/${tag_to_del}.pem"
        local key_to_del="${SINGBOX_DIR}/${tag_to_del}.key"
        if [ -f "$cert_to_del" ] || [ -f "$key_to_del" ]; then
            _info "正在删除节点关联的证书文件: ${cert_to_del}, ${key_to_del}"
            rm -f "$cert_to_del" "$key_to_del"
        fi
    fi
    
    # === 根据之前读取的节点类型清理相关配置 ===
    if [ "$node_type" == "third-party-adapter" ]; then
        # === 第三方适配层：删除 outbound 和 route ===
        _info "检测到第三方适配层，正在清理关联配置..."
        
        # 先查找对应的 outbound (必须在删除 route 之前)
        local outbound_tag=$(jq -r --arg inbound "$tag_to_del" '.route.rules[] | select(.inbound == $inbound) | .outbound' "$CONFIG_FILE" 2>/dev/null | head -n 1)
        
        # 删除 route 规则
        _atomic_modify_json "$CONFIG_FILE" "del(.route.rules[] | select(.inbound == \"$tag_to_del\"))" || true
        
        # 删除对应的 outbound
        if [ -n "$outbound_tag" ] && [ "$outbound_tag" != "null" ]; then
            _atomic_modify_json "$CONFIG_FILE" "del(.outbounds[] | select(.tag == \"$outbound_tag\"))" || true
            _info "已删除关联的 outbound: $outbound_tag"
        fi
    else
        # === 普通节点：只有 inbound，没有额外的 outbound 和 route ===
        # 主脚本创建的节点通常只包含 inbound，outbound 是全局的（如 direct）
        # 如果有特殊的 outbound（如某些协议的专用配置），也要删除
        
        # 检查是否有基于此 inbound 的 route 规则（通常不应该有，但为了清理干净）
        local has_route=$(jq -e ".route.rules[]? | select(.inbound == \"$tag_to_del\")" "$CONFIG_FILE" 2>/dev/null)
        if [ -n "$has_route" ]; then
            _info "检测到关联的路由规则，正在清理..."
            _atomic_modify_json "$CONFIG_FILE" "del(.route.rules[] | select(.inbound == \"$tag_to_del\"))" || true
        fi
        
        # 注意：不删除任何 outbound，因为普通节点的 outbound 通常是共享的全局 outbound
        # （如 "direct"），删除会影响其他节点
    fi
    # === 清理逻辑结束 ===
    
    _success "节点 ${display_name_to_del} 已删除！"
    _manage_service "restart"
}

_check_config() {
    _info "正在检查 sing-box 配置文件..."
    local result=$(${SINGBOX_BIN} check -c ${CONFIG_FILE})
    if [[ $? -eq 0 ]]; then
        _success "配置文件 (${CONFIG_FILE}) 格式正确。"
    else
        _error "配置文件检查失败:"
        echo "$result"
    fi
}

_modify_port() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warning "当前没有任何节点。"
        return
    fi
    
    _info "--- 修改节点端口 ---"
    
    # 列出所有节点
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local display_names=()
    
    local i=1
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag')
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port')
        
        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")
        
        # 查找显示名称
        local proxy_name_to_find=""
        local proxy_obj_by_port=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}')' ${CLASH_YAML_FILE} | head -n 1)
        if [ -n "$proxy_obj_by_port" ]; then
            proxy_name_to_find=$(echo "$proxy_obj_by_port" | ${YQ_BINARY} eval '.name' -)
        fi
        if [[ -z "$proxy_name_to_find" ]]; then
            proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | grep -i "${type}" | head -n 1)
        fi
        if [[ -z "$proxy_name_to_find" ]]; then
            proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | head -n 1)
        fi
        
        local display_name=${proxy_name_to_find:-$tag}
        display_names+=("$display_name")
        
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${GREEN}${port}${NC}"
        ((i++))
    done < <(jq -c '.inbounds[]' "$CONFIG_FILE")
    
    read -p "请输入要修改端口的节点编号 (输入 0 返回): " num
    
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
    
    _info "当前节点: ${display_name_to_modify} (${type_to_modify})"
    _info "当前端口: ${old_port}"
    
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
    
    # 检查端口是否已被占用
    if jq -e ".inbounds[] | select(.listen_port == $new_port)" "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "端口 $new_port 已被其他节点使用！"
        return
    fi
    
    _info "正在修改端口: ${old_port} -> ${new_port}"
    
    # 1. 修改 config.json
    _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].listen_port = $new_port" || return
    
    # 2. 修改 clash.yaml
    local proxy_name_in_yaml=""
    local proxy_obj_by_port_yaml=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${old_port}')' ${CLASH_YAML_FILE} | head -n 1)
    if [ -n "$proxy_obj_by_port_yaml" ]; then
        proxy_name_in_yaml=$(echo "$proxy_obj_by_port_yaml" | ${YQ_BINARY} eval '.name' -)
    fi
    
    if [ -n "$proxy_name_in_yaml" ]; then
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == "'${proxy_name_in_yaml}'") | .port) = '${new_port}
    fi
    
    # 3. 处理证书文件重命名（Hysteria2, TUIC, AnyTLS）
    if [ "$type_to_modify" == "hysteria2" ] || [ "$type_to_modify" == "tuic" ] || [ "$type_to_modify" == "anytls" ]; then
        local old_cert="${SINGBOX_DIR}/${tag_to_modify}.pem"
        local old_key="${SINGBOX_DIR}/${tag_to_modify}.key"
        
        # 生成新的 tag (基于新端口)
        local new_tag_suffix="$new_port"
        if [ "$type_to_modify" == "hysteria2" ]; then
            local new_tag="hy2-in-${new_tag_suffix}"
        elif [ "$type_to_modify" == "tuic" ]; then
            local new_tag="tuic-in-${new_tag_suffix}"
        else
            local new_tag="anytls-in-${new_tag_suffix}"
        fi
        
        local new_cert="${SINGBOX_DIR}/${new_tag}.pem"
        local new_key="${SINGBOX_DIR}/${new_tag}.key"
        
        # 重命名证书文件
        if [ -f "$old_cert" ] && [ -f "$old_key" ]; then
            mv "$old_cert" "$new_cert"
            mv "$old_key" "$new_key"
            
            # 更新配置中的证书路径
            _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].tls.certificate_path = \"$new_cert\"" || return
            _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].tls.key_path = \"$new_key\"" || return
        fi
        
        # 更新 tag
        _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].tag = \"$new_tag\"" || return
        
        # 更新 metadata.json 中的 key
        if jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
            local meta_content=$(jq ".\"$tag_to_modify\"" "$METADATA_FILE")
            _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_modify\") | . + {\"$new_tag\": $meta_content}" || return
        fi
    fi
    
    _success "端口修改成功: ${old_port} -> ${new_port}"
    _manage_service "restart"
}

# --- 更新管理脚本 ---
_update_script() {
    _info "--- 更新脚本 ---"
    
    if [ "$SCRIPT_UPDATE_URL" == "YOUR_GITHUB_RAW_URL_HERE/singbox.sh" ]; then
        _error "错误：您尚未在脚本中配置 SCRIPT_UPDATE_URL 变量。"
        _warning "请编辑此脚本，找到 SCRIPT_UPDATE_URL 并填入您正确的 GitHub raw 链接。"
        return 1
    fi

    # 更新主脚本
    _info "正在从 GitHub 下载主脚本 (singbox.sh)..."
    local temp_script_path="${SELF_SCRIPT_PATH}.tmp"
    
    if wget -qO "$temp_script_path" "$SCRIPT_UPDATE_URL"; then
        if [ ! -s "$temp_script_path" ]; then
            _error "主脚本下载失败或文件为空！"
            rm -f "$temp_script_path"
            return 1
        fi
        
        chmod +x "$temp_script_path"
        mv "$temp_script_path" "$SELF_SCRIPT_PATH"
        _success "主脚本 (singbox.sh) 更新成功！"
    else
        _error "主脚本下载失败！请检查网络或 GitHub 链接。"
        rm -f "$temp_script_path"
        return 1
    fi
    
    # 需要更新的子脚本列表
    local sub_scripts=("advanced_relay.sh" "parser.sh" "utils.sh")
    
    for script_name in "${sub_scripts[@]}"; do
        # 定义可能的路径
        local paths=("/root/${script_name}" "./${script_name}")
        local updated=false
        
        _info "正在尝试更新子脚本: ${script_name}..."
        
        for script_path in "${paths[@]}"; do
            if [ -f "$script_path" ]; then
                local script_url="${GITHUB_RAW_BASE}/${script_name}"
                local temp_sub_path="${script_path}.tmp"
                
                if wget -qO "$temp_sub_path" "$script_url"; then
                    if [ -s "$temp_sub_path" ]; then
                        chmod +x "$temp_sub_path"
                        mv "$temp_sub_path" "$script_path"
                        _success "子脚本 (${script_name}) 于 ${script_path} 更新成功！"
                        updated=true
                    else
                        rm -f "$temp_sub_path"
                    fi
                else
                    rm -f "$temp_sub_path"
                fi
            fi
        done
        
        if [ "$updated" = false ]; then
            _warning "子脚本 ${script_name} 未在常用路径中找到或下载失败，跳过更新。"
        fi
    done
    
    _success "所有脚本更新操作已完成！"
    _info "请重新运行脚本以加载新版本："
    echo -e "${YELLOW}bash ${SELF_SCRIPT_PATH}${NC}"
    exit 0
}

_update_singbox_core() {
    _info "--- 更新 Sing-box 核心 ---"
    _info "这将下载并覆盖 Sing-box 的最新稳定版。"
    
    # 1. 调用已有的安装函数，它会下载最新版
    _install_sing_box
    
    if [ $? -eq 0 ]; then
        _success "Sing-box 核心更新成功！"
        # 2. 重启主服务
        _info "正在重启 [主] 服务 (sing-box)..."
        _manage_service "restart"
        _success "[主] 服务已重启。"
        # 3. 提醒重启线路机
        _warning "如果您的 [线路机] 服务 (sing-box-relay) 也在本机运行，"
        _warning "请使用 [菜单 10] -> [重启] 来应用核心更新。"
    else
        _error "Sing-box 核心更新失败。"
    fi
}

# --- 进阶功能 (子脚本) ---
_advanced_features() {
    local script_name="advanced_relay.sh"
    # 优先检查 /root 目录 (用户要求)
    local script_path="/root/${script_name}"
    
    # [开发测试兼容] 如果 /root 下没有，但当前目录下有 (比如手动上传了)，则使用当前目录的
    if [ ! -f "$script_path" ] && [ -f "./${script_name}" ]; then
        script_path="./${script_name}"
    fi

    # 如果都不存在，则下载
    if [ ! -f "$script_path" ]; then
        _info "本地未检测到进阶脚本，正在尝试下载..."
        local download_url="${GITHUB_RAW_BASE}/${script_name}"
        
        if wget -qO "$script_path" "$download_url"; then
            chmod +x "$script_path"
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
        # 赋予权限并执行
        chmod +x "$script_path"
        bash "$script_path"
    else
        _error "找不到进阶脚本文件: ${script_path}"
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
        echo "  ║         sing-box 管理脚本 v${SCRIPT_VERSION}        ║"
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
        
        # 获取服务状态
        local service_status="○ 未知"
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
        fi
        
        # 获取 Argo 状态
        local argo_status="${RED}○ 未安装${NC}"
        if [ -f "$CLOUDFLARED_BIN" ]; then
            if pgrep -f "cloudflared" >/dev/null 2>&1; then
                argo_status="${GREEN}● 运行中${NC}"
            else
                argo_status="${YELLOW}○ 已安装 (未运行)${NC}"
            fi
        fi
        
        echo -e "  系统: ${CYAN}${os_info}${NC}  |  模式: ${CYAN}${INIT_SYSTEM}${NC}"
        echo -e "  Sing-box状态: ${service_status}  |  Argo状态: ${argo_status}"
        echo ""
        
        # 节点管理
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${GREEN}[1]${NC} 添加节点          ${GREEN}[2]${NC} Argo 隧道节点"
        echo -e "    ${GREEN}[3]${NC} 查看节点链接      ${GREEN}[4]${NC} 删除节点"
        echo -e "    ${GREEN}[5]${NC} 修改节点端口"
        echo ""
        
        # 服务控制
        echo -e "  ${CYAN}【服务控制】${NC}"
        echo -e "    ${GREEN}[6]${NC} 重启服务          ${GREEN}[7]${NC} 停止服务"
        echo -e "    ${GREEN}[8]${NC} 查看运行状态      ${GREEN}[9]${NC} 查看实时日志"
        echo -e "    ${GREEN}[10]${NC} 定时重启设置"
        echo ""
        
        # 配置与更新
        echo -e "  ${CYAN}【配置与更新】${NC}"
        echo -e "    ${GREEN}[11]${NC} 检查配置文件    ${GREEN}[12]${NC} 更新脚本"
        echo -e "    ${GREEN}[13]${NC} 更新核心        ${RED}[14]${NC} 卸载脚本"
        echo ""
        
        # 进阶功能
        echo -e "  ${CYAN}【进阶功能】${NC}"
        echo -e "    ${GREEN}[15]${NC} 落地/中转/第三方节点导入"
        echo ""
        
        echo -e "  ─────────────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 退出脚本"
        echo ""
        
        read -p "  请输入选项 [0-15]: " choice
 
        case $choice in
            1) _show_add_node_menu ;;
            2) _argo_menu ;;
            3) _view_nodes ;;
            4) _delete_node ;;
            5) _modify_port ;;
            6) _manage_service "restart" ;;
            7) _manage_service "stop" ;;
            8) _manage_service "status" ;;
            9) _view_log ;;
            10) _scheduled_restart_menu ;;
            11) _check_config ;;
            12) _update_script ;;
            13) _update_singbox_core ;;
            14) _uninstall ;; 
            15) _advanced_features ;;
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
        if [ "$INIT_SYSTEM" == "unknown" ]; then
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
    if [ -n "$current_cron" ]; then
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
                    if [ "$INIT_SYSTEM" == "systemd" ]; then
                        systemctl disable --now sing-box-restart.timer 2>/dev/null
                        rm -f /etc/systemd/system/sing-box-restart.timer /etc/systemd/system/sing-box-restart.service
                        systemctl daemon-reload
                    elif [ "$INIT_SYSTEM" == "openrc" ]; then
                        rc-service sing-box-timer stop 2>/dev/null
                        rc-update del sing-box-timer default 2>/dev/null
                        rm -f /etc/init.d/sing-box-timer /usr/local/bin/sb-timer.sh
                    fi
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

# 快速部署模式 - 静默创建3个节点
_quick_deploy() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}     sing-box 快速部署模式${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    
    # 获取公网 IP
    _init_server_ip
    if [ -z "$server_ip" ]; then
        _error "无法获取公网 IP，快速部署终止"
        exit 1
    fi
    _success "服务器 IP: ${server_ip}"
    
    # 生成3个不重复的随机端口
    local ports=()
    while [ ${#ports[@]} -lt 3 ]; do
        local p=$(shuf -i 10000-60000 -n 1)
        # 确保端口不重复
        local duplicate=false
        for existing in "${ports[@]}"; do
            if [ "$existing" -eq "$p" ]; then
                duplicate=true
                break
            fi
        done
        if [ "$duplicate" = false ]; then
            # 确保端口未被占用 (逻辑与系统双重检查)
            if ! jq -e ".inbounds[] | select(.listen_port == $p)" "$CONFIG_FILE" >/dev/null 2>&1 && ! _check_port_occupied "$p"; then
                ports+=("$p")
            fi
        fi
    done
    
    local port_reality=${ports[0]}
    local port_hy2=${ports[1]}
    local port_tuic=${ports[2]}
    
    local sni="www.apple.com"
    local name_prefix="Quick"
    
    # 用于收集分享链接
    local links=()
    
    # IPv6 处理
    local yaml_ip="$server_ip"
    local link_ip="$server_ip"
    [[ "$server_ip" == *":"* ]] && link_ip="[$server_ip]"
    
    _info "正在创建节点..."
    echo ""
    
    # ===== 1. VLESS-Reality =====
    _info "[1/3] 创建 VLESS-Reality 节点..."
    local tag_reality="vless-in-${port_reality}"
    local uuid_reality=$(${SINGBOX_BIN} generate uuid)
    local keypair=$(${SINGBOX_BIN} generate reality-keypair)
    local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local sid=$(${SINGBOX_BIN} generate rand --hex 8)
    local flow="xtls-rprx-vision"
    
    local inbound_reality=$(jq -n --arg t "$tag_reality" --arg p "$port_reality" --arg u "$uuid_reality" --arg f "$flow" --arg sn "$sni" --arg pk "$pk" --arg sid "$sid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":$f}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_reality]"
    
    local meta_reality=$(jq -n --arg pk "$pbk" --arg sid "$sid" '{"publicKey": $pk, "shortId": $sid}')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag_reality\": $meta_reality}"
    
    local proxy_reality=$(jq -n --arg n "${name_prefix}-Reality-${port_reality}" --arg s "$yaml_ip" --arg p "$port_reality" --arg u "$uuid_reality" --arg sn "$sni" --arg pk "$pbk" --arg sid "$sid" --arg f "$flow" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"flow":$f,"tls":true,"servername":$sn,"reality-opts":{"public-key":$pk,"short-id":$sid},"client-fingerprint":"chrome","network":"tcp"}')
    _add_node_to_yaml "$proxy_reality"
    
    local link_reality="vless://${uuid_reality}@${link_ip}:${port_reality}?security=reality&encryption=none&pbk=${pbk}&fp=chrome&type=tcp&flow=${flow}&sni=${sni}&sid=${sid}#$(_url_encode "${name_prefix}-Reality-${port_reality}")"
    links+=("$link_reality")
    _success "  端口: ${port_reality}"
    
    # ===== 2. Hysteria2 =====
    _info "[2/3] 创建 Hysteria2 节点..."
    local tag_hy2="hy2-in-${port_hy2}"
    local password_hy2=$(${SINGBOX_BIN} generate rand --hex 16)
    local cert_hy2="${SINGBOX_DIR}/${tag_hy2}.pem"
    local key_hy2="${SINGBOX_DIR}/${tag_hy2}.key"
    
    _generate_self_signed_cert "$sni" "$cert_hy2" "$key_hy2"
    
    local inbound_hy2=$(jq -n --arg t "$tag_hy2" --arg p "$port_hy2" --arg pw "$password_hy2" --arg cert "$cert_hy2" --arg key "$key_hy2" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_hy2]"
    
    local meta_hy2=$(jq -n '{"up": "500 Mbps", "down": "500 Mbps"}')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag_hy2\": $meta_hy2}"
    
    local proxy_hy2=$(jq -n --arg n "${name_prefix}-Hy2-${port_hy2}" --arg s "$yaml_ip" --arg p "$port_hy2" --arg pw "$password_hy2" --arg sn "$sni" \
        '{"name":$n,"type":"hysteria2","server":$s,"port":($p|tonumber),"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"up":"500 Mbps","down":"500 Mbps"}')
    _add_node_to_yaml "$proxy_hy2"
    
    local link_hy2="hysteria2://${password_hy2}@${link_ip}:${port_hy2}?sni=${sni}&insecure=1#$(_url_encode "${name_prefix}-Hy2-${port_hy2}")"
    links+=("$link_hy2")
    _success "  端口: ${port_hy2}"
    
    # ===== 3. TUIC =====
    _info "[3/3] 创建 TUIC 节点..."
    local tag_tuic="tuic-in-${port_tuic}"
    local uuid_tuic=$(${SINGBOX_BIN} generate uuid)
    local password_tuic=$(${SINGBOX_BIN} generate rand --hex 16)
    local cert_tuic="${SINGBOX_DIR}/${tag_tuic}.pem"
    local key_tuic="${SINGBOX_DIR}/${tag_tuic}.key"
    
    _generate_self_signed_cert "$sni" "$cert_tuic" "$key_tuic"
    
    local inbound_tuic=$(jq -n --arg t "$tag_tuic" --arg p "$port_tuic" --arg u "$uuid_tuic" --arg pw "$password_tuic" --arg cert "$cert_tuic" --arg key "$key_tuic" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_tuic]"
    
    local proxy_tuic=$(jq -n --arg n "${name_prefix}-TUIC-${port_tuic}" --arg s "$yaml_ip" --arg p "$port_tuic" --arg u "$uuid_tuic" --arg pw "$password_tuic" --arg sn "$sni" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"congestion-controller":"bbr","udp-relay-mode":"native"}')
    _add_node_to_yaml "$proxy_tuic"
    
    local link_tuic="tuic://${uuid_tuic}:${password_tuic}@${link_ip}:${port_tuic}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "${name_prefix}-TUIC-${port_tuic}")"
    links+=("$link_tuic")
    _success "  端口: ${port_tuic}"
    
    # 重启服务
    _info "正在启动服务..."
    _manage_service "restart"
    
    # 生成 Base64 订阅
    local all_links=""
    for link in "${links[@]}"; do
        all_links+="${link}\n"
    done
    local base64_sub=$(echo -e "$all_links" | base64 -w 0)
    
    # 输出节点信息
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}     sing-box 快速部署完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "服务器 IP: ${CYAN}${server_ip}${NC}"
    echo ""
    echo -e "${YELLOW}[VLESS-Reality]${NC} 端口: ${port_reality}"
    echo -e "${link_reality}"
    echo ""
    echo -e "${YELLOW}[Hysteria2]${NC} 端口: ${port_hy2}"
    echo -e "${link_hy2}"
    echo ""
    echo -e "${YELLOW}[TUIC]${NC} 端口: ${port_tuic}"
    echo -e "${link_tuic}"
    echo ""
    echo -e "${GREEN}----------------------------------------${NC}"
    echo -e "${YELLOW}Base64 订阅（可直接导入客户端）:${NC}"
    echo -e "${CYAN}${base64_sub}${NC}"
    echo -e "${GREEN}----------------------------------------${NC}"
    echo ""
    echo -e "运行 ${YELLOW}sb${NC} 进入管理菜单"
    echo -e "${GREEN}========================================${NC}"
    
    # 写入 MOTD (SSH 登录显示)
    local motd_file="/etc/motd"
    cat > "$motd_file" << EOF
=====================================
    sing-box 节点信息
=====================================
服务器 IP: ${server_ip}

[VLESS-Reality] 端口: ${port_reality}
${link_reality}

[Hysteria2] 端口: ${port_hy2}
${link_hy2}

[TUIC] 端口: ${port_tuic}
${link_tuic}

-------------------------------------
Base64 订阅:
${base64_sub}
-------------------------------------
运行 sb 进入管理菜单
=====================================
EOF
    _success "节点信息已写入 /etc/motd (SSH登录时自动显示)"
}

# 批量创建节点 (v11.3 深度向导版)
_batch_create_nodes() {
    local input_str="$1"
    if [ -z "$input_str" ]; then
        _info "请输入协议编号（空格或逗号分隔，如: 1,2,5,8）"
        read -p "协议列表: " input_str
    fi
    [ -z "$input_str" ] && return 1

    # 1. 解析协议列表
    local proto_ids=$(echo "$input_str" | tr ',' ' ' | xargs)
    local proto_count=0
    local has_complex=false # 2,3,5,7
    local has_sni_req=false # 1,4,5,6
    local has_ws=false      # 2,3
    local has_hy2=false     # 5
    local has_ss=false      # 7

    local ss_sub_count=0
    for pid in $proto_ids; do
        if [[ "$pid" == "7" ]]; then
            has_ss=true
        else
            ((proto_count++))
        fi
        [[ "$pid" =~ ^(2|3|5|7)$ ]] && has_complex=true
        [[ "$pid" =~ ^(1|4|5|6)$ ]] && has_sni_req=true
        [[ "$pid" =~ ^(2|3)$ ]] && has_ws=true
        [[ "$pid" == "5" ]] && has_hy2=true
    done

    [ $proto_count -eq 0 ] && { _error "未选择任何协议"; return 1; }

    # 2. 引导向导
    _info "--- 批量部署引导向导 ---"
    
    # 2.1 SNI 收集
    local batch_sni="www.apple.com"
    if [ "$has_sni_req" = true ]; then
        read -p "请输入统一伪装域名 (SNI) [默认: $batch_sni]: " input_sni
        batch_sni=${input_sni:-$batch_sni}
    fi

    # 2.2 WS 模式收集
    local ws_mode="direct"
    local batch_ws_domain=""
    local ws_cdn_ports=() # 存储协议索引对应的端口
    local bulk_proto_count=$proto_count
    
    if [ "$has_ws" = true ]; then
        echo "检测到 WS 协议，请输入绑定的真实域名 (用于证书签发与 CDN 指向):"
        read -p "域名: " batch_ws_domain
        [[ -z "$batch_ws_domain" ]] && batch_ws_domain="www.apple.com" # 保底
        
        echo "请选择连接模式:"
        echo " 1) 直连模式 (默认)"
        echo " 2) CDN/优选域名模式"
        read -p "选择 [1-2]: " ws_choice
        if [ "$ws_choice" == "2" ]; then
            ws_mode="cdn"
            _info "CDN 模式下，WS 协议 (2,3) 的端口需独立设置，不计入批量分布端口中。"
            
            # 对每个选中的 WS 协议单独取端口
            local ws_p_idx=0
            local proto_array=($proto_ids)
            for i in "${!proto_array[@]}"; do
                local p=${proto_array[$i]}
                if [[ "$p" == "2" || "$p" == "3" ]]; then
                    while true; do
                        read -p "请输入协议 [$p] (WS+TLS) 的专用回源端口: " p_ws
                        if _check_port_occupied "$p_ws"; then
                            _error "端口 $p_ws 已被占用，请重试。"
                        elif [[ ! "$p_ws" =~ ^[0-9]+$ ]]; then
                            _error "无效端口"; 
                        else
                            ws_cdn_ports[$i]=$p_ws
                            ((bulk_proto_count--))
                            break
                        fi
                    done
                fi
            done
        fi
    fi

    # 2.3 Hy2 专项
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
        echo "选择 Shadowsocks 批量加密方式 (支持多选，如 1,2,3):"
        echo " 1) aes-256-gcm (默认)"
        echo " 2) ss-2022"
        echo " 3) ss-2022-padding"
        read -p "选择 [1-3]: " ss_choice
        ss_variant=${ss_choice:-1}
        # 计算 SS 实际需要的端口数
        local ss_needed=$(echo "$ss_variant" | tr ',' ' ' | wc -w)
        bulk_proto_count=$((bulk_proto_count + ss_needed))
        # 总计数还是要增加，因为 SS 不在 ws_cdn 逻辑里
        proto_count=$((proto_count + ss_needed))
    fi

    # 3. 端口规划
    local ports_list=()
    if [ $bulk_proto_count -gt 0 ]; then
        _info "除 CDN 节点外，共需批量规划 $bulk_proto_count 个端口。"
        while true; do
            read -p "请输入端口号 (范围如 10001-10004 或空格分隔): " p_input
            local current_p_list=()
            if [[ "$p_input" == *"-"* ]]; then
                local start_p=$(echo $p_input | cut -d'-' -f1)
                local end_p=$(echo $p_input | cut -d'-' -f2)
                for ((p=start_p; p<=end_p; p++)); do current_p_list+=($p); done
            else
                current_p_list=($p_input)
            fi
            
            if [ ${#current_p_list[@]} -lt $bulk_proto_count ]; then
                _error "输入端口数量不足（仅 ${#current_p_list[@]} 个），请重新输入。"
            else
                ports_list=("${current_p_list[@]}")
                break
            fi
        done
    fi

    # 4. 执行安装循环
    local idx=0
    local bulk_idx=0
    local proto_array=($proto_ids)
    for i in "${!proto_array[@]}"; do
        local pid=${proto_array[$i]}
        
        if [ "$pid" == "7" ]; then
            local ss_variants=$(echo "$ss_variant" | tr ',' ' ')
            for v in $ss_variants; do
                local current_port=${ports_list[$bulk_idx]}
                _info "正在安装 Shadowsocks (变体 $v) 到端口 $current_port..."
                export BATCH_MODE="true"
                export BATCH_PORT="$current_port"
                export BATCH_SS_VARIANT="$v"
                _add_shadowsocks_menu
                ((bulk_idx++))
            done
        else
            local current_port=""
            if [[ "$ws_mode" == "cdn" && ( "$pid" == "2" || "$pid" == "3" ) ]]; then
                current_port=${ws_cdn_ports[$i]}
                _info "正在安装分发节点 [$pid] 到 CDN 专用端口 $current_port..."
            else
                current_port=${ports_list[$bulk_idx]}
                _info "正在安装协议 [$pid] 到端口 $current_port..."
                ((bulk_idx++))
            fi
            
            export BATCH_MODE="true"
            export BATCH_PORT="$current_port"
            export BATCH_SNI="$batch_sni"
            export BATCH_WS_TLS_DOMAIN="$batch_ws_domain"
            export BATCH_WS_MODE="$ws_mode"
            export BATCH_HY2_OBFS="$hy2_obfs"
            export BATCH_HY2_HOP="$hy2_hop_range"

            case $pid in
                1) _add_vless_reality ;;
                2) _add_vless_ws_tls ;;
                3) _add_trojan_ws_tls ;;
                4) _add_anytls ;;
                5) _add_hysteria2 ;;
                6) _add_tuic ;;
                8) _add_vless_tcp ;;
                9) _add_socks ;;
            esac
        fi
    done

    unset BATCH_MODE BATCH_PORT BATCH_SNI BATCH_WS_MODE BATCH_HY2_OBFS BATCH_HY2_HOP BATCH_SS_VARIANT BATCH_WS_TLS_DOMAIN
    _success "批量创建任务已全部提交。"
    _manage_service restart
}

_show_add_node_menu() {
    local needs_restart=false
    local action_result
    clear
    echo -e "${CYAN}"
    echo '  ╔═══════════════════════════════════════╗'
    echo '  ║          sing-box 添加节点            ║'
    echo '  ╚═══════════════════════════════════════╝'
    echo -e "${NC}"
    echo ""
    
    echo -e "  ${CYAN}【协议选择】${NC}"
    echo -e "    ${GREEN}[1]${NC} VLESS (Vision+REALITY)"
    echo -e "    ${GREEN}[2]${NC} VLESS (WebSocket+TLS)"
    echo -e "    ${GREEN}[3]${NC} Trojan (WebSocket+TLS)"
    echo -e "    ${GREEN}[4]${NC} AnyTLS"
    echo -e "    ${GREEN}[5]${NC} Hysteria2"
    echo -e "    ${GREEN}[6]${NC} TUICv5"
    echo -e "    ${GREEN}[7]${NC} Shadowsocks"
    echo -e "    ${GREEN}[8]${NC} VLESS (TCP)"
    echo -e "    ${GREEN}[9]${NC} SOCKS5"
    echo ""
    
    echo -e "  ${CYAN}【快捷功能】${NC}"
    echo -e "   ${GREEN}[10]${NC} 批量创建节点"
    echo ""
    
    echo -e "  ─────────────────────────────────────────"
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    
    read -p "  请输入选项 [0-10]: " choice

    # 如果输入包含逗号或空格，自动进入批量处理模式
    if [[ "$choice" == *","* ]] || [[ "$choice" == *" "* ]]; then
        _batch_create_nodes "$choice"
        return
    fi

    case $choice in
        1) _add_vless_reality; action_result=$? ;;
        2) _add_vless_ws_tls; action_result=$? ;;
        3) _add_trojan_ws_tls; action_result=$? ;;
        4) _add_anytls; action_result=$? ;;
        5) _add_hysteria2; action_result=$? ;;
        6) _add_tuic; action_result=$? ;;
        7) _add_shadowsocks_menu; action_result=$? ;;
        8) _add_vless_tcp; action_result=$? ;;
        9) _add_socks; action_result=$? ;;
        10) _batch_create_nodes; return ;;
        0) return ;;
        *) _error "无效输入，请重试。" ;;
    esac

    if [ "$action_result" -eq 0 ] 2>/dev/null; then
        needs_restart=true
    fi

    if [ "$needs_restart" = true ]; then
        _info "配置已更新"
        _manage_service "restart"
    fi
}

# --- 脚本入口 ---

main() {
    _check_root
    _detect_init_system
    
    # 强制预创建目录，防止后续 cp/mv 因路径不存在报错 (保底机制)
    mkdir -p "${SINGBOX_DIR}" 2>/dev/null
    
    # 1. 始终检查依赖
    _install_dependencies
    
    # 获取归口后的公网 IP (在依赖检查后执行以确保 curl 可用)
    _init_server_ip

    local first_install=false
    # 2. 检查 sing-box 程序
    if [ ! -f "${SINGBOX_BIN}" ]; then
        _info "检测到 sing-box 未安装..."
        _install_sing_box
        first_install=true
    fi
    
    # 3. 检查配置文件
    if [ ! -f "${CONFIG_FILE}" ] || [ ! -f "${CLASH_YAML_FILE}" ]; then
         _info "检测到主配置文件缺失，正在初始化..."
         _initialize_config_files
    fi

    # 3.1 初始化中转配置 (配置隔离)
    _init_relay_config
    
    # 3.2 [关键修复] 清理主配置文件中的旧版残留
    if _cleanup_legacy_config; then
        _manage_service restart
    fi
    
    # [BUG FIX] 检查并修复旧版服务文件 (使用了 -C 的情况)
    # 因为 metadata.json 也是 json，-C 会错误加载它导致服务失败
    if [ -f "$SERVICE_FILE" ]; then
        local need_update=false
        
        # 检查1: 是否使用了 -C 参数 (旧版目录加载模式)
        if grep -q "\-C " "$SERVICE_FILE"; then
            _warn "检测到旧版服务配置(目录加载模式导致冲突)，正在修复..."
            need_update=true
        fi
        
        # 检查2: OpenRC 是否缺少 command_background (新版必需的设置)
        # 如果没有这个设置，说明是旧版服务文件，需要更新
        if [ "$INIT_SYSTEM" == "openrc" ] && ! grep -q "command_background" "$SERVICE_FILE"; then
            _warn "检测到旧版 OpenRC 服务配置，正在修复以兼容 Alpine..."
            need_update=true
        fi
        
        if [ "$need_update" = true ]; then
            # 强制覆盖旧服务文件
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                 _create_systemd_service
                 systemctl daemon-reload
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                 _create_openrc_service
            fi
            # 标记需要重启
            if systemctl is-active sing-box >/dev/null 2>&1 || rc-service sing-box status >/dev/null 2>&1; then
                _manage_service restart
            fi
            _success "服务配置修复完成。"
        fi
    fi

    # [PATH FIX] 确保 relay.json 存在，防止升级用户启动失败
    if [ ! -s "${SINGBOX_DIR}/relay.json" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
    fi

    # 4. 如果是首次安装，才创建服务和启动
	_create_service_files
	
	# 5. 如果是首次安装，启动服务
    if [ "$first_install" = true ]; then
        _info "首次安装完成！正在启动 sing-box (主服务)..."
        _manage_service "start"
    fi
    
    # 6. 快速部署模式检测
    if [ "$QUICK_DEPLOY_MODE" = true ]; then
        _quick_deploy
        exit 0
    fi
    
    _main_menu
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        -q|--quick-deploy)
            QUICK_DEPLOY_MODE=true
            shift
            ;;
        keepalive)
            _argo_keepalive
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

main

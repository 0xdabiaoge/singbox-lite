#!/bin/bash

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

# [修复] 独立定义 _install_yq，确保子脚本可独立运行
_install_yq() {
    if ! command -v yq &>/dev/null; then
        _info "安装 yq..."
        local arch=$(uname -m)
        case $arch in x86_64|amd64) arch='amd64' ;; aarch64|arm64) arch='arm64' ;; *) arch='amd64' ;; esac
        wget -qO "$YQ_BINARY" "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$arch"
        chmod +x "$YQ_BINARY"
    fi
}

# 核心环境检测 (与主脚本 singbox.sh 保持一致)
_detect_init_system() {
    if [ -f /sbin/openrc-run ] || command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    elif command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
    else
        INIT_SYSTEM="unknown"
    fi
}
[ -z "$INIT_SYSTEM" ] && _detect_init_system

# 公网 IP 获取 (带全局缓存)
server_ip=""
_get_public_ip() {
    [ -n "$server_ip" ] && [ "$server_ip" != "null" ] && { echo "$server_ip"; return; }
    local ip=$(timeout 5 curl -s4 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s4 --max-time 2 ipinfo.io/ip 2>/dev/null)
    [ -z "$ip" ] && ip=$(timeout 5 curl -s6 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s6 --max-time 2 ipinfo.io/ip 2>/dev/null)
    server_ip="$ip"
    echo "$ip"
}

# 端口冲突检测 (与主脚本 singbox.sh 保持一致，区分 TCP/UDP)
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

# IPTables 规则保存
_save_iptables_rules() {
    _info "正在保存 IPTables 规则..."
    if command -v netfilter-persistent &>/dev/null; then
        # Debian/Ubuntu: 使用 netfilter-persistent 统一持久化 (含 v4+v6)
        netfilter-persistent save >/dev/null 2>&1
    else
        # Alpine / 通用方案: 分别保存 v4 和 v6 规则到标准路径
        if command -v iptables-save &>/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
        if command -v ip6tables-save &>/dev/null; then
            mkdir -p /etc/iptables
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
        fi
    fi
    # Alpine OpenRC: 尝试使用 rc-service 保存
    if command -v rc-service &>/dev/null; then
        rc-service iptables save 2>/dev/null
        rc-service ip6tables save 2>/dev/null
    fi
}

# 原子修改 JSON (与主脚本 singbox.sh 保持一致，不静默吞掉 jq 错误)
_atomic_modify_json() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local tmp="${file}.tmp"
    if jq "$filter" "$file" > "$tmp"; then mv "$tmp" "$file"
    else _error "修改JSON失败: $file"; rm -f "$tmp"; return 1; fi
}

# 单个原子修改 YAML
_atomic_modify_yaml() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local tmp="${file}.tmp"
    cp "$file" "$tmp"
    if ${YQ_BINARY} eval "$filter" -i "$file" 2>/dev/null; then
        rm "$tmp"
    else
        _error "修改 YAML 失败: $file"; mv "$tmp" "$file"; return 1
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
    esac
}

# 日志记录函数
_log_operation() {
    local operation="$1"
    local details="$2"
    local LOG_FILE="${RELAY_AUX_DIR}/relay_operations.log"
    [ -d "$RELAY_AUX_DIR" ] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] $operation: $details" >> "$LOG_FILE"
}

# YAML 操作辅助函数
_add_node_to_relay_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    
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
    
    # 将 JSON 写入安全临时文件 (使用 mktemp 避免竞态条件)
    local temp_json=$(mktemp /tmp/relay_node_XXXXXX.json)
    echo "$proxy_json" > "$temp_json"
    
    # 使用环境变量传递 JSON 字符串，确保安全性
    export NODE_JSON="$(cat "$temp_json")"
    ${YQ_BINARY} eval '.proxies += [env(NODE_JSON)]' -i "$RELAY_CLASH_YAML" 2>/dev/null
    
    # 使用环境变量避免名称中特殊字符问题
    export PROXY_NAME="$proxy_name"
    ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "中转节点") | .proxies += [env(PROXY_NAME)] | .proxies |= unique)' -i "$RELAY_CLASH_YAML" 2>/dev/null
    
    # 清理临时文件
    rm -f "$temp_json"
    
    _info "已添加节点到 YAML 配置: ${proxy_name}"
}

_remove_node_from_relay_yaml() {
    local proxy_name="$1"
    # 使用本地定义的全局 YQ_BINARY
    
    if [ ! -f "$YQ_BINARY" ]; then
        return
    fi
    
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        return
    fi
    
    # 删除节点 - 使用环境变量避免特殊字符问题
    export PROXY_NAME="$proxy_name"
    ${YQ_BINARY} eval 'del(.proxies[] | select(.name == env(PROXY_NAME)))' -i "$RELAY_CLASH_YAML" 2>/dev/null
    ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "中转节点") | .proxies |= del(.[] | select(. == env(PROXY_NAME))))' -i "$RELAY_CLASH_YAML" 2>/dev/null
    
    _info "已从 YAML 配置中删除节点: ${proxy_name}"
}


# 初始化辅助目录
_init_relay_dirs() {
    # 确保辅助目录存在
    if [ ! -d "$RELAY_AUX_DIR" ]; then
        mkdir -p "$RELAY_AUX_DIR"
        _info "已创建辅助目录: $RELAY_AUX_DIR"
    fi
    
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
  - name: 中转节点
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,中转节点
EOF
        _info "已初始化 YAML 配置文件: $RELAY_CLASH_YAML"
    fi

    # 确保 relay.json 存在
    if [ ! -f "$RELAY_CONFIG_FILE" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE"
        _info "已初始化中转配置文件: $RELAY_CONFIG_FILE"
    fi
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
        if ! timeout 10 wget -qO "$prod_parser" "$PARSER_URL"; then
             _error "解析脚本下载失败，请检查网络！"
             return 1
        fi
        PARSER_BIN="$prod_parser"
        _success "解析脚本下载成功。"
    fi
    
    # 确保有执行权限
    chmod +x "$PARSER_BIN"
    # 更新全局或局部变量以便后续使用
    _PARSER_PATH="$PARSER_BIN"
}

# --- 2.1 导入第三方节点链接 ---
_import_link_config() {
    _check_parser || return
    local PARSER_BIN="$_PARSER_PATH"

    echo -e "${CYAN}"
    echo '  ╔═══════════════════════════════════════╗'
    echo '  ║   配置为 [中转机] (导入第三方链接)    ║'
    echo '  ╚═══════════════════════════════════════╝'
    echo -e "${NC}"
    echo "支持协议: VLESS-Reality, VLESS-WS， Hy2 (Hysteria2), TUICv5, Shadowsocks, Trojan-WS, AnyTLS"
    echo ""
    read -p "  请输入节点分享链接: " share_link
    
    if [ -z "$share_link" ]; then _error "输入为空。"; return; fi
    
    _info "正在解析链接..."
    local outbound_json=$(bash "$PARSER_BIN" "$share_link")
    
    if [ -z "$outbound_json" ] || echo "$outbound_json" | jq -e '.error' >/dev/null 2>&1; then
        _error "链接解析失败！"
        local err_msg=$(echo "$outbound_json" | jq -r '.error // "未知错误"')
        _error "错误信息: $err_msg"
        return
    fi
    
    local dest_type=$(echo "$outbound_json" | jq -r '.type')
    local dest_addr=$(echo "$outbound_json" | jq -r '.server')
    local dest_port=$(echo "$outbound_json" | jq -r '.server_port')
    
    # [屏蔽逻辑] 检查是否为 SS-2022
    if [ "$dest_type" == "shadowsocks" ]; then
        local dest_method=$(echo "$outbound_json" | jq -r '.method // empty')
        if [[ "$dest_method" == *"2022"* ]]; then
             echo -e "${YELLOW}================================================================${NC}"
             _warn "检测到导入的节点协议为 Shadowsocks-2022 !"
             _warn "由于本机 (中转机) 未进行精确时间同步，连接极大概率会失败 (Time skew)。"
             _warn "建议更换其他协议，或务必确保已执行 chronyd 时间同步。"
             echo -e "${YELLOW}================================================================${NC}"
             read -p "是否仍要继续? (y/N): " continue_choice
             if [[ "$continue_choice" != "y" && "$continue_choice" != "Y" ]]; then
                 return
             fi
        fi
    fi
    
    # 修正 outbound_tag 占位符
    outbound_json=$(echo "$outbound_json" | jq '.tag = "TEMP_TAG"')

    _finalize_relay_setup "$dest_type" "$dest_addr" "$dest_port" "$outbound_json"
}

# 检查依赖 (主脚本已预装绝大部分，此处仅做快速校验)
_check_deps() {
    # [修复] 移除 Bash 数组语法，防止在部分环境（如 Ash/Dash）下闪退
    for cmd in jq openssl wget curl yq; do
        if ! command -v $cmd &>/dev/null; then
            _error "缺少关键依赖: $cmd"
            _warn "请先运行主脚本 [1) 安装环境]。"
            exit 1
        fi
    done
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
        # [安全增强] 使用 AES-256-CBC 加密 Token，防止明文泄露敏感信息
        local passphrase=$(openssl rand -hex 8)
        local encrypted_token=$(echo "$outbound_json" | openssl enc -aes-256-cbc -pbkdf2 -a -A -pass "pass:${passphrase}" 2>/dev/null)
        if [ -n "$encrypted_token" ]; then
            # Token 格式: ENC:<密钥>:<加密内容>  (中转机通过前缀识别加密Token)
            local token_final="ENC:${passphrase}:${encrypted_token}"
            echo -e "\n  ${GREEN}成功！全协议加密 Token 已生成:${NC}"
            echo -e "  ${YELLOW}${token_final}${NC}\n"
        else
            # openssl 加密失败时回退到 Base64 (兼容性保底)
            local token_base64=$(echo "$outbound_json" | base64 | tr -d '\n')
            echo -e "\n  ${GREEN}成功！全协议 Token 已生成 (Base64):${NC}"
            echo -e "  ${YELLOW}${token_base64}${NC}\n"
            _warn "openssl 加密不可用，已回退到 Base64 编码 (明文传输)。"
        fi
        _info "使用说明: 请在中转机上使用 [2] 导入此 Token。"
    else
        _error "Token 生成失败。"
    fi
    
    read -p "  按回车继续..."
}

# --- 通用：完成中转配置 (Inbound + Outbound写入) ---
# 参数: $1=dest_type, $2=dest_addr, $3=dest_port, $4=outbound_json
_finalize_relay_setup() {
    local dest_type="$1"
    local dest_addr="$2"
    local dest_port="$3"
    local outbound_json="$4"
    
    # [核心连通性拦截] 拦截强制启用 Vision 的第三方节点
    if [ "$dest_type" == "vless" ]; then
        local flow_val=$(echo "$outbound_json" | jq -r '.flow // empty')
        if [ "$flow_val" == "xtls-rprx-vision" ]; then
            echo ""
            _error "检测到目标落地节点强制启用了 [xtls-rprx-vision] 流控！"
            _error "根据底层的物理核心限制，跨协议应用层中转无法处理 Vision 流量。"
            _warn  "请按回车键返回主菜单，然后改用端口转发！"
            echo ""
            read -p "  按回车键返回..."
            return 1
        fi
        
        # 对于其它可能遗留的未知 flow 属性，为求安全也一律安全剥离
        outbound_json=$(echo "$outbound_json" | jq 'del(.flow)')
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
    case "$relay_choice" in
        1) relay_type="vless-reality" ;;
        2) relay_type="hysteria2" ;;
        3) relay_type="tuic" ;;
        4) relay_type="anytls" ;;
        *) _error "无效选项"; return ;;
    esac
    
    # --- 配置入口详细信息 ---
    while true; do
        read -p "  请输入本机监听端口 (回车随机): " listen_port
        [[ -z "$listen_port" ]] && listen_port=$(( $(od -An -tu2 -N2 /dev/urandom | tr -d ' ') % 40001 + 10000 ))
        
        if _check_port_occupied "$listen_port"; then
            _error "端口 $listen_port 已被系统占用，请重新输入！"
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
        openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1
        openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${entrance_sni}" >/dev/null 2>&1
    fi

    # 构造路由规则内容 (修复：定义被误删的变量)
    local rule_json=$(jq -n --arg it "$inbound_tag" --arg ot "$outbound_tag" '{"inbound": $it, "outbound": $ot}')
    
    # [作用域修复] 统一获取公网IP，避免在每个分支中重复声明 local server_ip
    local relay_server_ip=$(_get_public_ip)
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
                
                local iptables_available="false"
                if command -v iptables &>/dev/null; then
                    # 探测宿主机是否扣留了 NAT 映射执行权限（部分劣质 LXC/Docker 典型症状）
                    if iptables -t nat -L PREROUTING -n &>/dev/null; then
                        iptables_available="true"
                    fi
                fi
                
                if [ "$iptables_available" == "true" ]; then
                    iptables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $listen_port
                    if command -v ip6tables &>/dev/null && ip6tables -t nat -L PREROUTING -n &>/dev/null; then
                        ip6tables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $listen_port 2>/dev/null
                    fi
                    hop_str="&mport=${port_range}"
                    _info "已注入底层 iptables 极速端口映射: UDP ${port_range} -> ${listen_port}"
                else
                    _warn "环境受限：原生容器 (LXC/Docker) 缺失必需的系统级 iptables NAT 操作权限。"
                    _warn "高级中转为了节点本身的绝对稳定，不支持易崩溃的 JSON 多实例监听平替，现已安全截停并取消本次跳跃设定。"
                    port_range=""
                fi
            else
                _warn "跳跃端口格式错误，已取消该功能。"
                port_range=""
            fi
        fi
        
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg sn "$entrance_sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"server_name":$sn,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')

        link="hysteria2://${password}@${link_ip}:${listen_port}?sni=${entrance_sni}&insecure=1&up=10000&down=10000${hop_str}#$(_url_encode "${node_name}")"
        
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
            
        link="anytls://${password}@${link_ip}:${listen_port}?security=tls&sni=${entrance_sni}&insecure=1&allowInsecure=1&type=tcp#$(_url_encode "${node_name}")"
    fi
    
    # 2. 写入配置到主配置文件
    _info "正在写入配置..."
    
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    if [ ! -f "$CONFIG_FILE" ]; then echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$CONFIG_FILE"; fi
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    if jq -e ".inbounds[] | select(.tag == \"$inbound_tag\")" "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "中转入口 tag \"$inbound_tag\" 已存在！"
        return 1
    fi
    # 合并写入 Inbounds, Outbounds 和 Rules
    local combined_filter=".inbounds += [$inbound_json] | .outbounds = [$outbound_json] + .outbounds"
    if ! jq -e '.route' "$CONFIG_FILE" >/dev/null 2>&1; then
        combined_filter="${combined_filter} | . + {\"route\":{\"rules\":[]}}"
    fi
    combined_filter="${combined_filter} | .route.rules += [$rule_json]"
    
    if ! _atomic_modify_json "$CONFIG_FILE" "$combined_filter"; then
        mv "${CONFIG_FILE}.bak" "$CONFIG_FILE"
        _error "配置写入失败，已回滚"
        return 1
    fi
    
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        mv "${CONFIG_FILE}.bak" "$CONFIG_FILE"
        _error "配置验证失败，已回滚"; return 1
    fi
    
    _success "配置已更新！正在重启服务..."
    _manage_service restart
    _save_iptables_rules
    
    # 3. 存储链接信息与扩展参数清理信息
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local metadata=$(jq -n --arg link "$link" --arg created "$(date '+%Y-%m-%d %H:%M:%S')" --arg relay_type "$relay_type" \
        --arg landing_type "$dest_type" --arg landing_addr "${dest_addr}:${dest_port}" --arg node_name "$node_name" --arg hop "$port_range" \
        '{link: $link, created_at: $created, relay_type: $relay_type, landing_type: $landing_type, landing_addr: $landing_addr, node_name: $node_name} | if $hop != "" then .port_hopping = $hop else . end')
    jq --arg tag "$inbound_tag" --argjson meta "$metadata" '.[$tag] = $meta' "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
    _log_operation "CREATE_RELAY" "Type: $relay_type, Port: $listen_port, Landing: ${dest_type}@${dest_addr}:${dest_port}"
    
    # 4. 添加到中转机专用 YAML 配置 (复用上方已获取的 relay_server_ip)
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
    [ -n "$proxy_json" ] && _add_node_to_relay_yaml "$proxy_json"
    
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
    
    # [安全增强] 智能检测加密Token (ENC:密钥:内容) 或旧版Base64 Token
    if [[ "$token_input" == ENC:* ]]; then
        _info "检测到加密 Token，正在解密..."
        local passphrase=$(echo "$token_input" | cut -d':' -f2)
        local encrypted_data=$(echo "$token_input" | cut -d':' -f3-)
        decoded_json=$(echo "$encrypted_data" | openssl enc -aes-256-cbc -pbkdf2 -d -a -A -pass "pass:${passphrase}" 2>/dev/null)
        if [ -z "$decoded_json" ] || ! echo "$decoded_json" | jq . >/dev/null 2>&1; then
            _error "Token 解密失败！密钥可能不正确。"
            return
        fi
        _success "Token 解密成功。"
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
            _info "正在批量删除..."
            
            # 清理历史可能存在的 iptables 跳跃端口规则
            if [ -f "${RELAY_AUX_DIR}/relay_links.json" ]; then
                jq -r 'to_entries | .[] | select(.value.port_hopping) | "\(.key)|\(.value.port_hopping)"' "${RELAY_AUX_DIR}/relay_links.json" 2>/dev/null | while IFS="|" read -r ptag hop; do
                    local psuffix=$(echo "$ptag" | grep -oE "[0-9]+$")
                    local hstart="${hop%-*}"
                    local hend="${hop#*-}"
                    if command -v iptables &>/dev/null; then iptables -t nat -D PREROUTING -p udp --dport ${hstart}:${hend} -j REDIRECT --to-ports $psuffix 2>/dev/null; fi
                    if command -v ip6tables &>/dev/null; then ip6tables -t nat -D PREROUTING -p udp --dport ${hstart}:${hend} -j REDIRECT --to-ports $psuffix 2>/dev/null; fi
                done
                _save_iptables_rules 2>/dev/null
            fi
            
            # 简化逻辑：直接重置配置文件
            echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE"
            echo '{}' > "${RELAY_AUX_DIR}/relay_links.json"
            rm -f ${RELAY_AUX_DIR}/*.pem ${RELAY_AUX_DIR}/*.key 2>/dev/null
            
            # 清空 YAML
            if [ -f "$RELAY_CLASH_YAML" ] && [ -f "$YQ_BINARY" ]; then
                ${YQ_BINARY} eval '.proxies = []' -i "$RELAY_CLASH_YAML"
                ${YQ_BINARY} eval '.proxy-groups[0].proxies = []' -i "$RELAY_CLASH_YAML"
            fi
             _manage_service restart
             _success "全部中转已清空"
        fi
        return
    fi

    # 验证输入
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        _error "无效序号"
        return
    fi
    
    local selected_rule="${rules_list[$((choice-1))]}"
    local in_tag=$(echo "$selected_rule" | jq -r '.inbound')
    local out_tag=$(echo "$selected_rule" | jq -r '.outbound')
    
    _info "正在删除中转链路: $in_tag -> $out_tag ..."
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$in_tag\")) | del(.outbounds[] | select(.tag == \"$out_tag\")) | del(.route.rules[] | select(.inbound == \"$in_tag\"))"
    
    # 彻底同步清理：如果还有该端口的残留 outbound (防止手动操作产生垃圾)
    local port_suffix=$(echo "$in_tag" | grep -oE "[0-9]+$")
    if [ -n "$port_suffix" ]; then
        _atomic_modify_json "$CONFIG_FILE" "del(.outbounds[] | select(.tag == \"relay-out-$port_suffix\"))" 2>/dev/null
    fi
    
    if [ -f "$LINKS_FILE" ]; then
        local node_name_yaml=$(jq -r --arg t "$in_tag" '.[$t].node_name // empty' "$LINKS_FILE")
        local port_hopping=$(jq -r --arg t "$in_tag" '.[$t].port_hopping // empty' "$LINKS_FILE")
        
        [ -n "$node_name_yaml" ] && _remove_node_from_relay_yaml "$node_name_yaml"
        
        # 将端口跳跃相关的 iptables 规则彻底卸载脱勾
        if [ -n "$port_hopping" ]; then
            local hop_start="${port_hopping%-*}"
            local hop_end="${port_hopping#*-}"
            if command -v iptables &>/dev/null; then
                iptables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port_suffix 2>/dev/null
            fi
            if command -v ip6tables &>/dev/null; then
                ip6tables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port_suffix 2>/dev/null
            fi
            _save_iptables_rules 2>/dev/null
            _info "已卸载绑定的 iptables UDP 端口跳跃范围转发规则 (${port_hopping})"
        fi
        
        _atomic_modify_json "$LINKS_FILE" "del(.\""$in_tag"\")"
    fi
    
    # 清理证书
    rm -f "${RELAY_AUX_DIR}/${in_tag}.pem" "${RELAY_AUX_DIR}/${in_tag}.key"
    
    _success "已移除中转链路 [$in_tag]。"
    _manage_service restart
}

# --- 5. 修改中转路由端口 (功能恢复) ---
_modify_relay_port() {
    echo -e "\n  ${CYAN}【修改中转路由端口】${NC}"
    
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null)' "$CONFIG_FILE" 2>/dev/null)
    
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
    
    while true; do
        read -p "  请输入新的端口号: " new_port
        if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
             _error "无效端口"; continue
        fi
        
        if _check_port_occupied "$new_port"; then
             _error "端口 $new_port 已被系统占用，请重试！"
        else
             break
        fi
    done
    
    _info "正在修改端口..."
    _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$in_tag\") | .listen_port) = ($new_port|tonumber)"
    
    # [修复] 3. 同步更新 relay_links.json 中的链接端口与节点说明
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local old_node_name=""
    local new_node_name=""
    if [ -f "$LINKS_FILE" ]; then
        if jq -e ".\"$in_tag\"" "$LINKS_FILE" >/dev/null 2>&1; then
            old_node_name=$(jq -r ".\"$in_tag\".node_name // \"\"" "$LINKS_FILE")
            local current_link=$(jq -r ".\"$in_tag\".link // \"\"" "$LINKS_FILE")
            
            # 生成新节点说明名字 (替换端口数字)
            new_node_name=$(echo "$old_node_name" | sed "s/${old_port}/${new_port}/g")
            
            # 1. 链接备注与端口同步
            if [ -n "$current_link" ]; then
                local new_link=$(echo "$current_link" | sed "s/${old_port}/${new_port}/g")
                _atomic_modify_json "$LINKS_FILE" ".\"$in_tag\".link = \"$new_link\""
            fi
            
            # 2. 节点说明同步
            if [ -n "$new_node_name" ]; then
                _atomic_modify_json "$LINKS_FILE" ".\"$in_tag\".node_name = \"$new_node_name\""
            fi
        fi
    fi
    
    _info "端口修改已提交，链接元数据已同步更新。"
    
    # 4. 同步更新 YAML 配置文件中的节点名与端口
    local YQ_BINARY="/usr/local/bin/yq"
    if [ -f "$RELAY_CLASH_YAML" ] && [ -f "$YQ_BINARY" ] && [ -n "$old_node_name" ]; then
        _info "正在同步更新 YAML 节点全链路信息..."
        export OLD_RELAY_NAME="$old_node_name"
        export NEW_RELAY_NAME="$new_node_name"
        export NEW_RELAY_PORT="$new_port"
        
        # 1. 改名
        ${YQ_BINARY} eval '(.proxies[] | select(.name == env(OLD_RELAY_NAME)) | .name) = env(NEW_RELAY_NAME)' -i "$RELAY_CLASH_YAML"
        # 2. 改端口
        ${YQ_BINARY} eval '(.proxies[] | select(.name == env(NEW_RELAY_NAME)) | .port) = (env(NEW_RELAY_PORT)|tonumber)' -i "$RELAY_CLASH_YAML"
        # 3. 更新所有分组中的引用
        ${YQ_BINARY} eval '(.proxy-groups[].proxies[] | select(. == env(OLD_RELAY_NAME))) = env(NEW_RELAY_NAME)' -i "$RELAY_CLASH_YAML"
        
        _success "YAML 节点名同步完成: ${old_node_name} -> ${new_node_name}"
    fi

    # 联动更新端口跳跃的 iptables 映射规则 (否则跳跃流量仍被转发到旧端口)
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    if [ -f "$LINKS_FILE" ]; then
        local hop_info=$(jq -r --arg t "$in_tag" '.[$t].port_hopping // empty' "$LINKS_FILE" 2>/dev/null)
        if [ -n "$hop_info" ]; then
            local hop_start="${hop_info%-*}"
            local hop_end="${hop_info#*-}"
            if command -v iptables &>/dev/null && iptables -t nat -L PREROUTING -n &>/dev/null; then
                iptables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $old_port 2>/dev/null
                iptables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $new_port
            fi
            if command -v ip6tables &>/dev/null && ip6tables -t nat -L PREROUTING -n &>/dev/null; then
                ip6tables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $old_port 2>/dev/null
                ip6tables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $new_port 2>/dev/null
            fi
            _info "已将端口跳跃映射从 ${old_port} 联动更新到 ${new_port}"
        fi
    fi

    # 记录操作
    _log_operation "MODIFY_RELAY_PORT" "Tag: $in_tag, Old Port: $old_port, New Port: $new_port"

    _manage_service restart
    _save_iptables_rules
    _success "服务已重启"
    read -p "  按回车键继续..."
}


# ============================================================
# --- 端口转发管理模块 (Port Forwarding) ---
# 智能双引擎方案:
#   引擎A (iptables DNAT): 内核级转发, TCP+UDP 全通, KVM/特权LXC 优先
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

_pf_format_to_destination() {
    local family="$1"
    local ip="$2"
    local port="$3"
    if [ "$family" == "ipv6" ]; then
        echo "[${ip}]:${port}"
    else
        echo "${ip}:${port}"
    fi
}

_pf_can_write_iptables_rule() {
    local bin="$1"
    shift
    command -v "$bin" &>/dev/null || return 1
    "$bin" "$@" &>/dev/null || return 1
    local delete_args=("$@")
    local i
    for ((i=0; i<${#delete_args[@]}; i++)); do
        if [ "${delete_args[$i]}" == "-A" ]; then
            delete_args[$i]="-D"
            break
        fi
    done
    "$bin" "${delete_args[@]}" &>/dev/null
}

_pf_has_ip6tables_nat() {
    command -v ip6tables &>/dev/null && ip6tables -t nat -L PREROUTING -n &>/dev/null 2>&1
}

# 确保元数据文件存在
_pf_ensure_metadata() {
    [ -f "$PF_METADATA_FILE" ] || echo '{}' > "$PF_METADATA_FILE"
}

# 统计端口转发规则数量 (基于元数据)
_pf_count() {
    _pf_ensure_metadata
    jq 'length' "$PF_METADATA_FILE" 2>/dev/null || echo 0
}

# 启用内核 IP 转发 (iptables DNAT 的前提条件)
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
        if [ "$engine" == "iptables" ]; then
            engine_label="${GREEN}iptables${NC}"
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
    local CRON_CMD="*/5 * * * * ${SCRIPT_PATH} pf-dns-refresh >/dev/null 2>&1"
    local CRON_TAG="# pf-dns-auto-refresh"
    
    # 检查是否已安装
    if crontab -l 2>/dev/null | grep -qF "$CRON_TAG"; then
        return 0
    fi
    
    # 添加 cron 任务
    (crontab -l 2>/dev/null | grep -v "$CRON_TAG"; echo "${CRON_CMD} ${CRON_TAG}") | crontab -
    _info "已安装域名动态刷新定时任务 (每 5 分钟检查一次)"
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

    local can_nat_v4="false"
    local can_filter_v4="false"
    if _pf_can_write_iptables_rule iptables -t nat -A PREROUTING -p tcp --dport 65535 -j DNAT --to-destination 127.0.0.1:65535; then
        can_nat_v4="true"
    fi
    if _pf_can_write_iptables_rule iptables -A FORWARD -p tcp --dport 65535 -j ACCEPT; then
        can_filter_v4="true"
    fi

    if [ "$can_nat_v4" == "true" ] && [ "$can_filter_v4" == "true" ]; then
        PF_ENGINE="iptables"
    fi

    case "$PF_ENV_KIND" in
        host|kvm)
            if [ "$PF_ENGINE" == "iptables" ]; then
                PF_ACCESS_HINT="当前环境具备完整 netfilter 权限，将使用内核级 iptables 转发。"
            else
                PF_ACCESS_HINT="当前环境缺少完整 netfilter 权限，将回退到 sing-box 用户态转发。"
            fi
            ;;
        lxc)
            if [ "$PF_ENGINE" == "iptables" ]; then
                PF_ACCESS_HINT="当前 LXC 具备 NET_ADMIN/iptables 能力，将使用内核级 iptables 转发。"
            else
                PF_ACCESS_HINT="当前 LXC 权限受限，将使用 sing-box 用户态转发；TCP/UDP 都可创建。"
            fi
            ;;
        docker|podman)
            PF_PUBLISH_HINT="true"
            if [ "$PF_ENGINE" == "iptables" ]; then
                PF_ACCESS_HINT="当前容器具备宿主级 netfilter 能力，将使用 iptables 转发。"
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

_pf_prepare_iptables_target() {
    local raw_addr="$1"
    local addr="$(_pf_normalize_target_addr "$raw_addr")"

    if _pf_is_ipv4_literal "$addr"; then
        printf 'ipv4\t%s\tfalse\n' "$addr"
        return 0
    fi
    if _pf_is_ipv6_literal "$addr"; then
        _pf_has_ip6tables_nat || return 1
        printf 'ipv6\t%s\tfalse\n' "$addr"
        return 0
    fi

    local resolved=""
    local family=""
    resolved=$(_pf_resolve_domain_family "$addr" "ipv4")
    if [ -n "$resolved" ]; then
        family="ipv4"
    elif _pf_has_ip6tables_nat; then
        resolved=$(_pf_resolve_domain_family "$addr" "ipv6")
        [ -n "$resolved" ] && family="ipv6"
    fi

    [ -z "$resolved" ] && return 1
    printf '%s\t%s\ttrue\n' "$family" "$resolved"
}

_pf_ensure_masquerade() {
    local target_ip="$1"
    local family="${2:-ipv4}"
    local bin="iptables"

    if [ "$family" == "ipv6" ]; then
        bin="ip6tables"
        _pf_has_ip6tables_nat || return 0
    fi

    "$bin" -t nat -A POSTROUTING -d "$target_ip" -j MASQUERADE 2>/dev/null
}

_pf_apply_forward_filter_rules() {
    local op="$1"
    local family="$2"
    local proto="$3"
    local target_ip="$4"
    local target_port="$5"
    local bin="iptables"

    if [ "$family" == "ipv6" ]; then
        bin="ip6tables"
        command -v "$bin" &>/dev/null || return 0
        "$bin" -L FORWARD -n &>/dev/null 2>&1 || return 0
    else
        command -v "$bin" &>/dev/null || return 0
    fi

    "$bin" "$op" FORWARD -p "$proto" -d "$target_ip" --dport "$target_port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    "$bin" "$op" FORWARD -p "$proto" -s "$target_ip" --sport "$target_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
}

_pf_apply_iptables_rules() {
    local action="$1"
    local listen_port="$2"
    local target_ip="$3"
    local target_port="$4"
    local network="$5"
    local family="$6"
    local bin="iptables"
    local rc=0

    if [ "$family" == "ipv6" ]; then
        bin="ip6tables"
        _pf_has_ip6tables_nat || return 1
    fi

    local chain_flag="-A"
    [ "$action" == "delete" ] && chain_flag="-D"
    local to_dest
    to_dest=$(_pf_format_to_destination "$family" "$target_ip" "$target_port")
    local proto
    for proto in tcp udp; do
        if [[ "$network" != "$proto" && "$network" != "tcp+udp" ]]; then
            continue
        fi
        if ! "$bin" -t nat "$chain_flag" PREROUTING -p "$proto" --dport "$listen_port" -j DNAT --to-destination "$to_dest" 2>/dev/null; then
            [ "$action" == "add" ] && rc=1
        fi
        if ! "$bin" -t nat "$chain_flag" OUTPUT -p "$proto" --dport "$listen_port" -j DNAT --to-destination "$to_dest" 2>/dev/null; then
            [ "$action" == "add" ] && rc=1
        fi
        _pf_apply_forward_filter_rules "$chain_flag" "$family" "$proto" "$target_ip" "$target_port"
    done

    if [ "$action" == "add" ]; then
        _pf_ensure_masquerade "$target_ip" "$family"
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

    [ ! -f "$RELAY_CONFIG_FILE" ] && echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE"

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

    jq --arg port "$listen_port" --argjson meta "$meta" '.[$port] = $meta' "$PF_METADATA_FILE" > "${PF_METADATA_FILE}.tmp" \
        && mv "${PF_METADATA_FILE}.tmp" "$PF_METADATA_FILE"
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

    if [ "$PF_ENGINE" == "iptables" ]; then
        _info "=== 添加端口转发规则 (引擎: iptables DNAT) ==="
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
        if _check_port_occupied "$listen_port"; then
            _error "端口 $listen_port 已被系统占用，请换一个"
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
    if [ "$PF_ENGINE" == "iptables" ]; then
        echo -e "  ${CYAN}【信息】已启用内核级 iptables 转发${NC}"
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
    if [ "$PF_ENGINE" == "iptables" ]; then
        local resolved_payload=""
        resolved_payload=$(_pf_prepare_iptables_target "$target_addr")
        if [ $? -ne 0 ] || [ -z "$resolved_payload" ]; then
            _error "目标地址无法解析为可用的 IPv4/IPv6，无法创建 iptables 转发规则"
            read -p "  按回车继续..."; return
        fi
        IFS=$'\t' read -r target_family resolved_ip target_is_domain <<< "$resolved_payload"
        [ "$target_is_domain" == "true" ] && _success "域名已解析: $target_addr -> $resolved_ip (${target_family})"
        _pf_enable_forwarding
        if ! _pf_apply_iptables_rules "add" "$listen_port" "$resolved_ip" "$target_port" "$network" "$target_family"; then
            _error "iptables 规则写入失败"
            read -p "  按回车继续..."; return
        fi
        _save_iptables_rules
    else
        if ! _pf_apply_singbox_rules "add" "$listen_port" "$target_addr" "$target_port" "$network"; then
            _error "配置写入失败"
            read -p "  按回车继续..."; return
        fi
        _manage_service restart
    fi

    _pf_store_metadata "$listen_port" "$PF_ENGINE" "$custom_name" "$target_addr" "$target_port" "$network" "$network_display" "$target_family" "$resolved_ip" "$target_is_domain"

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

    if [ "$sel_engine" == "iptables" ]; then
        _pf_apply_iptables_rules "delete" "$selected_port" "$del_dest" "$sel_tport" "$sel_net" "$sel_family"
        _save_iptables_rules
    else
        _pf_apply_singbox_rules "delete" "$selected_port"
        _manage_service restart
    fi

    jq "del(.\"$selected_port\")" "$PF_METADATA_FILE" > "${PF_METADATA_FILE}.tmp" \
        && mv "${PF_METADATA_FILE}.tmp" "$PF_METADATA_FILE"

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

    local old_resolved=$(jq -r ".\"$selected_port\".resolved_ip // empty" "$PF_METADATA_FILE")
    local old_del_dest="${old_resolved:-$old_addr}"
    local old_family=$(jq -r ".\"$selected_port\".target_family // empty" "$PF_METADATA_FILE")
    [ -z "$old_family" ] && old_family=$(_pf_guess_target_family "$old_del_dest")

    local delete_ok="true"
    if [ "$old_engine" == "iptables" ]; then
        _pf_apply_iptables_rules "delete" "$selected_port" "$old_del_dest" "$old_tport" "$old_net" "$old_family"
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
    if [ "$PF_ENGINE" == "iptables" ]; then
        local resolved_payload=""
        resolved_payload=$(_pf_prepare_iptables_target "$new_addr")
        if [ $? -ne 0 ] || [ -z "$resolved_payload" ]; then
            _error "目标地址无法解析为可用的 IPv4/IPv6，正在恢复旧规则..."
            if [ "$old_engine" == "iptables" ]; then
                _pf_apply_iptables_rules "add" "$selected_port" "$old_del_dest" "$old_tport" "$old_net" "$old_family" >/dev/null 2>&1
                _save_iptables_rules
            else
                _pf_apply_singbox_rules "add" "$selected_port" "$old_addr" "$old_tport" "$old_net" >/dev/null 2>&1 && _manage_service restart >/dev/null 2>&1
            fi
            _error "修改失败，已恢复旧规则"
            read -p "  按回车继续..."; return
        fi
        IFS=$'\t' read -r target_family resolved_ip target_is_domain <<< "$resolved_payload"
        [ "$target_is_domain" == "true" ] && _success "域名已解析: $new_addr -> $resolved_ip (${target_family})"
        if _pf_apply_iptables_rules "add" "$selected_port" "$resolved_ip" "$new_tport" "$new_net" "$target_family"; then
            apply_ok="true"
            _save_iptables_rules
        fi
    else
        if _pf_apply_singbox_rules "add" "$selected_port" "$new_addr" "$new_tport" "$new_net"; then
            if _manage_service restart; then
                apply_ok="true"
            else
                _pf_apply_singbox_rules "delete" "$selected_port" >/dev/null 2>&1
            fi
        fi
    fi

    if [ "$apply_ok" != "true" ]; then
        _error "新规则创建失败，正在恢复旧规则..."
        if [ "$old_engine" == "iptables" ]; then
            _pf_apply_iptables_rules "add" "$selected_port" "$old_del_dest" "$old_tport" "$old_net" "$old_family" >/dev/null 2>&1
            _save_iptables_rules
        else
            _pf_apply_singbox_rules "add" "$selected_port" "$old_addr" "$old_tport" "$old_net" >/dev/null 2>&1 && _manage_service restart >/dev/null 2>&1
        fi
        _error "修改失败，已恢复旧规则"
        read -p "  按回车继续..."; return
    fi

    _pf_store_metadata "$selected_port" "$PF_ENGINE" "$new_name" "$new_addr" "$new_tport" "$new_net" "$new_net_display" "$target_family" "$resolved_ip" "$target_is_domain"

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

    local need_singbox_restart=false
    while IFS=$'\t' read -r port engine addr tport net resolved family; do
        [ -z "$port" ] && continue
        local del_dest="${resolved:-$addr}"
        [ "$del_dest" == "null" ] && del_dest="$addr"
        if [ -z "$family" ] || [ "$family" == "null" ]; then
            family=$(_pf_guess_target_family "$del_dest")
        fi

        if [ "$engine" == "iptables" ]; then
            _pf_apply_iptables_rules "delete" "$port" "$del_dest" "$tport" "$net" "$family"
        else
            _pf_apply_singbox_rules "delete" "$port"
            need_singbox_restart=true
        fi
    done < <(jq -r 'to_entries[] | [.key, .value.engine, .value.target_addr, (.value.target_port|tostring), .value.network, (.value.resolved_ip // "null"), (.value.target_family // "null")] | @tsv' "$PF_METADATA_FILE" 2>/dev/null)

    echo '{}' > "$PF_METADATA_FILE"
    _save_iptables_rules
    if [ "$need_singbox_restart" = true ]; then
        _manage_service restart
    fi

    _success "所有端口转发规则已清空"
    _pf_auto_manage_dns_cron
    read -p "  按回车继续..."
}

_pf_dns_refresh() {
    [ ! -f "$PF_METADATA_FILE" ] && return 0
    local updated=false

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
        _pf_apply_iptables_rules "delete" "$port" "$old_ip" "$tport" "$network" "$family"
        _pf_apply_iptables_rules "add" "$port" "$new_ip" "$tport" "$network" "$family"

        jq --arg p "$port" --arg ip "$new_ip" '.[$p].resolved_ip = $ip' "$PF_METADATA_FILE" > "${PF_METADATA_FILE}.tmp" \
            && mv "${PF_METADATA_FILE}.tmp" "$PF_METADATA_FILE"

        updated=true
    done < <(jq -r 'to_entries[] | select(.value.engine == "iptables" and .value.target_is_domain == true and .value.resolved_ip != null) | [.key, .value.target_addr, .value.resolved_ip, (.value.target_port|tostring), .value.network, (.value.target_family // "ipv4")] | @tsv' "$PF_METADATA_FILE" 2>/dev/null)

    if [ "$updated" = true ]; then
        if command -v iptables-save &>/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
        if command -v ip6tables-save &>/dev/null; then
            mkdir -p /etc/iptables
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
        fi
        logger -t "pf-dns-refresh" "iptables 规则已自动更新"
    fi
}

_pf_auto_manage_dns_cron() {
    [ ! -f "$PF_METADATA_FILE" ] && return 0

    local domain_count
    domain_count=$(jq '[to_entries[] | select(.value.engine == "iptables" and .value.target_is_domain == true and .value.resolved_ip != null)] | length' "$PF_METADATA_FILE" 2>/dev/null || echo 0)
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
        if [ "$engine" == "iptables" ]; then
            echo -e "  ${GREEN}[$i]${NC} 【${name}】:${CYAN}${port}${NC} -> ${CYAN}${addr}:${tport}${NC}  [${YELLOW}${net_display}${NC}]  引擎: ${GREEN}iptables${NC}"
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
    if [ "$cur_engine" == "iptables" ]; then
        echo -e "  当前引擎: ${GREEN}iptables${NC}  ->  切换目标: ${YELLOW}singbox${NC}"
        echo -e "  ${YELLOW}规则: 【${cur_name}】:${selected_port} -> ${cur_addr}:${cur_tport} [${cur_net_display}]${NC}"
        echo ""
        read -p "  确认将此规则从 iptables 切换到 singbox 用户态转发？(y/N): " confirm
        [ "$confirm" != "y" ] && return

        # 删除旧 iptables 规则
        [ -z "$cur_family" ] && cur_family=$(_pf_guess_target_family "$cur_del_dest")
        _pf_apply_iptables_rules "delete" "$selected_port" "$cur_del_dest" "$cur_tport" "$cur_net" "$cur_family"
        _save_iptables_rules

        # 用原始域名/IP 建 singbox 规则（singbox 自己做 DNS 解析）
        if ! _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net"; then
            _pf_apply_iptables_rules "add" "$selected_port" "$cur_del_dest" "$cur_tport" "$cur_net" "$cur_family" >/dev/null 2>&1
            _save_iptables_rules
            _error "切换失败，已恢复旧的 iptables 规则"
            read -p "  按回车继续..."; return
        fi
        if ! _manage_service restart; then
            _pf_apply_singbox_rules "delete" "$selected_port" >/dev/null 2>&1
            _pf_apply_iptables_rules "add" "$selected_port" "$cur_del_dest" "$cur_tport" "$cur_net" "$cur_family" >/dev/null 2>&1
            _save_iptables_rules
            _error "切换失败，已恢复旧的 iptables 规则"
            read -p "  按回车继续..."; return
        fi

        # 更新 metadata：引擎改为 singbox，清除 iptables 专用字段
        jq --arg p "$selected_port" \
            '.[$p].engine = "singbox" | del(.[$p].resolved_ip) | del(.[$p].target_family) | del(.[$p].target_is_domain)' \
            "$PF_METADATA_FILE" > "${PF_METADATA_FILE}.tmp" \
            && mv "${PF_METADATA_FILE}.tmp" "$PF_METADATA_FILE"

        _success "已切换到 singbox 引擎，规则生效！"
        echo -e "  ${YELLOW}注意: singbox 用户态转发 UDP 性能低于 iptables，但兼容性更好（如 QUIC/Hysteria2）${NC}"

    else
        # singbox → iptables
        echo -e "  当前引擎: ${YELLOW}singbox${NC}  ->  切换目标: ${GREEN}iptables${NC}"
        echo -e "  ${YELLOW}规则: 【${cur_name}】:${selected_port} -> ${cur_addr}:${cur_tport} [${cur_net_display}]${NC}"
        echo ""

        # 先检测 iptables 是否可用
        _pf_detect_engine
        if [ "$PF_ENGINE" != "iptables" ]; then
            _error "当前环境无法使用 iptables 引擎（缺少 netfilter 权限），无法切换"
            read -p "  按回车继续..."; return
        fi

        read -p "  确认将此规则从 singbox 切换到 iptables 内核转发？(y/N): " confirm
        [ "$confirm" != "y" ] && return

        # 删除旧 singbox 规则
        if ! _pf_apply_singbox_rules "delete" "$selected_port"; then
            _error "旧的 singbox 规则删除失败，无法切换"
            read -p "  按回车继续..."; return
        fi
        if ! _manage_service restart; then
            _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net" >/dev/null 2>&1
            _manage_service restart >/dev/null 2>&1
            _error "切换失败，已恢复旧的 singbox 规则"
            read -p "  按回车继续..."; return
        fi

        # iptables 需要解析域名拿到 IP
        local new_family=""
        local new_resolved=""
        local new_is_domain="false"
        local resolved_payload=""
        resolved_payload=$(_pf_prepare_iptables_target "$cur_addr")
        if [ $? -ne 0 ] || [ -z "$resolved_payload" ]; then
            _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net" >/dev/null 2>&1
            _manage_service restart >/dev/null 2>&1
            _error "目标地址无法解析为可用的 IPv4/IPv6，已恢复旧的 singbox 规则"
            read -p "  按回车继续..."; return
        fi
        IFS=$'\t' read -r new_family new_resolved new_is_domain <<< "$resolved_payload"
        [ "$new_is_domain" == "true" ] && _success "域名已解析: $cur_addr -> $new_resolved (${new_family})"

        _pf_enable_forwarding
        if ! _pf_apply_iptables_rules "add" "$selected_port" "$new_resolved" "$cur_tport" "$cur_net" "$new_family"; then
            _pf_apply_singbox_rules "add" "$selected_port" "$cur_addr" "$cur_tport" "$cur_net" >/dev/null 2>&1
            _manage_service restart >/dev/null 2>&1
            _error "切换失败，已恢复旧的 singbox 规则"
            read -p "  按回车继续..."; return
        fi
        _save_iptables_rules

        # 更新 metadata：引擎改为 iptables，补充 iptables 专用字段
        local updated_meta
        updated_meta=$(jq --arg p "$selected_port" --arg fam "$new_family" --arg ip "$new_resolved" \
            '.[$p].engine = "iptables" | .[$p].target_family = $fam | .[$p].resolved_ip = $ip' \
            "$PF_METADATA_FILE")
        if [ "$new_is_domain" == "true" ]; then
            updated_meta=$(echo "$updated_meta" | jq --arg p "$selected_port" '.[$p].target_is_domain = true')
        fi
        echo "$updated_meta" > "${PF_METADATA_FILE}.tmp" \
            && mv "${PF_METADATA_FILE}.tmp" "$PF_METADATA_FILE"

        _success "已切换到 iptables 引擎，规则生效！"
    fi

    _pf_auto_manage_dns_cron
    read -p "  按回车继续..."
}

_port_forward_menu() {
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
    _check_deps
    _init_relay_dirs
    _install_yq

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
        echo "  ║                (v15)                  ║"
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
        else
            rc-service "$service_name" status 2>/dev/null | grep -q "started" && service_status="${GREEN}● 运行中${NC}"
        fi

        echo -e "  系统版本: ${CYAN}${os_info}${NC}"
        echo -e "  中转服务: ${service_status} (${service_name})"
        echo ""
        echo -e "  ${CYAN}【基础配置】${NC}"
        echo -e "    ${GREEN}[1]${NC} 落地机：生成全协议 Token"
        echo -e "    ${GREEN}[2]${NC} 中转机：通过 Token 导入规则"
        echo -e "    ${GREEN}[3]${NC} 中转机：通过第三方链接导入"
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
                   echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE"
                   echo '{}' > "${RELAY_AUX_DIR}/relay_links.json"
                   rm -f ${RELAY_AUX_DIR}/*.pem ${RELAY_AUX_DIR}/*.key 2>/dev/null
                   if [ -f "$RELAY_CLASH_YAML" ] && [ -f "$YQ_BINARY" ]; then
                       export PROXY_NAME_DUMMY="DUMMY"
                       ${YQ_BINARY} eval '.proxies = [] | .proxy-groups[0].proxies = []' -i "$RELAY_CLASH_YAML" 2>/dev/null
                   fi
                   _manage_service restart
                   _success "全部中转已清空"
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
        _pf_dns_refresh
        exit 0
        ;;
esac

_menu

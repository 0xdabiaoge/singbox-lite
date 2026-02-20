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

# 核心环境检测
_detect_init_system() {
    if [ -f /etc/openrc/rc.conf ]; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="systemd"
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

# 端口冲突检测
_check_port_occupied() {
    local port=$1
    if command -v netstat &>/dev/null; then
        netstat -tuln | grep -q ":$port "
    elif command -v ss &>/dev/null; then
        ss -tuln | grep -q ":$port "
    else
        lsof -i ":$port" &>/dev/null
    fi
}

# IPTables 规则保存
_save_iptables_rules() {
    _info "正在保存 IPTables 规则..."
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    fi
}

# 原子修改 JSON
_atomic_modify_json() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local tmp="${file}.tmp"
    if jq "$filter" "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        _error "修改 JSON 失败: $file"; rm -f "$tmp"; return 1
    fi
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
    
    # 使用 utils.sh 中定义的全局 YQ_BINARY
    if [ ! -f "$YQ_BINARY" ]; then
        _warn "未找到 yq 工具，跳过 YAML 配置生成"
        return
    fi
    
    # 检查 YAML 文件是否存在
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        _warn "YAML 配置文件不存在，跳过添加"
        return
    fi
    
    # 将 JSON 写入临时文件
    local temp_json="/tmp/relay_node_$$.json"
    echo "$proxy_json" > "$temp_json"
    
    # 使用环境变量传递 JSON 字符串，确保安全性
    export NODE_JSON="$(cat $temp_json)"
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
    # 使用 utils.sh 中定义的全局 YQ_BINARY
    
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
                [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.apple.com" # 极简保底

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
                [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.apple.com"
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
            [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.apple.com"

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
            [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.apple.com"

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
            [ -z "$sni" ] || [ "$sni" == "null" ] && sni="www.apple.com"
            outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg pw "$password" --arg sni "$sni" \
                '{"type":"anytls","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"password":$pw,"tls":{"enabled":true,"server_name":$sni,"insecure":true}}')
            ;;
            
        *)
            _error "暂不支持对协议 [$type] 自动生成 Token。"
            return
            ;;
    esac
    
    if [ -n "$outbound_json" ]; then
        local token_base64=$(echo "$outbound_json" | base64 | tr -d '\n')
        echo -e "\n  ${GREEN}成功！全协议 Token 已生成 (v11.3):${NC}"
        echo -e "  ${YELLOW}${token_base64}${NC}\n"
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
        [[ -z "$listen_port" ]] && listen_port=$(( RANDOM % 40001 + 10000 ))
        
        if _check_port_occupied "$listen_port"; then
            _error "端口 $listen_port 已被系统占用，请重新输入！"
        else
            _info "端口 $listen_port 可用。"
            break
        fi
    done
    
    read -p "  请输入中转机入口 SNI (回车默认 www.apple.com): " entrance_sni
    [[ -z "$entrance_sni" ]] && entrance_sni="www.apple.com"
    
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
             
        local server_ip=$(_get_public_ip)
        link="vless://${uuid}@${server_ip}:${listen_port}?encryption=none&flow=${flow}&security=reality&sni=${entrance_sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#$(_url_encode "${node_name}")"
        
    elif [ "$relay_type" == "hysteria2" ]; then
        local password=$($SINGBOX_BIN generate rand --hex 16)
        
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg sn "$entrance_sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"server_name":$sn,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')

        local server_ip=$(_get_public_ip)
        link="hysteria2://${password}@${server_ip}:${listen_port}?sni=${entrance_sni}&insecure=1&up=10000&down=10000#$(_url_encode "${node_name}")"
        
    elif [ "$relay_type" == "tuic" ]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        local password=$($SINGBOX_BIN generate rand --hex 16)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg pw "$password" --arg sn "$entrance_sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"server_name":$sn,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
            
        local server_ip=$(_get_public_ip)
        link="tuic://${uuid}:${password}@${server_ip}:${listen_port}?sni=${entrance_sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "${node_name}")"
        
    elif [ "$relay_type" == "anytls" ]; then
        local password=$($SINGBOX_BIN generate uuid)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg sn "$entrance_sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"anytls","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"name":"default","password":$pw}],"padding_scheme":["stop=2","0=100-200","1=100-200"],"tls":{"enabled":true,"server_name":$sn,"certificate_path":$cert,"key_path":$key}}')
            
        local server_ip=$(_get_public_ip)
        link="anytls://${password}@${server_ip}:${listen_port}?security=tls&sni=${entrance_sni}&insecure=1&allowInsecure=1&type=tcp#$(_url_encode "${node_name}")"
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
    
    # 3. 存储链接信息
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local metadata=$(jq -n --arg link "$link" --arg created "$(date '+%Y-%m-%d %H:%M:%S')" --arg relay_type "$relay_type" \
        --arg landing_type "$dest_type" --arg landing_addr "${dest_addr}:${dest_port}" --arg node_name "$node_name" \
        '{link: $link, created_at: $created, relay_type: $relay_type, landing_type: $landing_type, landing_addr: $landing_addr, node_name: $node_name}')
    jq --arg tag "$inbound_tag" --argjson meta "$metadata" '.[$tag] = $meta' "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
    _log_operation "CREATE_RELAY" "Type: $relay_type, Port: $listen_port, Landing: ${dest_type}@${dest_addr}:${dest_port}"
    
    # 4. 添加到中转机专用 YAML 配置
    local server_ip=$(_get_public_ip)
    local proxy_json=""
    if [ "$relay_type" == "vless-reality" ]; then
        local uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        local flow=$(echo "$inbound_json" | jq -r '.users[0].flow')
        local pk=$(echo "$inbound_json" | jq -r '.tls.reality.private_key')
        local sid=$(echo "$inbound_json" | jq -r '.tls.reality.short_id[0]')
        local pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$server_ip" --arg p "$listen_port" --arg u "$uuid" --arg sn "$sn" --arg pbk "$pbk" --arg sid "$sid" --arg flow "$flow" \
            '{name:$n,type:"vless",server:$s,port:($p|tonumber),uuid:$u,tls:true,udp:true,network:"tcp",flow:$flow,servername:$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    elif [ "$relay_type" == "hysteria2" ]; then
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$server_ip" --arg p "$listen_port" --arg pw "$password" --arg sn "$sn" \
            '{name:$n,type:"hysteria2",server:$s,port:($p|tonumber),password:$pw,sni:$sn,"skip-cert-verify":true,alpn:["h3"]}')
    elif [ "$relay_type" == "tuic" ]; then
        local uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid')
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$server_ip" --arg p "$listen_port" --arg u "$uuid" --arg pw "$password" --arg sn "$sn" \
            '{name:$n,type:"tuic",server:$s,port:($p|tonumber),uuid:$u,password:$pw,sni:$sn,"skip-cert-verify":true,alpn:["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    elif [ "$relay_type" == "anytls" ]; then
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        proxy_json=$(jq -n --arg n "$node_name" --arg s "$server_ip" --arg p "$listen_port" --arg pw "$password" --arg sn "$sn" \
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
    decoded_json=$(echo "$token_input" | base64 -d 2>/dev/null)
    local decode_status=$?
    if [ $decode_status -ne 0 ] || [ -z "$decoded_json" ] || ! echo "$decoded_json" | jq . >/dev/null 2>&1; then
        _error "Token 无效或无法解码！"
        return
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
        [ -n "$node_name_yaml" ] && _remove_node_from_relay_yaml "$node_name_yaml"
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

    # 记录操作
    _log_operation "MODIFY_RELAY_PORT" "Tag: $in_tag, Old Port: $old_port, New Port: $new_port"

    _manage_service restart
    _save_iptables_rules
    _success "服务已重启"
    read -p "  按回车键继续..."
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
        echo "  ║                (v12)                  ║"
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
        echo -e "  ─────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        read -p "  请输入选项 [0-7]: " choice
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
            0) exit 0 ;;
            *) _error "无效输入"; sleep 1 ;;
        esac
    done
}
_menu

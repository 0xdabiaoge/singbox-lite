#!/bin/bash

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 全局变量 ---
# 主脚本配置路径（落地机和中转机共用）
MAIN_CONFIG_FILE="/usr/local/etc/sing-box/config.json"
MAIN_METADATA_FILE="/usr/local/etc/sing-box/metadata.json"

# 辅助文件目录（用于存储中转机的证书和链接信息）
RELAY_AUX_DIR="/etc/singbox"

SINGBOX_BIN="/usr/local/bin/sing-box"

# --- 辅助函数 ---
_info() { echo -e "${CYAN}[信息] $1${NC}"; }
_success() { echo -e "${GREEN}[成功] $1${NC}"; }
_warn() { echo -e "${YELLOW}[注意] $1${NC}"; }
_error() { echo -e "${RED}[错误] $1${NC}"; }

# 日志记录函数
_log_operation() {
    local operation="$1"
    local details="$2"
    local LOG_FILE="${RELAY_AUX_DIR}/relay_operations.log"
    [ -d "$RELAY_AUX_DIR" ] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] $operation: $details" >> "$LOG_FILE"
}


# 获取公网IP
_get_public_ip() {
    local ip=$(timeout 5 curl -s4 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s4 --max-time 2 ipinfo.io/ip 2>/dev/null)
    if [ -z "$ip" ]; then
        ip=$(timeout 5 curl -s6 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s6 --max-time 2 ipinfo.io/ip 2>/dev/null)
    fi
    if [ -z "$ip" ]; then
        _warn "无法自动获取公网IP"
        read -p "请手动输入服务器IP地址: " ip
        if [ -z "$ip" ]; then
            ip="YOUR_IP"
        fi
    fi
    echo "$ip"
}

# 检查依赖
_check_deps() {
    if ! command -v jq &>/dev/null; then
        _error "缺少 'jq' 工具，请先安装。"
        exit 1
    fi
    
    # 确保辅助目录存在
    if [ ! -d "$RELAY_AUX_DIR" ]; then
        _info "创建辅助目录: $RELAY_AUX_DIR"
        mkdir -p "$RELAY_AUX_DIR"
    fi
}

# --- 1. 落地机配置 (生成 Token) ---
_landing_config() {
    _info "正在读取本机节点配置..."
    
    if [ ! -f "$MAIN_CONFIG_FILE" ]; then
        _error "配置文件不存在: $MAIN_CONFIG_FILE"
        _warn "请先在主菜单中添加节点。"
        return
    fi
    
    # 获取本机IP，用于生成Token中的地址
    local server_ip=$(_get_public_ip)

    # 筛选支持的协议: VLESS-TCP (不含 Reality), Shadowsocks (aes-256-gcm, 2022-blake3-aes-128-gcm)
    local nodes=$(jq -c '.inbounds[] | select(
        (.type=="vless" and (.tls.enabled == false or .tls == null)) or 
        (.type=="shadowsocks" and (.method == "aes-256-gcm" or .method == "2022-blake3-aes-128-gcm"))
    )' "$MAIN_CONFIG_FILE")

    if [ -z "$nodes" ]; then
        _error "未找到符合要求的落地节点协议。"
        _warn "支持列表: VLESS-TCP（无TLS）, Shadowsocks（aes-256-gcm / 2022-blake3-aes-128-gcm）"
        _warn "请先去主菜单 [1) 添加节点] 创建上述类型的节点。"
        return
    fi

    echo "================================================"
    echo "  请选择用作 [落地] 的节点 (将把流量转发到此节点)"
    echo "================================================"
    
    local i=1
    local node_list=()
    
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag')
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port')
        local desc="${tag} (${type}:${port})"
        
        echo -e " ${GREEN}$i)${NC} $desc"
        node_list+=("$node")
        ((i++))
    done <<< "$nodes"
    
    echo " 0) 返回"
    read -p "请输入选项: " choice
    
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        return
    fi
    
    local selected_node=${node_list[$((choice-1))]}
    local tag=$(echo "$selected_node" | jq -r '.tag')
    local type=$(echo "$selected_node" | jq -r '.type')
    local port=$(echo "$selected_node" | jq -r '.listen_port')
    
    # --- 提取字段并构建 Token JSON ---
    local token_json=""
    
    case "$type" in
        "vless")
            local uuid=$(echo "$selected_node" | jq -r '.users[0].uuid')
            # VLESS-TCP (无 TLS，无 Reality)
            token_json=$(jq -n \
                --arg ip "$server_ip" --arg p "$port" --arg u "$uuid" \
                '{type: "vless", addr: $ip, port: $p, uuid: $u}')
            ;;
        "shadowsocks")
            local method=$(echo "$selected_node" | jq -r '.method')
            local pw=$(echo "$selected_node" | jq -r '.password')
            token_json=$(jq -n \
                --arg ip "$server_ip" --arg p "$port" --arg m "$method" --arg pw "$pw" \
                '{type: "shadowsocks", addr: $ip, port: $p, method: $m, password: $pw}')
            ;;
    esac
    
    if [ -n "$token_json" ]; then
        local token_base64=$(echo "$token_json" | base64 | tr -d '\n')
        echo ""
        _success "Token 生成成功！"
        echo -e "${YELLOW}请复制以下 Token 到 [中转机] 使用：${NC}"
        echo "---------------------------------------------------"
        echo "$token_base64"
        echo "---------------------------------------------------"
    else
        _error "Token 生成失败 (未知错误)。"
    fi
    
    read -p "按回车键继续..."
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
    echo "请选择本机的 [中转入口] 协议 (客户端连接此协议):"
    echo " 1) VLESS-Reality"
    echo " 2) Hysteria2"
    echo " 3) TUICv5"
    read -p "请输入选项 [1-3]: " relay_choice
    
    local relay_type=""
    case "$relay_choice" in
        1) relay_type="vless-reality" ;;
        2) relay_type="hysteria2" ;;
        3) relay_type="tuic" ;;
        *) _error "无效选项"; return ;;
    esac
    
    # --- 配置入口详细信息 ---
    read -p "请输入本机监听端口 (回车随机): " listen_port
    [[ -z "$listen_port" ]] && listen_port=$(shuf -i 10000-50000 -n 1)
    
    read -p "请输入伪装域名 SNI (回车默认 www.microsoft.com): " sni
    [[ -z "$sni" ]] && sni="www.microsoft.com"
    
    local default_name="${relay_type}-Relay-${listen_port}"
    read -p "请输入节点名称 (回车: ${default_name}): " node_name
    [[ -z "$node_name" ]] && node_name="$default_name"
    
    # --- 生成配置 ---
    local tag_suffix="${listen_port}"
    local inbound_tag="${relay_type}-in-${tag_suffix}"
    local outbound_tag="relay-out-${tag_suffix}" # 对应的出口
    
    # 更新 outbound_json 中的 tag
    # 注意：传入的 outbound_json 必须是 jq 构造好的对象，我们需要修改它的 tag 字段
    outbound_json=$(echo "$outbound_json" | jq --arg t "$outbound_tag" '.tag = $t')

    # 1. 生成 Inbound (本机入口)
    local inbound_json=""
    
    # 证书处理 (Hy2/Tuic 需要) - 存储在辅助目录
    if [[ "$relay_type" == "hysteria2" || "$relay_type" == "tuic" ]]; then
        local cert_path="${RELAY_AUX_DIR}/${inbound_tag}.pem"
        local key_path="${RELAY_AUX_DIR}/${inbound_tag}.key"
        _info "正在生成自签名证书..."
        openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1
        openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${sni}" >/dev/null 2>&1
    fi
    
    if [ "$relay_type" == "vless-reality" ]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        local keypair=$($SINGBOX_BIN generate reality-keypair)
        local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
        local pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
        local sid=$($SINGBOX_BIN generate rand --hex 8)
        
        # 默认开启 XTLS-Vision 流控
        local flow="xtls-rprx-vision"

        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg f "$flow" --arg sn "$sni" --arg pk "$pk" --arg sid "$sid" \
            '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":$f}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
             
        local server_ip=$(_get_public_ip)
        local link="vless://${uuid}@${server_ip}:${listen_port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#${node_name}"
        
    elif [ "$relay_type" == "hysteria2" ]; then
        local password=$($SINGBOX_BIN generate rand --hex 16)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
            
        local server_ip=$(_get_public_ip)
        local link="hysteria2://${password}@${server_ip}:${listen_port}?sni=${sni}&insecure=1#${node_name}"
        
    elif [ "$relay_type" == "tuic" ]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        local password=$($SINGBOX_BIN generate rand --hex 16)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
            
        local server_ip=$(_get_public_ip)
        local link="tuic://${uuid}:${password}@${server_ip}:${listen_port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#${node_name}"
    fi
    
    # 2. 写入配置到主配置文件
    _info "正在写入配置..."
    
    # 使用主配置文件
    local CONFIG_FILE="$MAIN_CONFIG_FILE"
    
    # 如果配置文件不存在，报错（中转机也应该先安装主脚本）
    if [ ! -f "$CONFIG_FILE" ]; then
        _error "配置文件不存在: $CONFIG_FILE"
        _warn "请先在中转机上执行以下操作："
        echo -e "  ${YELLOW}1.${NC} 下载主脚本到中转机"
        echo -e "  ${YELLOW}2.${NC} 运行主脚本安装 sing-box"
        echo -e "  ${YELLOW}3.${NC} 然后再使用进阶功能配置中转"
        return
    fi
    
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    jq ".inbounds += [$inbound_json]" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    jq ".outbounds = [$outbound_json] + .outbounds" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    local rule_json=$(jq -n --arg it "$inbound_tag" --arg ot "$outbound_tag" '{"inbound": $it, "outbound": $ot}')
    
    if ! jq -e '.route' "$CONFIG_FILE" >/dev/null; then
         jq '. += {"route":{"rules":[]}}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
    if ! jq -e '.route.rules' "$CONFIG_FILE" >/dev/null; then
         jq '.route.rules = []' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
    
    jq ".route.rules += [$rule_json]" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 验证配置文件有效性
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        _error "配置文件格式错误！正在回滚..."
        mv "${CONFIG_FILE}.bak" "$CONFIG_FILE"
        _log_operation "CONFIG_ERROR" "配置验证失败，已回滚"
        return 1
    fi
    
    _success "配置已更新！正在重启服务..."
    
    if [ -f "/etc/init.d/sing-box" ]; then
        rc-service sing-box restart
    else
        systemctl restart sing-box
    fi
    
    # 3. 存储链接信息到辅助目录（增强元数据）
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    if [ ! -f "$LINKS_FILE" ]; then
        echo '{}' > "$LINKS_FILE"
    fi
    
    # 使用 jq 添加或更新链接（包含元数据）
    local metadata=$(jq -n \
        --arg link "$link" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        --arg relay_type "$relay_type" \
        --arg landing_type "$dest_type" \
        --arg landing_addr "${dest_addr}:${dest_port}" \
        --arg node_name "$node_name" \
        '{link: $link, created_at: $created, relay_type: $relay_type, landing_type: $landing_type, landing_addr: $landing_addr, node_name: $node_name}')
    
    jq --arg tag "$inbound_tag" --argjson meta "$metadata" '.[$tag] = $meta' "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
    
    # 记录操作日志
    _log_operation "CREATE_RELAY" "Type: $relay_type, Port: $listen_port, Landing: ${dest_type}@${dest_addr}:${dest_port}"
    
    echo "==================================================="
    _success "中转配置成功！"
    echo -e "中转节点: ${YELLOW}$node_name${NC}"
    echo -e "分享链接: ${CYAN}$link${NC}"
    echo "==================================================="
    
    read -p "按回车键继续..."
}

# --- 2. 中转机配置 (导入 Token) ---
_relay_config() {
    echo "================================================"
    echo "           配置为 [中转机] (导入 Token) "
    echo "================================================"
    echo "请输入来自 [落地机] 的 Token 字符串:"
    read -r token_input
    
    if [ -z "$token_input" ]; then _error "输入为空。"; return; fi
    
    local decoded_json=$(echo "$token_input" | base64 -d 2>/dev/null)
    if [ $? -ne 0 ] || ! echo "$decoded_json" | jq . >/dev/null 2>&1; then
        _error "Token 无效或无法解码！"
        return
    fi
    
    local dest_addr=$(echo "$decoded_json" | jq -r '.addr')
    local dest_port=$(echo "$decoded_json" | jq -r '.port')
    local dest_type=$(echo "$decoded_json" | jq -r '.type')
    
    # 构造 outbound
    local outbound_json=""
    local outbound_tag="TEMP_TAG" # 将在 finalize 中被修正

    if [ "$dest_type" == "vless" ]; then
        local uuid=$(echo "$decoded_json" | jq -r '.uuid')
        outbound_json=$(jq -n --arg t "$outbound_tag" --arg ip "$dest_addr" --arg p "$dest_port" --arg u "$uuid" \
            '{"type":"vless","tag":$t,"server":$ip,"server_port":($p|tonumber),"uuid":$u,"packet_encoding":"xudp","tls":{"enabled":false}}')
    elif [ "$dest_type" == "shadowsocks" ]; then
        local method=$(echo "$decoded_json" | jq -r '.method')
        local password=$(echo "$decoded_json" | jq -r '.password')
        outbound_json=$(jq -n --arg t "$outbound_tag" --arg ip "$dest_addr" --arg p "$dest_port" --arg m "$method" --arg pw "$password" \
            '{"type":"shadowsocks","tag":$t,"server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
    else
        _error "不支持的协议类型: $dest_type"
        _warn "仅支持: VLESS-TCP, Shadowsocks"
        return
    fi
    
    if [ -z "$outbound_json" ]; then _error "Outbound 生成失败"; return; fi

    _finalize_relay_setup "$dest_type" "$dest_addr" "$dest_port" "$outbound_json"
}



# --- 3. 查看中转路由 ---
_view_relays() {
    _info "正在扫描本机配置的中转路由..."
    
    local CONFIG_FILE="$MAIN_CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then _error "配置文件不存在。"; return; fi
    
    # 查找所有 route.rules 中包含 inbound 和 outbound 的规则
    # 假设中转规则是特定的 tag 格式？或者只要有 inbound/outbound 对应即可
    # 我们的生成逻辑：inbound="...-in-PORT", outbound="relay-out-PORT"
    
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null)' "$CONFIG_FILE")
    
    if [ -z "$rules" ]; then
        _warn "当前没有任何中转路由规则。"
        read -p "按回车键继续..."
        return
    fi
    
    echo "==================================================="
    echo "              当前中转节点链接"
    echo "==================================================="
    
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local i=1
    
    while IFS= read -r rule; do
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local out_tag=$(echo "$rule" | jq -r '.outbound')
        
        # 从本地存储文件中查找链接和元数据
        local link=""
        local metadata=""
        local created_at=""
        local landing_info=""
        local landing_type=""
        
        if [ -f "$LINKS_FILE" ]; then
            metadata=$(jq -r --arg t "$in_tag" '.[$t] // empty' "$LINKS_FILE")
            if [ -n "$metadata" ]; then
                # 检查是否为新格式（对象）或旧格式（字符串）
                if echo "$metadata" | jq -e '.link' >/dev/null 2>&1; then
                    # 新格式：包含元数据
                    link=$(echo "$metadata" | jq -r '.link')
                    created_at=$(echo "$metadata" | jq -r '.created_at // "未知"')
                    landing_info=$(echo "$metadata" | jq -r '.landing_addr // "未知"')
                    landing_type=$(echo "$metadata" | jq -r '.landing_type // "未知"')
                else
                    # 旧格式：直接是链接字符串（向后兼容）
                    link="$metadata"
                    created_at="--"
                    landing_info="--"
                    landing_type="--"
                fi
            fi
        fi
        
        if [ -n "$link" ]; then
            # 从 inbound 获取一些基本信息用于display
            local inbound=$(jq -c --arg t "$in_tag" '.inbounds[] | select(.tag == $t)' "$CONFIG_FILE")
            local port=$(echo "$inbound" | jq -r '.listen_port')
            local type=$(echo "$inbound" | jq -r '.type')
            
            echo -e "${CYAN}$i)${NC} [$type] 端口: ${port} -> 落地: ${landing_type}@${landing_info}"
            echo -e "   ${GREEN}创建时间:${NC} $created_at"
            echo -e "   ${YELLOW}链接:${NC} $link"
        else
            _warn "$i) 无法找到链接信息 (标签: $in_tag)"
        fi
        
        ((i++))
    done <<< "$rules"
    
    echo "==================================================="
    read -p "按回车键继续..."
}

# --- 4. 删除中转路由 ---
_delete_relay() {
    _info "准备删除中转路由..."
    
    local CONFIG_FILE="$MAIN_CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then _error "配置文件不存在。"; return; fi
    
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null)' "$CONFIG_FILE")
    
    if [ -z "$rules" ]; then
        _warn "没有可删除的中转路由。"
        read -p "按回车键继续..."
        return
    fi
    
    echo "==================================================="
    echo "              删除中转路由"
    echo "==================================================="
    
    local i=1
    local rule_list=()
    
    while IFS= read -r rule; do
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local out_tag=$(echo "$rule" | jq -r '.outbound')
        local inbound=$(jq -c --arg t "$in_tag" '.inbounds[] | select(.tag == $t)' "$CONFIG_FILE")
        local port="Unknown"
        local type="Unknown"
        if [ -n "$inbound" ]; then
             port=$(echo "$inbound" | jq -r '.listen_port')
             type=$(echo "$inbound" | jq -r '.type')
        fi
        
        echo -e " ${RED}$i)${NC} 端口: ${port} (类型: ${type}) [In: ${in_tag} -> Out: ${out_tag}]"
        rule_list+=("$rule")
        ((i++))
    done <<< "$rules"
    
    echo " 0) 取消"
    echo " A) 删除所有中转路由"
    read -p "请输入要删除的序号: " choice
    
    # 处理批量删除
    if [[ "$choice" == "A" || "$choice" == "a" ]]; then
        echo ""
        _warn "即将删除所有 $((i-1)) 个中转路由！"
        read -p "$(echo -e ${RED})确认删除所有? (yes/N): $(echo -e ${NC})" confirm_all
        if [[ "$confirm_all" == "yes" ]]; then
            _info "正在批量删除所有中转路由..."
            
            # 使用主配置文件
            cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
            
            # 删除所有路由规则
            jq '.route.rules = [.route.rules[] | select(.inbound == null or .outbound == null)]' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            
            # 收集所有中转 inbound 和 outbound 的 tag
            local all_in_tags=$(jq -r '.route.rules[] | select(.inbound != null and .outbound != null) | .inbound' "$CONFIG_FILE" 2>/dev/null || true)
            local all_out_tags=$(jq -r '.route.rules[] | select(.inbound != null and .outbound != null) | .outbound' "$CONFIG_FILE" 2>/dev/null || true)
            
            # 删除所有中转相关的 inbounds 和 outbounds（通过原始备份中的路由规则）
            while IFS= read -r rule; do
                local in_tag=$(echo "$rule" | jq -r '.inbound')
                local out_tag=$(echo "$rule" | jq -r '.outbound')
                jq "del(.inbounds[] | select(.tag == \"$in_tag\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
                jq "del(.outbounds[] | select(.tag == \"$out_tag\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
                rm -f "${RELAY_AUX_DIR}/${in_tag}.pem" "${RELAY_AUX_DIR}/${in_tag}.key"
            done <<< "$rules"
            
            # 清空链接存储
            local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
            echo '{}' > "$LINKS_FILE"
            
            _log_operation "DELETE_ALL_RELAYS" "Deleted all $((i-1)) relay routes"
            
            # 重启服务
            if [ -f "/etc/init.d/sing-box" ]; then
                rc-service sing-box restart
            else
                systemctl restart sing-box
            fi
            
            _success "所有中转路由已删除！"
            read -p "按回车键继续..."
            return
        else
            _info "已取消批量删除"
            return
        fi
    fi
    
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        return
    fi
    
    local selected_rule=${rule_list[$((choice-1))]}
    local in_tag_del=$(echo "$selected_rule" | jq -r '.inbound')
    local out_tag_del=$(echo "$selected_rule" | jq -r '.outbound')
    
    # 添加删除确认
    echo ""
    _warn "即将删除中转路由: ${in_tag_del} -> ${out_tag_del}"
    read -p "$(echo -e ${YELLOW})确认删除? (y/N): $(echo -e ${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "已取消删除"
        return
    fi
    
    _info "正在删除中转路由: ${in_tag_del} -> ${out_tag_del}"
    
    # 修改配置文件
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    # 1. 删除 rule
    jq "del(.route.rules[] | select(.inbound == \"$in_tag_del\" and .outbound == \"$out_tag_del\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 2. 删除 inbound
    jq "del(.inbounds[] | select(.tag == \"$in_tag_del\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 3. 删除 outbound
    jq "del(.outbounds[] | select(.tag == \"$out_tag_del\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 4. 清理证书 (如果有) - 从辅助目录
    rm -f "${RELAY_AUX_DIR}/${in_tag_del}.pem" "${RELAY_AUX_DIR}/${in_tag_del}.key"
    
    # 5. 清理存储的链接
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    if [ -f "$LINKS_FILE" ]; then
        jq --arg t "$in_tag_del" 'del(.[$t])' "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
    fi
    
    # 6. 清理旧备份文件（保留最近3个）
    ls -t ${CONFIG_FILE}.bak* 2>/dev/null | tail -n +4 | xargs -r rm 2>/dev/null
    
    # 记录删除操作
    _log_operation "DELETE_RELAY" "Tag: $in_tag_del, Outbound: $out_tag_del"
    
    _success "删除成功！正在重启服务..."
    
    if [ -f "/etc/init.d/sing-box" ]; then
        rc-service sing-box restart
    else
        systemctl restart sing-box
    fi
    
    _success "服务已重启。"
    read -p "按回车键继续..."
}

# --- 菜单 ---
_advanced_menu() {
    _check_deps
    while true; do
        clear
        echo "========================================"
        echo "       sing-box 进阶功能 (中转/落地)"
        echo "========================================"
        echo " 1) 落地机配置 (VLESS-TCP / Shadowsocks)"
        echo " 2) 中转机配置 (导入 Token)"
        echo " 3) 查看中转节点链接"
        echo " 4) 删除中转路由"
        echo "----------------------------------------"
        echo " 0) 退出"
        echo "========================================"
        read -p "请输入选项: " choice
        
        case $choice in
            1) _landing_config ;;
            2) _relay_config ;;
            3) _view_relays ;;
            4) _delete_relay ;;
            0) exit 0 ;;
            *) echo "无效选择" ;;
        esac
    done
}

_advanced_menu

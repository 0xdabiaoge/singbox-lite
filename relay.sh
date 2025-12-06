#!/bin/bash
# Universal Sing-box Relay Manager
# 保存为: relay.sh

# --- 全局变量 ---
SINGBOX_BIN="/usr/local/bin/sing-box"
CONFIG_DIR="/etc/sing-box"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SERVICE_NAME="sing-box-relay"
SELF_PATH="/root/relay.sh" # 脚本自我复制的目标路径

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 核心工具函数 ---
_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
_error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }
_check_deps() {
    if ! command -v jq &>/dev/null; then
        if [ -f /etc/alpine-release ]; then apk add --no-cache jq curl bash openssl
        elif command -v apt-get &>/dev/null; then apt-get update && apt-get install -y jq curl openssl
        elif command -v yum &>/dev/null; then yum install -y jq curl openssl
        fi
    fi
}
_install_core() {
    if [ -f "$SINGBOX_BIN" ]; then return; fi
    _info "正在安装 Sing-box 核心..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;; aarch64|arm64) arch_tag='arm64' ;;
        *) _error "不支持的架构: $arch" ;;
    esac
    local url=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    wget -qO sing-box.tar.gz "$url" || _error "下载失败"
    tar -xzf sing-box.tar.gz
    mv sing-box-*/sing-box "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf sing-box.tar.gz sing-box-*
}
_ensure_self_persist() {
    # 确保脚本保存在 /root/relay.sh 以便 Option 10 调用
    if [[ "$0" != "$SELF_PATH" ]]; then
        cp "$0" "$SELF_PATH"
        chmod +x "$SELF_PATH"
    fi
}
_reload_service() {
    if command -v systemctl &>/dev/null; then
        systemctl restart "$SERVICE_NAME"
    elif command -v rc-service &>/dev/null; then
        rc-service "$SERVICE_NAME" restart
    else
        $SINGBOX_BIN run -c $CONFIG_FILE > /var/log/sing-box-relay.log 2>&1 &
    fi
    _info "服务已重启"
}

# --- 功能函数 ---

# 1. 解析 Token 并生成配置片段
_parse_token_to_json() {
    local token="$1"
    local inbound_port="$2"
    local inbound_proto="$3" # vless/hy2/tuic
    local sni="$4"
    local tag_suffix="$inbound_port"
    
    local decoded=$(echo "$token" | base64 -d 2>/dev/null)
    if ! echo "$decoded" | jq . >/dev/null 2>&1; then _error "Token 无效"; fi
    
    local l_type=$(echo "$decoded" | jq -r .type)
    local out_tag="out-${tag_suffix}"
    local in_tag="in-${tag_suffix}"
    
    # 构建 Outbound (落地)
    local outbound=$(echo "$decoded" | jq --arg tag "$out_tag" '. + {"tag": $tag}')
    if [[ "$l_type" =~ ^(vless|trojan|hysteria2|tuic)$ ]]; then
         outbound=$(echo "$outbound" | jq '.tls += {"insecure": true}')
    fi
    
    # 构建 Inbound (入口)
    local inbound=""
    local uuid=$($SINGBOX_BIN generate uuid)
    local password=$($SINGBOX_BIN generate rand 16 --hex)
    
    case "$inbound_proto" in
        vless) # Vision + Reality
            local kp=$($SINGBOX_BIN generate reality-keypair)
            local pk=$(echo "$kp" | awk '/PrivateKey/ {print $2}')
            local pub=$(echo "$kp" | awk '/PublicKey/ {print $2}')
            local sid=$($SINGBOX_BIN generate rand 8 --hex)
            inbound=$(jq -n --arg p "$inbound_port" --arg t "$in_tag" --arg u "$uuid" --arg s "$sni" --arg pk "$pk" --arg sid "$sid" \
                '{type:"vless",tag:$t,listen:"::",listen_port:($p|tonumber),users:[{uuid:$u,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$s,reality:{enabled:true,handshake:{server:$s,server_port:443},private_key:$pk,short_id:[$sid]}}}')
            echo "vless://${uuid}@$(curl -s4 icanhazip.com):${inbound_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${sid}&type=tcp#Relay-${inbound_port}" > "/tmp/relay_link_${inbound_port}.txt"
            ;;
        hy2)
            _gen_cert "$sni" "$in_tag"
            inbound=$(jq -n --arg p "$inbound_port" --arg t "$in_tag" --arg pw "$password" --arg c "${CONFIG_DIR}/${in_tag}.pem" --arg k "${CONFIG_DIR}/${in_tag}.key" \
                '{type:"hysteria2",tag:$t,listen:"::",listen_port:($p|tonumber),users:[{password:$pw}],tls:{enabled:true,certificate_path:$c,key_path:$k,alpn:["h3"]}}')
            echo "hysteria2://${password}@$(curl -s4 icanhazip.com):${inbound_port}?sni=${sni}&insecure=1#Relay-${inbound_port}" > "/tmp/relay_link_${inbound_port}.txt"
            ;;
        tuic)
            _gen_cert "$sni" "$in_tag"
            inbound=$(jq -n --arg p "$inbound_port" --arg t "$in_tag" --arg u "$uuid" --arg pw "$password" --arg c "${CONFIG_DIR}/${in_tag}.pem" --arg k "${CONFIG_DIR}/${in_tag}.key" \
                '{type:"tuic",tag:$t,listen:"::",listen_port:($p|tonumber),users:[{uuid:$u,password:$pw}],congestion_control:"bbr",tls:{enabled:true,certificate_path:$c,key_path:$k,alpn:["h3"]}}')
            echo "tuic://${uuid}:${password}@$(curl -s4 icanhazip.com):${inbound_port}?sni=${sni}&alpn=h3&congestion_control=bbr&allow_insecure=1#Relay-${inbound_port}" > "/tmp/relay_link_${inbound_port}.txt"
            ;;
    esac
    
    # 写入 Config
    local rule="{\"inbound\":\"$in_tag\",\"outbound\":\"$out_tag\"}"
    
    # 初始化 Config 如果不存在
    if [ ! -f "$CONFIG_FILE" ]; then
        echo '{"log":{"level":"info"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[]}}' > "$CONFIG_FILE"
    fi
    
    # 原子写入
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq ".inbounds += [$inbound]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".outbounds += [$outbound]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$rule]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

_gen_cert() {
    openssl ecparam -genkey -name prime256v1 -out "${CONFIG_DIR}/$2.key" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "${CONFIG_DIR}/$2.key" -out "${CONFIG_DIR}/$2.pem" -subj "/CN=$1" >/dev/null 2>&1
}

# --- 菜单动作 ---

_add_relay() {
    local token=""
    echo "===================================================="
    echo "步骤 1: 请输入落地机生成的 Token"
    read -p "Token: " token
    [ -z "$token" ] && return
    
    echo "----------------------------------------------------"
    echo "步骤 2: 选择中转入口协议"
    echo "  1) VLESS Vision+Reality (推荐)"
    echo "  2) Hysteria2"
    echo "  3) TUIC v5"
    read -p "选择 [1-3]: " choice
    local proto="vless"
    case "$choice" in 2) proto="hy2";; 3) proto="tuic";; esac
    
    echo "----------------------------------------------------"
    read -p "步骤 3: 监听端口 (留空随机): " port
    [ -z "$port" ] && port=$((RANDOM % 45000 + 10000))
    read -p "步骤 4: 伪装域名 (默认 www.microsoft.com): " sni
    [ -z "$sni" ] && sni="www.microsoft.com"
    
    _info "正在配置..."
    _parse_token_to_json "$token" "$port" "$proto" "$sni"
    _reload_service
    
    echo ""
    _info "添加成功！链接如下："
    cat "/tmp/relay_link_${port}.txt"
    rm -f "/tmp/relay_link_${port}.txt"
    echo ""
    read -p "按回车继续..."
}

_list_relays() {
    clear
    echo "--- 当前中转节点 ---"
    # 简易解析，仅供参考
    jq -r '.inbounds[] | "\(.tag) -> 端口: \(.listen_port) (类型: \(.type))"' "$CONFIG_FILE" 2>/dev/null
    echo ""
    read -p "按回车继续..."
}

_delete_relay() {
    _list_relays
    read -p "请输入要删除的节点 Tag (例如 in-12345): " tag
    if [ -z "$tag" ]; then return; fi
    
    # 查找对应的 outbound tag (通过 port 关联通常是 in-PORT 和 out-PORT)
    local port=$(echo "$tag" | cut -d'-' -f2)
    local out_tag="out-${port}"
    
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq "del(.inbounds[] | select(.tag == \"$tag\"))" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq "del(.outbounds[] | select(.tag == \"$out_tag\"))" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq "del(.route.rules[] | select(.inbound == \"$tag\"))" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    rm -f "${CONFIG_DIR}/${tag}.pem" "${CONFIG_DIR}/${tag}.key"
    _reload_service
    _info "删除完成。"
}

# --- 入口 ---
_init_system() {
    if command -v systemctl &>/dev/null; then
        cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Sing-box Relay
After=network.target
[Service]
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable ${SERVICE_NAME}
    fi
}

main() {
    _check_deps
    _install_core
    mkdir -p "$CONFIG_DIR"
    _ensure_self_persist
    
    # 如果带 token 参数，执行自动安装模式 (Option 9 生成的命令会走到这里)
    if [[ "$1" == "--token" ]]; then
        _init_system
        # 交互式询问入口参数，或者你可以修改这里变为全自动
        # 为了兼容 Option 9 生成的命令：
        echo "===================================================="
        echo "检测到快速部署模式"
        echo "请选择中转入口协议:"
        echo "  1) VLESS Reality"
        echo "  2) Hysteria2"
        echo "  3) TUIC v5"
        read -p "选择 [1-3]: " c
        local p="vless"
        case "$c" in 2) p="hy2";; 3) p="tuic";; esac
        read -p "端口 (留空随机): " pt
        [ -z "$pt" ] && pt=$((RANDOM % 45000 + 10000))
        _parse_token_to_json "$2" "$pt" "$p" "www.microsoft.com"
        _reload_service
        cat "/tmp/relay_link_${pt}.txt"
        rm -f "/tmp/relay_link_${pt}.txt"
        exit 0
    fi

    # 否则进入管理菜单 (Option 10 调用会走到这里)
    while true; do
        clear
        echo "=============================="
        echo "   Sing-box 中转管理脚本"
        echo "=============================="
        echo "  1. 添加中转 (需 Token)"
        echo "  2. 查看列表"
        echo "  3. 删除中转"
        echo "  4. 重启服务"
        echo "  0. 退出"
        echo "=============================="
        read -p "选项: " opt
        case "$opt" in
            1) _add_relay ;;
            2) _list_relays ;;
            3) _delete_relay ;;
            4) _reload_service ;;
            0) exit 0 ;;
        esac
    done
}

main "$@"

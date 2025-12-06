#!/bin/bash
# 通用 Sing-box 中转脚本 (Universal Relay Script)
# 用法: bash <(curl -sL https://.../relay.sh) --token <BASE64_TOKEN>

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 全局变量 ---
SINGBOX_BIN="/usr/local/bin/sing-box"
CONFIG_DIR="/etc/sing-box"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SERVICE_NAME="sing-box-relay"

# --- 依赖检查 ---
_check_deps() {
    if ! command -v jq &>/dev/null; then
        echo -e "${YELLOW}正在安装 jq...${NC}"
        if [ -f /etc/alpine-release ]; then apk add --no-cache jq curl bash openssl
        elif command -v apt-get &>/dev/null; then apt-get update && apt-get install -y jq curl openssl
        elif command -v yum &>/dev/null; then yum install -y jq curl openssl
        fi
    fi
}

# --- 辅助函数 ---
_url_encode() { echo -n "$1" | jq -s -R -r @uri; }
_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
_error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# --- 安装 Sing-box ---
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

# --- 生成自签名证书 ---
_gen_cert() {
    local domain=$1
    local name=$2
    openssl ecparam -genkey -name prime256v1 -out "${CONFIG_DIR}/${name}.key" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "${CONFIG_DIR}/${name}.key" -out "${CONFIG_DIR}/${name}.pem" -subj "/CN=${domain}" >/dev/null 2>&1
}

# --- 主逻辑：解析 Token 并生成配置 ---
_main() {
    local TOKEN=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --token) TOKEN="$2"; shift ;;
            *) shift ;;
        esac
        shift
    done

    if [ -z "$TOKEN" ]; then
        echo "===================================================="
        echo -e "${RED}错误：未提供配置令牌 (--token)${NC}"
        echo "请从落地机脚本获取完整的安装命令。"
        echo "===================================================="
        exit 1
    fi

    _check_deps
    _install_core
    mkdir -p "$CONFIG_DIR"

    # 1. 解码 Token
    local DECODED_JSON=$(echo "$TOKEN" | base64 -d 2>/dev/null)
    if ! echo "$DECODED_JSON" | jq . >/dev/null 2>&1; then
        _error "Token 解析失败，格式无效。"
    fi

    # 2. 提取落地机信息 (Outbound)
    local L_TYPE=$(echo "$DECODED_JSON" | jq -r .type)
    local L_SERVER=$(echo "$DECODED_JSON" | jq -r .server)
    local L_PORT=$(echo "$DECODED_JSON" | jq -r .server_port)
    local L_TAG="relay-out"
    
    _info "检测到落地节点协议: ${YELLOW}${L_TYPE}${NC} -> ${L_SERVER}:${L_PORT}"

    # 3. 构建 Outbound JSON (根据不同协议)
    # 注意：这里我们直接复用 decoded_json 中的大部分字段，但需要调整结构以适应 outbound
    local OUTBOUND_JSON=""
    
    # 基础结构
    local BASE_OUTBOUND=$(echo "$DECODED_JSON" | jq --arg tag "$L_TAG" '. + {"tag": $tag}')
    
    # 针对特定协议的修正 (Sing-box Outbound 结构微调)
    case "$L_TYPE" in
        shadowsocks)
            OUTBOUND_JSON="$BASE_OUTBOUND"
            ;;
        vless|trojan)
            # 确保 TLS 和 Transport 正确
            # 落地机通常是 Server 配置，我们需要转为 Client 配置
            # 这里的 Token 生成器(主脚本) 必须确保传过来的是 Client 兼容的结构
            # 比如: skip-cert-verify 需要在 token 生成时或者这里强制加上
            OUTBOUND_JSON=$(echo "$BASE_OUTBOUND" | jq '.tls += {"insecure": true}')
            ;;
        hysteria2|tuic)
            OUTBOUND_JSON=$(echo "$BASE_OUTBOUND" | jq '.tls += {"insecure": true}')
            ;;
        *)
            _error "暂不支持的中转落地协议: $L_TYPE"
            ;;
    esac

    # 4. 配置中转机入口 (Inbound)
    echo "===================================================="
    echo "请选择 [中转机] 的入口协议 (客户端连接到本机的协议):"
    echo "  1) VLESS Vision + Reality (推荐)"
    echo "  2) Hysteria2"
    echo "  3) TUIC v5"
    echo "===================================================="
    read -p "请选择 [1-3]: " IN_CHOICE

    local INBOUND_JSON=""
    local LISTEN_PORT
    read -p "请输入中转监听端口 (留空随机): " LISTEN_PORT
    [ -z "$LISTEN_PORT" ] && LISTEN_PORT=$((RANDOM % 45000 + 10000))
    
    local UUID=$($SINGBOX_BIN generate uuid)
    local PASSWORD=$($SINGBOX_BIN generate rand 16 --hex)
    local SNI="www.microsoft.com"
    local LINK=""

    case "$IN_CHOICE" in
        1) # VLESS Reality
            local KP=$($SINGBOX_BIN generate reality-keypair)
            local PK=$(echo "$KP" | awk '/PrivateKey/ {print $2}')
            local PUB=$(echo "$KP" | awk '/PublicKey/ {print $2}')
            local SID=$($SINGBOX_BIN generate rand 8 --hex)
            
            INBOUND_JSON=$(jq -n \
                --argport "$LISTEN_PORT" --arg uuid "$UUID" --arg pk "$PK" --arg pub "$PUB" --arg sid "$SID" --arg sni "$SNI" \
                '{
                    "type": "vless", "tag": "in-relay", "listen": "::", "listen_port": ($argport|tonumber),
                    "users": [{"uuid": $uuid, "flow": "xtls-rprx-vision"}],
                    "tls": {
                        "enabled": true, "server_name": $sni,
                        "reality": {"enabled": true, "handshake": {"server": $sni, "server_port": 443}, "private_key": $pk, "short_id": [$sid]}
                    }
                }')
             LINK="vless://${UUID}@$(curl -s4 icanhazip.com):${LISTEN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp&headerType=none#Relay-VLESS"
             ;;
        2) # Hysteria2
            _gen_cert "$SNI" "hy2"
            INBOUND_JSON=$(jq -n \
                --argport "$LISTEN_PORT" --arg pw "$PASSWORD" --arg cert "${CONFIG_DIR}/hy2.pem" --arg key "${CONFIG_DIR}/hy2.key" \
                '{
                    "type": "hysteria2", "tag": "in-relay", "listen": "::", "listen_port": ($argport|tonumber),
                    "users": [{"password": $pw}],
                    "tls": {"enabled": true, "certificate_path": $cert, "key_path": $key, "alpn": ["h3"]}
                }')
            LINK="hysteria2://${PASSWORD}@$(curl -s4 icanhazip.com):${LISTEN_PORT}?sni=${SNI}&insecure=1#Relay-Hy2"
            ;;
        3) # TUIC
            _gen_cert "$SNI" "tuic"
            INBOUND_JSON=$(jq -n \
                --argport "$LISTEN_PORT" --arg uuid "$UUID" --arg pw "$PASSWORD" --arg cert "${CONFIG_DIR}/tuic.pem" --arg key "${CONFIG_DIR}/tuic.key" \
                '{
                    "type": "tuic", "tag": "in-relay", "listen": "::", "listen_port": ($argport|tonumber),
                    "users": [{"uuid": $uuid, "password": $pw}],
                    "congestion_control": "bbr",
                    "tls": {"enabled": true, "certificate_path": $cert, "key_path": $key, "alpn": ["h3"]}
                }')
            LINK="tuic://${UUID}:${PASSWORD}@$(curl -s4 icanhazip.com):${LISTEN_PORT}?sni=${SNI}&alpn=h3&congestion_control=bbr&allow_insecure=1#Relay-TUIC"
            ;;
        *) _error "无效选择" ;;
    esac

    # 5. 生成最终 Config
    cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [ $INBOUND_JSON ],
  "outbounds": [ $OUTBOUND_JSON, { "type": "direct", "tag": "direct" } ],
  "route": { "rules": [ { "inbound": "in-relay", "outbound": "relay-out" } ] }
}
EOF

    # 6. 启动服务
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
        systemctl daemon-reload && systemctl enable ${SERVICE_NAME} && systemctl restart ${SERVICE_NAME}
    else
        # 简单 OpenRC 支持
        $SINGBOX_BIN run -c $CONFIG_FILE > /var/log/sing-box-relay.log 2>&1 &
    fi

    echo ""
    _info "✅ 中转服务已部署！"
    echo -e "🔗 中转链接: ${YELLOW}${LINK}${NC}"
    echo "===================================================="
}

_main "$@"
#!/bin/bash
# sing-box-alpine-final.sh
# An ultra-streamlined script for Alpine Linux.
# Version: 5.4
# Author: Gemini
# Features:
# - VLESS (TCP/REALITY), Hysteria2, TUICv5, Shadowsocks, SOCKS5.
# - Uses OFFICIAL sing-box binary from GitHub.
# - Uses self-signed certificates (no domain needed).
# - Auto-generates and manages a full Clash Meta compatible YAML config based on user template.
# - Full node management (add/delete with YAML sync).
# - Self-destructing uninstall.

# --- 全局变量和样式 ---
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'
CONFIG_FILE="/usr/local/etc/sing-box/config.json"
YAML_FILE="/usr/local/etc/sing-box/clash.yaml"

# --- Alpine/系统兼容性函数 ---

function check_and_install_deps() {
    if [ ! -f /etc/alpine-release ]; then
        echo -e "${RED}警告: 此脚本专为 Alpine Linux 设计。${NC}"
    fi
    echo "正在检查并安装所需依赖 (curl, jq, openssl)..."
    local pkgs_to_install=""
    local required_pkgs="curl jq openssl"
    for pkg in $required_pkgs; do
        if ! apk -e info "$pkg" >/dev/null 2>&1; then
            pkgs_to_install="$pkgs_to_install $pkg"
        fi
    done
    if [ -n "$pkgs_to_install" ]; then
        echo "正在安装缺失的依赖: $pkgs_to_install"
        apk update
        if ! apk add $pkgs_to_install; then
            echo -e "${RED}依赖安装失败，请手动执行 'apk add $pkgs_to_install' 后重试。${NC}"
            exit 1
        fi
    else
        echo "所有依赖均已满足。"
    fi
}

function configure_openrc_service() {
    echo "正在配置 sing-box OpenRC 启动服务..."
    cat > "/etc/init.d/sing-box" <<EOF
#!/sbin/openrc-run
description="sing-box service"
supervisor=supervise-daemon
name="sing-box"
command="/usr/local/bin/sing-box"
command_args="run -c ${CONFIG_FILE}"
command_user="root"
pidfile="/run/\${RC_SVCNAME}.pid"
depend() {
    need net
    after firewall
}
EOF
    chmod +x "/etc/init.d/sing-box"
    echo "OpenRC 服务配置完成。"
}

function manage_service() {
    local action="$1"
    if [ -f /etc/init.d/sing-box ]; then
        rc-service sing-box "$action"
    else
        echo -e "${RED}服务文件不存在，请先安装。${NC}"
    fi
}

# --- 核心辅助函数 ---

function get_local_ip() {
    ip_v4=$(curl -s4 --max-time 2 icanhazip.com)
    ip_v6=$(curl -s6 --max-time 2 icanhazip.com)
    if [[ -z "$ip_v4" && -z "$ip_v6" ]]; then
        echo -e "${RED}无法获取本机IP地址！${NC}"
        exit 1
    fi
    server_ip=${ip_v4:-$ip_v6}
}

function install_sing_box() {
    echo "正在从官方源安装最新稳定版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) echo -e "${RED}不支持的架构：$arch${NC}"; exit 1 ;;
    esac
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    if [ -z "$download_url" ]; then
        echo -e "${RED}无法从 GitHub API 获取 sing-box 下载链接。${NC}"
        exit 1
    fi
    echo "下载链接: $download_url"
    if ! wget -qO sing-box.tar.gz "$download_url"; then
        echo -e "${RED}下载失败!${NC}"; exit 1
    fi
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    mv "$temp_dir/sing-box-"*"-linux-${arch_tag}/sing-box" /usr/local/bin/
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x /usr/local/bin/sing-box
    echo "sing-box 安装成功。"
}

function initialize_config_files() {
    mkdir -p /usr/local/etc/sing-box
    if [ ! -f "$CONFIG_FILE" ] || ! jq . "$CONFIG_FILE" >/dev/null 2>&1; then
        echo '{
            "log": {"level": "info", "timestamp": true},
            "inbounds": [],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }' > "$CONFIG_FILE"
    fi
    if [ ! -f "$YAML_FILE" ]; then
        echo "正在根据模板创建全新的 clash.yaml 配置文件..."
        cat > "$YAML_FILE" << 'EOF'
mixed-port: 7890
allow-lan: true
bind-address: "*"
find-process-mode: strict
mode: rule
unified-delay: false
tcp-concurrent: true
log-level: debug
ipv6: true
global-client-fingerprint: chrome
external-controller: 127.0.0.1:9090
external-ui: ui
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
tun:
  enable: false
  stack: mixed
  dns-hijack:
    - 0.0.0.0:53
  auto-detect-interface: true
  auto-route: true
  auto-redirect: true
  mtu: 1500
profile:
  store-selected: false
  store-fake-ip: true
sniffer:
  enable: true
  override-destination: false
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "+.push.apple.com"
dns:
  enable: true
  prefer-h3: false
  respect-rules: true
  listen: 0.0.0.0:53
  ipv6: true
  default-nameserver:
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
    - 1.1.1.1
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: blacklist
  fake-ip-filter:
    - "*"
    - "+.lan"
    - "+.local"
  nameserver-policy:
    "rule-set:cn_domain,private_domain":
      - https://120.53.53.53/dns-query
      - https://223.5.5.5/dns-query
    "rule-set:category-ads-all":
      - rcode://success
    "rule-set:geolocation-!cn":
      - "https://dns.cloudflare.com/dns-query"
      - "https://dns.google/dns-query"
  nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
    - https://cloudflare-dns.com/dns-query
  proxy-server-nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query

proxies:

proxy-groups:
  - name: Proxy
    type: select
    proxies:

rules:
  - RULE-SET,private_ip,DIRECT,no-resolve
  - RULE-SET,category-ads-all,REJECT
  - RULE-SET,cn_domain,DIRECT
  - RULE-SET,geolocation-!cn,Proxy
  - RULE-SET,cn_ip,DIRECT
  - MATCH,Proxy

rule-anchor:
  ip: &ip {type: http, interval: 86400, behavior: ipcidr, format: mrs}
  domain: &domain {type: http, interval: 86400, behavior: domain, format: mrs}
rule-providers:
  private_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs"
  cn_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
  geolocation-!cn:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs"
  category-ads-all:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs"
  private_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs"
  cn_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
EOF
    fi
}

function generate_self_signed_cert() {
    local cert_path="/usr/local/etc/sing-box/cert.pem"
    local key_path="/usr/local/etc/sing-box/private.key"
    if [ -f "$cert_path" ] && [ -f "$key_path" ]; then
        echo "检测到已存在的自签名证书，将继续使用。"
        return
    fi
    echo "正在生成自签名证书 (CN=www.microsoft.com)..."
    openssl ecparam -genkey -name prime256v1 -out "$key_path"
    openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=www.microsoft.com"
    echo "自签名证书生成成功。"
}

function get_listen_port() {
    while true; do
        read -p "请输入监听端口 : " listen_port
        if [[ "$listen_port" =~ ^[0-9]+$ && "$listen_port" -ge 1 && "$listen_port" -le 65535 ]]; then
            break
        else
            echo -e "${RED}请输入一个 1-65535 之间的有效端口号。${NC}"
        fi
    done
}
function get_uuid() {
    read -p "请输入 UUID (默认随机): " uuid
    uuid=${uuid:-$(sing-box generate uuid)}
}
function get_password() {
    read -p "请输入密码 (默认随机): " password
    password=${password:-$(sing-box generate rand --hex 16)}
}

# --- YAML 配置生成 (v5.4 - FIX) ---
function append_yaml_config() {
    local node_type=$1
    local proxy_name=""
    local proxy_block=""

    case $node_type in
        "vless-tcp")
            local port=$2 uuid=$3
            proxy_name="vless-tcp-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: vless
    server: ${server_ip}
    port: ${port}
    uuid: ${uuid}
    network: tcp
    udp: true
    tls: false
EOF
)
            ;;
        "vless-reality")
            local port=$2 uuid=$3 server_name=$4 public_key=$5 short_id=$6
            proxy_name="vless-reality-vision-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: vless
    server: ${server_ip}
    port: ${port}
    uuid: ${uuid}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${server_name}
    reality-opts:
      public-key: ${public_key}
      short-id: ${short_id}
EOF
)
            ;;
        "hysteria2")
            local port=$2 password=$3
            proxy_name="hysteria2-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: hysteria2
    server: ${server_ip}
    port: ${port}
    password: ${password}
    alpn:
      - h3
    sni: www.microsoft.com
    skip-cert-verify: true
EOF
)
            ;;
        "tuic")
            local port=$2 uuid=$3 password=$4
            proxy_name="tuic-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    server: ${server_ip}
    port: ${port}
    type: tuic
    uuid: ${uuid}
    password: ${password}
    sni: www.microsoft.com
    alpn: [h3]
    udp-relay-mode: native
    skip-cert-verify: true
    congestion-controller: bbr
EOF
)
            ;;
        "shadowsocks")
            local port=$2 method=$3 password=$4
            proxy_name="ss-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: ss
    server: ${server_ip}
    port: ${port}
    cipher: ${method}
    password: ${password}
EOF
)
            ;;
        "socks")
            local port=$2 username=$3 password=$4
            proxy_name="socks-${port}"
            proxy_block=$(cat <<EOF
  - name: ${proxy_name}
    type: socks5
    server: ${server_ip}
    port: ${port}
    username: ${username}
    password: ${password}
EOF
)
            ;;
    esac
    
    # 使用 awk 将新的 proxy_block 插入到 `proxies:` 关键字下面
    awk -v block="$proxy_block" '1; /^proxies:$/ {print block}' "$YAML_FILE" > "${YAML_FILE}.tmp" && mv "${YAML_FILE}.tmp" "$YAML_FILE"

    # 将 proxy_name 插入到 Proxy 组的 proxies 列表中
    local line_num=$(awk '/- name: Proxy/,/proxies:/ {if (/proxies:/) print NR}' "$YAML_FILE" | tail -n 1)
    if [ -n "$line_num" ]; then
        sed -i "${line_num}a\\      - ${proxy_name}" "$YAML_FILE"
    fi
}

# --- 节点搭建函数 ---

function vless_tcp_install() {
    echo "--- 正在配置 VLESS (TCP) 节点 ---"
    get_listen_port
    get_uuid
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg uuid "$uuid" \
        '{"type": "vless", "tag": "vless-tcp-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"uuid": $uuid}], "tls": {"enabled": false}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "vless-tcp" "$listen_port" "$uuid"
    echo -e "${CYAN}VLESS (TCP) 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, UUID: $uuid"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function vless_reality_install() {
    echo "--- 正在配置 VLESS (REALITY) 节点 ---"
    get_listen_port
    get_uuid
    read -p "请输入伪装域名 (默认 www.microsoft.com): " server_name
    server_name=${server_name:-"www.microsoft.com"}
    local keypair=$(sing-box generate reality-keypair)
    local private_key=$(echo "$keypair" | grep PrivateKey | awk '{print $2}')
    local public_key=$(echo "$keypair" | grep PublicKey | awk '{print $2}')
    local short_id=$(sing-box generate rand --hex 8)
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg uuid "$uuid" --arg server_name "$server_name" --arg private_key "$private_key" --arg short_id "$short_id" \
        '{"type": "vless", "tag": "vless-reality-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"uuid": $uuid, "flow": "xtls-rprx-vision"}], "tls": {"enabled": true, "server_name": $server_name, "reality": {"enabled": true, "handshake": {"server": $server_name, "server_port": 443}, "private_key": $private_key, "short_id": [$short_id]}}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "vless-reality" "$listen_port" "$uuid" "$server_name" "$public_key" "$short_id"
    echo -e "${CYAN}VLESS (REALITY) 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, UUID: $uuid"
    echo "ServerName: $server_name, Short ID: $short_id, Public Key: $public_key"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function hysteria2_install() {
    echo "--- 正在配置 Hysteria2 (自签证书) 节点 ---"
    generate_self_signed_cert
    get_listen_port
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg password "$password" \
        '{"type": "hysteria2", "tag": "hy2-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"password": $password}], "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "/usr/local/etc/sing-box/cert.pem", "key_path": "/usr/local/etc/sing-box/private.key"}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "hysteria2" "$listen_port" "$password"
    echo -e "${CYAN}Hysteria2 节点添加成功!${NC}"
    echo -e "${YELLOW}请注意：此节点使用自签名证书，客户端需开启“跳过证书验证”。${NC}"
    echo "地址: $server_ip, 端口: $listen_port, 密码: $password"
    echo "SNI: www.microsoft.com"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function tuic_install() {
    echo "--- 正在配置 TUICv5 (自签证书) 节点 ---"
    generate_self_signed_cert
    get_listen_port
    get_uuid
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg uuid "$uuid" --arg password "$password" \
        '{"type": "tuic", "tag": "tuic-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"uuid": $uuid, "password": $password}], "congestion_control": "bbr", "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "/usr/local/etc/sing-box/cert.pem", "key_path": "/usr/local/etc/sing-box/private.key"}}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "tuic" "$listen_port" "$uuid" "$password"
    echo -e "${CYAN}TUICv5 节点添加成功!${NC}"
    echo -e "${YELLOW}请注意：此节点使用自签名证书，客户端需开启“跳过证书验证”。${NC}"
    echo "地址: $server_ip, 端口: $listen_port, UUID: $uuid, 密码: $password"
    echo "SNI: www.microsoft.com"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function shadowsocks_install() {
    echo "--- 正在配置 Shadowsocks (aes-256-gcm) 节点 ---"
    get_listen_port
    local ss_method="aes-256-gcm"
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg ss_method "$ss_method" --arg password "$password" \
        '{"type": "shadowsocks", "tag": "ss-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "method": $ss_method, "password": $password}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "shadowsocks" "$listen_port" "$ss_method" "$password"
    echo -e "${CYAN}Shadowsocks 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, 加密方式: $ss_method, 密码: $password"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

function socks_install() {
    echo "--- 正在配置 SOCKS5 节点 ---"
    get_listen_port
    read -p "请输入用户名 (默认随机): " username
    username=${username:-$(sing-box generate rand --hex 8)}
    get_password
    local new_inbound=$(jq -n --arg listen_port "$listen_port" --arg username "$username" --arg password "$password" \
        '{"type": "socks", "tag": "socks-in-'$listen_port'", "listen": "::", "listen_port": ($listen_port | tonumber), "users": [{"username": $username, "password": $password}]}')
    jq ".inbounds += [$new_inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    append_yaml_config "socks" "$listen_port" "$username" "$password"
    echo -e "${CYAN}SOCKS5 节点添加成功!${NC}"
    echo "地址: $server_ip, 端口: $listen_port, 用户名: $username, 密码: $password"
    echo -e "${CYAN}Clash YAML 配置文件已更新: ${YAML_FILE}${NC}"
}

# --- 管理功能 ---

function manage_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${YELLOW}当前没有任何已配置的节点。${NC}"
        return
    fi
    echo "--- 节点管理 ---"
    jq -r '.inbounds[] | "\(.tag) (\(.type)) @ \(.listen_port)"' "$CONFIG_FILE" | cat -n
    echo "------------------"
    read -p "请输入要删除的节点编号 (输入 0 返回): " node_num
    if [[ ! "$node_num" =~ ^[0-9]+$ ]]; then echo -e "${RED}无效输入。${NC}"; return; fi
    if [ "$node_num" -eq 0 ]; then return; fi
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$node_num" -gt "$node_count" ]; then echo -e "${RED}编号超出范围。${NC}"; return; fi

    local index_to_delete=$((node_num - 1))
    local tag_to_delete=$(jq -r ".inbounds[${index_to_delete}].tag" "$CONFIG_FILE")
    
    # 从JSON中删除
    jq "del(.inbounds[${index_to_delete}])" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    echo "节点已从 sing-box 配置中删除。"

    # 从YAML中删除
    if [ -f "$YAML_FILE" ] && [ -n "$tag_to_delete" ]; then
        local port_to_delete=$(echo "$tag_to_delete" | awk -F'-' '{print $NF}')
        local type_prefix=$(echo "$tag_to_delete" | sed -E 's/(-in-).+//')
        local proxy_name_to_delete=""
        
        case "$type_prefix" in
            "vless-tcp") proxy_name_to_delete="vless-tcp-${port_to_delete}" ;;
            "vless-reality") proxy_name_to_delete="vless-reality-vision-${port_to_delete}" ;;
            "hy2") proxy_name_to_delete="hysteria2-${port_to_delete}" ;;
            "tuic") proxy_name_to_delete="tuic-${port_to_delete}" ;;
            "ss") proxy_name_to_delete="ss-${port_to_delete}" ;;
            "socks") proxy_name_to_delete="socks-${port_to_delete}" ;;
        esac

        if [ -n "$proxy_name_to_delete" ]; then
            # 使用awk删除proxies下的块
            awk -v name="${proxy_name_to_delete}" '
                BEGIN { in_block=0 }
                $0 ~ "- name: " name { in_block=1 }
                !in_block { print }
                in_block && ($0 ~ /^- name:/ || $0 ~ /^proxy-groups:/) { in_block=0; print }
            ' "$YAML_FILE" | sed '/^$/d' > tmp.yaml && mv tmp.yaml "$YAML_FILE"

            # 使用sed删除proxy-groups下的引用
            sed -i "/- ${proxy_name_to_delete}/d" "$YAML_FILE"
            echo "节点已从 Clash YAML 配置中删除。"
        fi
    fi
    
    echo -e "${CYAN}节点删除成功！正在重启服务...${NC}"
    manage_service "restart"
}

function uninstall_script() {
    local script_path=$(readlink -f "$0")
    read -p "确定要卸载 sing-box 并删除所有相关文件和此脚本吗? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "卸载已取消。"
        return
    fi
    echo "正在停止并禁用服务..."
    manage_service "stop"
    rc-update del sing-box default >/dev/null 2>&1
    echo "正在删除文件..."
    rm -rf /usr/local/bin/sing-box /usr/local/etc/sing-box /etc/init.d/sing-box
    echo "清理完成。"
    rm -f "$script_path"
    echo "脚本 '$script_path' 已自毁。"
    echo "再见！"
    exit 0
}


# --- 主菜单 ---
function main_menu() {
    if [ ! -f /usr/local/bin/sing-box ]; then
        install_sing_box
        configure_openrc_service
        rc-update add sing-box default
    fi
    initialize_config_files
    get_local_ip

    clear
    echo "sing-box Alpine 安装脚本"
    echo "=========================================="
    echo -e "请选择要搭建的节点类型:"
    echo -e " ${CYAN}1)${NC} VLESS (TCP)"
    echo -e " ${CYAN}2)${NC} VLESS (REALITY)"
    echo -e " ${CYAN}3)${NC} Hysteria2 (自签证书, 无需域名)"
    echo -e " ${CYAN}4)${NC} TUICv5 (自签证书, 无需域名)"
    echo -e " ${CYAN}5)${NC} Shadowsocks (aes-256-gcm)"
    echo -e " ${CYAN}6)${NC} Socks5"
    echo "------------------------------------------"
    echo -e " ${YELLOW}7)${NC} 节点管理 (删除节点)"
    echo -e " ${YELLOW}8)${NC} 重启 sing-box 服务"
    echo -e " ${YELLOW}9)${NC} 彻底卸载 sing-box"
    echo -e " ${YELLOW}0)${NC} 退出脚本"
    echo "=========================================="
    read -p "请输入选项 [0-9]: " choice

    local is_install_action=false
    case $choice in
        1) vless_tcp_install; is_install_action=true ;;
        2) vless_reality_install; is_install_action=true ;;
        3) hysteria2_install; is_install_action=true ;;
        4) tuic_install; is_install_action=true ;;
        5) shadowsocks_install; is_install_action=true ;;
        6) socks_install; is_install_action=true ;;
        7) manage_nodes ;;
        8) manage_service "restart" ;;
        9) uninstall_script ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效输入，请重试。${NC}" ;;
    esac

    if [ "$is_install_action" = true ]; then
        echo "正在重启 sing-box 使配置生效..."
        manage_service "restart"
        sleep 1
        manage_service "status"
    fi
    
    echo
    read -p "按任意键返回主菜单..."
    main_menu
}

# --- 脚本入口 ---

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误：本脚本需要以 root 权限运行！${NC}"
    exit 1
fi

check_and_install_deps
main_menu

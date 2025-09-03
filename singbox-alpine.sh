#!/bin/bash

# --- 全局变量和样式 ---
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'
CONFIG_FILE="/usr/local/etc/sing-box/config.json"
YAML_FILE="/usr/local/etc/sing-box/clash.yaml"
META_FILE="/usr/local/etc/sing-box/metadata.json"
SERVICE_FILE_OPENRC="/etc/init.d/sing-box"
server_ip=""
YQ_BINARY="/usr/bin/yq" # 在Alpine中，yq通常安装在这里

# --- 核心辅助函数 ---

function safe_write_to_file() {
    local file_path="$1"
    local temp_content_path="$2"

    if [ ! -f "$file_path" ]; then
        mv "$temp_content_path" "$file_path"
        return
    fi

    cp "$file_path" "$file_path.bak"
    if mv "$temp_content_path" "$file_path"; then
        rm -f "$file_path.bak"
    else
        echo -e "${RED}文件写入失败: $file_path, 正在从备份恢复...${NC}"
        mv "$file_path.bak" "$file_path"
        exit 1
    fi
}

function url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}

function get_local_ip() {
    server_ip=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s6 --max-time 2 icanhazip.com || curl -s6 --max-time 2 ipinfo.io/ip)
    fi
    if [ -z "$server_ip" ]; then
        echo -e "${RED}无法获取本机的公网 IP 地址！${NC}"; exit 1
    fi
}

# --- 系统与依赖函数 ---

function check_and_install_deps() {
    if [ ! -f /etc/alpine-release ]; then
        echo -e "${YELLOW}警告: 此脚本专为 Alpine Linux 设计, 但仍会尝试运行。${NC}"
    fi
    echo "正在检查并安装所需依赖 ..."
    local pkgs_to_install=""
    # 添加 yq 和 openrc 相关工具
    local required_pkgs="curl jq openssl wget yq openrc"
    for pkg in $required_pkgs; do
        if ! apk -e info "$pkg" >/dev/null 2>&1; then
            pkgs_to_install="$pkgs_to_install $pkg"
        fi
    done
    if [ -n "$pkgs_to_install" ]; then
        echo "正在安装缺失的依赖: $pkgs_to_install"
        if ! apk update || ! apk add --no-cache $pkgs_to_install; then
            echo -e "${RED}依赖安装失败，请手动执行 'apk add $pkgs_to_install' 后重试。${NC}"
            exit 1
        fi
    fi
    echo "所有依赖均已满足。"
}

function install_sing_box() {
    echo "正在安装最新稳定版 sing-box..."
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
    
    if [ -z "$download_url" ]; then echo -e "${RED}无法从 GitHub API 获取 sing-box 下载链接。${NC}"; exit 1; fi
    wget -qO sing-box.tar.gz "$download_url" || { echo -e "${RED}下载失败!${NC}"; exit 1; }

    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    mv "$temp_dir/sing-box-"*"/sing-box" /usr/local/bin/
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x /usr/local/bin/sing-box
    echo "sing-box 安装成功。"
}

function initialize_config_files() {
    mkdir -p /usr/local/etc/sing-box
    [ -s "$CONFIG_FILE" ] || echo '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONFIG_FILE"
    [ -s "$META_FILE" ] || echo "{}" > "$META_FILE"
    if [ ! -s "$YAML_FILE" ]; then
        echo "正在根据模板创建全新的 clash.yaml 配置文件..."
        cat > "$YAML_FILE" << 'EOF'
mixed-port: 7890
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: true
external-controller: 127.0.0.1:9090
proxies: []
proxy-groups:
  - name: Proxy
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
    fi
}

function generate_self_signed_cert() {
    local cert_path="/usr/local/etc/sing-box/cert.pem"
    local key_path="/usr/local/etc/sing-box/private.key"
    read -p "请输入用于生成证书的域名 (默认: www.microsoft.com): " domain
    domain=${domain:-"www.microsoft.com"}
    if [ ! -f "$cert_path" ]; then
        echo "正在为 ${domain} 生成自签名证书..."
        openssl ecparam -genkey -name prime256v1 -out "$key_path"
        openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${domain}"
    fi
}

# --- 服务管理 (OpenRC) ---

function create_openrc_service() {
    if [ -f "$SERVICE_FILE_OPENRC" ]; then return; fi
    echo "正在创建 OpenRC 服务文件..."
    cat > "$SERVICE_FILE_OPENRC" <<EOF
#!/sbin/openrc-run

name="sing-box"
description="A universal proxy platform"

command="/usr/local/bin/sing-box"
command_args="run -c ${CONFIG_FILE}"
command_user="root"

pidfile="/var/run/sing-box.pid"
# supervise-daemon 将确保进程在后台运行并管理pid文件
supervisor=supervise-daemon

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$SERVICE_FILE_OPENRC"
    rc-update add sing-box default
    echo "OpenRC 服务创建并启用成功。"
}

function manage_service() {
    if ! command -v rc-service &> /dev/null; then
        echo -e "${RED}OpenRC 'rc-service' 命令未找到。无法管理服务。${NC}"
        return 1
    fi
    rc-service sing-box "$1"
}

# --- 节点和YAML管理 ---

function add_node_to_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)

    local temp_yaml=$(mktemp)
    cp "$YAML_FILE" "$temp_yaml"
    
    ${YQ_BINARY} eval-all \
        ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name) | .proxy-groups[] |= (select(.name == \"Proxy\") | .proxies |= . + [\"${proxy_name}\"] | .proxies |= unique)" \
        "$temp_yaml" > "${temp_yaml}.out"
    
    safe_write_to_file "$YAML_FILE" "${temp_yaml}.out"
    rm -f "$temp_yaml"
    echo "Clash YAML 配置文件已更新。"
}

function remove_node_from_yaml() {
    local proxy_name="$1"
    
    local temp_yaml=$(mktemp)
    cp "$YAML_FILE" "$temp_yaml"

    ${YQ_BINARY} eval-all \
        'del(.proxies[] | select(.name == "'${proxy_name}'")) | .proxy-groups[] |= (select(.name == "Proxy") | .proxies |= del(.[] | select(. == "'${proxy_name}'")))' \
        "$temp_yaml" > "${temp_yaml}.out"
    
    safe_write_to_file "$YAML_FILE" "${temp_yaml}.out"
    rm -f "$temp_yaml"
    echo "Clash YAML 配置文件已清理。"
}

# --- 节点搭建函数 (与systemd版本逻辑一致) ---

function vless_reality_install() {
    read -p "请输入监听端口: " port
    read -p "请输入伪装域名 (默认 www.microsoft.com): " server_name
    server_name=${server_name:-"www.microsoft.com"}
    local uuid=$(sing-box generate uuid)
    local keypair=$(sing-box generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(sing-box generate rand --hex 8)
    local tag="vless-in-${port}"
    local name="vless-reality-${port}"
    local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"
    
    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > config.tmp.json
    safe_write_to_file "$CONFIG_FILE" "config.tmp.json"
    
    jq ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\", \"proxyName\": \"$name\"}}" "$META_FILE" > meta.tmp.json
    safe_write_to_file "$META_FILE" "meta.tmp.json"
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    add_node_to_yaml "$proxy_json"
    echo -e "${CYAN}VLESS (REALITY) 节点添加成功!${NC}"
}

function hysteria2_install() {
    generate_self_signed_cert
    read -p "请输入监听端口: " port
    read -p "请输入密码 (默认随机): " password; password=${password:-$(sing-box generate rand --hex 16)}
    read -p "请输入上传速度 (默认 50 Mbps): " up_speed; up_speed=${up_speed:-"50 Mbps"}
    read -p "请输入下载速度 (默认 200 Mbps): " down_speed; down_speed=${down_speed:-"200 Mbps"}
    read -p "请输入伪装域名/SNI (默认 www.microsoft.com): " sni; sni=${sni:-"www.microsoft.com"}
    local obfs_password=""; read -p "是否开启QUIC流量混淆?(y/N): " q; [[ "$q" == "y" || "$q" == "Y" ]] && obfs_password=$(sing-box generate rand --hex 16)
    local tag="hy2-in-${port}"; local name="hysteria2-${port}"; local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"

    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/usr/local/etc/sing-box/cert.pem","key_path":"/usr/local/etc/sing-box/private.key"}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > config.tmp.json
    safe_write_to_file "$CONFIG_FILE" "config.tmp.json"

    jq ". + {\"$tag\": {\"proxyName\": \"$name\", \"up\": \"$up_speed\", \"down\": \"$down_speed\"$(if [ -n "$obfs_password" ]; then echo ", \"obfsPassword\": \"$obfs_password\""; fi)}}" "$META_FILE" > meta.tmp.json
    safe_write_to_file "$META_FILE" "meta.tmp.json"

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg pw "$password" --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" --arg sni "$sni" \
        '{"name":$n,"type":"hysteria2","server":$s,"port":($p|tonumber),"password":$pw,"sni":$sni,"skip-cert-verify":true,"alpn":["h3"],"up":$up,"down":$down} | if $op != "" then .obfs="salamander" | .["obfs-password"]=$op else . end')
    add_node_to_yaml "$proxy_json"

    echo -e "${CYAN}Hysteria2 节点添加成功!${NC}"
}

function tuic_install() {
    generate_self_signed_cert
    read -p "请输入监听端口: " port; uuid=$(sing-box generate uuid); password=$(sing-box generate rand --hex 16)
    read -p "请输入伪装域名/SNI (默认 www.microsoft.com): " sni; sni=${sni:-"www.microsoft.com"}
    local tag="tuic-in-${port}"; local name="tuic-${port}"; local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"

    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/usr/local/etc/sing-box/cert.pem","key_path":"/usr/local/etc/sing-box/private.key"}}')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > config.tmp.json
    safe_write_to_file "$CONFIG_FILE" "config.tmp.json"

    jq ". + {\"$tag\": {\"proxyName\": \"$name\"}}" "$META_FILE" > meta.tmp.json
    safe_write_to_file "$META_FILE" "meta.tmp.json"
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sni "$sni" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sni,"skip-cert-verify":true,"alpn":["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    add_node_to_yaml "$proxy_json"
    echo -e "${CYAN}TUICv5 节点添加成功!${NC}"
}

function shadowsocks_install() {
    read -p "请输入监听端口: " port; password=$(sing-box generate rand --hex 16)
    local tag="ss-in-${port}"; local name="ss-${port}"; local method="aes-256-gcm"; local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"
    
    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"type":"shadowsocks","tag":$t,"listen":"::","listen_port":($p|tonumber),"method":$m,"password":$pw}')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > config.tmp.json
    safe_write_to_file "$CONFIG_FILE" "config.tmp.json"

    jq ". + {\"$tag\": {\"proxyName\": \"$name\"}}" "$META_FILE" > meta.tmp.json
    safe_write_to_file "$META_FILE" "meta.tmp.json"

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"name":$n,"type":"ss","server":$s,"port":($p|tonumber),"cipher":$m,"password":$pw}')
    add_node_to_yaml "$proxy_json"
    echo -e "${CYAN}Shadowsocks 节点添加成功!${NC}"
}

function socks_install() {
    read -p "请输入监听端口: " port
    read -p "请输入用户名 (默认随机): " username; username=${username:-$(sing-box generate rand --hex 8)}
    read -p "请输入密码 (默认随机): " password; password=${password:-$(sing-box generate rand --hex 16)}
    local tag="socks-in-${port}"; local name="socks-${port}"; local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"

    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"type":"socks","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"username":$u,"password":$pw}]}')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > config.tmp.json
    safe_write_to_file "$CONFIG_FILE" "config.tmp.json"

    jq ". + {\"$tag\": {\"proxyName\": \"$name\"}}" "$META_FILE" > meta.tmp.json
    safe_write_to_file "$META_FILE" "meta.tmp.json"

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"name":$n,"type":"socks5","server":$s,"port":($p|tonumber),"username":$u,"password":$pw}')
    add_node_to_yaml "$proxy_json"

    echo -e "${CYAN}SOCKS5 节点添加成功!${NC}"
}


# --- 管理功能 ---

function view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then echo -e "${YELLOW}当前没有任何节点。${NC}"; return; fi
    echo "--- 当前节点信息 (共 $(jq '.inbounds | length' "$CONFIG_FILE") 个) ---"
    jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') type=$(echo "$node" | jq -r '.type') port=$(echo "$node" | jq -r '.listen_port')
        local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"
        echo "-------------------------------------"; echo -e " ${CYAN}节点: ${tag}${NC}"
        local url=""
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local sn=$(echo "$node" | jq -r '.tls.server_name'); local flow=$(echo "$node" | jq -r '.users[0].flow')
                local meta_obj=$(jq --arg t "$tag" '.[$t]' "$META_FILE"); local pk=$(echo "$meta_obj" | jq -r '.publicKey'); local sid=$(echo "$meta_obj" | jq -r '.shortId')
                url="vless://${uuid}@${display_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sn}&fp=chrome&flow=${flow}&pbk=${pk}&sid=${sid}#$(url_encode "$tag")"
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password')
                local meta_obj=$(jq --arg t "$tag" '.[$t]' "$META_FILE")
                local op=$(echo "$meta_obj" | jq -r '.obfsPassword')
                local proxy_name=$(echo "$meta_obj" | jq -r '.proxyName')
                local sni=""
                if [ -n "$proxy_name" ] && [ "$proxy_name" != "null" ]; then
                    sni=$(${YQ_BINARY} eval ".proxies[] | select(.name == \"${proxy_name}\").sni" "$YAML_FILE")
                fi
                local obfs_param=""; [[ -n "$op" && "$op" != "null" ]] && obfs_param="&obfs=salamander&obfs-password=${op}"
                url="hysteria2://${pw}@${display_ip}:${port}?sni=${sni}&insecure=1${obfs_param}#$(url_encode "$tag")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                local meta_obj=$(jq --arg t "$tag" '.[$t]' "$META_FILE")
                local proxy_name=$(echo "$meta_obj" | jq -r '.proxyName')
                local sni=""
                 if [ -n "$proxy_name" ] && [ "$proxy_name" != "null" ]; then
                    sni=$(${YQ_BINARY} eval ".proxies[] | select(.name == \"${proxy_name}\").sni" "$YAML_FILE")
                fi
                url="tuic://${uuid}:${pw}@${display_ip}:${port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(url_encode "$tag")"
                ;;
            "shadowsocks")
                local m=$(echo "$node" | jq -r '.method'); local pw=$(echo "$node" | jq -r '.password')
                local b64=$(echo -n "${m}:${pw}" | base64 | tr -d '\n')
                url="ss://${b64}@${display_ip}:${port}#$(url_encode "$tag")"
                ;;
            "socks")
                local u=$(echo "$node" | jq -r '.users[0].username'); local p=$(echo "$node" | jq -r '.users[0].password')
                echo "  类型: SOCKS5, 地址: $server_ip, 端口: $port, 用户: $u, 密码: $p"
                ;;
        esac
        [ -n "$url" ] && echo -e "  ${YELLOW}分享链接:${NC} ${url}"
    done
    echo "-------------------------------------"
}

function manage_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then echo -e "${YELLOW}当前没有任何节点。${NC}"; return; fi
    echo "--- 节点管理 (删除) ---"
    jq -r '.inbounds[] | "\(.tag) (\(.type)) @ \(.listen_port)"' "$CONFIG_FILE" | cat -n
    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    local count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$num" -gt "$count" ]; then echo -e "${RED}编号超出范围。${NC}"; return; fi

    local index=$((num - 1))
    local tag=$(jq -r ".inbounds[${index}].tag" "$CONFIG_FILE")
    local name=$(jq -r ".\"$tag\".proxyName" "$META_FILE")

    jq "del(.inbounds[${index}])" "$CONFIG_FILE" > config.tmp.json
    safe_write_to_file "$CONFIG_FILE" "config.tmp.json"
    
    jq "del(.\"$tag\")" "$META_FILE" > meta.tmp.json
    safe_write_to_file "$META_FILE" "meta.tmp.json"

    if [ -n "$name" ] && [ "$name" != "null" ]; then
        remove_node_from_yaml "$name"
    else
        echo -e "${YELLOW}警告: 未在元数据中找到节点的代理名称，可能无法完全清理 clash.yaml。${NC}"
    fi
    
    echo -e "${CYAN}节点 ${tag} 已删除！正在重启服务...${NC}"; manage_service "restart"
}

function uninstall_script() {
    read -p "确定要卸载 sing-box 并删除所有相关文件和此脚本吗? (y/N): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        manage_service "stop"
        rc-update del sing-box default >/dev/null 2>&1
        rm -rf /usr/local/bin/sing-box /usr/local/etc/sing-box "$SERVICE_FILE_OPENRC"
        echo "清理完成。脚本将自毁。再见！"
        rm -f "$0"
    else
        echo "卸载已取消。"
    fi
}

# --- 主菜单 ---
function main_menu() {
    clear
    echo -e "${CYAN}sing-box 安装与管理脚本 ( Alpine专用版 )${NC}"
    echo "=========================================="
    echo "--- 安装选项 ---"
    echo -e " ${CYAN}1)${NC} VLESS (REALITY)"
    echo -e " ${CYAN}2)${NC} Hysteria2 "
    echo -e " ${CYAN}3)${NC} TUICv5 "
    echo -e " ${CYAN}4)${NC} Shadowsocks (aes-256-gcm)"
    echo -e " ${CYAN}5)${NC} SOCKS5"
    echo "--- 管理选项 ---"
    echo -e " ${YELLOW}6)${NC} 查看节点分享链接"
    echo -e " ${YELLOW}7)${NC} 管理节点 (删除节点)"
    echo -e " ${YELLOW}8)${NC} 重启 sing-box 服务"
    echo -e " ${YELLOW}9)${NC} 卸载 sing-box"
    echo -e " ${YELLOW}0)${NC} 退出脚本"
    echo "=========================================="
    read -p "请输入选项 [0-9]: " choice

    local needs_restart=false
    case $choice in
        1) vless_reality_install; needs_restart=true ;;
        2) hysteria2_install; needs_restart=true ;;
        3) tuic_install; needs_restart=true ;;
        4) shadowsocks_install; needs_restart=true ;;
        5) socks_install; needs_restart=true ;;
        6) view_nodes ;;
        7) manage_nodes ;;
        8) manage_service "restart" ;;
        9) uninstall_script ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效输入，请重试。${NC}" ;;
    esac

    if [ "$needs_restart" = true ]; then
        echo "配置已更新，正在重启 sing-box..."; manage_service "restart"
    fi
}

# --- 脚本入口 ---

if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}错误：本脚本需要以 root 权限运行！${NC}"; exit 1; fi

if [ ! -f /usr/local/bin/sing-box ]; then
    check_and_install_deps
    install_sing_box
    initialize_config_files
    create_openrc_service
fi
get_local_ip

while true; do
    main_menu
    echo
    read -n 1 -s -r -p "按任意键返回主菜单..."
done


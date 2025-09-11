#!/bin/bash

# --- 全局变量和样式 ---
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'
CONFIG_FILE="/usr/local/etc/sing-box/config.json"
YAML_FILE="/usr/local/etc/sing-box/clash.yaml"
META_FILE="/usr/local/etc/sing-box/metadata.json"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
server_ip=""
YQ_BINARY="/usr/local/bin/yq"

# --- 系统与依赖函数 ---

function check_and_install_deps() {
    echo "正在检查并安装所需依赖 ..."
    local pkgs_to_install=""
    local required_pkgs="curl jq openssl wget"
    local pm=""

    # --- FIX: 增加对 dnf/yum 的支持 ---
    if command -v apt-get &>/dev/null; then
        pm="apt-get"
    elif command -v dnf &>/dev/null; then
        pm="dnf"
    elif command -v yum &>/dev/null; then
        pm="yum"
    else
        echo -e "${YELLOW}警告: 未能识别的包管理器, 无法自动安装依赖。请确保已安装: ${required_pkgs}${NC}"
    fi

    if [ -n "$pm" ]; then
        # 检查需要安装的包
        if [ "$pm" == "apt-get" ]; then
            for pkg in $required_pkgs; do
                if ! dpkg -s "$pkg" >/dev/null 2>&1; then
                    pkgs_to_install="$pkgs_to_install $pkg"
                fi
            done
        else # for yum/dnf
            for pkg in $required_pkgs; do
                if ! rpm -q "$pkg" >/dev/null 2>&1; then
                    pkgs_to_install="$pkgs_to_install $pkg"
                fi
            done
        fi

        # 安装缺失的包
        if [ -n "$pkgs_to_install" ]; then
            echo "正在安装缺失的依赖:$pkgs_to_install"
            if [ "$pm" == "apt-get" ]; then
                apt-get update
            fi
            if ! ($pm install -y $pkgs_to_install); then
                echo -e "${RED}依赖安装失败，请手动执行 '$pm install -y $pkgs_to_install' 后重试。${NC}"
                exit 1
            fi
        fi
    fi

    if ! command -v yq &>/dev/null; then
        echo "正在安装 yq (用于YAML处理)..."
        # --- FIX: 自动检测架构并下载对应版本的 yq ---
        local arch=$(uname -m)
        local yq_arch_tag
        case $arch in
            x86_64|amd64) yq_arch_tag='amd64' ;;
            aarch64|arm64) yq_arch_tag='arm64' ;;
            armv7l) yq_arch_tag='arm' ;;
            *) echo -e "${RED}yq 安装失败: 不支持的架构：$arch${NC}"; exit 1 ;;
        esac
        
        wget -qO ${YQ_BINARY} "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch_tag}"
        if [ $? -ne 0 ]; then
            echo -e "${RED}yq 下载失败，请检查网络或手动安装。${NC}"
            exit 1
        fi
        chmod +x ${YQ_BINARY}
    fi
    echo "所有依赖均已满足。"
}

# --- 服务管理 (systemd) ---

function create_systemd_service() {
    if [ -f "$SERVICE_FILE" ]; then return; fi
    echo "正在创建 systemd 服务文件..."
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box
    echo "systemd 服务创建并启用成功。"
}

function manage_service() {
    systemctl "$1" sing-box
}

# --- 核心辅助函数 ---
function url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}
export -f url_encode

function get_local_ip() {
    server_ip=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s6 --max-time 2 icanhazip.com || curl -s6 --max-time 2 ipinfo.io/ip)
    fi
    if [ -z "$server_ip" ]; then
        echo -e "${RED}无法获取本机的公网 IP 地址！${NC}"; exit 1
    fi
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
    if [ -z "$download_url" ]; then echo -e "${RED}无法获取 sing-box 下载链接。${NC}"; exit 1; fi
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
log-level: debug
ipv6: true
external-controller: 127.0.0.1:9090
external-ui: ui
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: [223.5.5.5, 114.114.114.114]
  nameserver: ['https://223.5.5.5/dns-query', 'https://1.1.1.1/dns-query']
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
    if [ ! -f "$cert_path" ]; then
        echo "正在为 www.microsoft.com 生成自签名证书..."
        openssl ecparam -genkey -name prime256v1 -out "$key_path"
        openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=www.microsoft.com"
    fi
}

# --- 节点和YAML管理 ---

function add_node_to_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)

    # 使用 yq 添加或更新 proxies 列表中的节点
    ${YQ_BINARY} eval-all ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name)" -i "$YAML_FILE"
    # 使用 yq 添加节点名称到 Proxy 组
    ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "Proxy") | .proxies |= . + ["'${proxy_name}'"] | .proxies |= unique)' -i "$YAML_FILE"
    
    echo "Clash YAML 配置文件已更新。"
}

function remove_node_from_yaml() {
    local proxy_name="$1"
    # 使用 yq 从 proxies 列表和 Proxy 组中删除节点
    ${YQ_BINARY} eval-all 'del(.proxies[] | select(.name == "'${proxy_name}'")) | .proxy-groups[] |= (select(.name == "Proxy") | .proxies |= del(.[] | select(. == "'${proxy_name}'")))' -i "$YAML_FILE"
    echo "Clash YAML 配置文件已清理。"
}

function vless_reality_install() {
    read -p "请输入监听端口: " port; uuid=$(sing-box generate uuid);
    server_name="www.microsoft.com"
    local keypair=$(sing-box generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(sing-box generate rand --hex 8)
    local tag="vless-in-${port}"
    local name="vless-reality-${port}"
    local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"
    
    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    jq ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\"}}" "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    add_node_to_yaml "$proxy_json"
    echo -e "${CYAN}VLESS (REALITY) 节点添加成功!${NC}"
}

function vless_tcp_install() {
    read -p "请输入监听端口: " port; uuid=$(sing-box generate uuid);
    local tag="vless-tcp-in-${port}"
    local name="vless-tcp-${port}"
    local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"
    
    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":""}],"tls":{"enabled":false}}')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":false,"network":"tcp"}')
    add_node_to_yaml "$proxy_json"
    echo -e "${CYAN}VLESS (TCP) 节点添加成功!${NC}"
}

function hysteria2_install() {
    generate_self_signed_cert
    read -p "请输入监听端口: " port
    read -p "请输入密码 (默认随机): " password; password=${password:-$(sing-box generate rand --hex 16)}
    read -p "请输入上传速度 (默认 50 Mbps): " up_speed; up_speed=${up_speed:-"50 Mbps"}
    read -p "请输入下载速度 (默认 200 Mbps): " down_speed; down_speed=${down_speed:-"200 Mbps"}

    local obfs_password=""; read -p "是否开启QUIC流量混淆?(y/N): " q; [[ "$q" == "y" || "$q" == "Y" ]] && obfs_password=$(sing-box generate rand --hex 16)
    local tag="hy2-in-${port}"; local name="hysteria2-${port}"; local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"

    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/usr/local/etc/sing-box/cert.pem","key_path":"/usr/local/etc/sing-box/private.key"}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"

    jq ". + {\"$tag\": {\"up\": \"$up_speed\", \"down\": \"$down_speed\"$(if [ -n "$obfs_password" ]; then echo ", \"obfsPassword\": \"$obfs_password\""; fi)}}" "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg pw "$password" --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" \
        '{"name":$n,"type":"hysteria2","server":$s,"port":($p|tonumber),"password":$pw,"sni":"www.microsoft.com","skip-cert-verify":true,"alpn":["h3"],"up":$up,"down":$down} | if $op != "" then .obfs="salamander" | .["obfs-password"]=$op else . end')
    add_node_to_yaml "$proxy_json"

    echo -e "${CYAN}Hysteria2 节点添加成功!${NC}"
}

function tuic_install() {
    generate_self_signed_cert
    read -p "请输入监听端口: " port; uuid=$(sing-box generate uuid); password=$(sing-box generate rand --hex 16)
    local tag="tuic-in-${port}"; local name="tuic-${port}"; local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"

    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/usr/local/etc/sing-box/cert.pem","key_path":"/usr/local/etc/sing-box/private.key"}}')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":"www.microsoft.com","skip-cert-verify":true,"alpn":["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    add_node_to_yaml "$proxy_json"
    echo -e "${CYAN}TUICv5 节点添加成功!${NC}"
}

function shadowsocks_install() {
    read -p "请输入监听端口: " port; password=$(sing-box generate rand --hex 16)
    local tag="ss-in-${port}"; local name="ss-${port}"; local method="aes-256-gcm"; local display_ip="$server_ip"; [[ "$server_ip" == *":"* ]] && display_ip="[$server_ip]"
    
    local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"type":"shadowsocks","tag":$t,"listen":"::","listen_port":($p|tonumber),"method":$m,"password":$pw}')
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"

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
    jq ".inbounds += [$inbound]" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"

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
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                if [ "$(echo "$node" | jq -r '.tls.reality.enabled')" == "true" ]; then
                    local sn=$(echo "$node" | jq -r '.tls.server_name'); local flow=$(echo "$node" | jq -r '.users[0].flow')
                    local meta=$(jq -r --arg t "$tag" '.[$t]' "$META_FILE"); local pk=$(echo "$meta" | jq -r '.publicKey'); local sid=$(echo "$meta" | jq -r '.shortId')
                    url="vless://${uuid}@${display_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sn}&fp=chrome&flow=${flow}&pbk=${pk}&sid=${sid}#$(url_encode "$tag")"
                else
                    url="vless://${uuid}@${display_ip}:${port}?type=tcp&security=none#$(url_encode "$tag")"
                fi
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password'); local meta=$(jq -r --arg t "$tag" '.[$t]' "$META_FILE"); local op=$(echo "$meta" | jq -r '.obfsPassword')
                local obfs_param=""; [[ -n "$op" && "$op" != "null" ]] && obfs_param="&obfs=salamander&obfs-password=${op}"
                url="hysteria2://${pw}@${display_ip}:${port}?sni=www.microsoft.com&insecure=1${obfs_param}#$(url_encode "$tag")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                url="tuic://${uuid}:${pw}@${display_ip}:${port}?sni=www.microsoft.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(url_encode "$tag")"
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
    local node_to_del_obj=$(jq ".inbounds[$index]" "$CONFIG_FILE")
    local tag_to_del=$(echo "$node_to_del_obj" | jq -r ".tag")
    local type_to_del=$(echo "$node_to_del_obj" | jq -r ".type")
    local port_to_del=$(echo "$node_to_del_obj" | jq -r ".listen_port")
    
    local name_to_del
    case "$type_to_del" in
        "vless")
            if [ "$(echo "$node_to_del_obj" | jq -r '.tls.reality.enabled')" == "true" ]; then
                name_to_del="vless-reality-${port_to_del}"
            else
                name_to_del="vless-tcp-${port_to_del}"
            fi
            ;;
        "hysteria2") name_to_del="hysteria2-${port_to_del}" ;;
        "tuic") name_to_del="tuic-${port_to_del}" ;;
        "shadowsocks") name_to_del="ss-${port_to_del}" ;;
        "socks") name_to_del="socks-${port_to_del}" ;;
        *)
            echo -e "${YELLOW}警告: 未知节点类型 '${type_to_del}'，无法确定 clash.yaml 中的节点名。${NC}"
            name_to_del="" # 设置为空, 避免错误删除
            ;;
    esac

    # 从 sing-box 配置文件中删除 inbound
    jq "del(.inbounds[${index}])" "$CONFIG_FILE" > tmp.json && mv tmp.json "$CONFIG_FILE"
    
    # 从元数据文件中删除条目
    jq "del(.\"$tag_to_del\")" "$META_FILE" > tmp_meta.json && mv tmp_meta.json "$META_FILE"
    
    # 从 clash.yaml 中删除节点
    if [ -n "$name_to_del" ]; then
        remove_node_from_yaml "$name_to_del"
    fi
    
    echo -e "${CYAN}节点 ${tag_to_del} 已删除！正在重启服务...${NC}"; manage_service "restart"
}

function uninstall_script() {
    read -p "确定要卸载 sing-box 并删除所有相关文件和此脚本吗? (y/N): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        manage_service "stop"
        systemctl disable sing-box >/dev/null 2>&1
        rm -rf /usr/local/bin/sing-box /usr/local/etc/sing-box "$SERVICE_FILE" "$YQ_BINARY"
        systemctl daemon-reload
        echo "清理完成。脚本已自毁。再见！"
        rm -f "$0"
    else
        echo "卸载已取消。"
    fi
}

# --- 主菜单 ---
function main_menu() {
    clear
    echo -e "${CYAN}sing-box 安装脚本 ${NC}"
    echo "----------------------------------------"
    echo -e "${YELLOW}安装选项 ---${NC}"
    echo "1) VLESS (REALITY)"
    echo "2) VLESS (TCP)"
    echo "3) Hysteria2 (自签证书)"
    echo "4) TUICv5 (自签证书)"
    echo "5) Shadowsocks (aes-256-gcm)"
    echo "6) SOCKS5"
    echo "----------------------------------------"
    echo -e "${YELLOW}管理选项 ---${NC}"
    echo "7) 查看节点分享链接"
    echo "8) 管理节点 (删除)"
    echo "9) 重启 sing-box 服务"
    echo "10) 卸载 sing-box"
    echo "0) 退出脚本"
    echo "========================================"
    read -p "请输入选项 [0-10]: " choice

    local needs_restart=false
    case $choice in
        1) vless_reality_install; needs_restart=true ;;
        2) vless_tcp_install; needs_restart=true ;;
        3) hysteria2_install; needs_restart=true ;;
        4) tuic_install; needs_restart=true ;;
        5) shadowsocks_install; needs_restart=true ;;
        6) socks_install; needs_restart=true ;;
        7) view_nodes ;;
        8) manage_nodes ;;
        9) manage_service "restart" ;;
        10) uninstall_script ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效输入，请重试。${NC}" ;;
    esac

    if [ "$needs_restart" = true ]; then
        echo "配置已更新，正在重启 sing-box..."; manage_service "restart"
    fi
}

# --- 脚本入口 ---

if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}错误：本脚本需要以 root 权限运行！${NC}"; exit 1; fi
# 首次运行的初始化流程
if [ ! -f /usr/local/bin/sing-box ]; then
    check_and_install_deps
    install_sing_box
    initialize_config_files
    create_systemd_service
fi
get_local_ip

while true; do
    main_menu
    echo
    read -n 1 -s -r -p "按任意键返回主菜单..."
done

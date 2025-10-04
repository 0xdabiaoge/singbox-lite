#!/bin/bash

# --- 全局变量和样式 ---
# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 文件路径常量
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_DIR="/usr/local/etc/sing-box"
CONFIG_FILE="${SINGBOX_DIR}/config.json"
CLASH_YAML_FILE="${SINGBOX_DIR}/clash.yaml"
METADATA_FILE="${SINGBOX_DIR}/metadata.json"
YQ_BINARY="/usr/local/bin/yq"
SELF_SCRIPT_PATH="$0"
LOG_FILE="/var/log/sing-box.log"
PID_FILE="/run/sing-box.pid"

# 系统特定变量
INIT_SYSTEM="" # 将存储 'systemd', 'openrc' 或 'direct'
SERVICE_FILE="" # 将根据 INIT_SYSTEM 设置

# 脚本元数据
SCRIPT_VERSION="2.2"

# 全局状态变量
server_ip=""

# --- 工具函数 ---

# 打印消息
_echo_style() {
    local color_prefix="$1"
    local message="$2"
    echo -e "${color_prefix}${message}${NC}"
}

_info() { _echo_style "${CYAN}" "$1"; }
_success() { _echo_style "${GREEN}" "$1"; }
_warning() { _echo_style "${YELLOW}" "$1"; }
_error() { _echo_style "${RED}" "$1"; }

# 捕获退出信号，清理临时文件
trap 'rm -f ${SINGBOX_DIR}/*.tmp' EXIT

# 检查root权限
_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        _error "错误：本脚本需要以 root 权限运行！"
        exit 1
    fi
}

# URL编码
_url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}
export -f _url_encode

# 获取公网IP
_get_public_ip() {
    _info "正在获取服务器公网 IP..."
    server_ip=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s6 --max-time 2 icanhazip.com || curl -s6 --max-time 2 ipinfo.io/ip)
    fi
    if [ -z "$server_ip" ]; then
        _error "无法获取本机的公网 IP 地址！请检查网络连接。"
        exit 1
    fi
    _success "获取成功: ${server_ip}"
}

# --- 系统环境适配 ---

_detect_init_system() {
    if [ -f "/sbin/openrc-run" ]; then
        INIT_SYSTEM="openrc"
        SERVICE_FILE="/etc/init.d/sing-box"
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
        SERVICE_FILE="/etc/systemd/system/sing-box.service"
    else
        INIT_SYSTEM="direct"
        SERVICE_FILE="" # 在直接管理模式下无服务文件
        _warning "未检测到 systemd 或 OpenRC。将使用直接进程管理模式。"
        _warning "注意：在此模式下，sing-box 服务无法开机自启。"
    fi
    _info "检测到管理模式为: ${INIT_SYSTEM}"
}

_install_dependencies() {
    _info "正在检查并安装所需依赖..."
    local pkgs_to_install=""
    local required_pkgs="curl jq openssl wget procps"
    local pm=""

    if command -v apk &>/dev/null; then
        pm="apk"
        required_pkgs="bash coreutils ${required_pkgs}"
    elif command -v apt-get &>/dev/null; then pm="apt-get";
    elif command -v dnf &>/dev/null; then pm="dnf";
    elif command -v yum &>/dev/null; then pm="yum";
    else _warning "未能识别的包管理器, 无法自动安装依赖。"; fi

    if [ -n "$pm" ]; then
        if [ "$pm" == "apk" ]; then
            for pkg in $required_pkgs; do ! apk -e info "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            if [ -n "$pkgs_to_install" ]; then
                _info "正在安装缺失的依赖:$pkgs_to_install"
                apk update && apk add --no-cache $pkgs_to_install || { _error "依赖安装失败"; exit 1; }
            fi
        else # for apt, dnf, yum
            if [ "$pm" == "apt-get" ]; then
                for pkg in $required_pkgs; do ! dpkg -s "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            else
                for pkg in $required_pkgs; do ! rpm -q "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            fi

            if [ -n "$pkgs_to_install" ]; then
                _info "正在安装缺失的依赖:$pkgs_to_install"
                [ "$pm" == "apt-get" ] && $pm update -y
                $pm install -y $pkgs_to_install || { _error "依赖安装失败"; exit 1; }
            fi
        fi
    fi

    if ! command -v yq &>/dev/null; then
        _info "正在安装 yq (用于YAML处理)..."
        local arch=$(uname -m)
        local yq_arch_tag
        case $arch in
            x86_64|amd64) yq_arch_tag='amd64' ;;
            aarch64|arm64) yq_arch_tag='arm64' ;;
            armv7l) yq_arch_tag='arm' ;;
            *) _error "yq 安装失败: 不支持的架构：$arch"; exit 1 ;;
        esac
        
        wget -qO ${YQ_BINARY} "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch_tag}" || { _error "yq 下载失败"; exit 1; }
        chmod +x ${YQ_BINARY}
    fi
    _success "所有依赖均已满足。"
}

_install_sing_box() {
    _info "正在安装最新稳定版 sing-box..."

    # 1. 检测架构
    local uname_arch="$(uname -m)"
    local arch_tag=""
    case "$uname_arch" in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l|armv7) arch_tag='armv7' ;;
        *)
            _error "不支持的架构：$uname_arch"
            exit 1
            ;;
    esac

    # 2. 判断 libc 类型
    local is_musl="false"
    if [ -f /etc/alpine-release ] || ldd --version 2>&1 | grep -qi musl; then
        is_musl="true"
    fi

    # 3. 构造正确的匹配正则 (最终修正：移除了所有 \ 转义符)
    local expected_name_regex=""
    if [ "$is_musl" = "true" ]; then
        expected_name_regex="linux-${arch_tag}-musl.tar.gz$"
    else
        expected_name_regex="linux-${arch_tag}.tar.gz$"
    fi

    # 4. 获取下载地址 (健壮逻辑)
    _info "正在从 SagerNet API 获取下载链接..."
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    
    # 直接在返回的 assets 列表中查找并提取最终下载链接
    local download_url=$(curl -fsSL "$api_url" | jq -r ".assets[] | select(.name | test(\"${expected_name_regex}\")) | .browser_download_url")

    # 5. 备用逻辑：如果 "latest" 版本为空，则从所有版本列表中查找
    if [ -z "$download_url" ]; then
        _warning "最新版 (latest) 中未找到可用文件，正在扫描所有历史版本..."
        api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
        download_url=$(curl -fsSL "$api_url" | jq -r "[.[] | .assets[] | select(.name | test(\"${expected_name_regex}\"))] | first | .browser_download_url")
    fi

    # 6. 最终检查
    if [ -z "$download_url" ] || [ "$download_url" = "null" ]; then
        _error "错误：无法在 SagerNet 的任何版本中找到匹配 '${expected_name_regex}' 的文件。"
        _error "请检查您的系统架构是否受支持，或稍后再试。"
        exit 1
    fi
    
    _success "成功获取下载链接: ${download_url}"

    # 7. 下载并安装
    local tmp_dir
    tmp_dir=$(mktemp -d)
    wget -qO "${tmp_dir}/singbox.tar.gz" "$download_url" || { _error "下载失败！"; rm -rf "$tmp_dir"; exit 1; }
    tar -xzf "${tmp_dir}/singbox.tar.gz" -C "$tmp_dir" || { _error "解压失败！"; rm -rf "$tmp_dir"; exit 1; }

    local extracted_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name "sing-box-*" | head -n 1)
    if [ -z "$extracted_dir" ]; then
        _error "未找到解压后的目录！"; rm -rf "$tmp_dir"; exit 1;
    fi

    install -m 755 "${extracted_dir}/sing-box" "/usr/local/bin/sing-box" || { _error "安装失败！"; rm -rf "$tmp_dir"; exit 1; }
    rm -rf "$tmp_dir"

    _success "sing-box 安装成功, 版本: $(/usr/local/bin/sing-box version 2>/dev/null || echo 未知)"
}

# --- 服务与配置管理 ---

_create_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
[Service]
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
}

_create_openrc_service() {
    cat > "$SERVICE_FILE" <<EOF
#!/sbin/openrc-run

description="sing-box service"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE}"
command_user="root"
pidfile="${PID_FILE}"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting sing-box"
    start-stop-daemon --start --background \\
        --make-pidfile --pidfile \${pidfile} \\
        --exec \${command} -- \${command_args} >> "${LOG_FILE}" 2>&1
    eend \$?
}

stop() {
    ebegin "Stopping sing-box"
    start-stop-daemon --stop --pidfile \${pidfile}
    eend \$?
}
EOF
    chmod +x "$SERVICE_FILE"
}

_create_service_files() {
    if [ "$INIT_SYSTEM" == "direct" ]; then
        _info "在直接管理模式下，无需创建服务文件。"
        return
    fi
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


_manage_service() {
    local action="$1"
    [ "$action" == "status" ] || _info "正在使用 ${INIT_SYSTEM} 执行: $action..."

    case "$INIT_SYSTEM" in
        systemd)
            case "$action" in
                start|stop|restart|enable|disable) systemctl "$action" sing-box ;;
                status) systemctl status sing-box --no-pager -l; return ;;
                *) _error "无效的服务管理命令: $action"; return ;;
            esac
            ;;
        openrc)
             if [ "$action" == "status" ]; then
                rc-service sing-box status
                return
             fi
             rc-service sing-box "$action"
            ;;
        direct)
            case "$action" in
                start)
                    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _warning "sing-box 似乎已在运行。"
                        return
                    fi
                    touch "$LOG_FILE"
                    nohup ${SINGBOX_BIN} run -c ${CONFIG_FILE} >> ${LOG_FILE} 2>&1 &
                    echo $! > ${PID_FILE}
                    sleep 1
                    if ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _success "sing-box 启动成功, PID: $(cat ${PID_FILE})。"
                    else
                        _error "sing-box 启动失败，请检查日志: ${LOG_FILE}"
                        rm -f ${PID_FILE}
                    fi
                    ;;
                stop)
                    if [ ! -f "$PID_FILE" ]; then
                        _warning "未找到 PID 文件，可能未在运行。"
                        return
                    fi
                    local pid=$(cat "$PID_FILE")
                    if ps -p $pid > /dev/null; then
                        kill $pid
                        sleep 1
                        if ps -p $pid > /dev/null; then
                           _warning "无法正常停止，正在强制终止..."
                           kill -9 $pid
                        fi
                    else
                        _warning "PID 文件中的进程 ($pid) 不存在。"
                    fi
                    rm -f ${PID_FILE}
                    ;;
                restart)
                    _manage_service "stop"
                    _manage_service "start"
                    ;;
                status)
                    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _success "sing-box 正在运行, PID: $(cat ${PID_FILE})。"
                    else
                        _error "sing-box 未运行。"
                    fi
                    return
                    ;;
                 *) _error "无效的命令: $action"; return ;;
            esac
            ;;
    esac
    _success "sing-box 服务已 $action"
}

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
    _warning "本操作将停止并禁用 sing-box 服务，删除所有相关文件以及本脚本自身。"
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        _manage_service "stop"
        if [ "$INIT_SYSTEM" == "systemd" ]; then
            systemctl disable sing-box >/dev/null 2>&1
            systemctl daemon-reload
        elif [ "$INIT_SYSTEM" == "openrc" ]; then
            rc-update del sing-box default >/dev/null 2>&1
        fi
        
        rm -rf ${SINGBOX_BIN} ${SINGBOX_DIR} ${SERVICE_FILE} ${YQ_BINARY} ${LOG_FILE} ${PID_FILE}
        _success "清理完成。脚本已自毁。再见！"
        rm -f "${SELF_SCRIPT_PATH}"
        exit 0
    else
        _info "卸载已取消。"
    fi
}

_initialize_config_files() {
    mkdir -p ${SINGBOX_DIR}
    [ -s "$CONFIG_FILE" ] || echo '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONFIG_FILE"
    [ -s "$METADATA_FILE" ] || echo "{}" > "$METADATA_FILE"
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

# --- [MODIFIED] 证书生成函数 ---
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

_add_node_to_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    _atomic_modify_yaml "$CLASH_YAML_FILE" ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name)"
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= . + ["'${proxy_name}'"] | .proxies |= unique)'
}

_remove_node_from_yaml() {
    local proxy_name="$1"
    _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == "'${proxy_name}'"))'
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= del(.[] | select(. == "'${proxy_name}'")))'
}

_add_vless_reality() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入伪装域名 (默认: microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"microsoft.com"}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    local uuid=$(${SINGBOX_BIN} generate uuid)
    local keypair=$(${SINGBOX_BIN} generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(${SINGBOX_BIN} generate rand --hex 8)
    local tag="vless-in-${port}"
    local name="VLESS-REALITY-${port}"
    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\"}}" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (REALITY) 节点添加成功!"
}

_add_vless_tcp() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-tcp-in-${port}"
    local name="VLESS-TCP-${port}"
    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":""}],"tls":{"enabled":false}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":false,"network":"tcp"}')
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (TCP) 节点添加成功!"
}

# --- [MODIFIED] 添加Hysteria2函数 ---
_add_hysteria2() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    read -p "请输入伪装域名 (默认: microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"microsoft.com"}

    local tag="hy2-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    
    # 为此节点生成专属证书
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1
    
    read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
    read -p "请输入上传速度 (默认 50 Mbps): " up_speed; up_speed=${up_speed:-"50 Mbps"}
    read -p "请输入下载速度 (默认 200 Mbps): " down_speed; down_speed=${down_speed:-"200 Mbps"}
    
    local obfs_password=""
    read -p "是否开启 QUIC 流量混淆 (salamander)? (y/N): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        _info "已启用 Salamander 混淆。"
    fi
    
    local name="Hysteria2-${port}"; local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local meta_json=$(jq -n --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" \
        '{ "up": $up, "down": $down } | if $op != "" then .obfsPassword = $op else . end')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg pw "$password" --arg sn "$server_name" --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" \
        '{"name":$n,"type":"hysteria2","server":$s,"port":($p|tonumber),"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"up":$up,"down":$down} | if $op != "" then .obfs="salamander" | .["obfs-password"]=$op else . end')
    _add_node_to_yaml "$proxy_json"
    
    _success "Hysteria2 节点添加成功!"
}

# --- [MODIFIED] 添加TUIC函数 ---
_add_tuic() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1

    read -p "请输入伪装域名 (默认: microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"microsoft.com"}

    local tag="tuic-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    
    # 为此节点生成专属证书
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1

    local uuid=$(${SINGBOX_BIN} generate uuid); local password=$(${SINGBOX_BIN} generate rand --hex 16)
    local name="TUICv5-${port}"; local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sn "$server_name" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    _add_node_to_yaml "$proxy_json"
    _success "TUICv5 节点添加成功!"
}

_add_shadowsocks_menu() {
    clear
    echo "========================================"
    _info "          添加 Shadowsocks 节点"
    echo "========================================"
    echo " 1) shadowsocks (aes-256-gcm)"
    echo " 2) shadowsocks-2022 (2022-blake3-aes-128-gcm)"
    echo "----------------------------------------"
    echo " 0) 返回"
    echo "========================================"
    read -p "请选择加密方式 [0-2]: " choice

    local method="" password="" name_prefix=""
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
        0) return 1 ;;
        *) _error "无效输入"; return 1 ;;
    esac

    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    local tag="${name_prefix}-in-${port}"; local name="${name_prefix}-${port}"; local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"type":"shadowsocks","tag":$t,"listen":"::","listen_port":($p|tonumber),"method":$m,"password":$pw}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"name":$n,"type":"ss","server":$s,"port":($p|tonumber),"cipher":$m,"password":$pw}')
    _add_node_to_yaml "$proxy_json"

    _success "Shadowsocks (${method}) 节点添加成功!"
    return 0
}

_add_socks() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    read -p "请输入用户名 (默认随机): " username; username=${username:-$(${SINGBOX_BIN} generate rand --hex 8)}
    read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
    local tag="socks-in-${port}"; local name="SOCKS5-${port}"; local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"type":"socks","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"username":$u,"password":$pw}]}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"name":$n,"type":"socks5","server":$s,"port":($p|tonumber),"username":$u,"password":$pw}')
    _add_node_to_yaml "$proxy_json"
    _success "SOCKS5 节点添加成功!"
}

_view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    
    _info "--- 当前节点信息 (共 $(jq '.inbounds | length' "$CONFIG_FILE") 个) ---"
    jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') type=$(echo "$node" | jq -r '.type') port=$(echo "$node" | jq -r '.listen_port')
        
        # 为了显示正确的分享链接，需要从clash.yaml中回溯IP/域名
        local proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}') | .name' ${CLASH_YAML_FILE} | head -n 1)
        local display_server=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
        local display_ip="$display_server"; [[ "$display_server" == *":"* ]] && display_ip="[$display_server]"
        
        echo "-------------------------------------"
        _info " 节点: ${tag}"
        local url=""
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                if [ "$(echo "$node" | jq -r '.tls.reality.enabled')" == "true" ]; then
                    local sn=$(echo "$node" | jq -r '.tls.server_name'); local flow=$(echo "$node" | jq -r '.users[0].flow')
                    local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE"); local pk=$(echo "$meta" | jq -r '.publicKey'); local sid=$(echo "$meta" | jq -r '.shortId')
                    url="vless://${uuid}@${display_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sn}&fp=chrome&flow=${flow}&pbk=${pk}&sid=${sid}#$(_url_encode "$tag")"
                else
                    url="vless://${uuid}@${display_ip}:${port}?type=tcp&security=none#$(_url_encode "$tag")"
                fi
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password');
                local sn=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE");
                local op=$(echo "$meta" | jq -r '.obfsPassword')
                local obfs_param=""; [[ -n "$op" && "$op" != "null" ]] && obfs_param="&obfs=salamander&obfs-password=${op}"
                url="hysteria2://${pw}@${display_ip}:${port}?sni=${sn}&insecure=1${obfs_param}#$(_url_encode "$tag")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                url="tuic://${uuid}:${pw}@${display_ip}:${port}?sni=${sn}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$tag")"
                ;;
            "shadowsocks")
                local m=$(echo "$node" | jq -r '.method'); local pw=$(echo "$node" | jq -r '.password')
                if [[ "$m" == "2022-blake3-aes-128-gcm" ]]; then
                     url="ss://$(_url_encode "${m}:${pw}")@${display_ip}:${port}#$(_url_encode "$tag")"
                else
                    local b64=$(echo -n "${m}:${pw}" | base64 | tr -d '\n')
                    url="ss://${b64}@${display_ip}:${port}#$(_url_encode "$tag")"
                fi
                ;;
            "socks")
                local u=$(echo "$node" | jq -r '.users[0].username'); local p=$(echo "$node" | jq -r '.users[0].password')
                _info "  类型: SOCKS5, 地址: $display_server, 端口: $port, 用户: $u, 密码: $p"
                ;;
        esac
        [ -n "$url" ] && echo -e "  ${YELLOW}分享链接:${NC} ${url}"
    done
    echo "-------------------------------------"
}

# --- [MODIFIED] 删除节点函数 ---
_delete_node() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    _info "--- 节点删除 ---"
    jq -r '.inbounds[] | "\(.tag) (\(.type)) @ \(.listen_port)"' "$CONFIG_FILE" | cat -n
    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    local count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$num" -gt "$count" ]; then _error "编号超出范围。"; return; fi

    local index=$((num - 1))
    local node_to_del_obj=$(jq ".inbounds[$index]" "$CONFIG_FILE")
    local tag_to_del=$(echo "$node_to_del_obj" | jq -r ".tag")
    local type_to_del=$(echo "$node_to_del_obj" | jq -r ".type")
    local port_to_del=$(echo "$node_to_del_obj" | jq -r ".listen_port")
    local proxy_name_to_del=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port_to_del}') | .name' ${CLASH_YAML_FILE} | head -n 1)

    read -p "$(echo -e ${YELLOW}"确定要删除节点 ${tag_to_del} 吗? (y/N): "${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "删除已取消。"
        return
    fi
    
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[${index}])" || return
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_del\")" || return
    if [ -n "$proxy_name_to_del" ]; then
        _remove_node_from_yaml "$proxy_name_to_del"
    fi

    # [NEW] 检查是否需要删除关联的证书文件
    if [ "$type_to_del" == "hysteria2" ] || [ "$type_to_del" == "tuic" ]; then
        local cert_to_del="${SINGBOX_DIR}/${tag_to_del}.pem"
        local key_to_del="${SINGBOX_DIR}/${tag_to_del}.key"
        if [ -f "$cert_to_del" ] || [ -f "$key_to_del" ]; then
            _info "正在删除节点关联的证书文件: ${cert_to_del}, ${key_to_del}"
            rm -f "$cert_to_del" "$key_to_del"
        fi
    fi
    
    _success "节点 ${tag_to_del} 已删除！"
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

_main_menu() {
    while true; do
        clear
        echo "===================================================="
        _info "      sing-box 全功能管理脚本 v${SCRIPT_VERSION}"
        echo "===================================================="
        _info "【节点管理】"
        echo "  1) 添加节点"
        echo "  2) 查看节点分享链接"
        echo "  3) 删除节点"
        echo "----------------------------------------------------"
        _info "【服务控制】"
        echo "  4) 重启 sing-box"
        echo "  5) 停止 sing-box"
        echo "  6) 查看 sing-box 运行状态"
        echo "  7) 查看 sing-box 实时日志"
        echo "----------------------------------------------------"
        _info "【脚本与配置】"
        echo "  8) 检查配置文件"
        echo "  9) 卸载 sing-box 及脚本"
        echo "----------------------------------------------------"
        echo "  0) 退出脚本"
        echo "===================================================="
        read -p "请输入选项 [0-9]: " choice

        case $choice in
            1) _show_add_node_menu ;;
            2) _view_nodes ;;
            3) _delete_node ;;
            4) _manage_service "restart" ;;
            5) _manage_service "stop" ;;
            6) _manage_service "status" ;;
            7) _view_log ;;
            8) _check_config ;;
            9) _uninstall ;;
            0) exit 0 ;;
            *) _error "无效输入，请重试。" ;;
        esac
        echo
        read -n 1 -s -r -p "按任意键返回主菜单..."
    done
}

_show_add_node_menu() {
    local needs_restart=false
    local action_result
    clear
    echo "========================================"
    _info "           sing-box 添加节点"
    echo "========================================"
    echo " 1) VLESS (Vision+REALITY)"
    echo " 2) VLESS (TCP)"
    echo " 3) Hysteria2"
    echo " 4) TUICv5"
    echo " 5) Shadowsocks"
    echo " 6) SOCKS5"
    echo "----------------------------------------"
    echo " 0) 返回主菜单"
    echo "========================================"
    read -p "请输入选项 [0-6]: " choice

    case $choice in
        1) _add_vless_reality; action_result=$? ;;
        2) _add_vless_tcp; action_result=$? ;;
        3) _add_hysteria2; action_result=$? ;;
        4) _add_tuic; action_result=$? ;;
        5) _add_shadowsocks_menu; action_result=$? ;;
        6) _add_socks; action_result=$? ;;
        0) return ;;
        *) _error "无效输入，请重试。" ;;
    esac

    if [ "$action_result" -eq 0 ]; then
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
    
    if [ ! -f "${SINGBOX_BIN}" ]; then
        _install_dependencies
        _install_sing_box
        _initialize_config_files
        _create_service_files
        _info "首次安装完成！正在启动 sing-box 服务..."
        _manage_service "start"
    fi
    
    _get_public_ip
    _main_menu
}

main

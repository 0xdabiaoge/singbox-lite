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
SCRIPT_VERSION="5.0" 
SCRIPT_UPDATE_URL="https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh" 

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

# --- URL 编码助手 ---
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
        _error "错误：未检测到 systemd 或 OpenRC 初始化系统。"
        _error "本脚本已不再支持 Direct (直接进程) 模式，请确保您的系统支持服务管理。"
        exit 1
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
    _warning "本操作将停止并禁用 [主脚本] 服务 (sing-box)，"
    _warning "删除所有相关文件 (包括 sing-box 主程序和 yq) 以及本脚本自身。"
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm_main
    
    if [[ "$confirm_main" != "y" && "$confirm_main" != "Y" ]]; then
        _info "卸载已取消。"
        return
    fi

    # [!!!] 新逻辑：增加一个保护标记，决定是否删除 sing-box 主程序
    local keep_singbox_binary=false
    
    local relay_script_path="/root/relay-install.sh"
    local relay_config_dir="/etc/sing-box" # 线路机配置目录
    local relay_detected=false

    if [ -f "$relay_script_path" ] || [ -d "$relay_config_dir" ]; then
        relay_detected=true
    fi

    if [ "$relay_detected" = true ]; then
        _warning "检测到 [线路机] 脚本/配置。是否一并卸载？"
        read -p "$(echo -e ${YELLOW}"是否同时卸载线路机服务? (y/N): "${NC})" confirm_relay
        
        if [[ "$confirm_relay" == "y" || "$confirm_relay" == "Y" ]]; then
            _info "正在卸载 [线路机]..."
            if [ -f "$relay_script_path" ]; then
                _info "正在执行: bash ${relay_script_path} uninstall"
                bash "${relay_script_path}" uninstall
                # [!] 注意：relay-install.sh 此时应该已经自删除了
                # [!] 但为保险起见，我们还是尝试删除一下，万一它失败了
                rm -f "$relay_script_path"
            else
                _warning "未找到 relay-install.sh，尝试手动清理线路机配置..."
                local relay_service_name="sing-box-relay"
                # [!!!] BUG 修复：使用 systemctl/rc-service 等命令，而不是引用 $INIT_SYSTEM
                if [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then
                    systemctl stop $relay_service_name >/dev/null 2>&1
                    systemctl disable $relay_service_name >/dev/null 2>&1
                    rm -f /etc/systemd/system/${relay_service_name}.service
                    systemctl daemon-reload
                elif [ -f "/sbin/openrc-run" ]; then
                    rc-service $relay_service_name stop >/dev/null 2>&1
                    rc-update del $relay_service_name default >/dev/null 2>&1
                    rm -f /etc/init.d/${relay_service_name}
                fi
                rm -rf "$relay_config_dir"
            fi
            _success "[线路机] 卸载完毕。"
            keep_singbox_binary=false 
        else
            _info "您选择了 [保留] 线路机服务。"
            _warning "为了保持线路机服务 [sing-box-relay] 正常运行："
            _success "sing-box 主程序 (${SINGBOX_BIN}) 将被 [保留]。"
            keep_singbox_binary=true 

            echo -e "${CYAN}----------------------------------------------------${NC}"
            _success "主脚本卸载后，您仍可使用以下命令管理 [线路机]："
            echo ""
            echo -e "  ${YELLOW}1. 查看链接:${NC} bash ${relay_script_path} view"
            echo -e "  ${YELLOW}2. 添加新中转:${NC} bash ${relay_script_path} add"
            echo -e "  ${YELLOW}3. 删除中转:${NC} bash ${relay_script_path} delete"
            
            local relay_service_name="sing-box-relay"
            local relay_log_file="/var/log/${relay_service_name}.log"
            
            # [!!!] 修正：此时 $INIT_SYSTEM 可能未定义，需重新检测
            if [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then
                echo -e "  ${YELLOW}4. 重启服务:${NC} systemctl restart ${relay_service_name}"
                echo -e "  ${YELLOW}5. 查看日志:${NC} journalctl -u ${relay_service_name} -f"
            elif [ -f "/sbin/openrc-run" ]; then
                echo -e "  ${YELLOW}4. 重启服务:${NC} rc-service ${relay_service_name} restart"
                echo -e "  ${YELLOW}5. 查看日志:${NC} tail -f ${relay_log_file}"
            fi
            echo ""
            _warning "--- [!] 如何彻底卸载 ---"
            _warning "当您不再需要线路机时，请登录并运行以下 [两] 条命令:"
            echo -e "  ${RED}1. bash ${relay_script_path} uninstall${NC}"
            echo -e "  ${RED}2. rm ${SINGBOX_BIN} ${relay_script_path}${NC}"
            echo -e "${CYAN}----------------------------------------------------${NC}"
            read -p "请仔细阅读以上信息，按任意键以继续卸载 [主脚本]..."
        fi
    fi
    # --- 联动逻辑结束 ---

    _info "正在卸载 [主脚本] (sing-box)..."
    _manage_service "stop"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl disable sing-box >/dev/null 2>&1
        systemctl daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-update del sing-box default >/dev/null 2>&1
    fi
    
    _info "正在删除主配置、yq、日志文件..."
    rm -rf ${SINGBOX_DIR} ${YQ_BINARY} ${SERVICE_FILE} ${LOG_FILE} ${PID_FILE}

    if [ "$keep_singbox_binary" = false ]; then
        _info "正在删除 sing-box 主程序..."
        rm -f ${SINGBOX_BIN}
    else
        _success "已 [保留] sing-box 主程序 (${SINGBOX_BIN})。"
    fi
    
    _success "清理完成。脚本已自毁。再见！"
    rm -f "${SELF_SCRIPT_PATH}"
    exit 0
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

_add_vless_ws_tls() {
    _info "--- VLESS (WebSocket+TLS) 设置向导 ---"
    
    # --- 步骤 1: 模式选择 ---
    echo "请选择连接模式："
    echo "  1. 直连模式 (回车默认, 适合直连使用)"
    echo "  2. 优选域名/IP模式 (适合IP被墙或者需要优选加速)"
    read -p "请输入选项 [1/2]: " mode_choice
    
    local client_server_addr=""
    local is_cdn_mode=false

    if [ "$mode_choice" == "2" ]; then
        # --- CDN 模式逻辑 ---
        is_cdn_mode=true
        _info "您选择了 [优选域名/IP模式]。"
        _info "请输入优选域名或优选IP"
        read -p "请输入 (回车默认 www.csgo.com): " cdn_input
        client_server_addr=${cdn_input:-"www.csgo.com"}
    else
        # --- 直连模式逻辑 ---
        _info "您选择了 [直连模式]。"
        _info "请输入客户端用于“连接”的地址:"
        _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
        _info "  - (其他)   您也可以手动输入一个IP或域名"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}
        
        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi
    fi

    # --- 步骤 2: 获取伪装域名 ---
    _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
    _info " (例如: xxx.987654.xyz)"
    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    # --- 步骤 3: 端口 (VPS监听端口) ---
    read -p "请输入监听端口 (直连模式下填写已经映射的端口，优选模式下填写CF回源设置的端口): " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1

    # 确定客户端连接端口
    local client_port="$port"
    if [ "$is_cdn_mode" == "true" ]; then
        client_port="443"
        _info "检测到 优选域名/IP模式 ，客户端连接端口已自动设置为: 443"
    fi

    # --- 步骤 4: 路径 ---
    read -p "请输入 WebSocket 路径 (回车则随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已为您生成随机 WebSocket 路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    # --- 步骤 5: 证书文件 ---
    _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
    _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
    _info "  - (或)   使用 Cloudflare 源服务器证书"
    read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
    [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

    read -p "请输入私钥文件 .key 的完整路径: " key_path
    [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
    
    # --- 步骤 6: 跳过验证 ---
    read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
    local skip_verify=false
    if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
        skip_verify=true
        _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
    fi
    
    # [!] 自定义名称 (核心修改点)
    local default_name="VLESS-WS-${port}"
    if [ "$is_cdn_mode" == "true" ]; then 
        default_name="VLESS-CDN-443" 
    fi
    
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-ws-in-${port}"
    
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
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

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
}

_add_trojan_ws_tls() {
    _info "--- Trojan (WebSocket+TLS) 设置向导 ---"
    
    # --- 步骤 1: 模式选择 ---
    echo "请选择连接模式："
    echo "  1. 直连模式 (回车默认, 适合直连使用)"
    echo "  2. 优选域名/IP模式 (适合IP被墙或者需要优选加速)"
    read -p "请输入选项 [1/2]: " mode_choice
    
    local client_server_addr=""
    local is_cdn_mode=false

    if [ "$mode_choice" == "2" ]; then
        # --- CDN 模式逻辑 ---
        is_cdn_mode=true
        _info "您选择了 [优选域名/IP模式]。"
        _info "请输入优选域名或优选IP"
        read -p "请输入 (回车默认 www.csgo.com): " cdn_input
        client_server_addr=${cdn_input:-"www.csgo.com"}
    else
        # --- 直连模式逻辑 ---
        _info "您选择了 [直连模式]。"
        _info "请输入客户端用于“连接”的地址:"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}
        
        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi
    fi

    # --- 步骤 2: 获取伪装域名 ---
    _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
    _info " (例如: xxx.987654.xyz)"
    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    # --- 步骤 3: 端口 (VPS监听端口) ---
    read -p "请输入监听端口 (直连模式下填写已经映射的端口，优选模式下填写CF回源设置的端口): " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1

    # 确定客户端连接端口
    local client_port="$port"
    if [ "$is_cdn_mode" == "true" ]; then
        client_port="443"
        _info "检测到 优选域名/IP模式 ，客户端连接端口已自动设置为: 443"
    fi

    # --- 步骤 4: 路径 ---
    read -p "请输入 WebSocket 路径 (回车则随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已为您生成随机 WebSocket 路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    # --- 步骤 5: 证书文件 ---
    _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
    read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
    [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

    read -p "请输入私钥文件 .key 的完整路径: " key_path
    [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
    
    # --- 步骤 6: 跳过验证 ---
    read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
    local skip_verify=false
    if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
        skip_verify=true
        _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
    fi

    # [!] Trojan: 使用密码
    read -p "请输入 Trojan 密码 (回车则随机生成): " password
    if [ -z "$password" ]; then
        password=$(${SINGBOX_BIN} generate rand --hex 16)
        _info "已为您生成随机密码: ${password}"
    fi

    # [!] 自定义名称 (核心修改点)
    local default_name="Trojan-WS-${port}"
    if [ "$is_cdn_mode" == "true" ]; then 
        default_name="Trojan-CDN-443" 
    fi
    
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local tag="trojan-ws-in-${port}"
    
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
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

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
}

_add_vless_reality() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入伪装域名 (默认: www.microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"www.microsoft.com"}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    # [!] 新增：自定义名称
    local default_name="VLESS-REALITY-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local keypair=$(${SINGBOX_BIN} generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(${SINGBOX_BIN} generate rand --hex 8)
    local tag="vless-in-${port}"
    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\"}}" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (REALITY) 节点 [${name}] 添加成功!"
}

_add_vless_tcp() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    # [!] 新增：自定义名称
    local default_name="VLESS-TCP-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-tcp-in-${port}"
    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":""}],"tls":{"enabled":false}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":false,"network":"tcp"}')
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (TCP) 节点 [${name}] 添加成功!"
}

_add_hysteria2() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    read -p "请输入伪装域名 (默认: www.microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"www.microsoft.com"}

    local tag="hy2-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1
    
    read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
    read -p "请输入上传速度 (默认 100 Mbps): " up_speed; up_speed=${up_speed:-"100 Mbps"}
    read -p "请输入下载速度 (默认 200 Mbps): " down_speed; down_speed=${down_speed:-"200 Mbps"}
    
    local obfs_password=""
    read -p "是否开启 QUIC 流量混淆 (salamander)? (y/N): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        _info "已启用 Salamander 混淆。"
    fi
    
    # [!] 新增：自定义名称
    local default_name="Hysteria2-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local meta_json=$(jq -n --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" \
        '{ "up": $up, "down": $down } | if $op != "" then .obfsPassword = $op else . end')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg pw "$password" --arg sn "$server_name" --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" \
        '{"name":$n,"type":"hysteria2","server":$s,"port":($p|tonumber),"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"up":$up,"down":$down} | if $op != "" then .obfs="salamander" | .["obfs-password"]=$op else . end')
    _add_node_to_yaml "$proxy_json"
    
    _success "Hysteria2 节点 [${name}] 添加成功!"
}

_add_tuic() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1

    read -p "请输入伪装域名 (默认: www.microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"www.microsoft.com"}

    local tag="tuic-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1

    local uuid=$(${SINGBOX_BIN} generate uuid); local password=$(${SINGBOX_BIN} generate rand --hex 16)
    
    # [!] 新增：自定义名称
    local default_name="TUICv5-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sn "$server_name" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    _add_node_to_yaml "$proxy_json"
    _success "TUICv5 节点 [${name}] 添加成功!"
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
    
    # [!] 新增：自定义名称
    local default_name="${name_prefix}-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local tag="${name_prefix}-in-${port}"; local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"type":"shadowsocks","tag":$t,"listen":"::","listen_port":($p|tonumber),"method":$m,"password":$pw}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"name":$n,"type":"ss","server":$s,"port":($p|tonumber),"cipher":$m,"password":$pw}')
    _add_node_to_yaml "$proxy_json"

    _success "Shadowsocks (${method}) 节点 [${name}] 添加成功!"
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
        local display_server=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
        # 移除方括号
        local display_ip=$(echo "$display_server" | tr -d '[]')
        
        echo "-------------------------------------"
        # [!] 已修改：使用 display_name
        _info " 节点: ${display_name}"
        local url=""
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                local transport_type=$(echo "$node" | jq -r '.transport.type')

                if [ "$transport_type" == "ws" ]; then
                    # VLESS + WS + TLS
                    local server_addr=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
                    local host_header=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .ws-opts.headers.Host' ${CLASH_YAML_FILE} | head -n 1)
                    local client_port=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .port' ${CLASH_YAML_FILE} | head -n 1)
                    local ws_path=$(echo "$node" | jq -r '.transport.path')
                    local encoded_path=$(_url_encode "$ws_path")
                    # [!] 已修改：使用 display_name
                    url="vless://${uuid}@${server_addr}:${client_port}?encryption=none&security=tls&type=ws&host=${host_header}&path=${encoded_path}#$(_url_encode "$display_name")"
                elif [ "$(echo "$node" | jq -r '.tls.reality.enabled')" == "true" ]; then
                    # VLESS + REALITY
                    local sn=$(echo "$node" | jq -r '.tls.server_name'); local flow=$(echo "$node" | jq -r '.users[0].flow')
                    local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE"); local pk=$(echo "$meta" | jq -r '.publicKey'); local sid=$(echo "$meta" | jq -r '.shortId')
                    # [!] 已修改：使用 display_name
                    url="vless://${uuid}@${display_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sn}&fp=chrome&flow=${flow}&pbk=${pk}&sid=${sid}#$(_url_encode "$display_name")"
                else
                    # VLESS + TCP
                    # [!] 已修改：使用 display_name
                    url="vless://${uuid}@${display_ip}:${port}?type=tcp&security=none#$(_url_encode "$display_name")"
                fi
                ;;
            
            # [!!!] 新增 TROJAN 支持
            "trojan")
                local password=$(echo "$node" | jq -r '.users[0].password')
                local transport_type=$(echo "$node" | jq -r '.transport.type')

                if [ "$transport_type" == "ws" ]; then
                    # Trojan + WS + TLS
                    local server_addr=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
                    local host_header=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .ws-opts.headers.Host' ${CLASH_YAML_FILE} | head -n 1)
                    local client_port=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .port' ${CLASH_YAML_FILE} | head -n 1)
                    local ws_path=$(echo "$node" | jq -r '.transport.path')
                    local encoded_path=$(_url_encode "$ws_path")
                    
                    # [!] 修复BUG：这里原来是 .servername，对于 Trojan 应该读取 .sni
                    local sni=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                    
                    # [!] 已修改：使用 display_name
                    url="trojan://$(_url_encode "$password")@${server_addr}:${client_port}?encryption=none&security=tls&type=ws&host=${host_header}&path=${encoded_path}&sni=${sni}#$(_url_encode "$display_name")"
                else
                    # Trojan (TCP)
                    _info "  类型: Trojan (TCP), 地址: $display_server, 端口: $port, 密码: [已隐藏]"
                fi
                ;;

            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password');
                local sn=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE");
                local op=$(echo "$meta" | jq -r '.obfsPassword')
                local obfs_param=""; [[ -n "$op" && "$op" != "null" ]] && obfs_param="&obfs=salamander&obfs-password=${op}"
                # [!] 已修改：使用 display_name
                url="hysteria2://${pw}@${display_ip}:${port}?sni=${sn}&insecure=1${obfs_param}#$(_url_encode "$display_name")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                # [!] 已修改：使用 display_name
                url="tuic://${uuid}:${pw}@${display_ip}:${port}?sni=${sn}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$display_name")"
                ;;
            "shadowsocks")
                local m=$(echo "$node" | jq -r '.method'); local pw=$(echo "$node" | jq -r '.password')
                if [[ "$m" == "2022-blake3-aes-128-gcm" ]]; then
                     # [!] 已修改：使用 display_name
                     url="ss://$(_url_encode "${m}:${pw}")@${display_ip}:${port}#$(_url_encode "$display_name")"
                else
                    local b64=$(echo -n "${m}:${pw}" | base64 | tr -d '\n')
                    # [!] 已修改：使用 display_name
                    url="ss://${b64}@${display_ip}:${port}#$(_url_encode "$display_name")"
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
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') 
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

    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    
    # [!] 已修改：现在 count 会在循环外被正确计算
    local count=${#inbound_tags[@]}
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
    
    # [!] 已修改：使用索引从 config.json 中删除
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[${index}])" || return
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_del\")" || return # Metadata 仍然使用 tag，这是正确的
    
    # [!] 已修改：使用找到的 proxy_name_to_del 从 clash.yaml 中删除
    if [ -n "$proxy_name_to_del" ]; then
        _remove_node_from_yaml "$proxy_name_to_del"
    fi

    # 证书清理逻辑不变 (基于 tag)，这是正确的
    if [ "$type_to_del" == "hysteria2" ] || [ "$type_to_del" == "tuic" ]; then
        local cert_to_del="${SINGBOX_DIR}/${tag_to_del}.pem"
        local key_to_del="${SINGBOX_DIR}/${tag_to_del}.key"
        if [ -f "$cert_to_del" ] || [ -f "$key_to_del" ]; then
            _info "正在删除节点关联的证书文件: ${cert_to_del}, ${key_to_del}"
            rm -f "$cert_to_del" "$key_to_del"
        fi
    fi
    
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

# 新增更新脚本及SingBox核心
_update_script() {
    _info "--- 更新此管理脚本 ---"
    
    if [ "$SCRIPT_UPDATE_URL" == "YOUR_GITHUB_RAW_URL_HERE/singbox.sh" ]; then
        _error "错误：您尚未在脚本中配置 SCRIPT_UPDATE_URL 变量。"
        _warning "请编辑此脚本，找到 SCRIPT_UPDATE_URL 并填入您正确的 GitHub raw 链接。"
        return 1
    fi

    _info "正在从 GitHub 下载最新脚本..."
    local temp_script_path="${SELF_SCRIPT_PATH}.tmp"
    
    if wget -qO "$temp_script_path" "$SCRIPT_UPDATE_URL"; then
        if [ ! -s "$temp_script_path" ]; then
            _error "下载失败或文件为空！请检查您的 SCRIPT_UPDATE_URL 链接。"
            rm -f "$temp_script_path"
            return 1
        fi
        
        # 赋予执行权限并替换旧脚本
        chmod +x "$temp_script_path"
        mv "$temp_script_path" "$SELF_SCRIPT_PATH"
        _success "脚本更新成功！"
        _info "请重新运行脚本以加载新版本："
        echo -e "${YELLOW}bash ${SELF_SCRIPT_PATH}${NC}"
        exit 0
    else
        _error "下载失败！请检查网络或 GitHub 链接。"
        rm -f "$temp_script_path"
        return 1
    fi
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

# [!] 已修改：菜单 9 现在只生成混合模式脚本
_generate_relay_script() {
    _info "--- 生成 [混合模式] 中转落地脚本 (第 1/2 步) ---"
    _info "此功能将生成一个新脚本，用于在“线路机”上部署。"
    _info "它会将“线路机”的流量转发到本机的 Shadowsocks 节点。"
    _warning "您必须已在本机上创建了一个 Shadowsocks 节点才能继续。"

    # 1. 查找本机可用的 SS 节点
    local ss_inbounds=$(jq -c '.inbounds[] | select(.type == "shadowsocks")' "$CONFIG_FILE")
    if [ -z "$ss_inbounds" ]; then
        _error "错误：未在本机找到任何 Shadowsocks (SS) 节点。"
        _warning "请先使用 [1) 添加节点] 菜单添加一个 Shadowsocks 节点作为落地。"
        return 1
    fi

    # 2. 让用户选择 SS 落地节点
    _info "请选择一个本机的 SS 节点作为“落地” (中转的出口)："
    local ss_options=()
    local i=1
    while IFS= read -r line; do
        local tag=$(echo "$line" | jq -r '.tag')
        local port=$(echo "$line" | jq -r '.listen_port')
        local method=$(echo "$line" | jq -r '.method')
        local type="shadowsocks"

        # --- 名称查找逻辑 ---
        local proxy_name_to_find=""
        local proxy_obj_by_port=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}')' ${CLASH_YAML_FILE} | head -n 1)
        if [ -n "$proxy_obj_by_port" ]; then
             proxy_name_to_find=$(echo "$proxy_obj_by_port" | ${YQ_BINARY} eval '.name' -)
        fi
        if [[ -z "$proxy_name_to_find" ]]; then
            proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' and .type == "ss") | .name' ${CLASH_YAML_FILE} | head -n 1)
        fi
        local display_name=${proxy_name_to_find:-$tag} 
        
        echo -e " ${CYAN}$i)${NC} ${display_name} (端口: ${port}, 方法: ${method})"
        ss_options+=("$line")
        ((i++))
    done <<< "$ss_inbounds"
    echo " 0) 返回"
    read -p "请输入选项: " choice

    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        _info "操作已取消。"
        return
    fi

    # 3. 解析所选节点
    local selected_json=${ss_options[$((choice-1))]}
    local INBOUND_METHOD=$(echo "$selected_json" | jq -r '.method')
    local INBOUND_PASSWORD=$(echo "$selected_json" | jq -r '.password')
    local INBOUND_PORT=$(echo "$selected_json" | jq -r '.listen_port')
    local INBOUND_IP=$server_ip
    
    _success "已选择落地节点：${INBOUND_IP}:${INBOUND_PORT} (方法: ${INBOUND_METHOD})"

    # 4. 生成脚本
    _info "--- 正在生成 [混合模式] 模板 (第 2/2 步) ---"
    local RELAY_SCRIPT_PATH="/root/relay-install.sh"
    
    _generate_relay_script_hybrid "$INBOUND_IP" "$INBOUND_PORT" "$INBOUND_METHOD" "$INBOUND_PASSWORD" "$RELAY_SCRIPT_PATH"
    
    if [ $? -eq 0 ]; then
        echo ""
        _success "✅ 线路机脚本已成功生成在: ${RELAY_SCRIPT_PATH}"
        
        # --- [新增] 临时 HTTP 服务器逻辑 ---
        echo ""
        _info "为了方便传输，是否在本机开启临时的 HTTP 下载服务器？"
        _info "开启后，您将获得一个 http://IP:端口/relay-install.sh 的链接。"
        _info "您只需在线路机的 [菜单 10] 中输入该链接即可自动下载。"
        
        read -p "$(echo -e ${YELLOW}"是否开启临时下载服务? (y/N): "${NC})" enable_http
        
        if [[ "$enable_http" == "y" || "$enable_http" == "Y" ]]; then
            # 定义标记变量：是否由脚本安装了python
            local installed_python_by_script=false

            # --- 1. 检测 Python3 ---
            if ! command -v python3 &>/dev/null; then
                _warning "未检测到 python3，正在尝试自动安装..."
                if [ -f /etc/alpine-release ]; then
                    if apk update && apk add --no-cache python3; then
                        installed_python_by_script=true
                    fi
                elif command -v apt-get &>/dev/null; then
                    if apt-get update && apt-get install -y python3; then
                        installed_python_by_script=true
                    fi
                elif command -v yum &>/dev/null; then
                    if yum install -y python3; then
                        installed_python_by_script=true
                    fi
                fi
            else
                _info "检测到系统已存在 Python3，跳过安装。"
            fi

            # --- 2. 再次检查 ---
            if ! command -v python3 &>/dev/null; then
                _error "Python3 安装失败，无法开启临时服务。请手动传输文件。"
            else
                # --- 3. 准备 IP 和 端口 ---
                echo ""
                _info "正在检测本机 IP 地址..."
                local local_ips=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1)
                echo -e "本机可用 IP 列表:\n${CYAN}${local_ips}${NC}"
                
                [ -z "$server_ip" ] && _get_public_ip
                read -p "请输入 HTTP 服务使用的 IP (回车默认 ${server_ip}): " user_ip
                local bind_ip=${user_ip:-$server_ip}

                local random_port=$(shuf -i 10000-60000 -n 1)
                read -p "请输入 HTTP 服务端口 (回车默认随机 ${random_port}): " user_port
                local http_port=${user_port:-$random_port}

                if ! [[ "$http_port" =~ ^[0-9]+$ ]] || [ "$http_port" -lt 1 ] || [ "$http_port" -gt 65535 ]; then
                    _warning "输入的端口无效 ($user_port)，已自动切换回随机端口: ${random_port}"
                    http_port=$random_port
                fi
                
                local download_url="http://${bind_ip}:${http_port}/relay-install.sh"
                
                echo ""
                echo -e "${GREEN}====================================================${NC}"
                echo -e "  临时下载服务已开启 (按 Ctrl+C 停止)"
                echo -e "  下载链接: ${YELLOW}${download_url}${NC}"
                echo -e "${GREEN}====================================================${NC}"
                _warning "注意：请确保防火墙已放行 TCP 端口: ${http_port}"
                _info "正在运行 HTTP 服务... 请现在去线路机操作 [菜单 10]。"
                _info "线路机下载完成后，请回到这里按 Ctrl+C 关闭服务。"
                
                local temp_web_dir=$(mktemp -d)
                cp "$RELAY_SCRIPT_PATH" "$temp_web_dir/relay-install.sh"
                
                pushd "$temp_web_dir" >/dev/null
                python3 -m http.server "$http_port"
                popd >/dev/null
                
                # --- [重点] 服务结束后的清理逻辑 ---
                # 立即屏蔽 SIGINT (Ctrl+C) 信号，防止用户多按跳过询问
                trap '' SIGINT

                rm -rf "$temp_web_dir"
                echo "" 
                _info "HTTP 服务已关闭，临时文件已清理。"

                # 只有当 Python 是由本脚本安装时，才询问是否卸载
                if [ "$installed_python_by_script" = true ]; then
                    echo ""
                    _warning "检测到 Python3 是由本脚本刚刚为您安装的。"
                    _warning "为了节省空间，建议将其卸载。"
                    
                    while true; do
                        # 使用 -r 防止反斜杠转义
                        read -r -p "$(echo -e ${YELLOW}"是否彻底卸载 Python3 及其依赖? (y/N): "${NC})" confirm_uninstall
                        case "$confirm_uninstall" in
                            [yY]|[yY][eE][sS])
                                _info "正在彻底卸载 Python3..."
                                if [ -f /etc/alpine-release ]; then
                                    apk del python3
                                elif command -v apt-get &>/dev/null; then
                                    apt-get remove -y python3 python3-minimal
                                    apt-get autoremove -y
                                elif command -v yum &>/dev/null; then
                                    yum remove -y python3
                                fi
                                _success "Python3 已成功卸载并清理。"
                                break
                                ;;
                            [nN]|[nN][oO]|"")
                                _info "已保留 Python3。"
                                break
                                ;;
                            *)
                                # 如果用户输入其他字符（包括狂按回车），提示重试
                                echo "请输入 y 或 n 进行确认。"
                                ;;
                        esac
                    done
                else
                    _info "系统原有的 Python3 将被保留。"
                fi

                # 恢复信号处理 (虽然函数马上结束了，但这是一个好习惯)
                trap - SIGINT
                return
            fi
        fi
        # --- [新增] 逻辑结束 ---

        echo ""
        _info "如果不使用链接下载，请手动传输文件："
        _info "请将 ${RELAY_SCRIPT_PATH} 传输到线路机的 /root 目录。"
        _info "然后在“线路机”上执行: chmod +x ${RELAY_SCRIPT_PATH} && ${RELAY_SCRIPT_PATH}"
        echo ""
        _warning "如需卸载此中转机配置，请在线路机上执行: bash ${RELAY_SCRIPT_PATH} uninstall"
        _warning "如需查看此中转机链接，请在线路机上执行: bash ${RELAY_SCRIPT_PATH} view"
        _warning "如需添加更多中转路由，请在线路机上执行: bash ${RELAY_SCRIPT_PATH} add"
        _warning "如需删除单个中转路由，请在线路机上执行: bash ${RELAY_SCRIPT_PATH} delete"
    else
        _error "线路机脚本生成失败。"
    fi
}

#
# --- 函数 4: [新] 混合模式 模板 (VLESS + Hy2 + TUICv5) ---
#
_generate_relay_script_hybrid() {
    local INBOUND_IP="$1"
    local INBOUND_PORT="$2"
    local INBOUND_METHOD="$3"
    local INBOUND_PASSWORD="$4"
    local RELAY_SCRIPT_PATH="$5"

    # 4. 插入模板 (这是一个为线路机准备的、自包含的脚本)
    cat > "$RELAY_SCRIPT_PATH" << 'RELAY_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail
# --- 占位符 (将被替换) ---
INBOUND_IP="__INBOUND_IP__"
INBOUND_PORT="__INBOUND_PORT__"
INBOUND_METHOD="__INBOUND_METHOD__"
INBOUND_PASSWORD="__INBOUND_PASSWORD__"
# --- 颜色 ---
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- URL 编码助手 ---
_url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}
export -f _url_encode

# --- 全局常量 ---
SERVICE_NAME="sing-box-relay"
CONFIG_DIR="/etc/sing-box" 
CONFIG_FILE="${CONFIG_DIR}/config.json"
LINK_FILE_VLESS="${CONFIG_DIR}/vless_links.txt" # 存储 TAG:LINK
LINK_FILE_HY2="${CONFIG_DIR}/hy2_links.txt" # 存储 TAG:LINK
LINK_FILE_TUIC="${CONFIG_DIR}/tuic_links.txt" # 存储 TAG:LINK
LOG_FILE="/var/log/${SERVICE_NAME}.log"
PID_FILE="/run/${SERVICE_NAME}.pid"
SINGBOX_BIN="/usr/local/bin/sing-box"

# --- 卸载功能 ---
action_uninstall() {
    info "正在卸载 sing-box (中转机: ${SERVICE_NAME})..."
    local INIT_SYSTEM=$(_detect_init_system)
    info "检测到 $INIT_SYSTEM 模式"
    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop $SERVICE_NAME >/dev/null 2>&1
            systemctl disable $SERVICE_NAME >/dev/null 2>&1
            rm -f /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload
            ;;
        openrc)
            rc-service $SERVICE_NAME stop >/dev/null 2>&1
            rc-update del $SERVICE_NAME default >/dev/null 2>&1
            rm -f /etc/init.d/${SERVICE_NAME}
            ;;
    esac
    info "服务 [${SERVICE_NAME}] 已停止并移除。"
    rm -rf "$CONFIG_DIR" 
    rm -f $LOG_FILE $PID_FILE
    warn "[!] 注意：sing-box 主程序 (${SINGBOX_BIN}) 未被删除。"
    info "中转机配置已删除。"

    info "脚本正在自删除... 再见！"
    rm -f "$0" # $0 指向当前脚本文件
    exit 0
}

# --- 查看链接功能 ---
action_view() {
    local link_found=false

    if [ -f "$LINK_FILE_VLESS" ] && [ -s "$LINK_FILE_VLESS" ]; then
        link_found=true
        info "--- VLESS Reality 中转链接 (共 $(wc -l < "$LINK_FILE_VLESS") 个) ---"
        echo ""
        local i=1
        while IFS= read -r line; do
            local link_only=$(echo "$line" | cut -d':' -f2-)
            echo -e "  ${CYAN}$i)${NC} \033[1;33m${link_only}\033[0m"
            ((i++))
        done < "$LINK_FILE_VLESS"
        echo ""
    fi
    
    if [ -f "$LINK_FILE_HY2" ] && [ -s "$LINK_FILE_HY2" ]; then
        link_found=true
        info "--- Hysteria2 中转链接 (共 $(wc -l < "$LINK_FILE_HY2") 个) ---"
        echo ""
        local i=1
        while IFS= read -r line; do
            local link_only=$(echo "$line" | cut -d':' -f2-)
            echo -e "  ${CYAN}$i)${NC} \033[1;33m${link_only}\033[0m"
            ((i++))
        done < "$LINK_FILE_HY2"
        echo ""
    fi
    
    if [ -f "$LINK_FILE_TUIC" ] && [ -s "$LINK_FILE_TUIC" ]; then
        link_found=true
        info "--- TUICv5 中转链接 (共 $(wc -l < "$LINK_FILE_TUIC") 个) ---"
        echo ""
        local i=1
        while IFS= read -r line; do
            local link_only=$(echo "$line" | cut -d':' -f2-)
            echo -e "  ${CYAN}$i)${NC} \033[1;33m${link_only}\033[0m"
            ((i++))
        done < "$LINK_FILE_TUIC"
        echo ""
    fi

    if [ "$link_found" = false ]; then
        err "未找到任何链接文件 (vless, hy2, 或 tuic)"
        err "请先运行一次安装 (不带参数) 或 'add' (添加)。"
        return 1
    fi
}

# --- 重启服务 助手 ---
_detect_init_system() {
    if [ -f "/sbin/openrc-run" ]; then echo "openrc";
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then echo "systemd";
    else echo "unknown"; fi 
}
_restart_relay_service() {
    local INIT_SYSTEM=$(_detect_init_system)
    if [ "$INIT_SYSTEM" == "unknown" ]; then 
        err "不支持的系统 init"
        exit 1
    fi
    info "正在使用 $INIT_SYSTEM 模式重启 [${SERVICE_NAME}]..."
    case "$INIT_SYSTEM" in
        systemd) systemctl restart $SERVICE_NAME ;;
        openrc) rc-service $SERVICE_NAME restart ;;
    esac
    sleep 1
    info "服务已重启。"
}

# --- 生成自签名证书 助手 (Hy2 和 TUICv5 使用) ---
_generate_self_signed_cert() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"
    info "正在为 ${domain} 生成自签名证书..."
    openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${domain}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then err "为 ${domain} 生成证书失败！"; return 1; fi
    info "证书 ${cert_path} 和私钥 ${key_path} 已成功生成。"
}

# --- 添加 VLESS 逻辑 (内部函数) ---
_action_add_vless() {
    info "--- 添加一个新的 VLESS+REALITY 中转路由 ---"
    info "步骤 1/3: 请输入 [新落地机] 的 SS 信息"
    read -p "  > 落地机 IP 地址: " NEW_INBOUND_IP
    read -p "  > 落地机 SS 端口: " NEW_INBOUND_PORT
    read -p "  > 落地机 SS 密码: " NEW_INBOUND_PASSWORD
    read -p "  > 落地机 SS 方法 (默认 2022-blake3-aes-128-gcm): " NEW_INBOUND_METHOD
    [ -z "$NEW_INBOUND_METHOD" ] && NEW_INBOUND_METHOD="2022-blake3-aes-128-gcm"
    info "步骤 2/3: 请输入 [线路机] (A) 的新入口配置"
    read -p "  > 线路机新监听端口 : " NEW_LISTEN_PORT
    read -p "  > 线路机新伪装SNI (默认 www.microsoft.com): " NEW_SNI
    [ -z "$NEW_SNI" ] && NEW_SNI="www.microsoft.com"
    if [ -z "$NEW_INBOUND_IP" ] || [ -z "$NEW_INBOUND_PORT" ] || [ -z "$NEW_LISTEN_PORT" ]; then
        err "IP 和 端口 不能为空！"; return 1; fi

    info "步骤 3/3: 请输入节点名称"
    local default_name="VLESS-R-${NEW_LISTEN_PORT}"
    read -p "  > 节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    info "正在生成新密钥..."
    local TAG_SUFFIX=$NEW_LISTEN_PORT
    local VLESS_TAG="vless-in-${TAG_SUFFIX}"
    local SS_TAG="relay-out-${TAG_SUFFIX}"
    local UUID=$($SINGBOX_BIN generate uuid)
    local REALITY_KEYS=$($SINGBOX_BIN generate reality-keypair)
    local REALITY_PK=$(echo "$REALITY_KEYS" | awk '/PrivateKey/ {print $2}')
    local REALITY_PUB=$(echo "$REALITY_KEYS" | awk '/PublicKey/ {print $2}')
    local REALITY_SID=$($SINGBOX_BIN generate rand 8 --hex)
    info "正在构建新的 JSON 片段..."
    local new_inbound_json=$(jq -n --arg t "$VLESS_TAG" --arg p "$NEW_LISTEN_PORT" --arg u "$UUID" --arg sn "$NEW_SNI" --arg pk "$REALITY_PK" --arg sid "$REALITY_SID" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"sniff":true,"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    local new_outbound_json=$(jq -n --arg t "$SS_TAG" --arg ip "$NEW_INBOUND_IP" --arg p "$NEW_INBOUND_PORT" --arg m "$NEW_INBOUND_METHOD" --arg pw "$NEW_INBOUND_PASSWORD" \
        '{"type":"shadowsocks","tag":$t,"server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
    local new_rule_json=$(jq -n --arg it "$VLESS_TAG" --arg ot "$SS_TAG" '{ "inbound": $it, "outbound": $ot }')

    info "正在原子化修改配置文件: $CONFIG_FILE"
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq ".inbounds += [$new_inbound_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".outbounds |= .[0:-1] + [$new_outbound_json] + .[-1:]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$new_rule_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    info "配置修改完毕！正在重启 [${SERVICE_NAME}]..."
    _restart_relay_service
    local PUB_IP=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip || echo "YOUR_RELAY_IP")
    [[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"
    local VLESS_LINK="vless://$UUID@$PUB_IP:$NEW_LISTEN_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$NEW_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID#$(_url_encode "$name")"
    
    echo "${VLESS_TAG}:${VLESS_LINK}" >> "$LINK_FILE_VLESS"
    echo ""
    info "✅ 新 VLESS 中转 [${name}] 添加成功！"
    info "VLESS Reality 中转节点 (新)："
    echo -e "\033[1;33m${VLESS_LINK}\033[0m"
    echo ""
    info "所有链接已保存到: ${LINK_FILE_VLESS}"
}

# --- 添加 Hy2 逻辑 (内部函数) ---
_action_add_hy2() {
    info "--- 添加一个新的 Hysteria2 中转路由 ---"
    info "步骤 1/3: 请输入 [新落地机] 的 SS 信息"
    read -p "  > 落地机 IP 地址: " NEW_INBOUND_IP
    read -p "  > 落地机 SS 端口: " NEW_INBOUND_PORT
    read -p "  > 落地机 SS 密码: " NEW_INBOUND_PASSWORD
    read -p "  > 落地机 SS 方法 (默认 2022-blake3-aes-128-gcm): " NEW_INBOUND_METHOD
    [ -z "$NEW_INBOUND_METHOD" ] && NEW_INBOUND_METHOD="2022-blake3-aes-128-gcm"
    
    info "步骤 2/3: 请输入 [线路机] (A) 的新入口配置"
    read -p "  > 线路机新监听端口 : " NEW_LISTEN_PORT
    read -p "  > 线路机新 Hysteria2 密码 (默认随机): " NEW_PASSWORD
    [ -z "$NEW_PASSWORD" ] && NEW_PASSWORD=$($SINGBOX_BIN generate rand 16 --hex)
    read -p "  > 线路机新伪装SNI (默认 www.microsoft.com): " NEW_SNI
    [ -z "$NEW_SNI" ] && NEW_SNI="www.microsoft.com"
    if [ -z "$NEW_INBOUND_IP" ] || [ -z "$NEW_INBOUND_PORT" ] || [ -z "$NEW_LISTEN_PORT" ]; then
        err "IP 和 端口 不能为空！"; return 1; fi

    info "步骤 3/3: 请输入节点名称"
    local default_name="Hy2-${NEW_LISTEN_PORT}"
    read -p "  > 节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    info "正在生成新证书..."
    local TAG_SUFFIX=$NEW_LISTEN_PORT
    local HY2_TAG="hy2-in-${TAG_SUFFIX}"
    local SS_TAG="relay-out-${TAG_SUFFIX}"
    local CERT_PATH="${CONFIG_DIR}/${HY2_TAG}.pem"
    local KEY_PATH="${CONFIG_DIR}/${HY2_TAG}.key"
    _generate_self_signed_cert "$NEW_SNI" "$CERT_PATH" "$KEY_PATH" || return 1
    
    info "正在构建新的 JSON 片段..."
    local new_inbound_json=$(jq -n --arg t "$HY2_TAG" --arg p "$NEW_LISTEN_PORT" --arg pw "$NEW_PASSWORD" --arg cert "$CERT_PATH" --arg key "$KEY_PATH" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"sniff":true,"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    local new_outbound_json=$(jq -n --arg t "$SS_TAG" --arg ip "$NEW_INBOUND_IP" --arg p "$NEW_INBOUND_PORT" --arg m "$NEW_INBOUND_METHOD" --arg pw "$NEW_INBOUND_PASSWORD" \
        '{"type":"shadowsocks","tag":$t,"server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
    local new_rule_json=$(jq -n --arg it "$HY2_TAG" --arg ot "$SS_TAG" '{ "inbound": $it, "outbound": $ot }')

    info "正在原子化修改配置文件: $CONFIG_FILE"
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq ".inbounds += [$new_inbound_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".outbounds |= .[0:-1] + [$new_outbound_json] + .[-1:]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$new_rule_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    info "配置修改完毕！正在重启 [${SERVICE_NAME}]..."
    _restart_relay_service
    local PUB_IP=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip || echo "YOUR_RELAY_IP")
    [[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"
    local HY2_LINK="hysteria2://${NEW_PASSWORD}@${PUB_IP}:${NEW_LISTEN_PORT}?sni=${NEW_SNI}&insecure=1#$(_url_encode "$name")"
    
    echo "${HY2_TAG}:${HY2_LINK}" >> "$LINK_FILE_HY2"
    echo ""
    info "✅ 新 Hysteria2 中转 [${name}] 添加成功！"
    info "Hysteria2 中转节点 (新)："
    echo -e "\033[1;33m${HY2_LINK}\033[0m"
    echo ""
    info "所有链接已保存到: ${LINK_FILE_HY2}"
}

# --- [!] 新增：添加 TUICv5 逻辑 (内部函数) ---
_action_add_tuic() {
    info "--- 添加一个新的 TUICv5 中转路由 ---"
    info "步骤 1/3: 请输入 [新落地机] 的 SS 信息"
    read -p "  > 落地机 IP 地址: " NEW_INBOUND_IP
    read -p "  > 落地机 SS 端口: " NEW_INBOUND_PORT
    read -p "  > 落地机 SS 密码: " NEW_INBOUND_PASSWORD
    read -p "  > 落地机 SS 方法 (默认 2022-blake3-aes-128-gcm): " NEW_INBOUND_METHOD
    [ -z "$NEW_INBOUND_METHOD" ] && NEW_INBOUND_METHOD="2022-blake3-aes-128-gcm"
    
    info "步骤 2/3: 请输入 [线路机] (A) 的新入口配置"
    read -p "  > 线路机新监听端口 : " NEW_LISTEN_PORT
    read -p "  > 线路机新 TUICv5 UUID (默认随机): " NEW_UUID
    [ -z "$NEW_UUID" ] && NEW_UUID=$($SINGBOX_BIN generate uuid)
    read -p "  > 线路机新 TUICv5 密码 (默认随机): " NEW_PASSWORD
    [ -z "$NEW_PASSWORD" ] && NEW_PASSWORD=$($SINGBOX_BIN generate rand 16 --hex)
    read -p "  > 线路机新伪装SNI (默认 www.microsoft.com): " NEW_SNI
    [ -z "$NEW_SNI" ] && NEW_SNI="www.microsoft.com"
    if [ -z "$NEW_INBOUND_IP" ] || [ -z "$NEW_INBOUND_PORT" ] || [ -z "$NEW_LISTEN_PORT" ]; then
        err "IP 和 端口 不能为空！"; return 1; fi

    info "步骤 3/3: 请输入节点名称"
    local default_name="TUICv5-${NEW_LISTEN_PORT}"
    read -p "  > 节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    info "正在生成新证书..."
    local TAG_SUFFIX=$NEW_LISTEN_PORT
    local TUIC_TAG="tuic-in-${TAG_SUFFIX}"
    local SS_TAG="relay-out-${TAG_SUFFIX}"
    local CERT_PATH="${CONFIG_DIR}/${TUIC_TAG}.pem"
    local KEY_PATH="${CONFIG_DIR}/${TUIC_TAG}.key"
    _generate_self_signed_cert "$NEW_SNI" "$CERT_PATH" "$KEY_PATH" || return 1
    
    info "正在构建新的 JSON 片段..."
    local new_inbound_json=$(jq -n --arg t "$TUIC_TAG" --arg p "$NEW_LISTEN_PORT" --arg u "$NEW_UUID" --arg pw "$NEW_PASSWORD" --arg cert "$CERT_PATH" --arg key "$KEY_PATH" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"sniff":true,"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    local new_outbound_json=$(jq -n --arg t "$SS_TAG" --arg ip "$NEW_INBOUND_IP" --arg p "$NEW_INBOUND_PORT" --arg m "$NEW_INBOUND_METHOD" --arg pw "$NEW_INBOUND_PASSWORD" \
        '{"type":"shadowsocks","tag":$t,"server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
    local new_rule_json=$(jq -n --arg it "$TUIC_TAG" --arg ot "$SS_TAG" '{ "inbound": $it, "outbound": $ot }')

    info "正在原子化修改配置文件: $CONFIG_FILE"
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq ".inbounds += [$new_inbound_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".outbounds |= .[0:-1] + [$new_outbound_json] + .[-1:]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$new_rule_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    info "配置修改完毕！正在重启 [${SERVICE_NAME}]..."
    _restart_relay_service
    local PUB_IP=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip || echo "YOUR_RELAY_IP")
    [[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"
    local TUIC_LINK="tuic://${NEW_UUID}:${NEW_PASSWORD}@${PUB_IP}:${NEW_LISTEN_PORT}?sni=${NEW_SNI}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$name")"
    
    echo "${TUIC_TAG}:${TUIC_LINK}" >> "$LINK_FILE_TUIC"
    echo ""
    info "✅ 新 TUICv5 中转 [${name}] 添加成功！"
    info "TUICv5 中转节点 (新)："
    echo -e "\033[1;33m${TUIC_LINK}\033[0m"
    echo ""
    info "所有链接已保存到: ${LINK_FILE_TUIC}"
}


# --- 添加新中转 动作 (混合模式调度器) ---
action_add() {
    if [ ! -f "$CONFIG_FILE" ]; then
        err "未找到主配置文件: $CONFIG_FILE"
        err "请先运行一次安装 (bash $0) 来创建第一个中转。"
        return 1
    fi
    
    info "--- 添加一个新的中转路由 ---"
    info "请选择要添加的 [入口] 协议类型："
    echo -e "  1) ${CYAN}VLESS (Vision+REALITY)${NC}"
    echo -e "  2) ${CYAN}Hysteria2${NC}"
    echo -e "  3) ${CYAN}TUICv5${NC}"
    echo "  0) 返回"
    read -p "请输入选项 [0-3]: " choice
    
    case "$choice" in
        1) _action_add_vless ;;
        2) _action_add_hy2 ;;
        3) _action_add_tuic ;;
        *) info "操作已取消。"; return ;;
    esac
}

# --- 删除中转 动作 (混合模式) ---
action_delete() {
    info "--- 删除一个中转路由 ---"
    if [ ! -f "$CONFIG_FILE" ] || ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        err "配置文件不存在或没有任何中转路由可删除。"
        return 1
    fi
    
    info "当前所有中转路由列表："
    local tags=()
    local types=()
    local i=1
    # [!] 混合模式：显示所有 VLESS, Hy2, TUICv5 类型的
    while IFS= read -r line; do
        local tag=$(echo "$line" | jq -r '.tag')
        local type=$(echo "$line" | jq -r '.type')
        local port=$(echo "$line" | jq -r '.listen_port')
        echo -e "  ${CYAN}$i)${NC} ${tag} (${YELLOW}${type}${NC}) (端口: ${port})"
        tags+=("$tag")
        types+=("$type")
        ((i++))
    done <<< $(jq -c '.inbounds[] | select(.type == "vless" or .type == "hysteria2" or .type == "tuic")' "$CONFIG_FILE")

    if [ ${#tags[@]} -eq 0 ]; then
        err "未找到可删除的 (VLESS, Hy2, 或 TUICv5) inbounds。"; return 1
    fi
    
    echo "  0) 返回"
    read -p "请输入要删除的中转编号: " choice
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -gt "${#tags[@]}" ]; then
        info "操作已取消。"; return
    fi
    
    local index=$((choice-1))
    local tag_to_del=${tags[$index]}
    local type_to_del=${types[$index]}
    
    warn "您选择了删除: ${tag_to_del} (类型: ${type_to_del})"
    
    local out_tag_to_del=$(jq -r --arg t "$tag_to_del" '.route.rules[] | select(.inbound == $t) | .outbound' "$CONFIG_FILE")
    
    if [ -z "$out_tag_to_del" ]; then
        err "严重错误：未能在路由规则中找到 ${tag_to_del} 对应的出站，"
        warn "将只删除 Inbound 和 Rule。请手动检查 Outbounds。"
        out_tag_to_del="NOT_FOUND_$(date +%s)" # 防止
    fi
    
    read -p "$(echo -e ${YELLOW}"确定要删除此中转吗? (y/N): "${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "删除已取消。"; return
    fi
    
    info "正在从配置中删除 ${tag_to_del} 和 ${out_tag_to_del}..."
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    
    jq "del(.inbounds[] | select(.tag == \"$tag_to_del\"))" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq "del(.outbounds[] | select(.tag == \"$out_tag_to_del\"))" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq "del(.route.rules[] | select(.inbound == \"$tag_to_del\"))" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # [!] 智能删除链接 (修复：使用 sed 替代 grep -v，解决删除唯一行失败的问题)
    if [ "$type_to_del" == "vless" ] && [ -f "$LINK_FILE_VLESS" ]; then
        info "正在从 VLESS 链接列表删除..."
        sed -i "/^${tag_to_del}:/d" "$LINK_FILE_VLESS"
    elif [ "$type_to_del" == "hysteria2" ] && [ -f "$LINK_FILE_HY2" ]; then
        info "正在从 Hysteria2 链接列表删除..."
        sed -i "/^${tag_to_del}:/d" "$LINK_FILE_HY2"
    elif [ "$type_to_del" == "tuic" ] && [ -f "$LINK_FILE_TUIC" ]; then
        info "正在从 TUICv5 链接列表删除..."
        sed -i "/^${tag_to_del}:/d" "$LINK_FILE_TUIC"
    fi
    
    # [!] 智能删除证书 (Hy2 和 TUICv5)
    if [ "$type_to_del" == "hysteria2" ] || [ "$type_to_del" == "tuic" ]; then
        local CERT_PATH="${CONFIG_DIR}/${tag_to_del}.pem"
        local KEY_PATH="${CONFIG_DIR}/${tag_to_del}.key"
        if [ -f "$CERT_PATH" ] || [ -f "$KEY_PATH" ]; then
            info "正在删除 ${type_to_del} 关联的证书文件..."
            rm -f "$CERT_PATH" "$KEY_PATH"
        fi
    fi
    
    info "配置修改完毕！正在重启 [${SERVICE_NAME}]..."
    _restart_relay_service
    
    info "✅ 中转路由 ${tag_to_del} 已成功删除！"
}

# --- 脚本主入口 ---
case "${1:-}" in
    uninstall) action_uninstall; exit 0 ;;
    view) action_view; exit 0 ;;
    add) action_add; exit 0 ;;
    delete) action_delete; exit 0 ;; 
    restart) _restart_relay_service; exit 0 ;; 
    "")
        info "--- 正在执行 [安装/重置] 混合模式中转服务 ---"
        ;;
    *)
        err "无效参数: ${1}"
        echo "用法: bash ${0} [install(默认)|add|delete|view|restart|uninstall]"
        exit 1
        ;;
esac
# --- 检查 Root (仅限安装) ---
if [ "$(id -u)" != "0" ]; then err "必须以 root 运行"; exit 1; fi
# --- 检测系统 (仅限安装) ---
detect_os() {
    OS="unknown"
    if [ -f /etc/os-release ]; then . /etc/os-release; case "$ID" in alpine) OS=alpine ;; debian|ubuntu) OS=debian ;; centos|rhel|fedora) OS=redhat ;; esac; fi
    info "检测到系统: $OS"
}
detect_os
# --- 安装依赖 (仅限安装) ---
install_deps() {
    info "安装依赖 (curl, jq, openssl, wget)..."
    case "$OS" in
        alpine) apk update && apk add --no-cache curl jq bash openssl ca-certificates wget ;;
        debian) apt-get update -y && apt-get install -y curl jq bash openssl ca-certificates wget ;;
        redhat) yum install -y curl jq bash openssl ca-certificates wget ;;
        *) err "不支持的系统，请手动安装 curl, jq, openssl, bash, wget"; exit 1 ;;
    esac
}
install_deps

# --- 安装 Sing-box (使用您主脚本的函数) ---
_install_sing_box() {
    info "正在安装最新稳定版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;; aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;; *) err "不支持的架构：$arch"; exit 1 ;;
    esac
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    if [ -z "$download_url" ]; then err "无法获取 sing-box 下载链接。"; exit 1; fi
    info "正在下载: $download_url"
    wget -qO sing-box.tar.gz "$download_url" || { err "下载失败!"; exit 1; }
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    mv "$temp_dir/sing-box-"*"/sing-box" ${SINGBOX_BIN}
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x ${SINGBOX_BIN}
    info "sing-box 安装成功, 版本: $(${SINGBOX_BIN} version)"
}
# --- sing-box 安装执行 (仅限安装) ---
install_singbox() {
    info "检查 sing-box..."
    if [ -f "$SINGBOX_BIN" ]; then info "sing-box 已安装，跳过。";
    else _install_sing_box; fi
    export PATH=$PATH:/usr/local/bin
}
install_singbox

# --- (安装流程) 混合模式 ---
info "--- 步骤 1/2: 配置 [落地机] (SS 节点) ---"
info "落地机 IP: $INBOUND_IP"
info "落地机 端口: $INBOUND_PORT"
info "落地机 方法: $INBOUND_METHOD"

info "--- 步骤 2/2: 配置 [线路机] (选择第一个入口) ---"
info "您正在安装 [混合模式] 脚本，请选择要安装的 [第一个] 中转协议："
echo -e "  1) ${CYAN}VLESS (Vision+REALITY)${NC}"
echo -e "  2) ${CYAN}Hysteria2${NC}"
echo -e "  3) ${CYAN}TUICv5${NC}"
read -p "请输入选项 [1-3]: " first_protocol

mkdir -p "$CONFIG_DIR" # 必须先创建目录

# [!] 定义通用变量
LISTEN_PORT=""
USER_SNI=""
NAME=""
SS_TAG=""

# [!] 根据选择执行不同的安装流程
case "$first_protocol" in
    1)
        # --- VLESS 安装逻辑 ---
        info "正在安装 VLESS+Reality 作为第一个路由..."
        read -p "输入 [线路机] 监听端口 (留空则随机 20000-65000): " USER_PORT
        if [ -z "$USER_PORT" ]; then
            LISTEN_PORT=$(shuf -i 20000-65000 -n 1 2>/dev/null || echo $((RANDOM % 45001 + 20000)))
            info "使用随机端口: $LISTEN_PORT"
        else LISTEN_PORT="$USER_PORT"; fi
        read -p "输入伪装域名(SNI) [回车默认: www.microsoft.com]: " USER_SNI
        [ -z "$USER_SNI" ] && USER_SNI="www.microsoft.com"
        info "使用 SNI: $USER_SNI"
        default_name="VLESS-R-${LISTEN_PORT}"
        read -p "输入节点名称 (默认: ${default_name}): " custom_name
        NAME=${custom_name:-$default_name}

        info "生成 Reality 密钥对"
        UUID=$($SINGBOX_BIN generate uuid)
        REALITY_KEYS=$($SINGBOX_BIN generate reality-keypair)
        REALITY_PK=$(echo "$REALITY_KEYS" | awk '/PrivateKey/ {print $2}')
        REALITY_PUB=$(echo "$REALITY_KEYS" | awk '/PublicKey/ {print $2}')
        REALITY_SID=$($SINGBOX_BIN generate rand 8 --hex)
        
        VLESS_TAG="vless-in-${LISTEN_PORT}"
        SS_TAG="relay-out-${LISTEN_PORT}"
        
        info "正在创建 [全新] 配置文件: $CONFIG_FILE"
        cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless", "tag": "$VLESS_TAG", "listen": "::", "listen_port": $LISTEN_PORT, "sniff": true,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true, "server_name": "$USER_SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$USER_SNI", "server_port": 443 },
          "private_key": "$REALITY_PK", "short_id": [ "$REALITY_SID" ], "max_time_difference": "1m"
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks", "tag": "$SS_TAG",
      "server": "$INBOUND_IP", "server_port": $INBOUND_PORT,
      "method": "$INBOUND_METHOD", "password": "$INBOUND_PASSWORD"
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [ { "inbound": "$VLESS_TAG", "outbound": "$SS_TAG" } ]
  }
}
EOF
        ;;
    2)
        # --- Hysteria2 安装逻辑 ---
        info "正在安装 Hysteria2 作为第一个路由..."
        read -p "输入 [线路机] 监听端口 (留空则随机 20000-65000): " USER_PORT
        if [ -z "$USER_PORT" ]; then
            LISTEN_PORT=$(shuf -i 20000-65000 -n 1 2>/dev/null || echo $((RANDOM % 45001 + 20000)))
            info "使用随机端口: $LISTEN_PORT"
        else LISTEN_PORT="$USER_PORT"; fi
        read -p "输入 Hysteria2 密码 [回车默认随机]: " USER_PASSWORD
        [ -z "$USER_PASSWORD" ] && USER_PASSWORD=$($SINGBOX_BIN generate rand 16 --hex) && info "使用随机密码: $USER_PASSWORD"
        read -p "输入伪装域名(SNI) [回车默认: www.microsoft.com]: " USER_SNI
        [ -z "$USER_SNI" ] && USER_SNI="www.microsoft.com"
        info "使用 SNI: $USER_SNI"
        default_name="Hy2-${LISTEN_PORT}"
        read -p "输入节点名称 (默认: ${default_name}): " custom_name
        NAME=${custom_name:-$default_name}

        info "正在生成自签名证书..."
        HY2_TAG="hy2-in-${LISTEN_PORT}"
        CERT_PATH="${CONFIG_DIR}/${HY2_TAG}.pem"
        KEY_PATH="${CONFIG_DIR}/${HY2_TAG}.key"
        openssl ecparam -genkey -name prime256v1 -out "$KEY_PATH" >/dev/null 2>&1
        openssl req -new -x509 -days 3650 -key "$KEY_PATH" -out "$CERT_PATH" -subj "/CN=${USER_SNI}" >/dev/null 2>&1
        info "证书生成完毕。"
        
        SS_TAG="relay-out-${LISTEN_PORT}"
        
        info "正在创建 [全新] 配置文件: $CONFIG_FILE"
        cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "hysteria2", "tag": "$HY2_TAG", "listen": "::", "listen_port": $LISTEN_PORT, "sniff": true,
      "users": [ { "password": "$USER_PASSWORD" } ],
      "tls": {
        "enabled": true, "alpn": ["h3"],
        "certificate_path": "$CERT_PATH", "key_path": "$KEY_PATH"
      }
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks", "tag": "$SS_TAG",
      "server": "$INBOUND_IP", "server_port": $INBOUND_PORT,
      "method": "$INBOUND_METHOD", "password": "$INBOUND_PASSWORD"
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [ { "inbound": "$HY2_TAG", "outbound": "$SS_TAG" } ]
  }
}
EOF
        ;;
    3)
        # --- TUICv5 安装逻辑 ---
        info "正在安装 TUICv5 作为第一个路由..."
        read -p "输入 [线路机] 监听端口 (留空则随机 20000-65000): " USER_PORT
        if [ -z "$USER_PORT" ]; then
            LISTEN_PORT=$(shuf -i 20000-65000 -n 1 2>/dev/null || echo $((RANDOM % 45001 + 20000)))
            info "使用随机端口: $LISTEN_PORT"
        else LISTEN_PORT="$USER_PORT"; fi
        read -p "输入 TUICv5 UUID [回车默认随机]: " USER_UUID
        [ -z "$USER_UUID" ] && USER_UUID=$($SINGBOX_BIN generate uuid) && info "使用随机 UUID"
        read -p "输入 TUICv5 密码 [回车默认随机]: " USER_PASSWORD
        [ -z "$USER_PASSWORD" ] && USER_PASSWORD=$($SINGBOX_BIN generate rand 16 --hex) && info "使用随机密码"
        read -p "输入伪装域名(SNI) [回车默认: www.microsoft.com]: " USER_SNI
        [ -z "$USER_SNI" ] && USER_SNI="www.microsoft.com"
        info "使用 SNI: $USER_SNI"
        default_name="TUICv5-${LISTEN_PORT}"
        read -p "输入节点名称 (默认: ${default_name}): " custom_name
        NAME=${custom_name:-$default_name}

        info "正在生成自签名证书..."
        TUIC_TAG="tuic-in-${LISTEN_PORT}"
        CERT_PATH="${CONFIG_DIR}/${TUIC_TAG}.pem"
        KEY_PATH="${CONFIG_DIR}/${TUIC_TAG}.key"
        openssl ecparam -genkey -name prime256v1 -out "$KEY_PATH" >/dev/null 2>&1
        openssl req -new -x509 -days 3650 -key "$KEY_PATH" -out "$CERT_PATH" -subj "/CN=${USER_SNI}" >/dev/null 2>&1
        info "证书生成完毕。"
        
        SS_TAG="relay-out-${LISTEN_PORT}"
        
        info "正在创建 [全新] 配置文件: $CONFIG_FILE"
        cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "tuic", "tag": "$TUIC_TAG", "listen": "::", "listen_port": $LISTEN_PORT, "sniff": true,
      "users": [ { "uuid": "$USER_UUID", "password": "$USER_PASSWORD" } ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true, "alpn": ["h3"],
        "certificate_path": "$CERT_PATH", "key_path": "$KEY_PATH"
      }
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks", "tag": "$SS_TAG",
      "server": "$INBOUND_IP", "server_port": $INBOUND_PORT,
      "method": "$INBOUND_METHOD", "password": "$INBOUND_PASSWORD"
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [ { "inbound": "$TUIC_TAG", "outbound": "$SS_TAG" } ]
  }
}
EOF
        ;;
    *)
        err "无效选择。"
        exit 1
        ;;
esac


# --- (安装流程) 创建服务 ---
info "创建并启动服务 [${SERVICE_NAME}]..."
INIT_SYSTEM=$(_detect_init_system)
info "使用 $INIT_SYSTEM 模式启动"
case "$INIT_SYSTEM" in
    systemd)
        cat > /etc/systemd/system/${SERVICE_NAME}.service << SYSTEMD
[Unit]
Description=Sing-box Relay (${SERVICE_NAME})
After=network.target
[Service]
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
[Install]
WantedBy=multi-user.target
SYSTEMD
        systemctl daemon-reload
        systemctl enable $SERVICE_NAME >/dev/null 2>&1 || true
        systemctl restart $SERVICE_NAME
        info "Systemd 服务 [${SERVICE_NAME}] 已启动"
        ;;
    openrc)
        cat > /etc/init.d/${SERVICE_NAME} << SVC
#!/sbin/openrc-run
name="${SERVICE_NAME}"
description="SingBox Relay Service"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE}"
command_background="yes"
pidfile="${PID_FILE}"
depend() { need net; }
SVC
        chmod +x /etc/init.d/${SERVICE_NAME}
        rc-update add $SERVICE_NAME default >/dev/null 2>&1 || true
        rc-service $SERVICE_NAME restart
        info "OpenRC 服务 [${SERVICE_NAME}] 已启动"
        ;;
esac

# --- (安装流程) 输出结果 ---
PUB_IP=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip || echo "YOUR_RELAY_IP")
[[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"

info "✅ 线路机 [安装/重置] 完成"
echo ""

# [!] 根据安装的第一个协议输出链接
case "$first_protocol" in
    1)
        VLESS_TAG="vless-in-${LISTEN_PORT}"
        VLESS_LINK="vless://$UUID@$PUB_IP:$LISTEN_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$USER_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID#$(_url_encode "$NAME")"
        echo "${VLESS_TAG}:${VLESS_LINK}" > "$LINK_FILE_VLESS"
        info "VLESS Reality 中转节点 [${NAME}]："
        echo -e "\033[1;33m${VLESS_LINK}\033[0m"
        echo ""
        info "链接已自动保存到: ${LINK_FILE_VLESS}"
        ;;
    2)
        HY2_TAG="hy2-in-${LISTEN_PORT}"
        HY2_LINK="hysteria2://${USER_PASSWORD}@${PUB_IP}:${LISTEN_PORT}?sni=${USER_SNI}&insecure=1#$(_url_encode "$NAME")"
        echo "${HY2_TAG}:${HY2_LINK}" > "$LINK_FILE_HY2"
        info "Hysteria2 中转节点 [${NAME}]："
        echo -e "\033[1;33m${HY2_LINK}\033[0m"
        echo ""
        info "链接已自动保存到: ${LINK_FILE_HY2}"
        ;;
    3)
        TUIC_TAG="tuic-in-${LISTEN_PORT}"
        TUIC_LINK="tuic://${USER_UUID}:${USER_PASSWORD}@${PUB_IP}:${LISTEN_PORT}?sni=${USER_SNI}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$NAME")"
        echo "${TUIC_TAG}:${TUIC_LINK}" > "$LINK_FILE_TUIC"
        info "TUICv5 中转节点 [${NAME}]："
        echo -e "\033[1;33m${TUIC_LINK}\033[0m"
        echo ""
        info "链接已自动保存到: ${LINK_FILE_TUIC}"
        ;;
esac

info "您可以随时使用 'bash ${0} view' 命令查看。"
info "如需添加 [更多] 中转 (VLESS / Hy2 / TUICv5), 请运行 'bash ${0} add'"
RELAY_TEMPLATE

    # 5. 替换占位符
    sed -i "s|__INBOUND_IP__|$INBOUND_IP|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PORT__|$INBOUND_PORT|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_METHOD__|$INBOUND_METHOD|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PASSWORD__|$INBOUND_PASSWORD|g" "$RELAY_SCRIPT_PATH"

    return 0
}

_manage_relay_installation() {
    _info "--- 线路机脚本管理 (请在线路机上运行) ---"
    local relay_script="/root/relay-install.sh"

    # --- [新增] 自动下载逻辑 ---
    if [ ! -f "$relay_script" ]; then
        _warning "未在 /root 目录下找到 [relay-install.sh] 脚本。"
        _info "如果您已经在落地机生成了下载链接，请输入链接进行自动下载。"
        echo ""
        read -p "请输入下载链接 (直接回车则退出): " download_url
        
        if [ -n "$download_url" ]; then
            _info "正在从 $download_url 下载脚本..."
            # 尝试下载
            if wget -O "$relay_script" "$download_url"; then
                if [ -s "$relay_script" ]; then
                    _success "下载成功！"
                    chmod +x "$relay_script"
                else
                    _error "下载的文件为空，请检查链接或网络。"
                    rm -f "$relay_script"
                    return 1
                fi
            else
                _error "下载失败，请检查防火墙设置或链接是否正确。"
                rm -f "$relay_script" # 清理可能残留的空文件
                return 1
            fi
        else
            _error "未输入链接，操作取消。"
            _info "  1. 请先在您的“落地机”上运行此脚本 (singbox.sh)。"
            _info "  2. 使用 [9) 生成中转落地脚本] 选项并开启 HTTP 服务。"
            _info "  3. 将生成的 http://... 链接填入此处。"
            return 1
        fi
    fi
    # --- [新增] 逻辑结束 ---

    chmod +x "$relay_script" # 确保有执行权限

    while true; do
        clear
        echo "===================================================="
        _info "      线路机 (中转机) 快捷管理"
        _info "      (正在管理: ${relay_script})"
        echo "===================================================="
        echo -e "  1) ${GREEN}安装 / 重置${NC} 第一个中转服务"
        echo -e "  2) ${GREEN}添加${NC} 新的中转路由 (VLESS / Hy2 / Tuic)"
        echo -e "  3) ${YELLOW}删除${NC} 一个指定的中转路由"
        echo -e "  4. ${CYAN}查看${NC} 所有中转节点链接"
        echo -e "  5) ${CYAN}重启${NC} 线路机服务"
        echo -e "  6) ${RED}卸载${NC} [所有] 线路机服务"
        echo "----------------------------------------------------"
        echo "  0) 返回主菜单"
        echo "===================================================="
        read -p "请输入选项 [0-6]: " choice

        case $choice in
            1)
                _info "正在执行: bash ${relay_script}"
                bash "${relay_script}"
                break
                ;;
            2)
                _info "正在执行: bash ${relay_script} add"
                bash "${relay_script}" add
                break
                ;;
            3)
                _info "正在执行: bash ${relay_script} delete"
                bash "${relay_script}" delete
                break
                ;;
            4)
                _info "正在执行: bash ${relay_script} view"
                bash "${relay_script}" view
                break
                ;;
            5)
                _info "正在执行: bash ${relay_script} restart"
                bash "${relay_script}" restart
                break
                ;;
            6)
                _info "正在执行: bash ${relay_script} uninstall"
                bash "${relay_script}" uninstall
                break
                ;;
            0)
                return
                ;;
            *)
                _error "无效输入，请重试。"
                sleep 1
                ;;
        esac
    done
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
        echo "  4. 重启 sing-box"
        echo "  5) 停止 sing-box"
        echo "  6) 查看 sing-box 运行状态"
        echo "  7) 查看 sing-box 实时日志"
        echo "----------------------------------------------------"
        _info "【脚本与配置】"
        echo "  8) 检查配置文件"
        echo -e "  9) ${GREEN}生成 [混合模式] 中转脚本${NC} (在“落地机”运行)"
        echo -e " 10) ${CYAN}管理 [混合模式] 中转脚本${NC} (在“线路机”运行)"
        echo "----------------------------------------------------"
        _info "【更新与卸载】"
        echo -e " 11) ${GREEN}更新脚本${NC}"
        echo -e " 12) ${GREEN}更新 Sing-box 核心${NC}"
        echo -e " 13) ${RED}卸载 sing-box 及脚本${NC}"
        echo "----------------------------------------------------"
        echo "  0) 退出脚本"
        echo "===================================================="
        read -p "请输入选项 [0-13]: " choice

        case $choice in
            1) _show_add_node_menu ;;
            2) _view_nodes ;;
            3) _delete_node ;;
            4) _manage_service "restart" ;;
            5) _manage_service "stop" ;;
            6) _manage_service "status" ;;
            7) _view_log ;;
            8) _check_config ;;
            9) _generate_relay_script ;; 
            10) _manage_relay_installation ;;
            11) _update_script ;;
            12) _update_singbox_core ;;
            13) _uninstall ;; 
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
    echo " 2) VLESS (WebSocket+TLS)"
    echo " 3) Trojan (WebSocket+TLS)"
    echo " 4) VLESS (TCP)"
    echo " 5) Hysteria2"
    echo " 6) TUICv5"
    echo " 7) Shadowsocks"
    echo " 8) SOCKS5"
    echo "----------------------------------------"
    echo " 0) 返回主菜单"
    echo "========================================"
    read -p "请输入选项 [0-8]: " choice

    case $choice in
        1) _add_vless_reality; action_result=$? ;;
        2) _add_vless_ws_tls; action_result=$? ;;
		3) _add_trojan_ws_tls; action_result=$? ;;
        4) _add_vless_tcp; action_result=$? ;;
        5) _add_hysteria2; action_result=$? ;;
        6) _add_tuic; action_result=$? ;;
        7) _add_shadowsocks_menu; action_result=$? ;;
        8) _add_socks; action_result=$? ;;
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
    
    # [!!!] 最终修复：
    # 1. 必须始终检查依赖 (yq)，因为 relay.sh 不会安装 yq
    # 2. 检查 sing-box 程序
    # 3. 检查配置文件
    
    # 1. 始终检查依赖 (特别是 yq)
    # _install_dependencies 函数内部有 "command -v" 检查，所以重复运行是安全的
    _info "正在检查核心依赖 (yq)..."
    _install_dependencies

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

    # 4. 如果是首次安装，才创建服务和启动
	_create_service_files
	
	# 5. 如果是首次安装，启动服务
    if [ "$first_install" = true ]; then
        _info "首次安装完成！正在启动 sing-box (主服务)..."
        _manage_service "start"
    fi
    
    _get_public_ip
    _main_menu
}

main

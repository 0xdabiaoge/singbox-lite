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
SCRIPT_VERSION="6.0" 
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
    
    echo ""
    echo "即将删除以下内容："
    echo -e "  ${RED}-${NC} 主配置目录: ${SINGBOX_DIR}"
    echo -e "  ${RED}-${NC} 中转辅助目录: /etc/singbox"
    if [ -f "/etc/singbox/relay_links.json" ]; then
        local relay_count=$(jq 'length' /etc/singbox/relay_links.json 2>/dev/null || echo "0")
        echo -e "  ${RED}-${NC} 中转节点数量: ${relay_count} 个"
    fi
    echo -e "  ${RED}-${NC} sing-box 二进制: ${SINGBOX_BIN}"
    echo -e "  ${RED}-${NC} 管理脚本: ${SELF_SCRIPT_PATH}"
    echo ""
    
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
    
    _info "正在删除主配置、yq、日志文件及进阶脚本..."
    rm -rf ${SINGBOX_DIR} ${YQ_BINARY} ${SERVICE_FILE} ${LOG_FILE} ${PID_FILE} "/root/advanced_relay.sh" "./advanced_relay.sh"
    
    # 清理中转路由辅助文件目录
    if [ -d "/etc/singbox" ]; then
        _info "正在清理中转路由辅助文件..."
        rm -rf /etc/singbox
    fi

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
        read -p "请输入 (回车默认 www.visa.com.hk): " cdn_input
        client_server_addr=${cdn_input:-"www.visa.com.hk"}
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
        read -p "请输入 (回车默认 www.visa.com.hk): " cdn_input
        client_server_addr=${cdn_input:-"www.visa.com.hk"}
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
    # IPv6处理：YAML用原始IP，链接用带[]的IP
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\"}}" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
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
    # IPv6处理：YAML用原始IP，链接用带[]的IP
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":""}],"tls":{"enabled":false}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" \
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
    
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local meta_json=$(jq -n --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" \
        '{ "up": $up, "down": $down } | if $op != "" then .obfsPassword = $op else . end')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg pw "$password" --arg sn "$server_name" --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" \
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

    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sn "$server_name" \
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

    local tag="${name_prefix}-in-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"type":"shadowsocks","tag":$t,"listen":"::","listen_port":($p|tonumber),"method":$m,"password":$pw}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
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
        # IPv6链接格式：添加[]
        local link_ip="$display_ip"; [[ "$display_ip" == *":"* ]] && link_ip="[$display_ip]"
        
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
                    url="vless://${uuid}@${link_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sn}&fp=chrome&flow=${flow}&pbk=${pk}&sid=${sid}#$(_url_encode "$display_name")"
                else
                    # VLESS + TCP
                    # [!] 已修改：使用 display_name
                    url="vless://${uuid}@${link_ip}:${port}?type=tcp&security=none#$(_url_encode "$display_name")"
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
                url="hysteria2://${pw}@${link_ip}:${port}?sni=${sn}&insecure=1${obfs_param}#$(_url_encode "$display_name")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                # [!] 已修改：使用 display_name
                url="tuic://${uuid}:${pw}@${link_ip}:${port}?sni=${sn}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$display_name")"
                ;;
            "shadowsocks")
                local method=$(echo "$node" | jq -r '.method')
                local password=$(echo "$node" | jq -r '.password')
                
                # 保持原格式：ss://method:password@server:port#name (URL编码)
                # [!] 已修改：使用 display_name
                url="ss://$(_url_encode "${method}:${password}")@${link_ip}:${port}#$(_url_encode "$display_name")"
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
    
    # === 关键修复：必须先读取 metadata 判断节点类型，再删除！===
    local node_metadata=$(jq -r --arg tag "$tag_to_del" '.[$tag] // empty' "$METADATA_FILE" 2>/dev/null)
    local node_type=""
    if [ -n "$node_metadata" ]; then
        node_type=$(echo "$node_metadata" | jq -r '.type // empty')
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
    
    # === 根据之前读取的节点类型清理相关配置 ===
    if [ "$node_type" == "third-party-adapter" ]; then
        # === 第三方适配层：删除 outbound 和 route ===
        _info "检测到第三方适配层，正在清理关联配置..."
        
        # 先查找对应的 outbound (必须在删除 route 之前)
        local outbound_tag=$(jq -r --arg inbound "$tag_to_del" '.route.rules[] | select(.inbound == $inbound) | .outbound' "$CONFIG_FILE" 2>/dev/null | head -n 1)
        
        # 删除 route 规则
        _atomic_modify_json "$CONFIG_FILE" "del(.route.rules[] | select(.inbound == \"$tag_to_del\"))" || true
        
        # 删除对应的 outbound
        if [ -n "$outbound_tag" ] && [ "$outbound_tag" != "null" ]; then
            _atomic_modify_json "$CONFIG_FILE" "del(.outbounds[] | select(.tag == \"$outbound_tag\"))" || true
            _info "已删除关联的 outbound: $outbound_tag"
        fi
    else
        # === 普通节点：只有 inbound，没有额外的 outbound 和 route ===
        # 主脚本创建的节点通常只包含 inbound，outbound 是全局的（如 direct）
        # 如果有特殊的 outbound（如某些协议的专用配置），也要删除
        
        # 检查是否有基于此 inbound 的 route 规则（通常不应该有，但为了清理干净）
        local has_route=$(jq -e ".route.rules[]? | select(.inbound == \"$tag_to_del\")" "$CONFIG_FILE" 2>/dev/null)
        if [ -n "$has_route" ]; then
            _info "检测到关联的路由规则，正在清理..."
            _atomic_modify_json "$CONFIG_FILE" "del(.route.rules[] | select(.inbound == \"$tag_to_del\"))" || true
        fi
        
        # 注意：不删除任何 outbound，因为普通节点的 outbound 通常是共享的全局 outbound
        # （如 "direct"），删除会影响其他节点
    fi
    # === 清理逻辑结束 ===
    
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

_modify_port() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warning "当前没有任何节点。"
        return
    fi
    
    _info "--- 修改节点端口 ---"
    
    # 列出所有节点
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local display_names=()
    
    local i=1
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag')
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port')
        
        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")
        
        # 查找显示名称
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
        
        local display_name=${proxy_name_to_find:-$tag}
        display_names+=("$display_name")
        
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${GREEN}${port}${NC}"
        ((i++))
    done < <(jq -c '.inbounds[]' "$CONFIG_FILE")
    
    read -p "请输入要修改端口的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    
    local count=${#inbound_tags[@]}
    if [ "$num" -gt "$count" ]; then
        _error "编号超出范围。"
        return
    fi
    
    local index=$((num - 1))
    local tag_to_modify=${inbound_tags[$index]}
    local type_to_modify=${inbound_types[$index]}
    local old_port=${inbound_ports[$index]}
    local display_name_to_modify=${display_names[$index]}
    
    _info "当前节点: ${display_name_to_modify} (${type_to_modify})"
    _info "当前端口: ${old_port}"
    
    read -p "请输入新的端口号: " new_port
    
    # 验证端口
    if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        _error "无效的端口号！"
        return
    fi
    
    if [ "$new_port" -eq "$old_port" ]; then
        _warning "新端口与当前端口相同，无需修改。"
        return
    fi
    
    # 检查端口是否已被占用
    if jq -e ".inbounds[] | select(.listen_port == $new_port)" "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "端口 $new_port 已被其他节点使用！"
        return
    fi
    
    _info "正在修改端口: ${old_port} -> ${new_port}"
    
    # 1. 修改 config.json
    _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].listen_port = $new_port" || return
    
    # 2. 修改 clash.yaml
    local proxy_name_in_yaml=""
    local proxy_obj_by_port_yaml=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${old_port}')' ${CLASH_YAML_FILE} | head -n 1)
    if [ -n "$proxy_obj_by_port_yaml" ]; then
        proxy_name_in_yaml=$(echo "$proxy_obj_by_port_yaml" | ${YQ_BINARY} eval '.name' -)
    fi
    
    if [ -n "$proxy_name_in_yaml" ]; then
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == "'${proxy_name_in_yaml}'") | .port) = '${new_port}
    fi
    
    # 3. 处理证书文件重命名（仅 Hysteria2 和 TUIC）
    if [ "$type_to_modify" == "hysteria2" ] || [ "$type_to_modify" == "tuic" ]; then
        local old_cert="${SINGBOX_DIR}/${tag_to_modify}.pem"
        local old_key="${SINGBOX_DIR}/${tag_to_modify}.key"
        
        # 生成新的 tag (基于新端口)
        local new_tag_suffix="$new_port"
        if [ "$type_to_modify" == "hysteria2" ]; then
            local new_tag="hy2-in-${new_tag_suffix}"
        else
            local new_tag="tuic-in-${new_tag_suffix}"
        fi
        
        local new_cert="${SINGBOX_DIR}/${new_tag}.pem"
        local new_key="${SINGBOX_DIR}/${new_tag}.key"
        
        # 重命名证书文件
        if [ -f "$old_cert" ] && [ -f "$old_key" ]; then
            mv "$old_cert" "$new_cert"
            mv "$old_key" "$new_key"
            
            # 更新配置中的证书路径
            _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].tls.certificate_path = \"$new_cert\"" || return
            _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].tls.key_path = \"$new_key\"" || return
        fi
        
        # 更新 tag
        _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index].tag = \"$new_tag\"" || return
        
        # 更新 metadata.json 中的 key
        if jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
            local meta_content=$(jq ".\"$tag_to_modify\"" "$METADATA_FILE")
            _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_modify\") | . + {\"$new_tag\": $meta_content}" || return
        fi
    fi
    
    _success "端口修改成功: ${old_port} -> ${new_port}"
    _manage_service "restart"
}

# 第三方节点导入功能
_import_third_party_node() {
    _info "--- 导入第三方节点 ---"
    echo "支持的协议：VLESS-Reality, Hysteria2, TUIC, Shadowsocks"
    echo ""
    
    read -p "请粘贴第三方节点分享链接: " third_party_link
    
    if [ -z "$third_party_link" ]; then
        _error "链接为空"
        return
    fi
    
    # 识别协议类型
    local protocol=""
    if [[ "$third_party_link" =~ ^vless:// ]]; then
        protocol="vless"
    elif [[ "$third_party_link" =~ ^hysteria2:// ]]; then
        protocol="hysteria2"
    elif [[ "$third_party_link" =~ ^tuic:// ]]; then
        protocol="tuic"
    elif [[ "$third_party_link" =~ ^ss:// ]]; then
        protocol="shadowsocks"
    else
        _error "不支持的协议！仅支持: vless, hysteria2, tuic, ss"
        return
    fi
    
    _info "识别协议: ${protocol}"
    
    # 解析链接
    local parse_result=""
    case "$protocol" in
        "vless")
            parse_result=$(_parse_vless_link "$third_party_link")
            ;;
        "hysteria2")
            parse_result=$(_parse_hysteria2_link "$third_party_link")
            ;;
        "tuic")
            parse_result=$(_parse_tuic_link "$third_party_link")
            ;;
        "shadowsocks")
            parse_result=$(_parse_shadowsocks_link "$third_party_link")
            ;;
    esac
    
    if [ -z "$parse_result" ]; then
        _error "链接解析失败"
        return
    fi
    
    # 显示解析结果
    local node_name=$(echo "$parse_result" | jq -r '.name')
    local server=$(echo "$parse_result" | jq -r '.server')
    local port=$(echo "$parse_result" | jq -r '.port')
    
    echo ""
    _success "解析成功！"
    echo "节点名称: ${node_name}"
    echo "服务器: ${server}:${port}"
    echo "协议: ${protocol}"
    echo ""
    
    # 选择本地适配协议
    echo "请选择本地适配协议（用于中转）:"
    echo "  1) VLESS-TCP（推荐）"
    echo "  2) Shadowsocks (aes-256-gcm)"
    echo "  3) Shadowsocks (2022-blake3-aes-128-gcm)"
    read -p "请输入选项 [1-3]: " adapter_choice
    
    local adapter_type=""
    local adapter_method=""
    case "$adapter_choice" in
        1) adapter_type="vless" ;;
        2) adapter_type="shadowsocks"; adapter_method="aes-256-gcm" ;;
        3) adapter_type="shadowsocks"; adapter_method="2022-blake3-aes-128-gcm" ;;
        *) _error "无效选项"; return ;;
    esac
    
    # 分配本地端口
    read -p "请输入本地监听端口 (回车随机): " local_port
    if [ -z "$local_port" ]; then
        local_port=$(shuf -i 10000-20000 -n 1)
    fi
    
    # 检查端口冲突
    if jq -e ".inbounds[] | select(.listen_port == $local_port)" "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "端口 $local_port 已被占用！"
        return
    fi
    
    # 自定义适配层名称
    local adapter_type_name="VLESS-TCP"
    if [ "$adapter_type" == "shadowsocks" ]; then
        adapter_type_name="SS-${adapter_method}"
    fi
    
    local default_adapter_name="Adapter-${node_name}-${adapter_type_name}"
    echo ""
    _info "即将创建本地适配层: 127.0.0.1:${local_port} (${adapter_type})"
    read -p "请输入适配层名称 (回车使用: ${default_adapter_name}): " custom_adapter_name
    
    local adapter_name="${custom_adapter_name:-$default_adapter_name}"
    
    _info "本地适配层: ${adapter_name}"
    
    # 生成配置
    _create_third_party_adapter "$protocol" "$parse_result" "$adapter_type" "$adapter_method" "$local_port" "$adapter_name"
}

# 解析 VLESS 链接
_parse_vless_link() {
    local link="$1"
    
    # vless://uuid@server:port?param1=value1&param2=value2#name
    local uuid=$(echo "$link" | sed 's|vless://\([^@]*\)@.*|\1|')
    local server=$(echo "$link" | sed 's|.*@\([^:]*\):.*|\1|')
    local port=$(echo "$link" | sed 's|.*:\([0-9]*\)?.*|\1|')
    local params=$(echo "$link" | sed 's|.*?\([^#]*\).*|\1|')
    local name=$(echo "$link" | sed 's|.*#\(.*\)|\1|' | sed 's/%20/ /g; s/%2F/\//g; s/%3A/:/g')
    
    # 解析参数
    local flow=""
    local security=""
    local sni=""
    local pbk=""
    local sid=""
    local fp="chrome"
    
    IFS='&' read -ra PARAM_ARRAY <<< "$params"
    for param in "${PARAM_ARRAY[@]}"; do
        local key=$(echo "$param" | cut -d= -f1)
        local value=$(echo "$param" | cut -d= -f2-)
        case "$key" in
            "flow") flow="$value" ;;
            "security") security="$value" ;;
            "sni"|"servername") sni="$value" ;;
            "pbk") pbk="$value" ;;
            "sid") sid="$value" ;;
            "fp") fp="$value" ;;
        esac
    done
    
    # 检查是否为 Reality
    if [ "$security" != "reality" ]; then
        _error "仅支持 VLESS-Reality 协议"
        return 1
    fi
    
    # 生成 JSON
    jq -n \
        --arg name "$name" \
        --arg server "$server" \
        --arg port "$port" \
        --arg uuid "$uuid" \
        --arg flow "$flow" \
        --arg sni "$sni" \
        --arg pbk "$pbk" \
        --arg sid "$sid" \
        --arg fp "$fp" \
        '{name:$name,server:$server,port:($port|tonumber),uuid:$uuid,flow:$flow,sni:$sni,pbk:$pbk,sid:$sid,fp:$fp}'
}

# 解析 Hysteria2 链接
_parse_hysteria2_link() {
    local link="$1"
    
    # hysteria2://password@server:port?param1=value1#name
    local password=$(echo "$link" | sed 's|hysteria2://\([^@]*\)@.*|\1|')
    local server_part=$(echo "$link" | sed 's|hysteria2://[^@]*@\([^?#]*\).*|\1|')
    
    # 分离 server 和 port
    local server=$(echo "$server_part" | cut -d: -f1)
    local port=$(echo "$server_part" | cut -d: -f2)
    
    # 提取参数
    local params=""
    if [[ "$link" == *"?"* ]]; then
        params=$(echo "$link" | sed 's|[^?]*?\([^#]*\).*|\1|')
    fi
    
    # 提取名称
    local name=""
    if [[ "$link" == *"#"* ]]; then
        name=$(echo "$link" | sed 's|.*#\(.*\)|\1|' | sed 's/%20/ /g; s/%2F/\//g; s/%3A/:/g')
    fi
    
    local sni=""
    local insecure="0"
    
    if [ -n "$params" ]; then
        IFS='&' read -ra PARAM_ARRAY <<< "$params"
        for param in "${PARAM_ARRAY[@]}"; do
            local key=$(echo "$param" | cut -d= -f1)
            local value=$(echo "$param" | cut -d= -f2-)
            case "$key" in
                "sni") sni="$value" ;;
                "insecure") insecure="$value" ;;
            esac
        done
    fi
    
    # 验证必需字段
    if [ -z "$password" ] || [ -z "$server" ] || [ -z "$port" ]; then
        _error "Hysteria2 链接解析失败，缺少必需字段"
        return 1
    fi
    
    # 验证端口是数字
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        _error "端口号无效: $port"
        return 1
    fi
    
    jq -n \
        --arg name "$name" \
        --arg server "$server" \
        --arg port "$port" \
        --arg password "$password" \
        --arg sni "$sni" \
        --arg insecure "$insecure" \
        '{name:$name,server:$server,port:($port|tonumber),password:$password,sni:$sni,insecure:($insecure|tonumber)}'
}

# 解析 TUIC 链接
_parse_tuic_link() {
    local link="$1"
    
    # tuic://uuid:password@server:port?param1=value1#name
    local uuid=$(echo "$link" | sed 's|tuic://\([^:]*\):.*|\1|')
    local password=$(echo "$link" | sed 's|tuic://[^:]*:\([^@]*\)@.*|\1|')
    local server_part=$(echo "$link" | sed 's|tuic://[^@]*@\([^?#]*\).*|\1|')
    
    # 分离 server 和 port
    local server=$(echo "$server_part" | cut -d: -f1)
    local port=$(echo "$server_part" | cut -d: -f2)
    
    # 提取参数
    local params=""
    if [[ "$link" == *"?"* ]]; then
        params=$(echo "$link" | sed 's|[^?]*?\([^#]*\).*|\1|')
    fi
    
    # 提取名称
    local name=""
    if [[ "$link" == *"#"* ]]; then
        name=$(echo "$link" | sed 's|.*#\(.*\)|\1|' | sed 's/%20/ /g; s/%2F/\//g; s/%3A/:/g')
    fi
    
    local sni=""
    local cc="bbr"
    local insecure="1"  # 第三方节点默认跳过证书验证
    
    if [ -n "$params" ]; then
        IFS='&' read -ra PARAM_ARRAY <<< "$params"
        for param in "${PARAM_ARRAY[@]}"; do
            local key=$(echo "$param" | cut -d= -f1)
            local value=$(echo "$param" | cut -d= -f2-)
            case "$key" in
                "sni") sni="$value" ;;
                "congestion_control"|"cc") cc="$value" ;;
                "insecure"|"allow_insecure") insecure="$value" ;;
            esac
        done
    fi
    
    # 如果没有 SNI，使用服务器地址
    if [ -z "$sni" ]; then
        sni="$server"
    fi
    
    # 验证必需字段
    if [ -z "$uuid" ] || [ -z "$password" ] || [ -z "$server" ] || [ -z "$port" ]; then
        _error "TUIC 链接解析失败，缺少必需字段"
        return 1
    fi
    
    # 验证端口是数字
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        _error "端口号无效: $port"
        return 1
    fi
    
    jq -n \
        --arg name "$name" \
        --arg server "$server" \
        --arg port "$port" \
        --arg uuid "$uuid" \
        --arg password "$password" \
        --arg sni "$sni" \
        --arg cc "$cc" \
        --arg insecure "$insecure" \
        '{name:$name,server:$server,port:($port|tonumber),uuid:$uuid,password:$password,sni:$sni,cc:$cc,insecure:($insecure|tonumber)}'
}

# 解析 Shadowsocks 链接
_parse_shadowsocks_link() {
    local link="$1"
    
    # Step 1: URL解码
    local decoded_link="$link"
    decoded_link="${decoded_link//%3A/:}"
    decoded_link="${decoded_link//%2B/+}"
    decoded_link="${decoded_link//%3D/=}"
    decoded_link="${decoded_link//%2F//}"
    
    # Step 2: 提取名称
    local name=""
    if [[ "$decoded_link" == *"#"* ]]; then
        name="${decoded_link##*#}"
    fi
    
    # Step 3: 移除 # 和 ? 部分
    decoded_link="${decoded_link%%\?*}"
    decoded_link="${decoded_link%%#*}"
    
    # Step 4: 提取 ss:// 后的部分
    local ss_body="${decoded_link#ss://}"
    
    # Step 5: 分离 @ 前后
    local method password server port
    
    if [[ "$ss_body" == *"@"* ]]; then
        # 格式: prefix@server:port
        local prefix="${ss_body%%@*}"
        local server_port="${ss_body##*@}"
        
        # 提取 server 和 port
        server="${server_port%:*}"
        port="${server_port##*:}"
        
        # 判断 prefix 是否是 Base64（尝试解码）
        local decoded_prefix=$(echo -n "$prefix" | base64 -d 2>/dev/null)
        
        if [ -n "$decoded_prefix" ] && [[ "$decoded_prefix" == *":"* ]]; then
            # Base64 格式
            method="${decoded_prefix%%:*}"
            password="${decoded_prefix#*:}"
        else
            # 明文格式
            method="${prefix%%:*}"
            password="${prefix#*:}"
        fi
    else
        # 格式: ss://base64(method:password@server:port)
        local decoded=$(echo -n "$ss_body" | base64 -d 2>/dev/null)
        
        if [ -z "$decoded" ]; then
            echo "解码失败" >&2
            return 1
        fi
        
        # 提取 method:password@server:port
        local method_pass="${decoded%%@*}"
        local server_port="${decoded##*@}"
        
        method="${method_pass%%:*}"
        password="${method_pass#*:}"
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    # 清理空白字符
    method=$(echo "$method" | xargs)
    password=$(echo "$password" | xargs)
    server=$(echo "$server" | xargs)
    port=$(echo "$port" | xargs)
    name=$(echo "$name" | xargs)
    
    # 调试信息输出到 stderr（不会被 $() 捕获）
    echo "解析结果: method=$method, server=$server, port=$port, name=$name" >&2
    
    # 验证
    if [ -z "$method" ] || [ -z "$password" ] || [ -z "$server" ] || [ -z "$port" ]; then
        echo "解析失败：缺少必需字段" >&2
        return 1
    fi
    
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo "端口无效: [$port]" >&2
        return 1
    fi
    
    # 只有这一行输出到 stdout（被 $() 捕获）
    jq -n \
        --arg name "$name" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg method "$method" \
        --arg password "$password" \
        '{name:$name,server:$server,port:$port,method:$method,password:$password}'
}

# 创建第三方节点适配层
_create_third_party_adapter() {
    local third_party_protocol="$1"
    local third_party_config="$2"
    local adapter_type="$3"
    local adapter_method="$4"
    local local_port="$5"
    local adapter_name="$6"  # 新增：自定义名称
    
    local adapter_tag="adapter-${adapter_type}-${local_port}"
    local outbound_tag="third-party-${third_party_protocol}-${local_port}"
    
    # 1. 创建本地适配层 Inbound
    local adapter_inbound=""
    if [ "$adapter_type" == "vless" ]; then
        local adapter_uuid=$(${SINGBOX_BIN} generate uuid)
        adapter_inbound=$(jq -n \
            --arg tag "$adapter_tag" \
            --arg port "$local_port" \
            --arg uuid "$adapter_uuid" \
            '{type:"vless",tag:$tag,listen:"127.0.0.1",listen_port:($port|tonumber),users:[{uuid:$uuid}],tls:{enabled:false}}')
    else
        # Shadowsocks
        local adapter_password=$(${SINGBOX_BIN} generate rand --hex 16)
        if [ "$adapter_method" == "2022-blake3-aes-128-gcm" ]; then
            adapter_password=$(${SINGBOX_BIN} generate rand --base64 16)
        fi
        adapter_inbound=$(jq -n \
            --arg tag "$adapter_tag" \
            --arg port "$local_port" \
            --arg method "$adapter_method" \
            --arg password "$adapter_password" \
            '{type:"shadowsocks",tag:$tag,listen:"127.0.0.1",listen_port:($port|tonumber),method:$method,password:$password}')
    fi
    
    # 2. 创建第三方节点 Outbound
    local third_party_outbound=""
    case "$third_party_protocol" in
        "vless")
            local server=$(echo "$third_party_config" | jq -r '.server')
            local port=$(echo "$third_party_config" | jq -r '.port')
            local uuid=$(echo "$third_party_config" | jq -r '.uuid')
            local flow=$(echo "$third_party_config" | jq -r '.flow')
            local sni=$(echo "$third_party_config" | jq -r '.sni')
            local pbk=$(echo "$third_party_config" | jq -r '.pbk')
            local sid=$(echo "$third_party_config" | jq -r '.sid')
            local fp=$(echo "$third_party_config" | jq -r '.fp')
            
            third_party_outbound=$(jq -n \
                --arg tag "$outbound_tag" \
                --arg server "$server" \
                --arg port "$port" \
                --arg uuid "$uuid" \
                --arg flow "$flow" \
                --arg sni "$sni" \
                --arg pbk "$pbk" \
                --arg sid "$sid" \
                --arg fp "$fp" \
                '{type:"vless",tag:$tag,server:$server,server_port:($port|tonumber),uuid:$uuid,flow:$flow,packet_encoding:"xudp",tls:{enabled:true,server_name:$sni,reality:{enabled:true,public_key:$pbk,short_id:$sid},utls:{enabled:true,fingerprint:$fp}}}')
            ;;
        "hysteria2")
            local server=$(echo "$third_party_config" | jq -r '.server')
            local port=$(echo "$third_party_config" | jq -r '.port')
            local password=$(echo "$third_party_config" | jq -r '.password')
            local sni=$(echo "$third_party_config" | jq -r '.sni')
            local insecure_raw=$(echo "$third_party_config" | jq -r '.insecure')
            local insecure="false"
            [[ "$insecure_raw" == "1" ]] && insecure="true"
            
            third_party_outbound=$(jq -n \
                --arg tag "$outbound_tag" \
                --arg server "$server" \
                --arg port "$port" \
                --arg password "$password" \
                --arg sni "$sni" \
                --argjson insecure "$insecure" \
                '{type:"hysteria2",tag:$tag,server:$server,server_port:($port|tonumber),password:$password,tls:{enabled:true,server_name:$sni,insecure:$insecure,alpn:["h3"]}}')
            ;;
        "tuic")
            local server=$(echo "$third_party_config" | jq -r '.server')
            local port=$(echo "$third_party_config" | jq -r '.port')
            local uuid=$(echo "$third_party_config" | jq -r '.uuid')
            local password=$(echo "$third_party_config" | jq -r '.password')
            local sni=$(echo "$third_party_config" | jq -r '.sni')
            local cc=$(echo "$third_party_config" | jq -r '.cc')
            local insecure_raw=$(echo "$third_party_config" | jq -r '.insecure')
            local insecure="false"
            [[ "$insecure_raw" == "1" ]] && insecure="true"
            
            third_party_outbound=$(jq -n \
                --arg tag "$outbound_tag" \
                --arg server "$server" \
                --arg port "$port" \
                --arg uuid "$uuid" \
                --arg password "$password" \
                --arg sni "$sni" \
                --arg cc "$cc" \
                --argjson insecure "$insecure" \
                '{type:"tuic",tag:$tag,server:$server,server_port:($port|tonumber),uuid:$uuid,password:$password,congestion_control:$cc,tls:{enabled:true,server_name:$sni,insecure:$insecure,alpn:["h3"]}}')
            ;;
        "shadowsocks")
            local server=$(echo "$third_party_config" | jq -r '.server')
            local port=$(echo "$third_party_config" | jq -r '.port')
            local method=$(echo "$third_party_config" | jq -r '.method')
            local password=$(echo "$third_party_config" | jq -r '.password')
            
            third_party_outbound=$(jq -n \
                --arg tag "$outbound_tag" \
                --arg server "$server" \
                --arg port "$port" \
                --arg method "$method" \
                --arg password "$password" \
                '{type:"shadowsocks",tag:$tag,server:$server,server_port:($port|tonumber),method:$method,password:$password}')
            ;;
    esac
    
    # 3. 创建路由规则
    local route_rule=$(jq -n \
        --arg inbound "$adapter_tag" \
        --arg outbound "$outbound_tag" \
        '{inbound:$inbound,outbound:$outbound}')
    
    # 4. 写入配置
    _info "正在写入配置..."
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$adapter_inbound]" || return
    _atomic_modify_json "$CONFIG_FILE" ".outbounds = [$third_party_outbound] + .outbounds" || return
    
    # 确保 route 存在
    if ! jq -e '.route' "$CONFIG_FILE" >/dev/null; then
        _atomic_modify_json "$CONFIG_FILE" '. += {"route":{"rules":[]}}' || return
    fi
    if ! jq -e '.route.rules' "$CONFIG_FILE" >/dev/null; then
        _atomic_modify_json "$CONFIG_FILE" '.route.rules = []' || return
    fi
    
    _atomic_modify_json "$CONFIG_FILE" ".route.rules += [$route_rule]" || return
    
    # 5. 保存元数据
    local node_name=$(echo "$third_party_config" | jq -r '.name')
    local metadata=$(jq -n \
        --arg type "third-party-adapter" \
        --arg source_protocol "$third_party_protocol" \
        --arg source_name "$node_name" \
        --arg adapter_name "$adapter_name" \
        --arg adapter_type "$adapter_type" \
        --arg adapter_port "$local_port" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        '{type:$type,source_protocol:$source_protocol,source_name:$source_name,adapter_name:$adapter_name,adapter_type:$adapter_type,adapter_port:($adapter_port|tonumber),created_at:$created}')
    
    _atomic_modify_json "$METADATA_FILE" ". + {\"$adapter_tag\": $metadata}" || return
    
    # 6. 添加到 clash.yaml
    if [ "$adapter_type" == "vless" ]; then
        local adapter_uuid=$(echo "$adapter_inbound" | jq -r '.users[0].uuid')
        local proxy_json=$(jq -n \
            --arg name "$adapter_name" \
            --arg port "$local_port" \
            --arg uuid "$adapter_uuid" \
            '{name:$name,type:"vless",server:"127.0.0.1",port:($port|tonumber),uuid:$uuid,tls:false,network:"tcp"}')
    else
        local adapter_password=$(echo "$adapter_inbound" | jq -r '.password')
        local proxy_json=$(jq -n \
            --arg name "$adapter_name" \
            --arg port "$local_port" \
            --arg method "$adapter_method" \
            --arg password "$adapter_password" \
            '{name:$name,type:"ss",server:"127.0.0.1",port:($port|tonumber),cipher:$method,password:$password}')
    fi
    
    _add_node_to_yaml "$proxy_json"
    
    _success "第三方节点导入成功！"
    echo ""
    echo "本地适配层信息："
    echo "  地址: 127.0.0.1:${local_port}"
    echo "  协议: ${adapter_type}"
    if [ "$adapter_type" == "vless" ]; then
        echo "  UUID: $(echo "$adapter_inbound" | jq -r '.users[0].uuid')"
    else
        echo "  加密: ${adapter_method}"
        echo "  密码: $(echo "$adapter_inbound" | jq -r '.password')"
    fi
    echo ""
    _info "此节点现在可作为落地机进行中转配置！"
    _info "请使用「进阶功能」生成 Token 并配置中转。"
    
    _manage_service "restart"
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

# --- 进阶功能 (子脚本) ---
_advanced_features() {
    local script_name="advanced_relay.sh"
    # 优先检查 /root 目录 (用户要求)
    local script_path="/root/${script_name}"
    
    # [开发测试兼容] 如果 /root 下没有，但当前目录下有 (比如手动上传了)，则使用当前目录的
    if [ ! -f "$script_path" ] && [ -f "./${script_name}" ]; then
        script_path="./${script_name}"
    fi

    # 如果都不存在，则下载
    if [ ! -f "$script_path" ]; then
        _info "本地未检测到进阶脚本，正在尝试下载..."
        # 假设用户仓库的 main 分支
        local download_url="https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/${script_name}"
        
        if wget -qO "$script_path" "$download_url"; then
            chmod +x "$script_path"
            _success "下载成功！"
        else
            _error "下载失败！请检查网络或确认 GitHub 仓库地址。"
            # 清理可能的空文件
            rm -f "$script_path"
            return 1
        fi
    fi

    # 执行脚本
    if [ -f "$script_path" ]; then
        # 赋予权限并执行
        chmod +x "$script_path"
        bash "$script_path"
    else
        _error "找不到进阶脚本文件: ${script_path}"
    fi
}

_main_menu() {
    while true; do
        clear
        echo "===================================================="
        _info "        sing-box 全功能管理脚本 v${SCRIPT_VERSION}"
        echo "===================================================="
        _info "【节点管理】"
        echo "  1) 添加节点"
        echo "  2) 查看节点分享链接"
        echo "  3) 删除节点"
        echo "  4) 修改节点端口"
        echo "  5) 导入第三方节点"
        echo "----------------------------------------------------"
        _info "【服务控制】"
        echo "  6) 重启 sing-box"
        echo "  7) 停止 sing-box"
        echo "  8) 查看 sing-box 运行状态"
        echo "  9) 查看 sing-box 实时日志"
        echo "----------------------------------------------------"
        _info "【脚本与配置】"
        echo " 10) 检查配置文件"
        echo "----------------------------------------------------"
        _info "【更新与卸载】"
        echo -e " 11) ${GREEN}更新脚本${NC}"
        echo -e " 12) ${GREEN}更新 Sing-box 核心${NC}"
        echo -e " 13) ${RED}卸载 sing-box 及脚本${NC}"
        echo "----------------------------------------------------"
        _info "【进阶功能】"
        echo -e " 14) ${CYAN}进阶功能 (落地/中转配置)${NC}"
        echo "----------------------------------------------------"
        echo "  0) 退出脚本"
        echo "===================================================="
        read -p "请输入选项 [0-14]: " choice

        case $choice in
            1) _show_add_node_menu ;;
            2) _view_nodes ;;
            3) _delete_node ;;
            4) _modify_port ;;
            5) _import_third_party_node ;;
            6) _manage_service "restart" ;;
            7) _manage_service "stop" ;;
            8) _manage_service "status" ;;
            9) _view_log ;;
            10) _check_config ;;
            11) _update_script ;;
            12) _update_singbox_core ;;
            13) _uninstall ;; 
            14) _advanced_features ;;
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

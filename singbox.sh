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
SCRIPT_VERSION="2.6"

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
                _info "正在删除线路机脚本文件: ${relay_script_path}"
                rm -f "$relay_script_path"
            else
                _warning "未找到 relay-install.sh，尝试手动清理线路机配置..."
                local relay_service_name="sing-box-relay"
                systemctl stop $relay_service_name >/dev/null 2>&1
                systemctl disable $relay_service_name >/dev/null 2>&1
                rc-service $relay_service_name stop >/dev/null 2>&1
                rc-update del $relay_service_name default >/dev/null 2>&1
                rm -f /etc/systemd/system/${relay_service_name}.service
                rm -f /etc/init.d/${relay_service_name}
                rm -rf "$relay_config_dir"
            fi
            _success "[线路机] 卸载完毕。"
            # 标记为 false，因为线路机也没了，可以安全删除主程序
            keep_singbox_binary=false 
        else
            _info "您选择了 [保留] 线路机服务。"
            _warning "为了保持线路机服务 [sing-box-relay] 正常运行："
            _success "sing-box 主程序 (${SINGBOX_BIN}) 将被 [保留]。"
            # [!!!] 核心修改：设置保护标记
            keep_singbox_binary=true 

            # --- [!!!] 新增：输出后续管理命令 ---
            echo -e "${CYAN}----------------------------------------------------${NC}"
            _success "主脚本卸载后，您仍可使用以下命令管理 [线路机]："
            echo ""
            echo -e "  ${YELLOW}1. 查看链接:${NC} bash ${relay_script_path} view"
            
            local relay_service_name="sing-box-relay"
            local relay_log_file="/var/log/${relay_service_name}.log"
            
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                echo -e "  ${YELLOW}2. 重启服务:${NC} systemctl restart ${relay_service_name}"
                echo -e "  ${YELLOW}3. 查看日志:${NC} journalctl -u ${relay_service_name} -f"
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                echo -e "  ${YELLOW}2. 重启服务:${NC} rc-service ${relay_service_name} restart"
                echo -e "  ${YELLOW}3. 查看日志:${NC} tail -f ${relay_log_file}"
            else # direct
                echo -e "  ${YELLOW}2. 重启服务:${NC} bash ${relay_script_path}"
                echo -e "  ${YELLOW}3. 查看日志:${NC} tail -f ${relay_log_file}"
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
    # [!!!] 核心修改：分步删除
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
    
    # 步骤 1: 获取连接地址 (用于 server 字段)
    _info "请输入客户端用于“连接”的地址:"
    _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
    _info "  - (其他)   您也可以手动输入一个IP或域名 (例如：xxx.123456.xyz)"
    read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
    
    # 如果用户回车，则使用 $server_ip，否则使用用户输入的值
    local client_server_addr=${connection_address:-$server_ip}
    
    # 如果用的是IP，且是IPv6，自动加上方括号
    if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
         client_server_addr="[${client_server_addr}]"
    fi

    # 步骤 2: 获取伪装域名 (用于 SNI 和 Host)
    _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
    _info " (例如: xxx.987654.xyz)"
    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    # 步骤 3: 端口
    read -p "请输入监听端口 : " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1

    # 步骤 4: 路径
    read -p "请输入 WebSocket 路径 (回车则随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已为您生成随机 WebSocket 路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    # 步骤 5: 证书文件
    _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
    _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
    _info "  - (或)   使用 Cloudflare 源服务器证书"
    read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
    [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

    read -p "请输入私钥文件 .key 的完整路径: " key_path
    [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
    
    # 步骤 6: 跳过验证
    read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
    local skip_verify=false
    if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
        skip_verify=true
        _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-ws-in-${port}"
    local name="VLESS-WS-${port}"
    
    # Inbound (服务器端) 配置: 使用 伪装域名 对应的证书
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

    # Proxy (客户端) 配置: 
    # server = connection_address (IP 或 域名)
    # servername = camouflage_domain (证书域名)
    # Host = camouflage_domain (证书域名)
    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$port" \
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
    _success "VLESS (WebSocket+TLS) 节点添加成功!"
    _success "客户端连接地址 (server): ${client_server_addr}"
    _success "客户端伪装域名 (servername/Host): ${camouflage_domain}"
    _success "客户端 UDP 转发已启用。"
}

_add_trojan_ws_tls() {
    _info "--- Trojan (WebSocket+TLS) 设置向导 ---"
    
    # 步骤 1: 获取连接地址 (用于 server 字段)
    _info "请输入客户端用于“连接”的地址:"
    _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
    _info "  - (其他)   您也可以手动输入一个IP或域名 (例如：xxx.123456.xyz)"
    read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
    
    # 如果用户回车，则使用 $server_ip，否则使用用户输入的值
    local client_server_addr=${connection_address:-$server_ip}
    
    # 如果用的是IP，且是IPv6，自动加上方括号
    if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
         client_server_addr="[${client_server_addr}]"
    fi

    # 步骤 2: 获取伪装域名 (用于 SNI 和 Host)
    _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
    _info " (例如: xxx.987654.xyz)"
    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    # 步骤 3: 端口
    read -p "请输入监听端口 : " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1

    # 步骤 4: 路径
    read -p "请输入 WebSocket 路径 (回车则随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已为您生成随机 WebSocket 路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    # 步骤 5: 证书文件 (逻辑同 vless-ws-tls)
    _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
    _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
    _info "  - (或)   使用 Cloudflare 源服务器证书"
    read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
    [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

    read -p "请输入私钥文件 .key 的完整路径: " key_path
    [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
    
    # 步骤 6: 跳过验证 (逻辑同 vless-ws-tls)
    read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
    local skip_verify=false
    if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
        skip_verify=true
        _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
    fi

    # [!] Trojan: 使用密码，而非UUID
    read -p "请输入 Trojan 密码 (回车则随机生成): " password
    if [ -z "$password" ]; then
        password=$(${SINGBOX_BIN} generate rand --hex 16)
        _info "已为您生成随机密码: ${password}"
    fi

    local tag="trojan-ws-in-${port}"
    local name="Trojan-WS-${port}"
    
    # Inbound (服务器端) 配置: (不变，是正确的)
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

    # [!!!] 修复：修改 Proxy (clash.yaml) 配置
    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$port" \
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
    _success "Trojan (WebSocket+TLS) 节点添加成功!"
    _success "客户端连接地址 (server): ${client_server_addr}"
    _success "客户端伪装域名 (sni/Host): ${camouflage_domain}"
    _success "客户端 UDP 转发已启用。"
}

_add_vless_reality() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入伪装域名 (默认: www.microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"www.microsoft.com"}
    
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

        # 优先使用 metadata.json 中的 IP (用于 REALITY 和 TCP)
        local display_server=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
        # 移除方括号
        local display_ip=$(echo "$display_server" | tr -d '[]')
        
        echo "-------------------------------------"
        _info " 节点: ${tag}"
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
                    url="vless://${uuid}@${server_addr}:${client_port}?encryption=none&security=tls&type=ws&host=${host_header}&path=${encoded_path}#$(_url_encode "$tag")"
                elif [ "$(echo "$node" | jq -r '.tls.reality.enabled')" == "true" ]; then
                    # VLESS + REALITY
                    local sn=$(echo "$node" | jq -r '.tls.server_name'); local flow=$(echo "$node" | jq -r '.users[0].flow')
                    local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE"); local pk=$(echo "$meta" | jq -r '.publicKey'); local sid=$(echo "$meta" | jq -r '.shortId')
                    url="vless://${uuid}@${display_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sn}&fp=chrome&flow=${flow}&pbk=${pk}&sid=${sid}#$(_url_encode "$tag")"
                else
                    # VLESS + TCP
                    url="vless://${uuid}@${display_ip}:${port}?type=tcp&security=none#$(_url_encode "$tag")"
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
                    local sni=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .servername' ${CLASH_YAML_FILE} | head -n 1)

                    url="trojan://$(_url_encode "$password")@${server_addr}:${client_port}?encryption=none&security=tls&type=ws&host=${host_header}&path=${encoded_path}&sni=${sni}#$(_url_encode "$tag")"
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

_generate_relay_script() {
    _info "--- 生成 VLESS+Reality 中转落地脚本 ---"
    _info "此功能将生成一个新脚本，用于在“线路机”上部署。"
    _info "它会将“线路机”的 VLESS 流量转发到本机的 Shadowsocks 节点。"
    _warning "您必须已在本机上创建了一个 Shadowsocks 节点才能继续。"

    # 1. 查找本机可用的 SS 节点
    local ss_inbounds=$(jq -c '.inbounds[] | select(.type == "shadowsocks")' "$CONFIG_FILE")
    if [ -z "$ss_inbounds" ]; then
        _error "错误：未在本机找到任何 Shadowsocks (SS) 节点。"
        _warning "请先使用 [1) 添加节点] 菜单添加一个 Shadowsocks 节点作为落地。"
        return 1
    fi

    # 2. 让用户选择
    _info "请选择一个本机的 SS 节点作为“落地”："
    local ss_options=()
    local i=1
    while IFS= read -r line; do
        local tag=$(echo "$line" | jq -r '.tag')
        local port=$(echo "$line" | jq -r '.listen_port')
        local method=$(echo "$line" | jq -r '.method')
        echo -e " ${CYAN}$i)${NC} ${tag} (端口: ${port}, 方法: ${method})"
        ss_options+=("$line") # 存储完整的 JSON 对象
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
    # $server_ip (全局变量) 已经由 main() 获取
    local INBOUND_IP=$server_ip
    
    _success "已选择落地节点：${INBOUND_IP}:${INBOUND_PORT} (方法: ${INBOUND_METHOD})"
    
    local RELAY_SCRIPT_PATH="/root/relay-install.sh"
    _info "正在生成线路机脚本: ${RELAY_SCRIPT_PATH} ..."

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
# [!!!] BUG 修复：为 action_view 定义颜色
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

# --- 全局常量 ---
SERVICE_NAME="sing-box-relay"
CONFIG_DIR="/etc/sing-box" # [!] 与主脚本的 /usr/local/etc/sing-box 隔离
CONFIG_FILE="${CONFIG_DIR}/config.json"
LINK_FILE="${CONFIG_DIR}/vless_links.txt" # [!] 多个链接
LOG_FILE="/var/log/${SERVICE_NAME}.log"
PID_FILE="/run/${SERVICE_NAME}.pid"
SINGBOX_BIN="/usr/local/bin/sing-box" # [!] 与主脚本共享

# --- 卸载功能 ---
action_uninstall() {
    info "正在卸载 sing-box (中转机: ${SERVICE_NAME})..."
    
    local INIT_SYSTEM="direct"
    if [ -f "/sbin/openrc-run" ]; then INIT_SYSTEM="openrc";
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then INIT_SYSTEM="systemd"; fi
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
        direct)
            if [ -f "$PID_FILE" ]; then kill $(cat "$PID_FILE") >/dev/null 2>&1 || true; fi
            ;;
    esac
    info "服务 [${SERVICE_NAME}] 已停止并移除。"

    rm -rf "$CONFIG_DIR" # 删除 /etc/sing-box
    rm -f $LOG_FILE $PID_FILE
    
    warn "[!] 注意：sing-box 主程序 (${SINGBOX_BIN}) 未被删除。"
    info "中转机配置已删除。卸载完成！"
}

# --- 查看链接功能 ---
action_view() {
    if [ -f "$LINK_FILE" ]; then
        info "VLESS Reality 中转链接如下 (共 $(wc -l < "$LINK_FILE") 个)："
        echo ""
        # 逐行读取并添加颜色
        local i=1
        while IFS= read -r line; do
            # [!!!] BUG 修复：现在 $CYAN 和 $NC 已定义
            echo -e "  ${CYAN}$i)${NC} \033[1;33m${line}\033[0m"
            ((i++))
        done < "$LINK_FILE"
        echo ""
    else
        err "未找到链接文件: $LINK_FILE"
        err "请先运行一次安装脚本 (不带参数)。"
    fi
}

# --- [!!!] 新增：重启服务 助手 ---
_detect_init_system() {
    if [ -f "/sbin/openrc-run" ]; then echo "openrc";
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then echo "systemd";
    else echo "direct"; fi
}
_restart_relay_service() {
    local INIT_SYSTEM=$(_detect_init_system)
    info "正在使用 $INIT_SYSTEM 模式重启 [${SERVICE_NAME}]..."
    
    case "$INIT_SYSTEM" in
        systemd) systemctl restart $SERVICE_NAME ;;
        openrc) rc-service $SERVICE_NAME restart ;;
        direct)
            if [ -f "$PID_FILE" ]; then
                kill $(cat "$PID_FILE") >/dev/null 2>&1 || true
                rm -f "$PID_FILE"
            fi
            nohup $SINGBOX_BIN run -c $CONFIG_FILE >> $LOG_FILE 2>&1 &
            echo $! > $PID_FILE
            ;;
    esac
    sleep 1
    info "服务已重启。"
}
# --- [!!!] 新增：添加新中转 动作 ---
action_add() {
    info "--- 添加一个新的中转路由 ---"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        err "未找到主配置文件: $CONFIG_FILE"
        err "请先运行一次安装 (bash $0) 来创建第一个中转。"
        return 1
    fi
    
    info "步骤 1/2: 请输入 [新落地机] 的 SS 信息"
    read -p "  > 落地机 IP 地址: " NEW_INBOUND_IP
    read -p "  > 落地机 SS 端口: " NEW_INBOUND_PORT
    read -p "  > 落地机 SS 密码: " NEW_INBOUND_PASSWORD
    read -p "  > 落地机 SS 方法 (默认 2022-blake3-aes-128-gcm): " NEW_INBOUND_METHOD
    [ -z "$NEW_INBOUND_METHOD" ] && NEW_INBOUND_METHOD="2022-blake3-aes-128-gcm"
    
    info "步骤 2/2: 请输入 [线路机] (A) 的新入口配置"
    read -p "  > 线路机新监听端口 : " NEW_LISTEN_PORT
    read -p "  > 线路机新伪装SNI (默认 www.microsoft.com): " NEW_SNI
    [ -z "$NEW_SNI" ] && NEW_SNI="www.microsoft.com"

    # 验证
    if [ -z "$NEW_INBOUND_IP" ] || [ -z "$NEW_INBOUND_PORT" ] || [ -z "$NEW_LISTEN_PORT" ]; then
        err "IP 和 端口 不能为空！"
        return 1
    fi

    info "正在生成新密钥..."
    local TAG_SUFFIX=$(date +%s) # 使用时间戳作为唯一标签
    local VLESS_TAG="vless-in-${TAG_SUFFIX}"
    local SS_TAG="relay-out-${TAG_SUFFIX}"
    
    local UUID=$($SINGBOX_BIN generate uuid)
    local REALITY_KEYS=$($SINGBOX_BIN generate reality-keypair)
    local REALITY_PK=$(echo "$REALITY_KEYS" | awk '/PrivateKey/ {print $2}')
    # [!!!] BUG 修复：REALTY_KEYS -> REALITY_KEYS
    local REALITY_PUB=$(echo "$REALITY_KEYS" | awk '/PublicKey/ {print $2}')
    local REALITY_SID=$($SINGBOX_BIN generate rand 8 --hex)

    info "正在构建新的 JSON 片段..."
    # 1. 新 Inbound
    local new_inbound_json=$(jq -n \
        --arg tag "$VLESS_TAG" \
        --arg port "$NEW_LISTEN_PORT" \
        --arg uuid "$UUID" \
        --arg sni "$NEW_SNI" \
        --arg pk "$REALITY_PK" \
        --arg sid "$REALITY_SID" \
        '{
            "type": "vless", "tag": $tag, "listen": "::", "listen_port": ($port|tonumber), "sniff": true,
            "users": [ { "uuid": $uuid, "flow": "xtls-rprx-vision" } ],
            "tls": {
                "enabled": true, "server_name": $sni,
                "reality": {
                    "enabled": true,
                    "handshake": { "server": $sni, "server_port": 443 },
                    "private_key": $pk, "short_id": [ $sid ], "max_time_difference": "1m"
                }
            }
        }')

    # 2. 新 Outbound
    local new_outbound_json=$(jq -n \
        --arg tag "$SS_TAG" \
        --arg ip "$NEW_INBOUND_IP" \
        --arg port "$NEW_INBOUND_PORT" \
        --arg method "$NEW_INBOUND_METHOD" \
        --arg pass "$NEW_INBOUND_PASSWORD" \
        '{
            "type": "shadowsocks", "tag": $tag, "server": $ip, "server_port": ($port|tonumber),
            "method": $method, "password": $pass
        }')
    
    # 3. 新 Rule
    local new_rule_json=$(jq -n \
        --arg in_tag "$VLESS_TAG" \
        --arg out_tag "$SS_TAG" \
        '{ "inbound": $in_tag, "outbound": $out_tag }')

    info "正在原子化修改配置文件: $CONFIG_FILE"
    # 安全地修改JSON文件
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    
    jq ".inbounds += [$new_inbound_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    # [!] 关键：插入到 "direct" 之前
    jq ".outbounds |= .[0:-1] + [$new_outbound_json] + .[-1:]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$new_rule_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"

    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    info "配置修改完毕！正在重启 [${SERVICE_NAME}]..."
    _restart_relay_service
    
    # --- 输出新链接 ---
    local PUB_IP=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip || echo "YOUR_RELAY_IP")
    [[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"
    
    local VLESS_LINK="vless://$UUID@$PUB_IP:$NEW_LISTEN_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$NEW_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID#relay-to-$(echo $NEW_INBOUND_IP | tr '.' '-')"
    
    # [!] 关键：追加 (>>)
    echo "$VLESS_LINK" >> "$LINK_FILE"

    echo ""
    info "✅ 新中转添加成功！"
    info "VLESS Reality 中转节点 (新)："
    echo -e "\033[1;33m${VLESS_LINK}\033[0m"
    echo ""
    info "所有链接已保存到: ${LINK_FILE}"
}

# --- 脚本主入口 ---
case "${1:-}" in
    uninstall)
        action_uninstall; exit 0 ;;
    view)
        action_view; exit 0 ;;
    add)
        action_add; exit 0 ;;
    "")
        # 继续执行安装
        info "--- 正在执行 [安装/重置] 中转服务 ---"
        ;;
    *)
        err "无效参数: ${1}"
        echo "用法: bash ${0} [install(默认)|add|view|uninstall]"
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

# --- [!!!] (安装流程) 生成 Reality  ---
info "--- 步骤 1/2: 配置 [落地机] ---"
# (从占位符获取信息)
info "落地机 IP: $INBOUND_IP"
info "落地机 端口: $INBOUND_PORT"
info "落地机 方法: $INBOUND_METHOD"

info "--- 步骤 2/2: 配置 [线路机] (本机) ---"
UUID=$($SINGBOX_BIN generate uuid)
info "生成 Reality 密钥对"
REALITY_KEYS=$($SINGBOX_BIN generate reality-keypair)
REALITY_PK=$(echo "$REALITY_KEYS" | awk '/PrivateKey/ {print $2}')
REALITY_PUB=$(echo "$REALITY_KEYS" | awk '/PublicKey/ {print $2}')
REALITY_SID=$($SINGBOX_BIN generate rand 8 --hex)
read -p "输入 [线路机] 监听端口 (留空则随机 20000-65000): " USER_PORT
if [ -z "$USER_PORT" ]; then
    LISTEN_PORT=$(shuf -i 20000-65000 -n 1 2>/dev/null || echo $((RANDOM % 45001 + 20000)))
    info "使用随机端口: $LISTEN_PORT"
else LISTEN_PORT="$USER_PORT"; fi

read -p "输入伪装域名(SNI) [回车默认: www.microsoft.com]: " USER_SNI
[ -z "$USER_SNI" ] && USER_SNI="www.microsoft.com"
info "使用 SNI: $USER_SNI"

# --- [!!!] (安装流程) 创建配置 ---
info "正在创建 [全新] 配置文件: $CONFIG_FILE"
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless", "tag": "vless-in-${LISTEN_PORT}", "listen": "::", "listen_port": $LISTEN_PORT, "sniff": true,
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
      "type": "shadowsocks", "tag": "relay-out-${LISTEN_PORT}",
      "server": "$INBOUND_IP", "server_port": $INBOUND_PORT,
      "method": "$INBOUND_METHOD", "password": "$INBOUND_PASSWORD"
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [ { "inbound": "vless-in-${LISTEN_PORT}", "outbound": "relay-out-${LISTEN_PORT}" } ]
  }
}
EOF

# --- [!!!] (安装流程) 创建服务 ---
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
    direct)
        info "使用 direct 模式 (nohup) 启动..."
        touch "$LOG_FILE"
        if [ -f "$PID_FILE" ]; then kill $(cat "$PID_FILE") >/dev/null 2>&1 || true; rm -f "$PID_FILE"; fi
        nohup $SINGBOX_BIN run -c $CONFIG_FILE >> $LOG_FILE 2>&1 &
        echo $! > $PID_FILE
        sleep 1
        if ps -p "$(cat $PID_FILE)" > /dev/null; then
            info "Direct 模式启动成功, PID: $(cat ${PID_FILE}). 日志: ${LOG_FILE}"
        else
            err "Direct 模式启动失败! 请检查日志: ${LOG_FILE}"; tail -n 20 $LOG_FILE
        fi
        ;;
esac

# --- [!!!] (安装流程) 输出结果 ---
PUB_IP=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip || echo "YOUR_RELAY_IP")
[[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"

VLESS_LINK="vless://$UUID@$PUB_IP:$LISTEN_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$USER_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID#relay-to-$(echo $INBOUND_IP | tr '.' '-')"

# [!] 关键：覆盖 (>)
echo "$VLESS_LINK" > "$LINK_FILE"

echo ""
info "✅ 线路机 [安装/重置] 完成"
info "VLESS Reality 中转节点："
echo -e "\033[1;33m${VLESS_LINK}\033[0m"
echo ""
info "链接已自动保存到: ${LINK_FILE}"
info "您可以随时使用 'bash ${0} view' 命令查看。"
info "如需添加 [更多] 中转, 请运行 'bash ${0} add'"
RELAY_TEMPLATE

    # 5. 替换占位符
    sed -i "s|__INBOUND_IP__|$INBOUND_IP|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PORT__|$INBOUND_PORT|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_METHOD__|$INBOUND_METHOD|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PASSWORD__|$INBOUND_PASSWORD|g" "$RELAY_SCRIPT_PATH"

    # 6. 最终输出
    echo ""
    _success "✅ 线路机脚本已成功生成在: ${RELAY_SCRIPT_PATH}"
    _info "请将此文件从“落地机”传输到“线路机”的 /root 目录。"
    _info "然后在“线路机”上执行: chmod +x ${RELAY_SCRIPT_PATH} && ${RELAY_SCRIPT_PATH}"
    echo ""
    _warning "如需卸载此中转机配置，请在线路机上执行: bash ${RELAY_SCRIPT_PATH} uninstall"
    _warning "如需查看此中转机链接，请在线路机上执行: bash ${RELAY_SCRIPT_PATH} view"
    _warning "如需添加更多中转路由，请在线路机上执行: bash ${RELAY_SCRIPT_PATH} add"
}

_manage_relay_installation() {
    _info "--- 线路机脚本管理 (请在线路机上运行) ---"
    local relay_script="/root/relay-install.sh"

    if [ ! -f "$relay_script" ]; then
        _error "错误：未在 /root 目录下找到 [relay-install.sh] 脚本。"
        _info "  1. 请先在您的“落地机”上运行此脚本 (singbox.sh)。"
        _info "  2. 使用 [9) 生成中转落地脚本] 选项。"
        _info "  3. 将“落地机”上生成的 [/root/relay-install.sh] 脚本"
        _info "     传输到本机 (线路机) 的 /root 目录下，然后再试。"
        return 1
    fi

    chmod +x "$relay_script" # 确保有执行权限

    while true; do
        clear
        echo "===================================================="
        _info "      线路机 (中转机) 快捷管理"
        _info "      (正在管理: ${relay_script})"
        echo "===================================================="
        echo -e "  1) ${GREEN}安装 / 重置${NC} 第一个中转服务"
        echo -e "  2) ${GREEN}添加${NC} 新的中转路由"
        echo -e "  3) ${CYAN}查看${NC} 所有中转节点链接"
        echo -e "  4) ${RED}卸载${NC} 线路机中转服务"
        echo "----------------------------------------------------"
        echo "  0) 返回主菜单"
        echo "===================================================="
        read -p "请输入选项 [0-4]: " choice

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
                _info "正在执行: bash ${relay_script} view"
                bash "${relay_script}" view
                break
                ;;
            4)
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
        echo "  4) 重启 sing-box"
        echo "  5) 停止 sing-box"
        echo "  6) 查看 sing-box 运行状态"
        echo "  7) 查看 sing-box 实时日志"
        echo "----------------------------------------------------"
        _info "【脚本与配置】"
        echo "  8) 检查配置文件"
        echo -e "  9) ${GREEN}生成中转落地脚本${NC} (在“落地机”运行)"
        echo -e " 10) ${CYAN}管理线路机脚本${NC} (在“线路机”运行)"
        echo -e " 11) ${RED}卸载 sing-box 及脚本${NC}"
        echo "----------------------------------------------------"
        echo "  0) 退出脚本"
        echo "===================================================="
        read -p "请输入选项 [0-11]: " choice

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
            11) _uninstall ;; 
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
    if [ "$first_install" = true ]; then
        _create_service_files
        _info "首次安装完成！正在启动 sing-box (主服务)..."
        _manage_service "start"
    fi
    
    _get_public_ip
    _main_menu
}

main
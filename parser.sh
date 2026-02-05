#!/bin/bash

# ==========================================================
# parser.sh - singbox-lite 专用节点链接解析脚本
# 功能：解析分享链接并输出 sing-box 标准 outbound JSON 片段
# ==========================================================

# 检查依赖
if ! command -v jq &>/dev/null; then
    echo '{"error": "缺少 jq 依赖"}'
    exit 1
fi

# URL 解码
_url_decode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}

# 解析 VLESS 链接
_parse_vless() {
    local link="$1"
    # vless://uuid@server:port?param1=value1&param2=value2#name
    local uuid=$(echo "$link" | sed 's|vless://\([^@]*\)@.*|\1|')
    local server_part=$(echo "$link" | sed 's|vless://[^@]*@\([^?#]*\).*|\1|')
    local server=$(echo "$server_part" | cut -d: -f1)
    local port=$(echo "$server_part" | cut -d: -f2)
    
    local params=$(echo "$link" | sed -n 's/.*?\([^#]*\).*/\1/p')
    local name=$(echo "$link" | sed 's|.*#\(.*\)|\1|')
    [ -n "$name" ] && name=$(_url_decode "$name")

    local flow="" security="" sni="" pbk="" sid="" fp="chrome" type="tcp" path="" host=""
    
    if [ -n "$params" ]; then
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
                "type") type="$value" ;;
                "path") path=$(_url_decode "$value") ;;
                "host") host="$value" ;;
            esac
        done
    fi

    local outbound=$(jq -n \
        --arg type "vless" \
        --arg tag "proxy" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --arg flow "$flow" \
        '{type:$type, tag:$tag, server:$server, server_port:$port, uuid:$uuid, flow:$flow}')

    # 处理传输层
    if [ "$type" == "ws" ]; then
        outbound=$(echo "$outbound" | jq --arg path "$path" --arg host "$host" '.transport = {type:"ws", path:$path, headers:{Host:$host}}')
    fi

    # 处理安全层
    if [ "$security" == "reality" ]; then
        outbound=$(echo "$outbound" | jq --arg sni "$sni" --arg pbk "$pbk" --arg sid "$sid" --arg fp "$fp" \
            '.tls = {enabled:true, server_name:$sni, reality:{enabled:true, public_key:$pbk, short_id:$sid}, utls:{enabled:true, fingerprint:$fp}}')
    elif [ "$security" == "tls" ]; then
        outbound=$(echo "$outbound" | jq --arg sni "$sni" --arg fp "$fp" \
            '.tls = {enabled:true, server_name:$sni, utls:{enabled:true, fingerprint:$fp}}')
    fi

    echo "$outbound"
}

# 解析 Hysteria2 链接
_parse_hy2() {
    local link="$1"
    # 支持 hysteria2:// 和 hy2://
    local proto="hysteria2"
    [[ "$link" =~ ^hy2:// ]] && proto="hy2"
    
    local password=$(echo "$link" | sed "s|${proto}://\([^@]*\)@.*|\1|")
    local server_part=$(echo "$link" | sed "s|${proto}://[^@]*@\([^?#]*\).*|\1|")
    local server=$(echo "$server_part" | cut -d: -f1)
    local port=$(echo "$server_part" | cut -d: -f2)
    local params=$(echo "$link" | sed -n 's/.*?\([^#]*\).*/\1/p')
    
    local sni="" insecure="false" obfs_type="" obfs_password=""
    if [ -n "$params" ]; then
        IFS='&' read -ra PARAM_ARRAY <<< "$params"
        for param in "${PARAM_ARRAY[@]}"; do
            local key=$(echo "$param" | cut -d= -f1)
            local value=$(echo "$param" | cut -d= -f2-)
            case "$key" in
                "sni") sni="$value" ;;
                "insecure"|"allow_insecure") [ "$value" == "1" ] && insecure="true" ;;
                "obfs") obfs_type="$value" ;;
                "obfs-password") obfs_password="$value" ;;
            esac
        done
    fi
    [ -z "$sni" ] && sni="$server"

    local outbound=$(jq -n \
        --arg server "$server" \
        --argjson port "$port" \
        --arg password "$password" \
        --arg sni "$sni" \
        --argjson insecure "$insecure" \
        '{
            "type": "hysteria2",
            "tag": "proxy",
            "server": $server,
            "server_port": $port,
            "password": $password,
            "tls": {
                "enabled": true,
                "server_name": $sni,
                "insecure": $insecure,
                "alpn": ["h3"]
            }
        }')

    if [ -n "$obfs_type" ]; then
        outbound=$(echo "$outbound" | jq --arg ot "$obfs_type" --arg op "$obfs_password" '.obfs = {type:$ot, password:$op}')
    fi

    echo "$outbound"
}

# 解析 TUIC 链接
_parse_tuic() {
    local link="$1"
    local auth=$(echo "$link" | sed 's|tuic://\([^@]*\)@.*|\1|')
    local uuid="${auth%%:*}"
    local password="${auth#*:}"
    local server_part=$(echo "$link" | sed 's|tuic://[^@]*@\([^?#]*\).*|\1|')
    local server=$(echo "$server_part" | cut -d: -f1)
    local port=$(echo "$server_part" | cut -d: -f2)
    local params=$(echo "$link" | sed -n 's/.*?\([^#]*\).*/\1/p')
    
    local sni="" cc="bbr" insecure="true"
    if [ -n "$params" ]; then
        IFS='&' read -ra PARAM_ARRAY <<< "$params"
        for param in "${PARAM_ARRAY[@]}"; do
            local key=$(echo "$param" | cut -d= -f1)
            local value=$(echo "$param" | cut -d= -f2-)
            case "$key" in
                "sni") sni="$value" ;;
                "congestion_control"|"cc") cc="$value" ;;
                "insecure"|"allow_insecure") [ "$value" == "0" ] && insecure="false" ;;
            esac
        done
    fi
    [ -z "$sni" ] && sni="$server"

    jq -n \
        --arg server "$server" \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --arg password "$password" \
        --arg sni "$sni" \
        --arg cc "$cc" \
        --argjson insecure "$insecure" \
        '{
            "type": "tuic",
            "tag": "proxy",
            "server": $server,
            "server_port": $port,
            "uuid": $uuid,
            "password": $password,
            "congestion_control": $cc,
            "tls": {
                "enabled": true,
                "server_name": $sni,
                "insecure": $insecure,
                "alpn": ["h3"]
            }
        }'
}

# 解析 Shadowsocks 链接
_parse_ss() {
    local link="$1"
    local link_no_name="${link%%#*}"
    local link_clean="${link_no_name%%\?*}"
    local ss_body="${link_clean#ss://}"
    local method password server port
    
    if [[ "$ss_body" == *"@"* ]]; then
        local prefix="${ss_body%%@*}"
        local server_port="${ss_body##*@}"
        server="${server_port%:*}"
        port="${server_port##*:}"
        if [[ "$prefix" != *":"* ]]; then
            prefix=$(echo -n "$prefix" | base64 -d 2>/dev/null)
        fi
        method="${prefix%%:*}"
        password="${prefix#*:}"
    else
        local decoded=$(echo -n "$ss_body" | base64 -d 2>/dev/null)
        local method_pass="${decoded%%@*}"
        local server_port="${decoded##*@}"
        method="${method_pass%%:*}"
        password="${method_pass#*:}"
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi

    port="${port%%\?*}"
    port="${port%%#*}"

    jq -n \
        --arg server "$server" \
        --argjson port "$port" \
        --arg method "$method" \
        --arg password "$password" \
        '{
            "type": "shadowsocks",
            "tag": "proxy",
            "server": $server,
            "server_port": $port,
            "method": $method,
            "password": $password
        }'
}

# 解析 Trojan 链接
_parse_trojan() {
    local link="$1"
    local password=$(echo "$link" | sed 's|trojan://\([^@]*\)@.*|\1|')
    local server_part=$(echo "$link" | sed 's|trojan://[^@]*@\([^?#]*\).*|\1|')
    local server=$(echo "$server_part" | cut -d: -f1)
    local port=$(echo "$server_part" | cut -d: -f2)
    local params=$(echo "$link" | sed -n 's/.*?\([^#]*\).*/\1/p')
    
    local sni="" type="tcp" path="" host=""
    if [ -n "$params" ]; then
        IFS='&' read -ra PARAM_ARRAY <<< "$params"
        for param in "${PARAM_ARRAY[@]}"; do
            local key=$(echo "$param" | cut -d= -f1)
            local value=$(echo "$param" | cut -d= -f2-)
            case "$key" in
                "sni") sni="$value" ;;
                "type") type="$value" ;;
                "path") path=$(_url_decode "$value") ;;
                "host") host="$value" ;;
            esac
        done
    fi

    local outbound=$(jq -n \
        --arg server "$server" \
        --argjson port "$port" \
        --arg password "$password" \
        '{
            "type": "trojan",
            "tag": "proxy",
            "server": $server,
            "server_port": $port,
            "password": $password
        }')

    if [ "$type" == "ws" ]; then
        outbound=$(echo "$outbound" | jq --arg path "$path" --arg host "$host" '.transport = {type:"ws", path:$path, headers:{Host:$host}}')
    fi
    
    outbound=$(echo "$outbound" | jq --arg sni "$sni" '.tls = {enabled:true, server_name:$sni}')
    
    echo "$outbound"
}

# 解析 AnyTLS 链接
_parse_anytls() {
    local link="$1"
    local password=$(echo "$link" | sed 's|anytls://\([^@]*\)@.*|\1|')
    local server_part=$(echo "$link" | sed 's|anytls://[^@]*@\([^?#]*\).*|\1|')
    local server=$(echo "$server_part" | cut -d: -f1)
    local port=$(echo "$server_part" | cut -d: -f2)
    local params=$(echo "$link" | sed -n 's/.*?\([^#]*\).*/\1/p')
    
    local sni=""
    if [ -n "$params" ]; then
        IFS='&' read -ra PARAM_ARRAY <<< "$params"
        for param in "${PARAM_ARRAY[@]}"; do
            local key=$(echo "$param" | cut -d= -f1)
            local value=$(echo "$param" | cut -d= -f2-)
            case "$key" in
                "sni") sni="$value" ;;
            esac
        done
    fi

    jq -n \
        --arg server "$server" \
        --argjson port "$port" \
        --arg password "$password" \
        --arg sni "$sni" \
        '{
            "type": "anytls",
            "tag": "proxy",
            "server": $server,
            "server_port": $port,
            "password": $password,
            "tls": {
                "enabled": true,
                "server_name": $sni
            }
        }'
}

# 主逻辑
case "$1" in
    vless://*) _parse_vless "$1" ;;
    hysteria2://*|hy2://*) _parse_hy2 "$1" ;;
    tuic://*) _parse_tuic "$1" ;;
    ss://*) _parse_ss "$1" ;;
    trojan://*) _parse_trojan "$1" ;;
    anytls://*) _parse_anytls "$1" ;;
    *) echo "{\"error\": \"不支持的协议类型\"}"; exit 1 ;;
esac

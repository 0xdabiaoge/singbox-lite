#!/bin/bash

# 核心环境定义
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
SINGBOX_DIR="/usr/local/etc/sing-box"

# [整合方案] 解析器核心解码函数 (独立实现，不依赖外部)
_url_decode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}

if ! command -v jq &>/dev/null; then
    echo '{"error": "缺少 jq 依赖"}'
    exit 1
fi

# 解析器使用的 URL 解码统一由主脚本或独立实现提供
_decode() { _url_decode "$1"; }

_get_param() {
    local params="$1"
    local key="$2"
    echo "$params" | sed -n "s/.*[\?&]${key}=\([^&]*\).*/\1/p"
}

# 解析 VLESS
_parse_vless() {
    local link="$1"
    local regex="vless://([^@]+)@([^:/?#]+):([0-9]+)\??([^#]*)#?(.*)"
    if [[ $link =~ $regex ]]; then
        local uuid="${BASH_REMATCH[1]}"
        local server="${BASH_REMATCH[2]}"
        local port="${BASH_REMATCH[3]}"
        local params="${BASH_REMATCH[4]}"
        local name=$(_decode "${BASH_REMATCH[5]}")

        local flow=$(_get_param "$params" "flow")
        local security=$(_get_param "$params" "security")
        local sni=$(_get_param "$params" "sni")
        [ -z "$sni" ] && sni=$(_get_param "$params" "servername")
        local pbk=$(_get_param "$params" "pbk")
        local sid=$(_get_param "$params" "sid")
        local fp=$(_get_param "$params" "fp")
        local type=$(_get_param "$params" "type")
        local path=$(_decode "$(_get_param "$params" "path")")
        local host=$(_get_param "$params" "host")

        local outbound=$(jq -n \
            --arg type "vless" \
            --arg tag "proxy" \
            --arg server "$server" \
            --argjson port "$port" \
            --arg uuid "$uuid" \
            --arg flow "${flow:-""}" \
            '{type:$type, tag:$tag, server:$server, server_port:$port, uuid:$uuid, flow:$flow}')

        [ "$type" == "ws" ] && outbound=$(echo "$outbound" | jq --arg path "${path:-"/"}" --arg host "$host" '.transport = {type:"ws", path:$path, headers:{Host:$host}}')
        
        if [ "$security" == "reality" ]; then
            outbound=$(echo "$outbound" | jq --arg sni "$sni" --arg pbk "$pbk" --arg sid "$sid" --arg fp "${fp:-"chrome"}" \
                '.tls = {enabled:true, server_name:$sni, reality:{enabled:true, public_key:$pbk, short_id:$sid}, utls:{enabled:true, fingerprint:$fp}}')
        elif [ "$security" == "tls" ]; then
            outbound=$(echo "$outbound" | jq --arg sni "$sni" --arg fp "${fp:-"chrome"}" \
                '.tls = {enabled:true, server_name:$sni, utls:{enabled:true, fingerprint:$fp}}')
        fi
        echo "$outbound"
    fi
}

# 解析 VMess
_parse_vmess() {
    local link="${1#vmess://}"
    # 处理 URL-safe Base64 并清理潜在的换行/空格污染
    local safe_link=$(echo -n "$link" | tr -- '-_' '+/'  | tr -d ' \n\r')
    local pad=$((4 - ${#safe_link} % 4))
    [ $pad -ne 4 ] && safe_link+=$(printf '=%.0s' $(seq 1 $pad))
    local decoded=$(echo -n "$safe_link" | base64 -d 2>/dev/null)
    [ -z "$decoded" ] && { echo '{"error": "Base64解码失败"}'; return; }
    
    local server=$(echo "$decoded" | jq -r '.add')
    local port=$(echo "$decoded" | jq -r '.port')
    local uuid=$(echo "$decoded" | jq -r '.id')
    local net=$(echo "$decoded" | jq -r '.net // "tcp"')
    local tls=$(echo "$decoded" | jq -r '.tls // ""')
    local path=$(echo "$decoded" | jq -r '.path // "/"')
    local host=$(echo "$decoded" | jq -r '.host // ""')
    local sni=$(echo "$decoded" | jq -r '.sni // ""')

    local outbound=$(jq -n --arg s "$server" --argjson p "$port" --arg u "$uuid" \
        '{type:"vmess", tag:"proxy", server:$s, server_port:$p, uuid:$u, security:"auto"}')

    [ "$tls" == "tls" ] && outbound=$(echo "$outbound" | jq --arg sni "$sni" '.tls = {enabled:true, server_name:$sni}')
    [ "$net" == "ws" ] && outbound=$(echo "$outbound" | jq --arg path "$path" --arg host "$host" '.transport = {type:"ws", path:$path, headers:{Host:$host}}')
    
    echo "$outbound"
}

# 解析 Trojan
_parse_trojan() {
    local link="$1"
    local regex="trojan://([^@]+)@([^:/?#]+):([0-9]+)\??([^#]*)#?(.*)"
    if [[ $link =~ $regex ]]; then
        local password="${BASH_REMATCH[1]}"
        local server="${BASH_REMATCH[2]}"
        local port="${BASH_REMATCH[3]}"
        local params="${BASH_REMATCH[4]}"
        local name=$(_decode "${BASH_REMATCH[5]}")

        local sni=$(_get_param "$params" "sni")
        local type=$(_get_param "$params" "type")
        local path=$(_decode "$(_get_param "$params" "path")")
        local host=$(_get_param "$params" "host")

        local outbound=$(jq -n --arg s "$server" --argjson p "$port" --arg pw "$password" \
            '{type:"trojan", tag:"proxy", server:$s, server_port:$p, password:$pw}')

        [ "$type" == "ws" ] && outbound=$(echo "$outbound" | jq --arg path "${path:-"/"}" --arg host "$host" '.transport = {type:"ws", path:$path, headers:{Host:$host}}')
        outbound=$(echo "$outbound" | jq --arg sni "${sni:-$server}" '.tls = {enabled:true, server_name:$sni}')
        
        echo "$outbound"
    fi
}

# 解析 Shadowsocks
_parse_ss() {
    local link="$1"
    local body="${link#ss://}"
    [[ "$body" == *"#"* ]] && body="${body%#*}"
    
    local method_pass server_port
    if [[ "$body" == *"@"* ]]; then
        local userinfo="${body%@*}"
        server_port="${body#*@}"
        [[ "$userinfo" != *":"* ]] && userinfo=$(echo -n "$userinfo" | base64 -d 2>/dev/null)
        method_pass="$userinfo"
    else
        local decoded=$(echo -n "$body" | base64 -d 2>/dev/null)
        method_pass="${decoded%@*}"
        server_port="${decoded#*@}"
    fi

    echo "$server_port" | grep -q "?" && server_port="${server_port%%\?*}"

    jq -n --arg s "${server_port%:*}" --argjson p "${server_port#*:}" --arg m "${method_pass%:*}" --arg pw "${method_pass#*:}" \
        '{type:"shadowsocks", tag:"proxy", server:$s, server_port:$p, method:$m, password:$pw}'
}

# 解析 Hysteria2
_parse_hy2() {
    local link="$1"
    local regex="(hysteria2|hy2)://([^@]+)@([^:/?#]+):([0-9]+)\??([^#]*)#?(.*)"
    if [[ $link =~ $regex ]]; then
        local password=$(_decode "${BASH_REMATCH[2]}")
        local server="${BASH_REMATCH[3]}"
        local port="${BASH_REMATCH[4]}"
        local params="${BASH_REMATCH[5]}"
        local sni=$(_get_param "$params" "sni")
        local obfs=$(_get_param "$params" "obfs")
        local opw=$(_get_param "$params" "obfs-password")

        local outbound=$(jq -n --arg s "$server" --argjson p "$port" --arg pw "$password" --arg sni "${sni:-$server}" \
            '{type:"hysteria2", tag:"proxy", server:$s, server_port:$p, password:$pw, tls:{enabled:true, server_name:$sni, insecure:true, alpn:["h3"]}}')
        [ -n "$obfs" ] && outbound=$(echo "$outbound" | jq --arg ot "$obfs" --arg op "$opw" '.obfs = {type:$ot, password:$op}')
        echo "$outbound"
    fi
}

# 解析 TUIC
_parse_tuic() {
    local link="$1"
    local regex="tuic://([^:]+):([^@]+)@([^:/?#]+):([0-9]+)\\??([^#]*)#?(.*)"
    if [[ $link =~ $regex ]]; then
        local uuid="${BASH_REMATCH[1]}"
        local password=$(_decode "${BASH_REMATCH[2]}")
        local server="${BASH_REMATCH[3]}"
        local port="${BASH_REMATCH[4]}"
        local params="${BASH_REMATCH[5]}"
        local sni=$(_get_param "$params" "sni")
        local cc=$(_get_param "$params" "congestion_control")
        [ -z "$cc" ] && cc="bbr"

        jq -n --arg s "$server" --argjson p "$port" --arg u "$uuid" --arg pw "$password" --arg sni "${sni:-$server}" --arg cc "$cc" \
            '{type:"tuic", tag:"proxy", server:$s, server_port:$p, uuid:$u, password:$pw, congestion_control:$cc, tls:{enabled:true, server_name:$sni, insecure:true, alpn:["h3"]}}'
    fi
}

# 解析 AnyTLS
_parse_anytls() {
    local link="$1"
    local regex="anytls://([^@]+)@([^:/?#]+):([0-9]+)\\??([^#]*)#?(.*)"
    if [[ $link =~ $regex ]]; then
        local password=$(_decode "${BASH_REMATCH[1]}")
        local server="${BASH_REMATCH[2]}"
        local port="${BASH_REMATCH[3]}"
        local params="${BASH_REMATCH[4]}"
        local sni=$(_get_param "$params" "sni")

        jq -n --arg s "$server" --argjson p "$port" --arg pw "$password" --arg sni "${sni:-$server}" \
            '{type:"anytls", tag:"proxy", server:$s, server_port:$p, password:$pw, tls:{enabled:true, server_name:$sni, insecure:true}}'
    fi
}

# 解析 SOCKS5
_parse_socks() {
    local link="$1"
    local regex="socks5://([^:]+):([^@]+)@([^:/?#]+):([0-9]+)#?(.*)"
    if [[ $link =~ $regex ]]; then
        local user="${BASH_REMATCH[1]}"
        local pass="${BASH_REMATCH[2]}"
        local server="${BASH_REMATCH[3]}"
        local port="${BASH_REMATCH[4]}"
        
        jq -n --arg s "$server" --argjson p "$port" --arg u "$user" --arg pw "$pass" \
            '{type:"socks", tag:"proxy", server:$s, server_port:$p, version:"5", users:[{username:$u, password:$pass}]}'
    fi
}

case "$1" in
    vless://*) _parse_vless "$1" ;;
    vmess://*) _parse_vmess "$1" ;;
    trojan://*) _parse_trojan "$1" ;;
    ss://*) _parse_ss "$1" ;;
    hysteria2://*|hy2://*) _parse_hy2 "$1" ;;
    tuic://*) _parse_tuic "$1" ;;
    anytls://*) _parse_anytls "$1" ;;
    socks5://*) _parse_socks "$1" ;;
    *) echo "{\"error\": \"不支持的协议\"}"; exit 1 ;;
esac

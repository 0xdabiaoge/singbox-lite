#!/bin/bash

# 第三方落地节点的严格解析器。
# 正常调用方式：printf '%s\n' "$link" | bash parser.sh MODE
# 第二个参数仅保留给测试使用，生产调用不要把凭据放入进程参数。

umask 077
export LC_ALL=C

DECODED_VALUE=""
NORMALIZED_PORT=""
GROUP_COUNT=0
PARSED_SERVER=""
PARSED_PORT=""
VLESS_UUID=""
VLESS_SERVER=""
VLESS_PORT=""
LINK_INPUT=""

declare -A QUERY_PARAMS=()
declare -A QUERY_PRESENT=()

_json_escape() {
    local escaped
    escaped="$1"
    escaped="${escaped//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    escaped="${escaped//$'\r'/\\r}"
    escaped="${escaped//$'\n'/\\n}"
    escaped="${escaped//$'\t'/\\t}"
    printf '%s' "$escaped"
}

_fatal() {
    local message escaped
    message="$1"
    escaped=$(_json_escape "$message")
    printf '{"error":"%s"}\n' "$escaped"
    exit 1
}

_url_decode() {
    local input plus_as_space decoded char hex
    input="$1"
    plus_as_space="${2:-0}"
    decoded=""

    while [[ -n "$input" ]]; do
        char="${input:0:1}"
        case "$char" in
            '%')
                (( ${#input} >= 3 )) || return 1
                hex="${input:1:2}"
                [[ "$hex" =~ ^[0-9A-Fa-f]{2}$ ]] || return 1
                [[ "$hex" != "00" ]] || return 1
                printf -v char '%b' "\\x${hex}"
                decoded+="$char"
                input="${input:3}"
                ;;
            '+')
                if [[ "$plus_as_space" == "1" ]]; then
                    decoded+=' '
                else
                    decoded+='+'
                fi
                input="${input:1}"
                ;;
            *)
                decoded+="$char"
                input="${input:1}"
                ;;
        esac
    done

    DECODED_VALUE="$decoded"
}

_decode_base64_urlsafe() {
    local input normalized core padding existing_padding needed_padding decoded
    input="$1"
    [[ -n "$input" ]] || return 1
    [[ "$input" =~ ^[A-Za-z0-9+/_-]+={0,2}$ ]] || return 1

    normalized="${input//-/+}"
    normalized="${normalized//_/\/}"
    core="${normalized%%=*}"
    padding="${normalized:${#core}}"
    existing_padding=${#padding}

    case $(( ${#core} % 4 )) in
        0) needed_padding=0 ;;
        2) needed_padding=2 ;;
        3) needed_padding=1 ;;
        *) return 1 ;;
    esac

    if (( existing_padding != 0 && existing_padding != needed_padding )); then
        return 1
    fi

    normalized="$core"
    while (( ${#normalized} % 4 != 0 )); do
        normalized+='='
    done

    if ! decoded=$(printf '%s' "$normalized" | base64 -d 2>/dev/null); then
        return 1
    fi
    [[ -n "$decoded" ]] || return 1
    [[ "$decoded" != *$'\r'* && "$decoded" != *$'\n'* ]] || return 1
    DECODED_VALUE="$decoded"
}

_normalize_port() {
    local raw value
    raw="$1"
    [[ "$raw" =~ ^[0-9]+$ ]] || return 1
    (( ${#raw} <= 5 )) || return 1
    value=$((10#$raw))
    (( value >= 1 && value <= 65535 )) || return 1
    NORMALIZED_PORT="$value"
}

_validate_ipv4() {
    local address octet value
    local -a octets
    address="$1"
    [[ "$address" != .* && "$address" != *. && "$address" != *..* ]] || return 1
    IFS='.' read -r -a octets <<< "$address"
    (( ${#octets[@]} == 4 )) || return 1

    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        value=$((10#$octet))
        (( value <= 255 )) || return 1
    done
}

_count_ipv6_groups() {
    local part group
    local -a groups
    part="$1"
    GROUP_COUNT=0
    [[ -n "$part" ]] || return 0
    [[ "$part" != :* && "$part" != *: ]] || return 1
    IFS=':' read -r -a groups <<< "$part"
    for group in "${groups[@]}"; do
        [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    done
    GROUP_COUNT=${#groups[@]}
}

_validate_ipv6() {
    local address ipv4_tail prefix left right after_first
    local left_count right_count
    address="$1"
    [[ "$address" == *:* ]] || return 1
    [[ "$address" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1

    if [[ "$address" == *.* ]]; then
        ipv4_tail="${address##*:}"
        _validate_ipv4 "$ipv4_tail" || return 1
        prefix="${address%:*}"
        address="${prefix}:0:0"
    fi

    if [[ "$address" == *::* ]]; then
        after_first="${address#*::}"
        [[ "$after_first" != *::* ]] || return 1
        left="${address%%::*}"
        right="$after_first"
        _count_ipv6_groups "$left" || return 1
        left_count=$GROUP_COUNT
        _count_ipv6_groups "$right" || return 1
        right_count=$GROUP_COUNT
        (( left_count + right_count < 8 )) || return 1
    else
        [[ "$address" != :* && "$address" != *: ]] || return 1
        _count_ipv6_groups "$address" || return 1
        (( GROUP_COUNT == 8 )) || return 1
    fi
}

_validate_hostname() {
    local hostname label
    local -a labels
    hostname="$1"
    (( ${#hostname} >= 1 && ${#hostname} <= 253 )) || return 1
    [[ "$hostname" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    [[ "$hostname" != .* && "$hostname" != *. && "$hostname" != *..* ]] || return 1

    IFS='.' read -r -a labels <<< "$hostname"
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

_validate_server() {
    local server
    server="$1"
    [[ -n "$server" ]] || return 1
    [[ "$server" != *[$'\t\r\n /?#@']* ]] || return 1

    if [[ "$server" == *:* ]]; then
        _validate_ipv6 "$server"
    elif [[ "$server" =~ ^[0-9.]+$ && "$server" == *.* ]]; then
        _validate_ipv4 "$server"
    else
        _validate_hostname "$server"
    fi
}

_split_host_port() {
    local endpoint
    endpoint="$1"
    PARSED_SERVER=""
    PARSED_PORT=""

    if [[ "$endpoint" =~ ^\[([^][]+)\]:([0-9]+)$ ]]; then
        PARSED_SERVER="${BASH_REMATCH[1]}"
        PARSED_PORT="${BASH_REMATCH[2]}"
    elif [[ "$endpoint" =~ ^([^:]+):([0-9]+)$ ]]; then
        PARSED_SERVER="${BASH_REMATCH[1]}"
        PARSED_PORT="${BASH_REMATCH[2]}"
    else
        return 1
    fi

    _validate_server "$PARSED_SERVER" || return 1
    _normalize_port "$PARSED_PORT" || return 1
    PARSED_PORT="$NORMALIZED_PORT"
}

_parse_query() {
    local query pair raw_key raw_value key value
    local -a pairs
    query="$1"
    QUERY_PARAMS=()
    QUERY_PRESENT=()
    [[ -n "$query" ]] || return 0

    IFS='&' read -r -a pairs <<< "$query"
    for pair in "${pairs[@]}"; do
        [[ -n "$pair" ]] || return 1
        raw_key="${pair%%=*}"
        if [[ "$pair" == *=* ]]; then
            raw_value="${pair#*=}"
        else
            raw_value=""
        fi

        _url_decode "$raw_key" 1 || return 1
        key="$DECODED_VALUE"
        _url_decode "$raw_value" 1 || return 1
        value="$DECODED_VALUE"
        [[ "$key" =~ ^[A-Za-z0-9._~-]+$ ]] || return 1
        [[ -z "${QUERY_PRESENT[$key]+x}" ]] || return 1
        QUERY_PRESENT["$key"]=1
        QUERY_PARAMS["$key"]="$value"
    done
}

_require_query_keys() {
    local allowed key
    allowed=" $* "
    for key in "${!QUERY_PRESENT[@]}"; do
        [[ "$allowed" == *" $key "* ]] || _fatal "节点链接包含当前模式不支持的查询参数"
    done
}

_parse_vless_uri() {
    local link body authority query raw_uuid endpoint
    link="$1"
    [[ "$link" == vless://* ]] || _fatal "链接必须以 vless:// 开头"
    body="${link#vless://}"
    body="${body%%#*}"
    [[ -n "$body" ]] || _fatal "VLESS 链接为空"

    if [[ "$body" == *\?* ]]; then
        authority="${body%%\?*}"
        query="${body#*\?}"
    else
        authority="$body"
        query=""
    fi

    [[ "$authority" == *@* ]] || _fatal "VLESS 链接缺少 UUID 或服务器地址"
    raw_uuid="${authority%%@*}"
    endpoint="${authority#*@}"
    [[ "$endpoint" != *@* ]] || _fatal "VLESS 链接的服务器地址格式错误"
    _url_decode "$raw_uuid" 0 || _fatal "VLESS UUID 包含无效 URL 编码"
    VLESS_UUID="$DECODED_VALUE"
    [[ "$VLESS_UUID" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || _fatal "VLESS UUID 格式无效"

    _split_host_port "$endpoint" || _fatal "VLESS 服务器地址或端口无效"
    VLESS_SERVER="$PARSED_SERVER"
    VLESS_PORT="$PARSED_PORT"
    _parse_query "$query" || _fatal "VLESS 查询参数格式无效或包含重复参数"
}

_require_tcp_transport() {
    local transport header_type encryption
    transport="${QUERY_PARAMS[type]-}"
    header_type="${QUERY_PARAMS[headerType]-}"
    encryption="${QUERY_PARAMS[encryption]-}"
    [[ -z "$transport" || "$transport" == "tcp" ]] || _fatal "仅支持 VLESS TCP 节点"
    [[ -z "$header_type" || "$header_type" == "none" ]] || _fatal "VLESS TCP 不支持额外头部伪装"
    [[ -z "$encryption" || "$encryption" == "none" ]] || _fatal "VLESS encryption 必须为 none"
}

_parse_vless_reality_vision() {
    local link security flow sni public_key short_id fingerprint output
    link="$1"
    _parse_vless_uri "$link"
    _require_query_keys encryption flow security sni servername fp pbk sid type headerType
    _require_tcp_transport

    security="${QUERY_PARAMS[security]-}"
    flow="${QUERY_PARAMS[flow]-}"
    sni="${QUERY_PARAMS[sni]-}"
    [[ -n "$sni" ]] || sni="${QUERY_PARAMS[servername]-}"
    public_key="${QUERY_PARAMS[pbk]-}"
    short_id="${QUERY_PARAMS[sid]-}"
    fingerprint="${QUERY_PARAMS[fp]-chrome}"

    [[ "$security" == "reality" ]] || _fatal "Reality 节点的 security 必须为 reality"
    [[ "$flow" == "xtls-rprx-vision" ]] || _fatal "Reality 节点的 flow 必须为 xtls-rprx-vision"
    _validate_server "$sni" || _fatal "Reality 节点缺少有效的 SNI"
    [[ "$public_key" =~ ^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$ ]] || _fatal "Reality 公钥 pbk 格式无效"
    [[ "$short_id" =~ ^[0-9A-Fa-f]{0,16}$ && $(( ${#short_id} % 2 )) -eq 0 ]] || _fatal "Reality short id 必须是长度不超过 16 的偶数位十六进制字符串"
    case "$fingerprint" in
        chrome|firefox|edge|safari|360|qq|ios|android|random|randomized) ;;
        *) _fatal "Reality uTLS 指纹不在 sing-box 支持列表中" ;;
    esac

    if ! output=$(jq -n \
        --arg server "$VLESS_SERVER" \
        --argjson port "$VLESS_PORT" \
        --arg uuid "$VLESS_UUID" \
        --arg sni "$sni" \
        --arg public_key "$public_key" \
        --arg short_id "$short_id" \
        --arg fingerprint "$fingerprint" \
        '{type:"vless",tag:"proxy",server:$server,server_port:$port,uuid:$uuid,network:"tcp",flow:"xtls-rprx-vision",tls:{enabled:true,server_name:$sni,reality:{enabled:true,public_key:$public_key,short_id:$short_id},utls:{enabled:true,fingerprint:$fingerprint}}}'); then
        _fatal "生成 VLESS + TCP + Reality + Vision outbound 失败"
    fi
    printf '%s\n' "$output"
}

_parse_vless_tcp() {
    local link security output
    link="$1"
    _parse_vless_uri "$link"
    _require_query_keys encryption security type headerType
    _require_tcp_transport

    security="${QUERY_PARAMS[security]-}"
    [[ -z "$security" || "$security" == "none" ]] || _fatal "纯 VLESS TCP 节点不能启用 TLS 或 Reality"

    if ! output=$(jq -n \
        --arg server "$VLESS_SERVER" \
        --argjson port "$VLESS_PORT" \
        --arg uuid "$VLESS_UUID" \
        '{type:"vless",tag:"proxy",server:$server,server_port:$port,uuid:$uuid,network:"tcp"}'); then
        _fatal "生成纯 VLESS TCP outbound 失败"
    fi
    printf '%s\n' "$output"
}

_parse_ss_uri() {
    local link expected_method body main query raw_userinfo endpoint decoded method_password
    local method password output key
    link="$1"
    expected_method="$2"
    [[ "$link" == ss://* ]] || _fatal "链接必须以 ss:// 开头"
    body="${link#ss://}"
    body="${body%%#*}"
    [[ -n "$body" ]] || _fatal "Shadowsocks 链接为空"

    if [[ "$body" == *\?* ]]; then
        main="${body%%\?*}"
        query="${body#*\?}"
    else
        main="$body"
        query=""
    fi

    if [[ -n "$query" ]]; then
        _parse_query "$query" || _fatal "Shadowsocks 查询参数格式无效"
        for key in "${!QUERY_PRESENT[@]}"; do
            [[ "${key,,}" != "plugin" ]] || _fatal "不支持带 plugin 的 Shadowsocks 节点"
        done
        _fatal "Shadowsocks 链接包含不支持的查询参数"
    fi

    if [[ "$main" == *@* ]]; then
        raw_userinfo="${main%@*}"
        endpoint="${main##*@}"
        endpoint="${endpoint%/}"
        [[ -n "$raw_userinfo" && -n "$endpoint" ]] || _fatal "Shadowsocks 链接格式无效"

        _url_decode "$raw_userinfo" 0 || _fatal "Shadowsocks 凭据包含无效 URL 编码"
        decoded="$DECODED_VALUE"
        if [[ "$decoded" == *:* ]]; then
            method_password="$decoded"
        else
            _decode_base64_urlsafe "$decoded" || _fatal "Shadowsocks SIP002 凭据 Base64 解码失败"
            method_password="$DECODED_VALUE"
        fi
    else
        _decode_base64_urlsafe "$main" || _fatal "Shadowsocks 整串 Base64 解码失败"
        decoded="$DECODED_VALUE"
        [[ "$decoded" == *@* ]] || _fatal "Shadowsocks 整串 Base64 内容格式无效"
        method_password="${decoded%@*}"
        endpoint="${decoded##*@}"
    fi

    [[ "$method_password" == *:* ]] || _fatal "Shadowsocks 链接缺少加密方法或密码"
    method="${method_password%%:*}"
    password="${method_password#*:}"
    [[ "$method" == "$expected_method" ]] || _fatal "Shadowsocks 链接的加密方法与所选类型不一致"
    [[ -n "$password" ]] || _fatal "Shadowsocks 密码不能为空"
    [[ "$password" != *$'\r'* && "$password" != *$'\n'* ]] || _fatal "Shadowsocks 密码包含无效控制字符"

    _split_host_port "$endpoint" || _fatal "Shadowsocks 服务器地址或端口无效"
    if ! output=$(jq -n \
        --arg server "$PARSED_SERVER" \
        --argjson port "$PARSED_PORT" \
        --arg method "$method" \
        --arg password "$password" \
        '{type:"shadowsocks",tag:"proxy",server:$server,server_port:$port,method:$method,password:$password}'); then
        _fatal "生成 Shadowsocks outbound 失败"
    fi
    printf '%s\n' "$output"
}

_read_link() {
    local argument_count extra read_status
    argument_count="$1"
    if (( argument_count == 2 )); then
        LINK_INPUT="$2"
    else
        LINK_INPUT=""
        if ! IFS= read -r LINK_INPUT; then
            [[ -n "$LINK_INPUT" ]] || _fatal "未从标准输入读取到节点链接"
        fi

        while true; do
            extra=""
            IFS= read -r extra
            read_status=$?
            extra="${extra%$'\r'}"
            [[ -z "$extra" ]] || _fatal "标准输入只能包含一条节点链接"
            (( read_status == 0 )) || break
        done
    fi

    LINK_INPUT="${LINK_INPUT%$'\r'}"
    [[ -n "$LINK_INPUT" ]] || _fatal "节点链接不能为空"
    [[ "$LINK_INPUT" != *$'\r'* && "$LINK_INPUT" != *$'\n'* ]] || _fatal "节点链接不能包含换行符"
}

(( $# == 1 || $# == 2 )) || _fatal "用法：bash parser.sh MODE（节点链接从标准输入传入）"

MODE="$1"
case "$MODE" in
    vless-reality-vision|vless-tcp|ss-aes-128-gcm|ss-aes-256-gcm) ;;
    *) _fatal "不支持的解析模式" ;;
esac

command -v jq >/dev/null 2>&1 || _fatal "缺少 jq 依赖"
case "$MODE" in
    ss-aes-128-gcm|ss-aes-256-gcm)
        command -v base64 >/dev/null 2>&1 || _fatal "缺少 base64 依赖"
        ;;
esac

_read_link "$#" "${2-}"

case "$MODE" in
    vless-reality-vision) _parse_vless_reality_vision "$LINK_INPUT" ;;
    vless-tcp) _parse_vless_tcp "$LINK_INPUT" ;;
    ss-aes-128-gcm) _parse_ss_uri "$LINK_INPUT" "aes-128-gcm" ;;
    ss-aes-256-gcm) _parse_ss_uri "$LINK_INPUT" "aes-256-gcm" ;;
esac

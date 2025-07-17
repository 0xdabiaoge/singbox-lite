## **SingBox精简版**

## **原作者项目地址**
- **https://github.com/Devmiston/sing-box**

## **修改的地方**
- **只保留了sing-box最新稳定版的安装方式**
- **移除了部分节点协议类型**
- **只生成Yaml配置文件，适用于Clash**
- **脚本修改全程由AI完成，难免出现BUG，仅在Debian&&Ubuntu系统下测试使用**

## **安装**
### **Debian&&Ubuntu使用以下命令安装依赖**
```
apt update && apt -y install curl wget tar socat jq git openssl uuid-runtime build-essential zlib1g-dev libssl-dev libevent-dev dnsutils xxd net-tools cron
```
### **使用以下命令运行脚本**

- **使用以下命令运行脚本**
```
wget -N -O /usr/local/bin/sb.sh https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox-lite.sh && chmod +x /usr/local/bin/sb.sh && ln -sf /usr/local/bin/sb.sh /usr/local/bin/sb && sb
```
## **使用方法**
- **如果开启ECH配置则不会生成Clash客户端配置文件。**
- **Clash客户端配置文件位于/usr/local/etc/sing-box/clash.yaml，下载后加载到 clash verge 客户端即可使用。**
- **节点信息查看: 所有创建的节点信息都会汇总保存在 /usr/local/etc/sing-box/output.txt 中，方便随时查看。**
- **卸载脚本: 在脚本主菜单选择 20 即可完全卸载，此操作会干净地移除所有相关文件、服务和定时任务，并自动删除脚本本身。**

## **脚本支持的节点类型**
- **SOCKS**
- **Direct (端口转发)**
- **VMess (+TCP/WS/gRPC, 可选 TLS)**
- **VLESS (+TCP/WS, 可选 REALITY)**
- **TUIC**
- **Juicity**
- **Trojan (+TCP/WS/gRPC, 需 TLS)**
- **Hysteria**
- **Hysteria2**
- **ShadowTLS**
- **NaiveProxy**
- **Shadowsocks**
- **WireGuard (WARP 解锁)** 

## **免责声明**
- **本项目仅供学习与技术交流，请在下载后 24 小时内删除，禁止用于商业或非法目的。**
- **使用本脚本所搭建的服务，请严格遵守部署服务器所在地、服务提供商和用户所在国家/地区的相关法律法规。**
- **对于任何因不当使用本脚本而导致的法律纠纷或后果，脚本作者及维护者概不负责。**

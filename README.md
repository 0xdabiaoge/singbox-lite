## **SingBox精简版**

## **原作者项目地址**
- **https://github.com/Devmiston/sing-box**

## **修改的地方**
- **只保留了sing-box最新稳定版的安装方式,自动获取官方最新稳定版**
- **移除了部分节点协议类型，节点管理中显示节点类型和监听端口**
- **生成Yaml配置文件，适用于Clash**
- **生成节点链接，适用于v2rayN**
- **脚本风格：Gemini2.5Pro，仅在Debian、Ubuntu系统下测试使用**

## **安装**
### **Debian&&Ubuntu使用以下命令安装依赖**
```
apt update && apt -y install curl wget tar jq openssl dnsutils net-tools cron coreutils
```
### **使用以下命令运行脚本**

- **自动创建快捷方式：sb**
```
wget -N -O /usr/local/bin/sb.sh https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox-lite.sh && chmod +x /usr/local/bin/sb.sh && ln -sf /usr/local/bin/sb.sh /usr/local/bin/sb && sb
```
## **使用方法**
- **如果开启ECH配置则不会生成Clash客户端配置文件。**
- **Clash客户端配置文件位于/usr/local/etc/sing-box/clash.yaml，下载后加载到 clash verge 客户端即可使用。**
- **节点链接在创建节点成功后会显示在下方，也可以通过菜单选择 14 查看节点信息中获取，复制粘贴到 v2rayN 即可使用**
- **节点信息查看: 所有创建的节点信息都会汇总保存在 /usr/local/etc/sing-box/output.txt 中，方便随时查看。**
- **卸载脚本: 在脚本主菜单选择 20 即可完全卸载，此操作会干净地移除所有相关文件、服务和定时任务，并自动删除脚本本身。**

## **精简版脚本支持的节点类型（仅保留较为常用的节点协议）**
- **SOCKS**
- **VMess (+TCP/WS/gRPC, 可选 TLS)**
- **VLESS (+TCP/WS, 可选 REALITY)**
- **TUIC**
- **Trojan (+TCP/WS/gRPC, 需 TLS)**
- **Hysteria2**
- **Shadowsocks**

## **yaml配置文件模板，可做参考**
- **脚本生成的yaml配置文件是默认配置，没有其他多余的写法，下面提供了一份包含链式代理的模板可供参考**
- **[Release](https://github.com/0xdabiaoge/singbox-lite/releases)**

## **免责声明**
- **本项目仅供学习与技术交流，请在下载后 24 小时内删除，禁止用于商业或非法目的。**
- **使用本脚本所搭建的服务，请严格遵守部署服务器所在地、服务提供商和用户所在国家/地区的相关法律法规。**
- **对于任何因不当使用本脚本而导致的法律纠纷或后果，脚本作者及维护者概不负责。**

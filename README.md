## **SingBox 精简版**

## 两个独立的脚本，分别适配Debian/CentOS/Ubuntu和Alpine，仅在上述系统中测试使用。

## **✨ 功能特性**
- **脚本风格：Gemini2.5Pro**
- **轻量高效：资源占用极低，适合小内存机器使用。**
- **自动识别IPV4，ipv6**
- **Hysteria2可选择开启QUIC流量混淆（需要客户端支持）**

### **使用以下命令运行脚本**

**快捷命令：sb**

**Debian/CentOS/Ubuntu**
```
(curl -LfsS https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -o /usr/local/bin/sb || wget -q https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -O /usr/local/bin/sb) && chmod +x /usr/local/bin/sb && sb
```

**Alpine**
```
(curl -LfsS https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox-alpine.sh -o /usr/local/bin/sb || wget -q https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox-alpine.sh -O /usr/local/bin/sb) && chmod +x /usr/local/bin/sb && sb
```
## **使用方法**
- **Clash客户端配置文件位于/usr/local/etc/sing-box/clash.yaml，下载后加载到 clash verge 客户端即可使用**
- **菜单选择查看节点分享链接，复制粘贴导入v2rayN即可使用**

## **脚本支持的节点类型**
- **VLESS (REALITY)**
- **Hysteria2（自签证书）**
- **TUICv5（自签证书）**
- **Shadowsocks (aes-256-gcm加密)**
- **Socks5**

## **更多yaml配置文件模板，可做参考**
- **[Release](https://github.com/0xdabiaoge/singbox-lite/releases)**

## **免责声明**
- **本项目仅供学习与技术交流，请在下载后 24 小时内删除，禁止用于商业或非法目的。**
- **使用本脚本所搭建的服务，请严格遵守部署服务器所在地、服务提供商和用户所在国家/地区的相关法律法规。**
- **对于任何因不当使用本脚本而导致的法律纠纷或后果，脚本作者及维护者概不负责。**

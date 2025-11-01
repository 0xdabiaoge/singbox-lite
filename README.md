## **SingBox 精简版**

## 适配标准版以及LXC、KVM等虚拟化的Debian/CentOS/Ubuntu和Alpine，同时支持Docker容器虚拟化的Debian、Alpine，仅在上述系统中测试使用。
## 重要提示：通过Docker容器虚拟化出来的系统有个小bug，重启机器后，需要重新进入脚本，重启一遍singbox，才能正常使用。

## **✨ 功能特性**
- **轻量高效：资源占用极低，适合小内存机器使用。**
- **自动识别IPV4，ipv6**
- **既有直连节点协议，也有落地节点协议**
- **Hysteria2可选择开启QUIC流量混淆（需要客户端支持）**

### **使用以下命令运行脚本**

**快捷命令：sb**

```
(curl -LfsS https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -o /usr/local/bin/sb || wget -q https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -O /usr/local/bin/sb) && chmod +x /usr/local/bin/sb && sb
```
## **使用方法**
- **Clash客户端配置文件位于/usr/local/etc/sing-box/clash.yaml，脚本默认的配置文件仅保证基础使用，效果不理想的请自行搜索解决**
- **菜单选择查看节点分享链接，复制粘贴导入v2rayN即可使用**

## **脚本支持的节点类型**
- **VLESS (Vision+REALITY)，推荐直连使用**
- **VLESS (WebSocket+TLS)，推荐直连使用，优选域名专用，目前仅支持手动上传域名证书文件**
- **VLESS (tcp)，推荐落地使用**
- **Hysteria2（自签证书），推荐直连使用**
- **TUICv5（自签证书），推荐直连使用**
- **Shadowsocks (aes-256-gcm，2022-blake3-aes-128-gcm)，推荐落地使用**
- **Socks5，推荐落地使用**



## **版本更新说明**
**2025.09.27更新要点：**

**1、增加自定义IP地址的输入，可手动输入IP地址或者直接使用机器默认IP，应对某些情况下需要手动修改节点链接。**

**2、修改伪装域名为自定义输入或者直接使用默认的伪装域名。**

**2025.09.30更新要点：**

**1、Hysteria2和TUICv5的自签证书可以手动输入自己想要的伪装域名**

**2、Hysteria2和TUICv5生成对应的自签证书，删除节点不会对另一种造成影响**

**2025.10.15更新要点：**

**1、新增Vless+WS+TLS节点协议**

**2、考虑到脚本以轻量为主，也考虑到NAT服务器的端口问题，TLS的域名证书文件需要自己制作下载后上传到机器上，域名证书不懂如何操作的自行前往YouTuBe搜索。
域名证书的.pem和.key文件上传到任意文件夹内即可，搭建节点的时候需要输入对应证书文件的绝对路径（例如：/root/xxxxx.pem，/root/xxxxx.key）**

**2025.11.01更新要点：**

**1、修改了Vless+WS+TLS的搭建方式，可选择跳过证书验证**

## **免责声明**
- **本项目仅供学习与技术交流，请在下载后 24 小时内删除，禁止用于商业或非法目的。**
- **使用本脚本所搭建的服务，请严格遵守部署服务器所在地、服务提供商和用户所在国家/地区的相关法律法规。**
- **对于任何因不当使用本脚本而导致的法律纠纷或后果，脚本作者及维护者概不负责。**

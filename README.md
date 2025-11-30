## **SingBox 精简版**

## 适配标准版以及LXC、KVM等虚拟化的Debian/CentOS/Ubuntu和Alpine，同时支持Docker容器虚拟化的Debian、Alpine，仅在上述系统中测试使用。
## 重要提示：通过Docker容器虚拟化出来的系统有个小bug，重启机器后，需要重新进入脚本，重启一遍singbox，才能正常使用。

## **✨ 功能特性**
- **轻量高效：资源占用极低，适合小内存机器使用。**
- **自动识别IPV4，ipv6**
- **既有直连节点协议，也有落地节点协议**
- **Hysteria2可选择开启QUIC流量混淆（需要客户端支持）**
- **内置SingBox路由规则 (Route Rules)转发，详细看版本更新说明**

## **脚本支持的节点类型**
- **VLESS (Vision+REALITY)，推荐直连使用**
- **VLESS (WebSocket+TLS)，推荐直连使用，优选域名专用，目前仅支持手动上传域名证书文件**
- **Trojan (WebSocket+TLS)，推荐直连使用，优选域名专用，目前仅支持手动上传域名证书文件**
- **VLESS (tcp)，推荐落地使用**
- **Hysteria2（自签证书），推荐直连使用**
- **TUICv5（自签证书），推荐直连使用**
- **Shadowsocks (aes-256-gcm，2022-blake3-aes-128-gcm)，推荐落地使用**
- **Socks5，推荐落地使用**

### **使用以下命令运行脚本**

**快捷命令：sb**

```
(curl -LfsS https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -o /usr/local/bin/sb || wget -q https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -O /usr/local/bin/sb) && chmod +x /usr/local/bin/sb && sb
```
## **使用方法**
- **Clash客户端配置文件位于/usr/local/etc/sing-box/clash.yaml，脚本默认的配置文件仅保证基础使用，效果不理想的请自行搜索解决**
- **菜单选择查看节点分享链接，复制粘贴导入v2rayN即可使用**
- **如果想查看SS的密码，请到/usr/local/etc/sing-box目录下，打开config.json文件查看**

## **线路机转发脚本命令使用方法**
- **1. 将落地机生成的relay-install.sh脚本文件上传到线路机的/root目录下，执行```chmod +x /root/relay-install.sh && /root/relay-install.sh```**
- **1. 查看链接: ```bash /root/relay-install.sh view```**
- **2. 添加中转路由: ```bash /root/relay-install.sh add```**
- **3. 删除指定中转路由: ```bash /root/relay-install.sh delete```**
- **2. 重启服务: Debian：```systemctl restart sing-box-relay```   Alpine：```rc-service sing-box-relay restart```**
- **3. 查看日志: Debian：```journalctl -u sing-box-relay -f```   Alpine：```tail -f /var/log/sing-box-relay.log```**

   **如何卸载**
- **1. 卸载线路机转发脚本及配置服务: ```bash /root/relay-install.sh uninstall```**

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

## **2025.11.18更新要点（重大更新）：**

**1、内置SingBox路由规则 (Route Rules)转发，灵感来自[singbox-deploy](https://github.com/caigouzi121380/singbox-deploy)，支持多个落地SS节点转发，感谢大佬提供的思路！**

**2、新增VLESS (Vision+REALITY)、Hysteria2、TUICv5三种转发落地的协议，基本上满足绝大部分需求，机器线路好的情况下更推荐使用VLESS (Vision+REALITY)**

**3、用法：先在落地机使用脚本搭建SS协议，加密方式尽量选择shadowsocks-2022 (2022-blake3-aes-128-gcm)，因为后续比较方便。
然后主菜单选择9、生成中转落地脚本，选择刚才创建的SS节点协议，会自动生成一份名为：relay-install.sh的脚本文件在/root目录下。
将relay-install.sh脚本文件下载下来后，上传到线路机的/root目录下，最后进入singbox脚本，选择10、管理线路机脚本，跳转的子菜单中选择1、安装 / 重置 第一个中转服务。
选择其中一个节点协议，输入一个未被使用的端口和SIN伪装域名即可，最后会输出一个节点链接。**

**4、线路机转发脚本可单独安装使用，通过命令进行管理。与singbox脚本共存，搭建节点不冲突，只需要注意端口的使用即可。卸载的时候会弹出选择提示，保留线路机脚本服务则不删除singbox主程序，通过输出的命令进行管理。**

**5、新增Trojan+WS+TLS节点协议的搭建，搭建方法和用法同Vless+WS+TLS**

**6、新增节点名称自定义功能，也可以回车使用默认节点名称。新增脚本更新和SingBox核心更新的功能**

**2025.11.30更新要点：**

**1、生成中转脚本时会提示是否安装Python 3以提供临时下载服务，所生成的HTTP链接复制到线路机——10管理 [混合模式] 中转脚本中使用，即可通过临时的HTTP链接将中转脚本下载过来，不需要手动上传线路机脚本了**

**2、下载完成后记得去落地机选择是否保留或删除Python 3，对于内存和存储空间有限的NAT机器，请务必删除。Python 3的卸载删除只针对首次安装，若机器原本就存在Python 3，会自动跳过卸载步骤。**

**2025.12.01更新要点：**

**1、VLESS (WebSocket+TLS)和Trojan (WebSocket+TLS)新增选择直连模式和优选域名&IP模式，直连模式与原来的搭建方式一致。优选域名&IP模式第一步可以自定义输入优选域名或者IP地址，端口需要填写在CF回源的端口，生成的节点链接和yaml配置文件，会自动改变为443端口，直接复制即可使用。**


## **免责声明**
- **本项目仅供学习与技术交流，请在下载后 24 小时内删除，禁止用于商业或非法目的。**
- **使用本脚本所搭建的服务，请严格遵守部署服务器所在地、服务提供商和用户所在国家/地区的相关法律法规。**
- **对于任何因不当使用本脚本而导致的法律纠纷或后果，脚本作者及维护者概不负责。**

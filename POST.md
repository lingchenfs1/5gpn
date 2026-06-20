# 折腾了一套"客户端只配个 DNS 就能用"的透明反代网关,开源分享

楼主最近给家里一堆不方便装客户端的设备(电视盒子、游戏机、还有公司专网的终端)折腾统一出口,索性把"分流 + 代理"全做到了**网关侧**,客户端啥都不用装,只配一个 DNS 就能用。代码整理了一下开源出来,顺手发个帖,欢迎拍砖。

> 一键安装(交互输入你自己的域名):
> ```bash
> sudo bash <(curl -fsSL https://raw.githubusercontent.com/lingchenfs1/5gpn/main/quick-install.sh)
> ```
> 仓库:**https://github.com/lingchenfs1/5gpn** · MIT 协议 · 512MB 小鸡能跑

---

## 一句话:它干嘛的

客户端把 DNS 指向这台网关(支持 **DoT / DNS over TLS**),就完事了:

- 被墙域名 → 网关用智能 DNS 把它解析成**网关自己的 IP**,流量被"骗"进网关的 SNI 透明代理,再转出去;
- 国内域名 → 走国内 DNS 竞速,正常直连;
- 其它海外域名 → 走海外 DNS。

全程不解密 TLS,只看 SNI,所以**性能很高**。Android 填个私人 DNS、iOS 扫码装个描述文件就行,电视/游戏机改下 DNS 也能用。

## 架构(很简单)

```
客户端 (DoT 853)
   │
   ▼
[dnsdist] ── 被墙域名 ──► 返回网关IP ──► [sniproxy   TCP 80/443]
   │                                     [quic-proxy UDP 443 / HTTP3]
   ├── 国内域名 ──► 国内 DNS 并发竞速
   └── 海外域名 ──► 海外 DNS 池
                                              │
                                              ▼
                                出口层(可切换 / 可按域名分流)
                       直出 / WireGuard / SOCKS5 / Shadowsocks
```

## 几个我自己觉得有意思的点

**🏎 国内 DNS 并发竞速**
国内 DNS 经常单个抽风导致页面卡半天。这里同时并发查多个国内公共 DNS 的 UDP 53,`150ms` 没结果就并发改走**国内 TCP 53**(对付 UDP 被污染/限速),再不行才上海外兜底。哪个先回用哪个,顺滑很多。

**📡 QUIC/HTTP3 也能透明代理**
老的 sniproxy 只管 TCP,不支持 UDP/QUIC。于是用 Go 标准库撸了个极简 QUIC SNI 代理:监听 UDP 443 → 按 RFC 9000 解密 QUIC Initial 包 → 抠出 ClientHello 里的 SNI → 双向转发。纯标准库零依赖。

**🔀 出口可切换、可分流(我最满意的部分)**
出口是在**路由层**做的(给代理进程的出站流量打 mark → 策略路由 → 选定的隧道/TUN),所以 TCP 和 QUIC 全自动跟着走,不用改任何代理代码。支持:

| 类型 | 怎么加 |
|------|--------|
| **WireGuard** | 远端 VPS 跑个一键脚本,把生成的配置粘进来 |
| **SOCKS5 / socks5h(远程DNS)** | `socks5://用户:密码@host:port` |
| **Shadowsocks / SS2022** | `ss://...` |
| **直出** | 网关自己的 IP |

还能写一份**域名分流规则**,按域名把不同网站分到不同出口/直连/拒绝,规则集支持本地域名表和远程 URL(会编译成紧凑的二进制规则集,40 个列表实测只占 200 多 KB、运行内存约 30MB)。

**🪶 低内存模式(自动)**
检测到内存 ≤ 1GB 自动开启:缩小缓存、调小 sysctl、按需启动的服务、给 Go 进程限内存、自动建 swap、编译限单线程防 OOM。512MB 的小鸡空闲占用压得很低。

**🤖 Telegram Bot 全程运维**
懒得 SSH 就用 Bot,中文菜单:

- 📊 状态:服务健康 + CPU/内存/磁盘/连接数/实时流量 一张卡
- 🌐 出口:切换 / 添加 / 删除 / 🩺 连通性检查
- 🧭 分流:看规则、改规则、分类→出口映射点点点
- 🔄 更新规则 · 🔐 续期证书 · ♻️ 重启 · 📜 日志 · 📱 iOS 二维码

只有白名单 ID 能操作,所有命令走固定白名单、不拼 shell。

## 一个真实踩坑(给后来人省点时间)

某次切到"按域名分流"后**全网都打不开**。一顿排查发现:既不是内存也不是 bug,而是我映射过去的某个 SOCKS5 节点**宕了**(主机在线但端口拒绝),偏偏它被设成了大部分流量 + 兜底规则的目标 → 全部黑洞。

教训:**单个出口挂了会无声地黑洞所有流量**。所以后来加了出口连通性预检——切换/分流时自动探测节点可达性,挂了就显眼告警,Bot 上也能一键 🩺 检查。排查类问题,先 `--check-exits` 看一眼节点死活,能省一大圈。

## 快速上手

```bash
# 一键装
sudo bash <(curl -fsSL https://raw.githubusercontent.com/lingchenfs1/5gpn/main/quick-install.sh)

# 客户端:Android 私人 DNS 填 your-domain.com;iOS 扫码装描述文件

# 常用命令
sudo ./install.sh --status        # 状态
sudo ./install.sh --set-exit <名字|local>   # 切出口
sudo ./install.sh --check-exits   # 看出口节点死活
```

## 技术栈

C(sniproxy)· Go(QUIC / DNS 竞速代理,纯标准库)· Python(Bot / 配置生成,纯标准库)· dnsdist · sing-box · nftables 策略路由 · systemd · certbot。

---

仓库在这:**https://github.com/lingchenfs1/5gpn**,MIT 协议,欢迎 issue / PR / 拍砖。觉得有用点个 star 呗 🙏

> 注:本项目仅用于合法的跨境业务互通与技术研究,请遵守当地法律法规。

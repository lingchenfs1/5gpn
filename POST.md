# 自建高性能透明反代网关:Smart DNS + SNI/QUIC 透明代理 + 多协议出口 + Telegram 全程运维

> 一套部署在服务器端的「透明反代 + 智能 DNS」基础设施。客户端只需把 DNS 指向它,无需装任何客户端,即可让被墙域名自动走代理;并支持把出口流量灵活切换 / 分流到 WireGuard / SOCKS5 / Shadowsocks 等不同节点。全程可在 Telegram Bot 上运维。

## 一、它解决什么问题

传统翻墙要在每台设备装客户端、配规则。而这套方案把「分流 + 代理」全做在 **网关侧**:

- 客户端只配一个 **DoT(DNS over TLS)** 地址即可(Android 私人 DNS、iOS 描述文件、桌面 Stubby 等)。
- 网关用 **dnsdist** 做智能 DNS:被墙域名(GFWList)解析时直接返回 **网关自己的 IP**,把客户端流量「骗」进网关的 SNI 透明代理;国内域名走国内 DNS 竞速;其它海外域名走海外 DNS 池。
- 网关用 **SNI 透明代理**(不解密 TLS,只看 SNI/Host)把流量转发出去,性能极高。

适合:5G 专网 / 企业内网统一出口、家庭旁路由、给一堆不方便装客户端的设备(电视、游戏机、IoT)提供统一代理。

## 二、整体架构

```
客户端 (DoT 53/853)
   │
   ▼
[dnsdist]  ── 被墙域名 ──►  返回网关IP ──►  [sniproxy   TCP 80/443]
   │                                        [quic-proxy UDP 443 (HTTP/3)]
   ├── 国内域名 ──► [china-dns-race-proxy] 并发竞速国内DNS
   └── 海外域名 ──► 海外 DNS 池
                                                  │
                                                  ▼
                                   出口层(可切换 / 可分流)
                          local 直出 / WireGuard / SOCKS5 / Shadowsocks
```

核心组件:

| 组件 | 协议/端口 | 作用 |
|------|-----------|------|
| dnsdist (PowerDNS) | 53、853(DoT) | 智能 DNS 分流 + DoT 服务 |
| sniproxy | TCP 80/443 | SNI 透明代理(C 语言,极快) |
| quic-proxy(Go) | UDP 443 | QUIC/HTTP3 的 SNI 透明代理 |
| china-dns-race-proxy(Go) | 本地 | 国内多个 DNS 并发竞速 + fallback |
| sing-box | TUN | 给 SOCKS5/SS 出口做 tun2socks |

## 三、几个比较满意的设计

### 1. 国内 DNS 并发竞速

国内 DNS 经常单个不通导致页面卡半天。这个 DNS 竞速代理同时并发查多个国内公共 DNS 的 **UDP 53**;`150ms` 还没结果就并发改走 **国内 TCP 53**;`750ms` 还不行才启用海外 fallback。哪个先回用哪个,体验顺滑很多。

### 2. QUIC 透明代理

原版 sniproxy 不支持 UDP/QUIC。这里用一个 Go 标准库实现的极简 QUIC SNI 代理:监听 UDP 443 → 按 RFC 9000 解密 QUIC Initial 包 → 提取 ClientHello 里的 SNI → 建立到真实后端的 UDP 会话双向转发。纯标准库、无第三方依赖。

热路径还做了优化:已建立的会话 **内联转发**(不为每个 UDP 包开 goroutine),只有新会话建立才异步,顺手修了一个并发首包会泄漏后端连接的 race。

### 3. 可切换 / 可分流的「出口」

这是最花功夫的部分。出口在 **路由层** 实现(给代理进程的出站流量打 fwmark → 策略路由 → 选定的隧道/TUN 设备),所以 TCP 和 UDP/QUIC 全自动跟着走,无需改任何代理代码。

支持的出口类型:

| 类型 | 引擎 | 添加方式 |
|------|------|----------|
| **WireGuard** | wg-quick(内核) | 粘贴 wg 客户端配置(远端 VPS 一键脚本生成) |
| **SOCKS5 / socks5h(远程DNS)** | sing-box TUN | `socks5://[用户:密码@]host:port` |
| **Shadowsocks / SS2022** | sing-box TUN | `ss://...`(SIP002,含 `2022-blake3-*`) |
| **local** | — | 网关自己直出 |

> 关键点:只有 **被代理的出站流量** 走出口,SSH / DNS / 证书续期等本机流量不受影响;并且 **回客户端的应答不打 mark**(否则会被错误地塞进隧道——这个坑真踩了)。

### 4. Surge 风格智能分流

可以导入一份 **Surge 规则**,按域名把代理流量分到不同出口 / 直连 / 拒绝:

```text
DOMAIN-SUFFIX,openai.com,AI
RULE-SET,https://example.com/streaming.list,Media
GEOSITE,telegram,Proxy
GEOIP,cn,direct
FINAL,Proxy
```

实现要点:

- 转换器自动 **丢弃服务器无意义的规则**(`PROCESS-NAME` / `SRC-IP` / `MAC-ADDRESS` 等)、**拆解 `OR/AND`**、剥离修饰符。
- 策略组保留为「**分类**」,再用一张 `分类=出口` 的映射表解析——这样可以「AI 走一个节点、流媒体走另一个、国内直连、广告拒绝」。
- 外部规则集会拉取并 **编译成 sing-box 二进制 `.srs`**:实测 40 个列表只占 ~232KB、运行内存约 30MB,512MB 小机也扛得住。

### 5. 低内存模式(自动)

检测到内存 ≤ 1GB 自动启用:dnsdist 缓存缩小、sysctl 参数按小机调、iOS 描述文件服务改 **systemd socket 按需启动**(平时 0 进程)、Go 代理加 `GOMEMLIMIT`、自动建 swap、编译限单线程防 OOM。512MB VPS 空闲占用能压到很低。

### 6. Telegram Bot 全程运维

不想 SSH 也能管。Bot 提供中文快捷菜单:

- 📊 **状态**:服务健康 + CPU / 内存 / 磁盘 / 连接数 / 实时流量 一张卡片
- 🌐 **出口**:切换 / 添加 / 删除 / 🩺 连通性检查
- 🧭 **智能分流**:查看 / 编辑规则、🎯 分类→出口映射逐项点选
- 🔄 更新规则 · 🔐 续期证书 · ♻️ 重启服务 · 📜 日志 · 📱 iOS 二维码

所有写操作都经 sing-box 校验,失败给干净的错误原因;只有白名单数字 ID 能操作,绝不把用户输入拼进 shell。

## 四、一个值得记录的排查

某次切到「智能分流」后流量 **全部失效**。一通排查后定位:不是内存、不是代码 bug,而是 **映射到的某个 SOCKS5 出口节点宕了**(主机在线但端口拒绝),而它恰好被设成了大部分流量 + 兜底规则的目标 → 全部黑洞。

教训:**单出口故障会无声黑洞所有流量**。于是加了出口连通性预检(切换/分流时自动探测节点 TCP 可达性,不可达就显著告警 + Bot 上一键 🩺 检查),让死节点无所遁形。

## 五、快速开始

```bash
# 1. 上传文件到服务器,运行安装脚本(交互输入你自己的域名)
chmod +x install.sh && sudo ./install.sh

# 2. 客户端配置 DoT:
#    Android → 私人 DNS 填 your-domain.com
#    iOS     → 扫码安装描述文件(仅蜂窝网启用)

# 常用管理命令
sudo ./install.sh --status
sudo ./install.sh --set-exit <name|local|smart>
sudo ./install.sh --check-exits
sudo ./install.sh --import-surge rule.conf
```

## 六、技术栈

C(sniproxy)· Go(QUIC 代理 / DNS 竞速代理,纯标准库)· Python(Bot / 配置生成,纯标准库)· dnsdist · sing-box · nftables 策略路由 · systemd · certbot。

---

**小结**:核心思路就是「**把分流和代理下沉到网关,客户端只配一个 DNS**」,再叠加多协议可切换出口 + 规则分流 + 一个能干活的 Telegram Bot。性能好、依赖少、单机 512MB 也能跑。

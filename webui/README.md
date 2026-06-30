# 部署网页控制台

`index.html` 是一个**纯静态、零依赖**的单文件控制台,不需要构建、也不需要它自己的后端——它只是通过浏览器调用网关的 HTTP API。所以"部署"就是"把这个 HTML 放到一个能打开的地方",怎么简单怎么来。

## 前置条件

1. **在网关上启用 API**(它才是真正的后端):

   ```bash
   sudo ./install.sh --setup-api
   ```

   执行后会打印 **API 地址**(`https://你的网关域名:8443`)和 **令牌**。在 Telegram Bot 里发 `/api` 也能随时查看。

2. 确认这个 API 端口(默认 `8443`)能从你浏览器所在的网络访问(`--setup-api` 已自动放行防火墙)。

> 面板和 API 已开好 CORS,面板放在任何域名下都能调用网关 API,跨域没问题。

---

## 方式一:本地直接打开(最快,自己用)

把 `index.html` 下载到电脑,**双击用浏览器打开**即可。填入 API 地址和令牌就能用,令牌存在浏览器本地,下次自动连。

适合自己临时用,不想折腾服务器。

## 方式二:丢到任意静态托管(零成本)

把 `index.html` 传到任何能放静态文件的地方,比如:

- GitHub Pages / Cloudflare Pages / Vercel / Netlify
- 对象存储(S3 / R2 / OSS)开静态网站
- 任意已有的网站目录

传上去就能用,没有别的步骤。

## 方式三(推荐):Cloudflare Pages(免费、自动 HTTPS、自动部署)

面板是单文件静态页,非常适合放 Cloudflare Pages。下面以仓库 `webui/index.html`、域名 `5gpn.fancdn.com` 为例。

### A. 连接 GitHub 自动部署(推荐,push 即更新)

1. 登录 Cloudflare → 左侧 **Workers & Pages** → **Create** → **Pages** 选项卡 → **Connect to Git**。
2. 授权并选择你的仓库(如 `lingchenfs1/5gpn`),分支 `main`。
3. 构建设置(关键,因为文件在 `webui/` 子目录):
   - **Framework preset**:`None`
   - **Build command**:**留空**
   - **Build output directory**:`webui`
   （Pages 会把 `webui/` 目录当作站点根目录发布,`webui/index.html` 即首页。)
4. **Save and Deploy**。约 1 分钟后得到一个 `xxx.pages.dev` 的临时地址,打开能看到面板即成功。
5. 以后只要 `git push`,Pages 自动重新部署,无需手动操作。

> 如果不想公开仓库里其它内容:Pages 只发布 `Build output directory` 指定的目录(这里是 `webui`),其余文件不会暴露在站点上。

### B. 直接上传(不连 Git,最快)

1. **Workers & Pages** → **Create** → **Pages** → **Upload assets**(直接上传)。
2. 给项目起个名(如 `5gpn-panel`)。
3. 把 `webui/index.html` 拖进去上传(只传这一个文件即可),**Deploy**。
4. 以后更新就再上传一次新的 `index.html`(Create a new deployment)。

### C. 绑定自己的域名 `5gpn.fancdn.com`

1. 进入该 Pages 项目 → **Custom domains** → **Set up a custom domain** → 输入 `5gpn.fancdn.com` → **Continue / Activate**。
2. 如果 `fancdn.com` 的 DNS 就托管在这个 Cloudflare 账号,它会**自动**创建所需的 CNAME 记录并签发证书,等几分钟变 **Active** 即可。
3. **清理旧解析**:之前 `5gpn.fancdn.com` 指向旧服务器(54.249.147.94)的 **A 记录要删掉**,否则和 Pages 的记录冲突。(Pages custom domain 会用 CNAME 接管。)
4. 打开 `https://5gpn.fancdn.com`,证书由 Cloudflare 自动提供,HTTPS 直接可用。

### D. 用起来

打开面板 → 填 **API 地址** `https://你的网关域名:8443` + **令牌**(网关上 `--setup-api` 生成,或 Telegram Bot `/api` 查看)→ 连接。

- 面板(Pages, HTTPS)调用网关 API(HTTPS),CORS 已是 `*`,跨域没问题、无混合内容。
- 令牌存在你浏览器本地,下次自动连。

### 常见问题

- **打开是 404 / 空白**:`Build output directory` 没填 `webui`,或上传时没把 `index.html` 放在根。改对后重新部署。
- **custom domain 一直 pending**:检查 `fancdn.com` 是否在这个 Cloudflare 账号下托管;以及旧的 A 记录是否还占用着 `5gpn.fancdn.com`,删掉它。
- **面板能开但连不上 API**:检查网关 8443 是否放行、令牌是否正确、网关证书是否有效(面板是 HTTPS,API 也必须是可信 HTTPS)。

---

## 方式四:用 nginx + 自己的域名 + HTTPS(自建服务器)

适合给一个固定网址、手机电脑随时打开。以 Debian/Ubuntu + nginx 为例:

### 1. DNS

把你的面板域名(例:`panel.example.com`)解析一条 **A 记录**指向这台 web 服务器的公网 IP。

### 2. 放文件 + 配 vhost

```bash
# 1) 放 HTML
sudo mkdir -p /var/www/panel.example.com
sudo cp index.html /var/www/panel.example.com/index.html

# 2) 写一个站点配置
sudo tee /etc/nginx/sites-available/panel.example.com >/dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name panel.example.com;
    root /var/www/panel.example.com;
    index index.html;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    location / { try_files $uri $uri/ /index.html; }
}
EOF

sudo ln -sf ../sites-available/panel.example.com /etc/nginx/sites-enabled/panel.example.com
sudo nginx -t && sudo systemctl reload nginx
```

### 3. 上 HTTPS(Let's Encrypt)

```bash
sudo apt install -y certbot python3-certbot-nginx   # 如未安装
sudo certbot --nginx -d panel.example.com --agree-tos --redirect -m you@example.com
```

certbot 会自动改好 nginx 配置、签发证书、加 HTTP→HTTPS 跳转,并自动续期。

打开 `https://panel.example.com`,填入 API 地址 + 令牌即可。

### 更新面板

以后 `index.html` 有更新,覆盖一份就行:

```bash
sudo cp index.html /var/www/panel.example.com/index.html
```

---

## 安全提醒

- 面板页面本身**不含任何密钥**,真正的钥匙是那串 **API 令牌**——只发给信任的人,只走 HTTPS。
- 想换令牌:改网关上 `/opt/proxy-gateway/etc/api.env` 里的 `API_TOKEN`,然后 `systemctl restart proxy-gateway-api`。
- 分享截图/链接给别人时,别把令牌也带上。

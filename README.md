# Trojan 个人节点（Xray）

这是面向单个个人节点的 Trojan 运维仓库。v3 使用 Xray 承载 Trojan 入站，
`/usr/local/sbin/trojan-certman` 是唯一管理入口。

## v3 是不兼容升级

v3 不再发布或安装旧 Go 管理器，也不再支持 Web 面板、多用户、MySQL/MariaDB、
远程自更新和 Docker 镜像。`trojan web` 与 `/auth/*` 已删除；认证失败的连接由
Xray 直接关闭，不配置指向管理面的 fallback。

升级只保持客户端侧兼容：继续使用原 Trojan 协议、域名、443 端口、证书、密码和
Clash 配置。服务端实现和管理方式会变化，因此不能把 v2 原地覆盖当作普通小版本升级。
旧实现只保留在 Git 历史中。

Xray `v26.3.27` 会对无 Flow 的 Trojan 输出 deprecated 警告。v3 固定该版本以避免
上游未来删除功能时发生隐式破坏，但这不是长期协议承诺；任何后续 Xray 升级都必须先跑
Clash 兼容 canary，不能只看配置语法通过。

## 支持边界

- Ubuntu 22.04 / 24.04，systemd，`x86_64` / `aarch64`。
- 单域名、单节点、单个 Trojan 凭据；不提供通用多用户面板。
- Xray 配置固定在 `/etc/xray/config.json`，权限为 `0640 root:xray`。
- 安装后的 CLI 从 `/usr/local/lib/trojan-certman-v3/asset` 读取固定的 systemd unit，
  不依赖仓库目录继续存在。
- Trojan 密码和 Cloudflare token 不得进入仓库、命令行参数或日志；通过 root 可读输入文件读取。
- Xray 以专用 `xray` 用户运行，只保留绑定 443 所需能力，并由 systemd 应用
  `NoNewPrivileges`、只读系统目录、私有临时目录和内核保护。
- Xray 默认拒绝经代理访问回环、RFC1918、link-local、CGNAT（含云 metadata）和
  IPv6 本地地址；个人凭据泄漏不应顺带暴露节点自身或云内网。

固定版本和 SHA-256 是安装、升级的硬门槛。仓库不提供 `latest`、短链、
管道执行下载内容或 Docker 发布链路。下载内容先进入 staging，版本和 SHA-256
匹配后才允许原子切换。当前脚本固定 Xray `v26.3.27` 和 acme.sh `3.1.4`；
发布新版本时必须在代码审查中同时更新版本、架构哈希和故障注入用例。

## 双节点本机自动化

`bin/trojan-node` 是本仓库专用的 macOS 本机编排器，不是通用 Cloudflare CLI。
它只认识 `config/nodes.json` 中的 `aiyun` 和 `aiyun2`，每次只允许操作一台。
节点 IP、域名、zone、凭据 placeholder 和 token 名是仓库跟踪的非 secret；密码、
Cloudflare token、SSH 私钥和私钥路径不进入清单。

它依赖 `personal` Keychain profile 以及支持以下机器接口的 canonical `creds`：

```text
creds set generic NAME FIELD --profile PROFILE --stdin
creds show generic NAME --fields FIELD... --profile PROFILE --format json
```

CLI 通过仓库跟踪的 `config/credentials-*.json` placeholder 自动调用 `creds exec`。
Cloudflare 管理 token 只进入本机进程，节点 password/token 按目标节点隔离；所有子进程
环境都会移除 `CREDS_*`。新值写回 Keychain 时只走 stdin，不进入 argv 或输出。

### 一次性人工门槛

1. 在 Cloudflare UI 创建 180 天管理 token，保存到
   `personal/generic/cloudflare-czyhandsome/token-manager`。权限仅为 User 的
   API Tokens Read/Write，以及精确 `czyhandsome.ink` zone 的 Zone Read/DNS Write；
   不设置来源 IP。CLI 会在到期 30 天内告警，但不会自动替换管理 token。
2. 先由人工用 `ssh aiyun` / `ssh aiyun2` 建立并确认本机 SSH 信任，再确认
   `~/.ssh/known_hosts` 中每个别名恰好有一个 ED25519 条目。CLI 只复用该既有信任，
   复制到临时 `0600` known_hosts 并设置 `HostKeyAlias`；缺失或重复都会停止，绝不通过
   `ssh-keyscan` 自动接纳新 key，也不使用 `StrictHostKeyChecking=no`。
3. 在控制台把当前 Mac 的 SSH 公钥写入 root 的 `authorized_keys`，确认 key-only
   BatchMode 登录。SSH 私钥不由 `creds` 管理。

### 命令面

```text
trojan-node credentials status|rotate --node NODE
trojan-node cloudflare zones
trojan-node cloudflare dns list|ensure --node NODE
trojan-node cloudflare token list|rotate-dns|revoke --node NODE
trojan-node host check --node NODE
trojan-node preflight --node NODE
trojan-node deploy --node NODE [--rotate-secrets] [--apply]
trojan-node verify --node NODE
```

### 自动化部署一台新机器

下面按 `aiyun2` 举例；部署 `aiyun` 时只替换 `NODE`。一次只处理一台，不要把两个节点
写进循环。开始前需要满足：VPS 是 clean Ubuntu 24.04、当前 Mac 已能用 key-only SSH
登录、Cloudflare 管理 token 已存入 `personal` profile、Homebrew 已安装 Mihomo。

```bash
git clone https://github.com/Czyhandsome/trojan.git
cd trojan

brew install mihomo
creds set generic cloudflare-czyhandsome token-manager \
  --profile personal --stdin

NODE=aiyun2
bin/trojan-node host check --node "$NODE"
bin/trojan-node credentials status --node "$NODE"
bin/trojan-node cloudflare dns list --node "$NODE"
bin/trojan-node preflight --node "$NODE"
```

`credentials status` 在 fresh install 前显示两个字段 `MISSING` 是正常的，管理 token 不在
这个输出里。`preflight` 必须确认 DNS 为 `ready`、系统为 Ubuntu 24.04、443 空闲、远端
`STATE` 为 `clean`。若只差 A 记录，先预览并执行受限的 DNS 修正：

```bash
bin/trojan-node cloudflare dns ensure --node "$NODE"
bin/trojan-node preflight --node "$NODE"
```

`dns ensure` 只会创建缺失的 DNS-only A，或修正唯一同名 A 的 IP、TTL 和代理状态。
多 A、AAAA、CNAME 或 zone 不唯一时会拒绝执行，需要人工在 Cloudflare 核对，不能靠删除
记录“试出来”。

preflight 通过后，先看一次脱敏部署计划，再执行同一计划：

```bash
bin/trojan-node deploy --node "$NODE" --rotate-secrets
bin/trojan-node deploy --node "$NODE" --rotate-secrets --apply
```

第二条命令会再次打印节点、域名、Git commit、归档 SHA-256 和 DNS action，并要求输入完整
节点名。确认后它才生成独立 Trojan 密码和受 VPS `/32` 限制的 Cloudflare DNS token，
写入 Keychain，安装远端 Xray，并运行隔离 Mihomo、20 次 GCP SSH 重连和 60 分钟
keepalive。整个命令可能运行一个多小时；最终出现 `"installed": true`、
`"idempotent": true` 才算完成。中途失败时保留第一条错误，不要马上重复 `--rotate-secrets`。

日后验证已安装节点使用：

```bash
bin/trojan-node verify --node "$NODE"
```

同一精确源码的 managed no-op 重跑使用 `deploy --node "$NODE" --apply`，不带
`--rotate-secrets`。provenance 与当前 Git commit 或归档 SHA-256 不一致时会拒绝；这不是
让人覆盖标记的提示，而是要求回到实际部署该节点的精确 commit，或按一次明确升级处理。

`credentials rotate` 和 `cloudflare token rotate-dns` 只更新 Cloudflare/Keychain，不能单独
把新 secret 安装进已经运行的 VPS。它们适合 fresh install 的准备和故障补偿，不是线上节点
的独立换密命令。

`deploy` 默认只打印脱敏计划；`--apply` 会显示精确节点、DNS action、Git commit、archive
SHA-256 和远端动作，并要求输入完整节点名。它从干净 worktree 的精确 commit 构建 tar，
通过严格 ED25519 临时 `known_hosts` 传入远端 staging，回读 SHA-256，再把 password/token
放入内存 tar，经 SSH stdin 写入 `/run/trojan-certman-input`。输入副本由 trap 精确清理，
安装失败仍交给现有事务安装器回滚。

Cloudflare DNS 只允许唯一同名 A 的 no-op/update 或缺失 A 的 create，强制 DNS-only 和
TTL Auto；多 A、任意同名 AAAA/CNAME、zone 不唯一都会停止，绝不自动删除。节点 DNS
token 的 permission-group ID 每次动态解析，权限固定为精确 zone 的 Zone Read/DNS Write，
来源固定为节点 IPv4 `/32`。新 token 必须先写入 Keychain；写入失败会撤销新 token，
成功后才撤销同名旧节点 token，不碰其他 token。

服务端验收包含 Xray active/enabled、`NRestarts=0`、443 owner/queue、配置权限、timers、
SAN/证书指纹和关闭端口。隔离客户端要求 Mihomo `v1.19.29` 或更新版本、
`127.0.0.1:17890`、无 TUN、严格 TLS，随后确认出口 IP、20 次 GCP `:50245` SSH 重连和
60 分钟 keepalive。它不会修改 Clash Verge。

首次安装并通过服务端与线上 TLS 验证后，CLI 会原子写入
`/var/lib/trojan-node/provenance.json`：目录 `0700 root:root`，文件 `0600 root:root`，
只包含节点身份、Git commit 和 archive SHA-256，不含 secret。后续独立 `deploy` 只有在
该标记字段完全匹配当前精确源码、文件类型/权限正确、Xray 与 TLS 仍健康时才允许按同一
凭据重跑；managed rerun 禁止 `--rotate-secrets`。部分残留、外来状态、源码不一致或仅仅
“看起来健康”都会停止。每次成功仍连续运行 installer 两次并比较 PID、重启数、配置和
证书身份，然后严格回读 provenance。

## Ubuntu 24.04 从零安装

下面是一份不依赖 AI 的 fresh install 手册。Ubuntu 22.04 的操作相同。它只适用于一台
没有 Xray、certman、相关 systemd unit、443 监听和残留托管文件的新机器。旧 Trojan
节点不能照此覆盖，必须走后文的 `adopt` / `cutover`。

严格说，这不是“所有事情一键完成”：DNS、Cloudflare 授权和密码必须先由人确认。
这些准备完成后，实际安装 Xray、申请证书、创建 systemd 服务和定时任务是一条命令。

### 1. 准备域名和 Cloudflare token

在 Cloudflare 控制台完成：

1. 为节点创建一条 **DNS only**（灰云）A 记录，值为 VPS 的公网 IPv4。不要创建错误的
   AAAA 记录；安装器不会创建或修改 A/AAAA 记录。
2. 在 **My Profile > API Tokens > Create Token** 创建只给该域名所在 zone 使用的 token。
3. 权限只授予 `Zone / Zone / Read` 和 `Zone / DNS / Edit`，Zone Resources 只包含目标
   zone；确认不会影响其他域名。可以时再把来源 IP 限制为 VPS 公网 IPv4。
4. 把 Trojan 密码保存进自己的密码管理器。不要复用 SSH、邮箱或 Cloudflare 密码。

等待 DNS 生效。后续所有示例都把 `trojan.example.com` 和 `203.0.113.10` 替换成自己的
真实值；不要原样复制占位符。

### 2. 登录服务器并做安装前检查

用 SSH 登录后进入 root shell，并安装安装器在最早阶段就需要的基础命令：

```bash
sudo -i
apt-get update
apt-get install -y ca-certificates curl git iproute2 openssl util-linux

DOMAIN=trojan.example.com
SERVER_IPV4=203.0.113.10

. /etc/os-release
printf 'OS=%s %s ARCH=%s\n' "$ID" "$VERSION_ID" "$(uname -m)"
getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u
printf 'EXPECTED_IPV4=%s\n' "$SERVER_IPV4"
ss -lntp 'sport = :443'
```

继续前必须同时满足：

- 输出是 Ubuntu `22.04` 或 `24.04`，架构是 `x86_64` 或 `aarch64`。
- `getent` 输出包含且只指向这台 VPS 的公网 IPv4。若不一致，先修 DNS 并等待传播。
- `ss` 没有输出；有输出说明 443 已被占用，不能继续 fresh install。
- 云厂商防火墙/安全组允许当前 SSH 端口和入站 TCP 443。若 UFW 已启用，先确认现有
  SSH 规则不会被切断，再执行 `ufw allow 443/tcp`；不要为了本项目盲目启用 UFW。

### 3. 获取完整源码

当前仓库还没有 v3 tag/release；旧 `v2.15.3` tag 和旧 `git.io/trojan-install` 都属于
已经淘汰的 Go 版 Trojan，不能使用。当前可执行来源是 Czyhandsome fork 的 `master`。
必须 clone 整个仓库，不能只下载脚本，因为安装器还要读取同目录的 `asset/`：

```bash
install -d -m 0700 /root/src
git clone --single-branch --branch master \
  https://github.com/Czyhandsome/trojan.git \
  /root/src/czyhandsome-xray
cd /root/src/czyhandsome-xray

git status --short --branch
git log -1 --oneline
test -f install-with-certman.sh
test -d asset
bash -n install-with-certman.sh
```

`git status` 应显示干净的 `master...origin/master`。保存 `git log -1 --oneline` 的提交号，
以后排障时用它确认实际安装来源。不要用 `curl ... | bash` 或任何短链直接执行网络响应。

### 4. 创建 root-only secret 输入文件

下面的 `read -s` 不会把 secret 放进命令历史或显示在屏幕上。输入前先从密码管理器复制
Trojan 密码，并准备好刚创建的 Cloudflare API token：

```bash
install -d -m 0700 /root/secure-input
install -m 0600 -o root -g root /dev/null /root/secure-input/trojan-password
install -m 0600 -o root -g root /dev/null /root/secure-input/cloudflare-token

read -rsp 'Trojan password: ' TROJAN_PASSWORD; printf '\n'
printf '%s\n' "$TROJAN_PASSWORD" > /root/secure-input/trojan-password
unset TROJAN_PASSWORD

read -rsp 'Cloudflare API token: ' CF_TOKEN; printf '\n'
printf '%s\n' "$CF_TOKEN" > /root/secure-input/cloudflare-token
unset CF_TOKEN

test -s /root/secure-input/trojan-password
test -s /root/secure-input/cloudflare-token
stat -c '%U:%G %a %n' /root/secure-input/trojan-password /root/secure-input/cloudflare-token
```

最后一条命令应显示两个文件都是 `root:root 600`。文件必须是普通文件、不能是符号链接，
且只能有一行非空值。不要 `cat`、截图、提交或把内容粘贴到聊天里。

### 5. 一条命令安装

仍在 `/root/src/czyhandsome-xray` 且处于 root shell 时执行：

```bash
env \
  CERT_DOMAIN="$DOMAIN" \
  CERTMAN_PASSWORD_INPUT_FILE=/root/secure-input/trojan-password \
  CERTMAN_CF_TOKEN_INPUT_FILE=/root/secure-input/cloudflare-token \
  ./install-with-certman.sh install
```

看到 `personal Xray Trojan node installed` 才表示安装器完成。它会下载并校验固定版本的
Xray 和 acme.sh，使用 Cloudflare DNS-01 申请证书，只创建临时 TXT 记录，然后安装
Xray 服务、续签 timer 和观测 timer。它不会修改域名的 A/AAAA 记录。

### 6. 服务端验收

安装完成后逐条执行：

```bash
trojan-certman status
trojan-certman snapshot
systemctl is-active xray.service
systemctl is-enabled xray.service
systemctl is-active trojan-certman-renew.timer trojan-certman-snapshot.timer
systemctl is-enabled trojan-certman-renew.timer trojan-certman-snapshot.timer
ss -lntp 'sport = :443'

openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

预期结果是：`status` 无失败项；服务与两个 timer 都是 `active` / `enabled`；443 的监听者
是 Xray；证书 SAN 包含 `$DOMAIN` 且尚未过期。只有 systemd 显示 active 不算完成，必须
同时通过 TLS 检查和下一节的真实客户端连接。

### 7. 客户端配置与端到端检查

Clash Meta / Mihomo 可使用以下最小配置。只在自己的本地配置中把占位值替换为真实域名
和密码，不要把生成后的配置提交到 Git：

```yaml
proxies:
  - name: czyhandsome-xray
    type: trojan
    server: trojan.example.com
    port: 443
    password: "replace-with-your-trojan-password"
    sni: trojan.example.com
    skip-cert-verify: false
    udp: true
```

客户端的 `server` 和 `sni` 必须是证书对应的域名，不能改填 IP；端口为 443，协议仍是
Trojan。不要关闭证书校验。先做一次节点延迟测试，再经该节点访问一个公网 IP 查询站点，
确认出口 IP 已变成 VPS 的公网 IP。最后断开并重新连接数次，确认不是偶然建立连接。

客户端配置完成且密码已保存在密码管理器后，`/root/secure-input/` 下的两个文件只是安装
输入副本；正式副本已安装到 `/etc/trojan-certman-v3/secrets/`。是否删除输入副本由你决定，
但无论保留或删除都必须避免普通用户可读。

### 8. 安装失败时怎么查

先保留终端里的第一条错误，不要反复重跑或手工删除 `/etc/xray`、
`/etc/trojan-certman-v3`。按问题查看：

```bash
journalctl -u xray.service -n 100 --no-pager
journalctl -u trojan-certman-renew.service -n 100 --no-pager
journalctl -u trojan-certman-snapshot.service -n 100 --no-pager
systemctl --no-pager --full status xray.service
trojan-certman snapshot
```

- `DNS-01 certificate issuance failed`：先核对 DNS 已指向本机、token 属于正确 zone，权限是
  `Zone:Read` 和 `DNS:Edit`；不要改成 Global API Key。
- `port 443 is already in use`：用 `ss -lntp 'sport = :443'` 找到真实监听者。不要直接杀进程。
- `partial or conflicting managed state exists`：机器并非 clean host，或上次状态无法安全证明
  归属。不要用 `rm -rf` 强行清场，应先根据第一条失败和日志判断状态。
- `password/token input ...`：重新检查文件是否为普通文件、`root:root 600`、单行非空；不要
  打印内容验证。
- 服务端全部正常但客户端失败：核对域名、443、Trojan 密码和 SNI，并确认客户端没有跳过
  或错误覆盖证书设置。

首次安装在所有只读检查通过后才记录事务。`ERR`、`INT`、`TERM` 或下次启动发现遗留
事务时，只清理能够证明由本次 fresh install 创建的 Xray/certman 状态，并恢复原 sysctl；
已经安装的 apt 依赖和空闲 `xray` 系统用户会保留。无法证明归属的 unit、443 监听、
残留文件或已有 acme.sh 目录会导致拒绝安装，不会被覆盖或删除。

完整且健康的托管安装再次运行同一安装命令时只验证状态并成功返回，不续签、不重启、
不改配置。若重跑时继续提供 secret 输入，它们必须与已安装值一致，否则无修改失败。

## 常用机器操作

下面的命令不依赖 AI。先分清执行位置：标有“服务器”的命令在 VPS 的 root shell 执行；
标有“Mac”的命令在本机执行。不要把密码、完整 Trojan URI 或生成后的 YAML 粘贴到 issue、
聊天、shell 参数或 Git 仓库。

### 看服务、端口、证书和最近日志（服务器）

```bash
sudo -i

trojan-certman status
trojan-certman snapshot
systemctl show xray.service -p ActiveState -p SubState -p MainPID -p NRestarts
systemctl is-active trojan-certman-renew.timer trojan-certman-snapshot.timer
systemctl is-enabled trojan-certman-renew.timer trojan-certman-snapshot.timer
ss -lntp 'sport = :443'
ss -lntp 'sport = :80 or sport = :18443 or sport = :34384'

journalctl -u xray.service --since '1 hour ago' --no-pager
journalctl -u trojan-certman-renew.service --since '24 hours ago' --no-pager
journalctl -u trojan-certman-snapshot.service --since '1 hour ago' --no-pager
```

正常节点应满足：Xray 为 active，`NRestarts` 没有异常增长，443 owner 是 Xray、queue 上限
为 4096，80/18443/34384 没有监听，两个 timer 均 active/enabled。`snapshot` 里的
ListenDrops/Overflows 要看增量；历史累计值不为 0 不等于此刻正在丢连接。

公网 TLS 要从另一台机器检查，不能只连接 `127.0.0.1`：

```bash
DOMAIN=introspect2.czyhandsome.ink
openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" \
  -verify_return_error </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -fingerprint -sha256 -ext subjectAltName
```

SAN 必须包含目标域名，证书未过期，握手不得依赖 `-verify 0` 或跳过校验。

### 只复制原始 Trojan 密码（Mac）

密码正式保存在服务器的
`/etc/trojan-certman-v3/secrets/trojan-password`，权限应为 `root:root 600`。确实需要原始
密码时直接通过 SSH 管道写入 macOS 剪贴板，避免先显示在终端：

```bash
SSH_TARGET=root@aiyun2
ssh "$SSH_TARGET" \
  'exec cat /etc/trojan-certman-v3/secrets/trojan-password' \
  | pbcopy
```

这条命令的 stdout 就是 secret。不要加 `tee`、调试回显或保存 shell trace。粘贴到目标客户端
后可用 `pbcopy </dev/null` 清空剪贴板。若只想确认文件健康，不读取正文：

```bash
ssh "$SSH_TARGET" \
  'stat -c "%U:%G %a %s %n" /etc/trojan-certman-v3/secrets/trojan-password'
```

### 生成 Trojan URI 并复制到剪贴板（Mac）

Trojan URI 是单节点导入链接，不是在线订阅服务。下面从服务器读取密码，通过 stdin 交给
本机 Python 做 URL encoding，最终只进入剪贴板：

```bash
SSH_TARGET=root@aiyun2
DOMAIN=introspect2.czyhandsome.ink
NODE_NAME=aiyun2

ssh "$SSH_TARGET" \
  'exec cat /etc/trojan-certman-v3/secrets/trojan-password' \
  | python3 -c '
import sys
from urllib.parse import quote

domain, name = sys.argv[1:]
raw = sys.stdin.read()
password = raw[:-1] if raw.endswith("\n") else raw
if not password or "\n" in password or "\r" in password:
    raise SystemExit("invalid password input")
encoded_password = quote(password, safe="")
encoded_domain = quote(domain, safe="")
encoded_name = quote(name, safe="")
print(f"trojan://{encoded_password}@{domain}:443?sni={encoded_domain}#{encoded_name}")
' "$DOMAIN" "$NODE_NAME" \
  | pbcopy
```

不同客户端对 URI 的可选参数支持不完全一致；必需信息只有协议 `trojan`、域名、443、密码、
SNI 和严格证书校验。客户端若不接受该 URI，使用下一节 YAML；导入后确认客户端没有开启
`allowInsecure` / `skip-cert-verify`，不要把跳过证书校验当成修复手段。

### 生成最小 Clash/Mihomo YAML（Mac）

下面把配置写到本机 root-only 风格的 `0600` 文件，不修改 Clash Verge 当前配置：

```bash
SSH_TARGET=root@aiyun2
DOMAIN=introspect2.czyhandsome.ink
NODE_NAME=aiyun2
OUTPUT="$HOME/Downloads/${NODE_NAME}-trojan.yaml"

umask 077
ssh "$SSH_TARGET" \
  'exec cat /etc/trojan-certman-v3/secrets/trojan-password' \
  | python3 -c '
import json
import sys

domain, name = sys.argv[1:]
raw = sys.stdin.read()
password = raw[:-1] if raw.endswith("\n") else raw
if not password or "\n" in password or "\r" in password:
    raise SystemExit("invalid password input")
print("proxies:")
print(f"  - name: {json.dumps(name, ensure_ascii=False)}")
print("    type: trojan")
print(f"    server: {json.dumps(domain)}")
print("    port: 443")
print(f"    password: {json.dumps(password)}")
print(f"    sni: {json.dumps(domain)}")
print("    skip-cert-verify: false")
print("    udp: true")
' "$DOMAIN" "$NODE_NAME" >"$OUTPUT"

chmod 0600 "$OUTPUT"
ls -l "$OUTPUT"
```

该 YAML 含明文密码。导入后要么把它移入受控配置目录，要么删除；不要放进 iCloud 公共目录、
Git 仓库或聊天附件。仓库不提供 HTTP subscription endpoint，因此不存在可以长期公开访问的
“订阅地址”。

### 改配置前检查，必要时受控重启（服务器）

只读检查配置：

```bash
/usr/local/bin/xray run -test -config /etc/xray/config.json
```

测试通过后，确实需要应用人工改动时才重启：

```bash
systemctl restart xray.service
systemctl is-active xray.service
systemctl show xray.service -p MainPID -p NRestarts
trojan-certman snapshot
```

不要把“重启后 active”当成完整验收；还要检查公网 TLS 和真实代理出口。正常续签、状态查看
和 snapshot 不需要手工重启 Xray。

### 证书续签与定时任务（服务器）

```bash
systemctl list-timers 'trojan-certman-*' --all
trojan-certman renew
trojan-certman status
journalctl -u trojan-certman-renew.service -n 100 --no-pager
```

`renew` 是正常到期检查，不会强制签发；证书未到续签时间时成功 skip 是正常结果。不要额外
给 acme.sh 配第二个 reload command，也不要日常使用 `--force`。

### 常见连接故障怎么分层（Mac 与服务器）

```bash
# Mac：DNS、TCP、TLS
dig +short A introspect2.czyhandsome.ink
nc -vz introspect2.czyhandsome.ink 443
openssl s_client -connect introspect2.czyhandsome.ink:443 \
  -servername introspect2.czyhandsome.ink -verify_return_error </dev/null

# 服务器：进程、队列、计数器、日志
trojan-certman snapshot
systemctl show xray.service -p MainPID -p NRestarts
ss -lntp 'sport = :443'
journalctl -u xray.service --since '15 minutes ago' --no-pager
```

- TCP 443 不通：先查云防火墙、安全组、进程和监听者，不要先改 Trojan 密码。
- TLS 失败：查 DNS、SNI、SAN、到期时间和线上/磁盘指纹，不要关闭证书校验。
- TLS 正常但代理失败：查密码、客户端 `type: trojan`、443、SNI 和客户端实际选中的节点。
- 代理网页正常但 SSH keepalive 断：同时看本地网络切换、代理出口变化、GCP 目标和
  `ListenDrops/Overflows` 增量，不能只怪 Xray。
- SSH 管理口在 `kex_exchange_identification` 前被关闭，但从其他出口能读到 banner：通常是
  当前出口 IP 被云侧或 sshd 临时限流；先停止密集重试并切回可信出口，不要删除 host key。

### 服务器重装后处理 SSH host key（Mac）

重装系统后 host key 正常会变化。先在云厂商控制台核对新机器身份和 ED25519 指纹，再更新
本机记录；不能看到警告就直接关闭严格校验：

```bash
ssh-keygen -F aiyun2
ssh-keygen -R aiyun2
ssh root@aiyun2
bin/trojan-node host check --node aiyun2
```

若 SSH alias 实际通过 `HostKeyAlias` 记录，`ssh-keygen -R` 的参数必须用同一个 alias。
重新连接时人工确认的指纹应与控制台一致。

## CLI

安装完成后只使用以下入口：

```text
trojan-certman install
trojan-certman adopt
trojan-certman renew
trojan-certman status
trojan-certman deploy-cert CERT_FILE KEY_FILE
trojan-certman snapshot
trojan-certman upgrade <xray-version> <sha256>
trojan-certman cutover
trojan-certman rollback
```

- `install`：新建单凭据 Xray 节点并通过 Cloudflare DNS-01 签发证书；A/AAAA 不自动切换。
- `adopt`：读取旧节点结构并准备迁移；重复执行不得改写已经有效的配置。
- `renew`：正常运行 acme.sh 周期检查，不强制续签。
- `deploy-cert`：校验 SAN、有效期、cert/key 匹配和 Xray 配置，随后切换证书版本。
- `snapshot`：输出不含敏感信息的服务、网络队列和 TLS 状态。
- `upgrade`：只接受源码当前固定的 Xray 版本及其对应 SHA-256，不是任意版本升级入口。
- `cutover`：在验证 canary 后，事务化停止旧服务并让 Xray 接管 443；失败自动恢复。
- `rollback`：切换后恢复旧 Trojan 服务；日常 Xray 升级时恢复上一版核心、配置和证书。

证书使用版本目录和 `current` / `previous` 原子指针。证书切换后若 Xray 启动失败、
TLS 握手失败或线上指纹与磁盘不一致，`deploy-cert` 必须自动恢复旧证书。acme.sh
只触发一次受控部署，不额外配置第二次 reload 或 restart。

旧节点迁移首次执行 `cutover` 时还必须通过 root-only 文件提供 Cloudflare token：

```bash
sudo env CERTMAN_CF_TOKEN_INPUT_FILE=/root/secure-input/cloudflare-token \
  /usr/local/sbin/trojan-certman-v3 cutover
```

token 会安装为 `/etc/trojan-certman-v3/secrets/cloudflare-token`（`0600 root:root`），
不会进入命令行参数或日志。续签检查始终显式使用 `dns_cf`，不依赖旧证书保存的
HTTP-01/webroot 方法；未到续签时间时接受 acme.sh 的 skip 状态，不使用 `--force`。

## 旧节点 adopt/cutover 与回滚

旧 Trojan 节点不能使用 fresh `install` 原地覆盖，应走 `adopt`、canary、`cutover`。
生产切换不是安装脚本的隐式步骤。以下步骤都要在现场回读后执行；停止旧服务、占用
443、取消端口映射等写操作必须获得针对当次目标的明确授权。

1. 只读回读当前二进制、配置、证书、unit、监听端口和容器依赖。只为精确文件创建
   带时间戳备份，不读取、打印或复制密码正文到日志。
2. 先在 `127.0.0.1:18443` 启动固定版本 Xray canary。通过 SSH 端口转发和隔离的
   Clash 配置验证现有 Trojan 客户端；canary 不接管公网 443。
3. 进入短维护窗口后停止旧核心，将已验证的 Xray 切到 443。验证 TLS、代理出口、
   DNS、GCP `:50245` SSH 握手和未经修改的现有 Clash 配置。
4. 任一验证失败立即运行 `sudo trojan-certman rollback`，恢复旧核心和 443。成功后
   旧二进制、配置和数据库卷至少保留 7 天。
5. 确认 MySQL 没有其他消费者后，才可单独取消公网 `34384` 映射；不删除数据库卷。
   旧 `trojan-web` 永久禁用。
6. 清理旧核心、数据库卷或历史备份是独立破坏性操作，迁移流程不会自动执行。

回滚前后都应保存 `trojan-certman snapshot` 输出，并确认 443 的实际监听者、TLS
指纹和代理出口。不能用“systemd 显示 active”替代这些端到端检查。

## 容量与观测

安装会提供可回滚的 `somaxconn=4096` 和 `tcp_max_syn_backlog=4096` 配置，并回读
443 实际 backlog。若它仍固定为 128，应记录为核心实现限制，不继续盲调 sysctl。

systemd timer 每分钟向 journald 写一行无敏感信息的快照，包括服务状态、重启次数、
FD 使用率、443 listen queue、conntrack、ListenDrops/Overflows、Syncookies、TLS
握手耗时、证书到期时间和 SHA-256 指纹。快照缺字段应标记为不可用，不能伪装成 0。

## 验收门槛

CI 在 Ubuntu 22.04 和 24.04 上运行 ShellCheck、Bats、`systemd-analyze verify` 和
Xray 配置检查。哈希不匹配、cert/key 不匹配、SAN 错误、服务启动失败、线上指纹
不符和升级中断都必须保持或恢复上一可用版本；CI 和日志不得出现 Trojan 密码、
Cloudflare token 或 SMTP 密钥。

公网最终只保留预期 SSH 与 443；80、34384 和 `/auth/*` 均不可达。隔离 Clash
配置需完成至少 20 次 GCP SSH 重连和 60 分钟 keepalive soak；切换后观察 24 小时，
无异常重启或与客户端故障同步的队列丢弃增量，才算迁移验收完成。

单节点仍无法抵抗跨境路由或云主机整体故障。v3 提高的是节点自身安全、容量、
可恢复性和可诊断性，不代表消除了线路单点。

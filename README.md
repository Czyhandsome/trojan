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
- Trojan 密码和 Cloudflare token 不得进入仓库、命令行参数或日志；通过 root 可读输入文件读取。
- Xray 以专用 `xray` 用户运行，只保留绑定 443 所需能力，并由 systemd 应用
  `NoNewPrivileges`、只读系统目录、私有临时目录和内核保护。
- Xray 默认拒绝经代理访问回环、RFC1918、link-local、CGNAT（含云 metadata）和
  IPv6 本地地址；个人凭据泄漏不应顺带暴露节点自身或云内网。

固定版本和 SHA-256 是安装、升级的硬门槛。仓库不提供 `latest`、短链、
管道执行下载内容或 Docker 发布链路。下载内容先进入 staging，版本和 SHA-256
匹配后才允许原子切换。当前脚本固定 Xray `v26.3.27` 和 acme.sh `3.1.4`；
发布新版本时必须在代码审查中同时更新版本、架构哈希和故障注入用例。

## CLI

从已校验的版本化 release 解包后，在仓库目录执行新装；不要直接执行网络响应：

```bash
sudo env \
  CERT_DOMAIN=trojan.example.com \
  CERTMAN_PASSWORD_INPUT_FILE=/root/secure-input/trojan-password \
  CERTMAN_CF_TOKEN_INPUT_FILE=/root/secure-input/cloudflare-token \
  ./install-with-certman.sh install
```

`install` 使用固定版本 acme.sh 和 Cloudflare DNS-01 签发证书，只创建临时 TXT 记录；
不会修改域名的 A/AAAA 记录。Cloudflare token 应限定到目标 zone 的 `Zone:Read` 与
`DNS:Edit`。生产 A/AAAA 切换仍是独立人工操作。

安装完成后只使用以下入口：

```text
trojan-certman install
trojan-certman adopt
trojan-certman renew
trojan-certman status
trojan-certman deploy-cert
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
- `upgrade`：只接受显式 Xray 版本和对应 SHA-256，校验后再切换。
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

## Aiyun 迁移与回滚

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

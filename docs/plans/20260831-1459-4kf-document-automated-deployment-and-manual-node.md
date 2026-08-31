# Aiyun 双节点 Xray 本机自动化恢复方案

## Summary

- 先完善自动化，再依次部署 Aiyun2、Aiyun1；每次只操作一台，首错停线。
- 保持现有远端 `install-with-certman.sh` 事务安装器不变，在 `trojan` 仓库新增专用本机 CLI `bin/trojan-node`。
- 使用 `personal` creds profile 保存并同步 Cloudflare 管理 token、两台独立 Trojan 密码和节点 DNS token。
- 所有旧节点凭据全部轮换；管理 token 不上传服务器，节点 token 限制为精确 zone、DNS 权限及 VPS `/32` 来源 IP。
- 本轮只用隔离 Mihomo 验收，不修改日常 Clash Verge 配置。因此部署完成后，现有 Clash 节点仍需后续专项更新密码。

## Interfaces and Repository Changes

### `creds` 最小公共接口扩展

在 `software-engineering-skills` 建立独立 T2 Task，新增：

```text
creds set generic NAME FIELD --profile PROFILE --stdin
creds show generic NAME --fields FIELD... --profile PROFILE --format json
```

- `--stdin` 与现有交互输入兼容并互斥；secret 只经 stdin 传入已签名 Keychain helper，不进入 argv、环境变量、临时文件或日志。
- 空输入、NUL、后端错误均 fail closed；输出只显示更新路径，不显示值。
- JSON show 只返回 `PRESENT/MISSING/ERROR` 和字段名，不返回值、service、account 或 helper 原始错误。
- 保持现有命令默认行为不变，增加 focused tests、完整 creds tests、repo validator 和 installer dry-run。
- 合并并从 canonical `master` 重装后，Trojan 自动化才能进入 live 阶段。

### Trojan 本机 CLI

在 `czyhandsome-bundles` 建立独立 T2 Task，只修改 `trojan` child repo，新增 Python 标准库实现的 `bin/trojan-node`：

```text
trojan-node credentials status|rotate --node NODE
trojan-node cloudflare zones
trojan-node cloudflare dns list|ensure --node NODE
trojan-node cloudflare token list|rotate-dns|revoke --node NODE
trojan-node host check --node NODE
trojan-node preflight --node NODE
trojan-node deploy --node NODE [--rotate-secrets] --apply
trojan-node verify --node NODE
```

- 不发展为通用 Cloudflare 平台工具；token 创建只允许本项目固定的 DNS-01 权限模板。
- `deploy` 无 `--apply` 时只输出脱敏计划；`--apply` 显示精确节点、DNS、token、Git SHA 和远端动作，并要求输入节点名确认，不提供首版 `--yes`。
- 新增仓库跟踪的非 secret JSON 清单，包含：
  - `aiyun → 23.95.133.118 / introspect.czyhandsome.ink`
  - `aiyun2 → 69.33.3.215 / introspect2.czyhandsome.ink`
  - SSH 用户、端口、Cloudflare zone、creds placeholder、token 名及控制台确认后的 ED25519 指纹。
- 网络扫描得到的候选指纹为：
  - Aiyun1：`SHA256:OhN1O7zXZSAoRQAr0oyTQRanB3WGCfbhWjdyaNcq/rs`
  - Aiyun2：`SHA256:7Qj/oiITURsUCUZFq6VZlbaC4MleC0a02Pm2MSj+Gg4`
- 上述候选必须分别在 BreaCloud Web Console 用 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` 核验后才能写入清单；不一致立即停止。
- CLI 使用临时专用 `known_hosts`，严格匹配清单指纹，不删除用户现有记录，不使用 `StrictHostKeyChecking=no`。

## Credential and Cloudflare Lifecycle

- 用户只需在 Cloudflare UI 创建一次 180 天管理 token，权限为：
  - User / API Tokens Read、Write
  - 精确 `czyhandsome.ink` zone 的 Zone Read、DNS Write
  - 不设置来源 IP 限制，以支持不同 Mac 和网络
- 管理 token 通过交互式 `creds set` 保存到：

```text
personal/generic/cloudflare-czyhandsome/token-manager
```

- CLI 在到期前 30 天告警；不自动延长或暗中替换管理 token。Cloudflare 官方支持用 `API Tokens Write` 创建用户 token，并支持精确 zone policy 与 `request.ip` 条件。[Cloudflare token API](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/)
- 两个节点分别保存：

```text
personal/generic/trojan-aiyun/password
personal/generic/trojan-aiyun/cloudflare-token
personal/generic/trojan-aiyun2/password
personal/generic/trojan-aiyun2/cloudflare-token
```

- `--rotate-secrets` 为节点生成独立高熵 Trojan 密码，并创建无到期时间的 DNS-01 token；节点 token 仅具备精确 zone 的 Zone Read、DNS Write，并限制来源为对应 VPS `/32`。
- 创建 token 后先经 `creds set --stdin` 落入 Keychain；写入失败则立即撤销刚创建的 token。成功后再撤销所有清单中精确匹配的旧节点 token，不碰其他 token。
- DNS 自动化仅允许：
  - 查询 zone 和记录；
  - 创建缺失的 DNS-only A 记录；
  - 更新唯一同名 A 的 IP、TTL Auto 和 `proxied=false`。
- 遇到多 A、AAAA、CNAME 或 zone 不唯一时拒绝执行，不自动删除记录。Cloudflare DNS 创建/更新使用官方 DNS Write API。[Cloudflare DNS API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)

## Deployment and Acceptance

1. 人工前置门槛：
   - 在控制台核验两台最终 ED25519 指纹。
   - 为当前 Mac 的 SSH 公钥建立 key-only root 登录；SSH 私钥不进入 creds。
   - 管理 token 已写入 `personal` profile，CLI 只检查 masked presence。
2. CLI 先执行只读 preflight：
   - 指纹、BatchMode SSH、Ubuntu 24.04、架构、443 空闲、无 Xray/certman 残留。
   - Cloudflare zone 唯一、A 记录正确、无 AAAA/CNAME 冲突。
   - 本地仓库干净，安装归档对应精确 Git commit。
3. 确认后：
   - 创建或轮换节点凭据及 token。
   - 从精确 commit 构建归档和 SHA-256，传到远端 staging 并回读校验。
   - secret 仅以内存 tar/SSH stdin 写入远端 `/run/trojan-certman-input`，权限 `0600 root:root`；无论成功失败都删除输入副本。
   - 执行现有 `install-with-certman.sh install`；远端安装失败依赖其事务回滚，CLI 不自行删除托管状态。
4. 部署顺序固定：
   - 先 Aiyun2；完整验收并确认后才单独授权 Aiyun1。
   - 两台不得用一个命令批量部署。
5. 每台验收：
   - Xray active/enabled、`NRestarts=0`、443 owner 为 Xray、queue 4096。
   - 配置权限 `0640 root:xray`，renew/snapshot timers active。
   - TLS SAN、有效期、指纹及线上握手正确。
   - 80、18443、34384 未监听。
   - 隔离 Mihomo 临时配置严格校验证书，代理出口为对应 VPS。
   - 20 次 GCP `:50245` SSH 重连和 60 分钟 keepalive 无代理层失败。
   - 重跑同一部署命令不得续签、重启或改变 PID、配置哈希和证书指纹。
6. 两台恢复后更新现有 `aiyun` 小时巡检的 PID、证书和网络计数器基线，继续只读观察 24 小时，不自动修复。

## Tests and Release Gates

- Trojan CLI 单测覆盖 Cloudflare API 分页/错误、权限组动态解析、DNS no-op/create/update/conflict、token 创建/落库/撤销补偿、host-key mismatch、SSH 失败和 secret 脱敏。
- 使用 fake `creds`、fake SSH 和本地 HTTP server；所有 argv、stdout、stderr、测试快照和 CI artifact 扫描不得出现测试 secret。
- 保留现有 Ubuntu 22.04/24.04 Bats、ShellCheck、systemd verify、Xray config 与固定 release 哈希检查。
- `creds` 依赖先合并、安装和验证；Trojan CLI 再以精确 PR commit 部署 Aiyun2、Aiyun1。
- 两台完成 live 验收和 24 小时观察后，重新跑完整 CI、安全 diff 和 secret scan，再取得独立合并授权；本轮不发布 `v3.0.0`、不修改 Clash、不恢复旧 Trojan/Web/MariaDB 数据。

## Locked Assumptions

- 两台均为 clean Ubuntu 24.04 fresh install，旧服务器数据视为不可信且不恢复。
- `/etc/hosts` 当前映射正确，公网 A 记录当前也分别指向对应 IP；执行时仍重新验证。
- 节点密码和节点 Cloudflare token全部轮换且互不复用。
- `personal` Keychain profile 为权威后端；iCloud 同步是当前 Mac 可见状态，不是立即完成或服务端完整性的证明。
- 管理 token 永不上传 VPS；节点 token长期有效但受 exact-zone、最低权限和来源 IP 限制。
- 当前日常 Clash 在密码轮换后不会自动恢复，本轮只证明服务端和隔离客户端链路可用。

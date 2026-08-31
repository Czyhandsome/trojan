# Trojan 个人节点（Xray）

这是面向个人 Xray/Trojan 节点的部署与运维仓库。服务端唯一管理入口是
`/usr/local/sbin/trojan-certman`；macOS 上用 `bin/trojan-node` 注册、部署和验收节点。
每条命令只处理一个节点。

## 五分钟 Quick Start

先手工完成 SSH key 分发和首次 host-key 信任。CLI 不运行 `ssh-copy-id`、
`ssh-keyscan`，也不会自动接受 host key：

```bash
ssh-copy-id aiyun3
ssh aiyun3 true

bin/trojan-node node add aiyun3 \
  --ssh-target aiyun3 \
  --domain introspect3.czyhandsome.ink

bin/trojan-node node show aiyun3
bin/trojan-node deploy --node aiyun3 --rotate-secrets
bin/trojan-node deploy --node aiyun3 --rotate-secrets --apply
```

`node add` 会先用 `ssh -G` 解析 alias，再检查唯一 ED25519 known-host 与
BatchMode 登录。它打印不含 secret 的注册计划，并要求输入完整节点名；确认后才把节点
原子写入 `~/.config/trojan-node/nodes.json`，权限为 `0600`。

部署前还需满足：

- `personal` Keychain profile 中存在 Cloudflare manager token；
- 当前 worktree 干净且对应精确 Git commit；
- Mihomo 为 `v1.19.29` 或更新版本；
- `~/.ssh/known_hosts` 已包含 GCP `[34.31.209.55]:50245` 的 ED25519 key；
- VPS 为受支持的 Ubuntu，SSH 已可 BatchMode 登录。

如果 SSH alias 的 effective hostname 不是公网 IPv4（例如使用域名或跳板），必须显式给出
节点公网出口 IP：

```bash
bin/trojan-node node add aiyun3 \
  --ssh-target root@node.example.net \
  --public-ip 203.0.113.30 \
  --domain introspect3.czyhandsome.ink
```

端口、`IdentityFile`、`ProxyJump` 等 SSH 细节写入 `~/.ssh/config`，不要拼到
`--ssh-target`。该参数只接受一个 OpenSSH destination；空白、前导选项和 shell 命令会被拒绝。

## 节点清单

```text
trojan-node node add NODE --ssh-target SSH_TARGET --domain DOMAIN \
  [--public-ip IPV4] [--zone ZONE]
trojan-node node list
trojan-node node show NODE
```

配置来源按以下顺序加载：

1. `~/.config/trojan-node/nodes.json`
2. 本地文件不存在时，兼容读取仓库 `config/nodes.json`

第一次 `node add` 会复制 legacy 节点到本地 inventory，再追加新节点；不会修改仓库文件。
配置保持 `schemaVersion: 1`，不含密码、token、SSH 私钥或私钥路径。可解析示例见
[`config/nodes.example.json`](config/nodes.example.json)。

| 字段 | 谁提供 | 用途与安全意义 |
| --- | --- | --- |
| node ID | 用户 | CLI 选择器；仅小写字母、数字和连字符，必须唯一 |
| `sshTarget` | 用户 | 单个 SSH alias 或 destination；复杂 SSH 参数放 `~/.ssh/config` |
| `domain` | 用户 | Trojan TLS 域名；必须属于目标 zone 且全局唯一 |
| `zone` | 默认/用户 | 默认 `czyhandsome.ink`；其他 zone 用 `--zone` 覆盖 |
| `address` | CLI 解析/用户 | 预期公网 IPv4；域名或跳板场景由 `--public-ip` 明确给出 |
| `sshUser` / `sshPort` | `ssh -G` | 注册时解析并固化，用于后续严格 SSH |
| `sshHostKey` | 已有 known_hosts | 固定 ED25519 trust alias；缺失或重复都 fail closed |
| `credential` | CLI 推导 | `trojan-NODE`；只标识 Keychain 记录，不包含值 |
| `cloudflareTokenName` | CLI 推导 | `trojan-NODE-dns01`；精确匹配 token 生命周期 |
| `sourceCidr` | CLI 推导 | `address/32`；限制节点 DNS token 的来源 IP |

节点 ID、domain、address、credential、Cloudflare token 名和 source CIDR 均要求唯一。
损坏或冲突的本地配置不会静默回退到仓库配置。

## 部署与验收

常用命令：

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

`deploy` 默认只在 stdout 打印最终脱敏 JSON 计划；`--apply` 仍会先打印相同计划并要求
输入完整节点名。人类可读进度全部写入 stderr，便于把 stdout 稳定交给脚本：

```text
[1/9] manifest       ok node=aiyun3
[2/9] cloudflare     ok dns_action=noop
[3/9] staging        ok commit=... archive_sha256=...
[4/9] ssh-preflight  ok remote_state=clean
[5/9] credentials    ok rotated=true
[6/9] install-1      running elapsed=30s
[7/9] install-2      ok
[8/9] server-verify  ok pid=... tls=ok
[9/9] client-verify  running reconnect=20/20
```

长操作每 30 秒输出一次只含阶段和 elapsed 的 heartbeat。20 次 reconnect 会逐次显示进度；
60 分钟 keepalive 每分钟显示 heartbeat。SSH、installer、Cloudflare 和 `creds` 原始输出不会
直接流式打印。Mihomo 使用内核动态分配的本地空闲端口，不修改 Clash Verge，也不固定占用
`17890`。

成功判据包括：

1. DNS 计划唯一且满足 DNS-only A 记录约束；
2. 精确 commit 构建的源码归档完成 SHA-256 回读；
3. installer 连续执行两次，第二次保持 managed identity 不变；
4. Xray、443、证书 SAN/指纹和线上 TLS 验证通过；
5. 隔离 Mihomo 出口 IP 正确；
6. GCP `:50245` 完成 20 次 reconnect 和 60 分钟 keepalive。

## 失败与安全恢复

部署失败会在 stderr 给出失败阶段及已经发生的副作用，例如：

```text
FAILED stage=client-acceptance dnsApplied=true credentialsRotated=true \
serverInstalled=true provenanceWritten=true clientVerified=false \
safeResume=trojan-node verify --node aiyun3
```

如果服务端安装与 provenance 已完成、只剩客户端验收失败，唯一安全恢复入口是：

```bash
bin/trojan-node verify --node aiyun3
```

此时不要再次使用 `--rotate-secrets`。若失败发生得更早，先按 stderr 中的副作用字段判断
DNS、credential rotation、server install 和 provenance 是否已经发生，不要靠盲目重跑猜状态。

`credentials rotate` 与 `cloudflare token rotate-dns` 只改变 Cloudflare/Keychain，不会把
新 secret 自动安装到已经运行的 VPS，因此不是线上节点的独立换密命令。

## Secret 与信任边界

- manager token 只进入本机进程；节点 password/token 按目标节点隔离。
- 每节点 `creds` placeholder 在运行时生成到临时目录，权限 `0600`，用完删除；仓库只保留
  全局 manager placeholder。
- secret 写回 Keychain 只走 stdin，不进入 argv、stdout、stderr 或清单。
- SSH 只复用用户已经确认的 ED25519 known-host，复制到临时 `0600` 文件；禁止
  `StrictHostKeyChecking=no` 和 `ssh-keyscan`。
- 新 token 先成功写入 Keychain，随后才撤销同名旧 token；写入失败会撤销刚创建的 token。

## 服务端支持边界

- Ubuntu 22.04 / 24.04，systemd，`x86_64` / `aarch64`。
- 单域名、单节点、单个 Trojan 凭据；不提供 Web 面板、多用户、数据库或 Docker 链路。
- Xray 配置固定在 `/etc/xray/config.json`，权限 `0640 root:xray`。
- Xray 以专用用户运行，仅保留绑定 443 所需能力；默认阻止代理访问本机、私网、
  link-local、CGNAT、云 metadata 和 IPv6 本地地址。
- Xray 和 acme.sh 版本及 SHA-256 固定在源码中，不使用 `latest` 或管道执行下载内容。

Xray `v26.3.27` 会对无 Flow 的 Trojan 输出 deprecated 警告。当前固定该版本是为了避免
上游变化造成隐式破坏，不是长期协议承诺；升级必须先跑客户端 canary。

## 机器操作手册

从零手动安装、服务/端口/证书检查、URI 与 Mihomo YAML 生成、受控重启、证书续签、
常见故障分层以及重装后的 SSH host-key 处理，统一见
[`docs/runbooks/node-operations.md`](docs/runbooks/node-operations.md)。README 只保留日常入口。

## 服务端 CLI

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

旧 Trojan 节点不能使用 fresh `install` 原地覆盖，应走 `adopt`、canary、`cutover`。
生产切换、停止旧服务和接管 443 必须单独授权；失败运行 `trojan-certman rollback`。
证书使用版本目录和 `current` / `previous` 原子指针，部署失败自动恢复旧证书。

## 容量、观测与验收门槛

安装提供可回滚的 `somaxconn=4096` 和 `tcp_max_syn_backlog=4096`，并回读 443 backlog。
systemd timer 每分钟向 journald 写一行无 secret 快照，包括服务、重启次数、FD、队列、
conntrack、ListenDrops/Overflows、Syncookies、TLS 延迟、证书期限和指纹。

CI 在 Ubuntu 22.04/24.04 上运行 ShellCheck、Bats、systemd verify 和 Xray 配置检查。
哈希、cert/key、SAN、服务启动、线上指纹或升级中断任一失败，都必须保持或恢复上一可用版本。
公网最终只保留预期 SSH 与 443；80、34384 和 `/auth/*` 均不可达。

单节点仍无法抵抗跨境路由或云主机整体故障。这里提升的是节点安全、可恢复性和可诊断性，
不是消除线路单点。

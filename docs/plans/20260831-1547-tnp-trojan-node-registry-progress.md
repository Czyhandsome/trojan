# Trojan 节点注册与可观察部署优化计划

## Summary

- 基于已合并的 `fork/master@baa0127` 创建新的个人 T2 Task、独立 worktree 和分支；不复用已结束的双节点恢复 Task。
- 将 `trojan-node` 从“两台硬编码机器”改成配置驱动的节点工具：用户只需准备 SSH alias、节点名和域名，即可注册并部署。
- 为所有长操作增加脱敏阶段进度、定时 heartbeat、失败阶段和安全恢复提示；保持最终 JSON 输出及 secret 边界不变。
- 不引入服务端控制面、数据库、通用 Cloudflare 框架或后台 daemon。

## Public Interfaces and Configuration

新增命令：

```bash
trojan-node node add NODE \
  --ssh-target SSH_TARGET \
  --domain DOMAIN \
  [--public-ip IPV4] \
  [--zone ZONE]

trojan-node node list
trojan-node node show NODE
```

推荐操作流：

```bash
ssh-copy-id aiyun3
ssh aiyun3 true

trojan-node node add aiyun3 \
  --ssh-target aiyun3 \
  --domain introspect3.czyhandsome.ink

trojan-node deploy --node aiyun3 --rotate-secrets --apply
```

- `--ssh-target` 只接受单个 OpenSSH destination，如 `aiyun3` 或 `root@1.2.3.4`；拒绝空白、前导选项和任意 shell 命令。端口、IdentityFile、ProxyJump 等放在 `~/.ssh/config`。
- `node add` 通过 `ssh -G` 解析 user、hostname、port 和 host-key alias，并执行严格 ED25519 known-host 与 BatchMode 检查；不运行 `ssh-copy-id`、`ssh-keyscan`，不自动接受 host key。
- effective hostname 必须是公网 IPv4；若 SSH alias 使用域名或跳板，要求显式 `--public-ip`，并在注册和部署时回读一致性。
- 节点 ID、domain、address、credential 名和 Cloudflare token 名必须唯一；节点 ID 限制为小写字母、数字和连字符。
- credential 名、DNS token 名和 `/32` source CIDR 由节点 ID/IP 自动生成；真实值仍只存在 Keychain/Cloudflare。
- `node add` 显示解析后的非敏感计划并要求输入完整节点名确认，然后原子写入配置。

配置来源顺序：

1. `~/.config/trojan-node/nodes.json`
2. 本地配置不存在时，读取仓库现有 `config/nodes.json` 作为兼容 fallback
3. 首次 `node add` 时复制 legacy 节点到本地配置，再追加新节点；不修改仓库文件

本地配置保持 `schemaVersion: 1` 和现有完整字段，新增可选 `sshTarget`；legacy 节点默认使用 `knownHostsAlias` 作为 target。文件权限固定为 `0600`，不含 secret。

移除 `NODE_NAMES` 及“必须恰好包含 aiyun/aiyun2”的限制。`--node` 在加载清单后校验，未知节点错误须列出可用 ID。

每节点 `config/credentials-*.json` 改为运行时生成临时 `0600` placeholder 文件，用完删除；保留全局 manager placeholder。新增节点不再要求新增仓库文件。

## Deployment Observability and Failure Handling

所有人类进度写入 `stderr`，最终 plan/result JSON 继续独占 `stdout`：

```text
[1/9] manifest       ok node=aiyun3
[2/9] ssh            ok root@1.2.3.4:22
[3/9] cloudflare     ok dns_action=noop
[4/9] credentials    ok password=PRESENT token=PRESENT
[5/9] staging        ok commit=... sha256=...
[6/9] install #1     running elapsed=30s
[6/9] install #1     ok
[7/9] install #2     ok idempotent=true
[8/9] server verify  ok pid=... tls=ok
[9/9] client verify  reconnect=20/20
[9/9] client verify  keepalive=17m/60m
```

- 每个外部阶段输出 start/ok；超过 30 秒的 subprocess 每 30 秒输出脱敏 heartbeat。
- 20 次 reconnect 逐次或按固定进度输出；60 分钟 soak 每分钟输出 elapsed/remaining。
- 不流式打印未经筛选的 SSH、installer、Cloudflare 或 creds 原始输出；失败只输出脱敏摘要。
- deploy 内部记录当前阶段及已发生副作用。失败时明确报告 DNS、credential rotation、server install、provenance 和 client acceptance 状态，并给出唯一安全恢复命令。
- 若服务端和 provenance 已完成、客户端验收失败，提示 `trojan-node verify --node NODE`；不得建议再次 `--rotate-secrets`。
- 在任何 Cloudflare/VPS 写入前检查本地客户端版本、GCP SSH known-host、worktree cleanliness 和 credential availability。
- Mihomo mixed port 改为动态空闲端口，不再固定 `17890`；并发进程不得因本地端口碰撞导致远端安装完成后才失败。
- 保持一条命令只处理一个节点；本轮不新增批量部署。

## Documentation

重组 README：

1. 五分钟 Quick Start
2. `node add/list/show`
3. 用户输入字段与 CLI 推导字段表
4. deploy/verify 阶段、耗时和成功判据
5. 失败后的副作用说明与恢复入口
6. 指向详细机器操作手册

配置表明确说明 node ID、sshTarget、domain、zone、expected address、credential/token 名及安全意义。

将现有服务检查、证书、URI/YAML、重装 host key 和常见故障内容移到 `docs/runbooks/node-operations.md`；README 保留摘要和链接，避免继续膨胀。仓库中的 example config 与 README 示例必须可由测试解析。

## Tests and Acceptance

- Manifest：任意节点数量、legacy fallback、本地配置优先、首次复制、权限、原子写入、损坏配置 fail closed。
- Registration：SSH alias/direct target、非默认 user/port、显式 public IP、missing/ambiguous host key、BatchMode 失败、重复字段、非法 ID/命令字符串。
- Credentials：动态 placeholder 内容、权限和清理；argv/stdout/stderr/测试快照不得出现 secret。
- Progress：阶段顺序、30 秒 heartbeat、reconnect/soak 进度、stdout JSON 稳定、失败副作用和 safe-resume 提示。
- Acceptance：动态 Mihomo 端口、端口冲突重试、server-complete/client-failed 恢复路径。
- 回归：现有 Python CLI 测试、52 个 Bats、ShellCheck、bash parse、Ruff、Mypy、`git diff --check` 和 secret-surface scan 全部通过。
- 兼容：升级后现有 `aiyun`、`aiyun2` 无需人工迁移即可执行 `host check/preflight/verify`。
- 新增节点验收：使用临时配置和 fake SSH/Cloudflare 完成离线 E2E；真实节点注册、Cloudflare/VPS 写入和部署必须另行获得精确 live 授权。

## Assumptions

- 所有节点继续使用同一个 `personal` creds profile 和默认 `czyhandsome.ink` zone；不同 zone 通过节点级 `--zone` 覆盖。
- 所有节点继续使用现有 GCP `:50245`、20 次 reconnect 和 60 分钟 keepalive 验收合同；本轮不把验收目标泛化。
- 节点配置是非敏感本机 inventory，不要求 Git commit；源码归档仍必须来自干净、精确 master commit。
- SSH key 分发和 host-key 首次信任始终由用户手工完成。

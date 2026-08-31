# Trojan 节点机器操作手册

本文收纳低频、偏机器侧的操作。日常注册和部署入口见仓库根目录 `README.md`。
所有示例中的域名、IP 和 SSH alias 都必须替换；涉及停止服务、接管 443、改 DNS 或重建
host key 的操作应先回读现场，再获得精确目标授权。

## Ubuntu fresh install

该流程只适用于没有 Xray、certman、相关 systemd unit、443 监听和托管残留的 Ubuntu
22.04/24.04。旧节点不能覆盖安装，应走 `adopt` / `cutover`。

先在 Cloudflare 创建 DNS-only A 记录，并创建只允许目标 zone 的 Zone Read / DNS Write
token。Trojan password 与 token 必须分别放入 root-only 文件，不能进入 argv、shell history
或仓库。

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

继续前必须确认系统与架构受支持、DNS 只指向目标 IPv4、443 未被占用，并且云防火墙允许
预期 SSH 端口和 TCP 443。不要为了本项目盲目启用或重置 UFW。

从受信任的精确 Git commit 获取完整源码并核对 worktree，不使用旧短链或管道执行下载：

```bash
git clone https://github.com/Czyhandsome/trojan.git
cd trojan
git status --short
git rev-parse HEAD
```

创建 root-only 输入目录和文件；输入真实值时关闭 shell tracing：

```bash
install -d -m 0700 /root/secure-input
install -m 0600 /dev/null /root/secure-input/trojan-password
install -m 0600 /dev/null /root/secure-input/cloudflare-token
```

随后用编辑器或不回显的交互方式写入值。安装命令只传文件路径：

```bash
sudo env \
  CERTMAN_DOMAIN=trojan.example.com \
  CERTMAN_PASSWORD_INPUT_FILE=/root/secure-input/trojan-password \
  CERTMAN_CF_TOKEN_INPUT_FILE=/root/secure-input/cloudflare-token \
  ./install-with-certman.sh install
```

安装成功并验收后，精确删除输入副本。不要删除仍由 certman 管理的 secret 文件。

## 服务、端口、证书和日志

在服务器执行：

```bash
sudo systemctl is-active xray
sudo systemctl is-enabled xray
sudo systemctl show xray -p MainPID -p NRestarts --no-pager
sudo ss -lntp 'sport = :443'
sudo stat -c '%a %U:%G %n' /etc/xray/config.json
sudo systemctl list-timers 'trojan-certman-*' --all --no-pager
sudo /usr/local/sbin/trojan-certman snapshot
sudo journalctl -u xray -n 100 --no-pager
```

从任意能访问公网的机器检查线上证书，不使用 `-k`：

```bash
DOMAIN=trojan.example.com
openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName -fingerprint -sha256
```

`systemctl active` 不是端到端成功证明。至少还要确认 443 实际 owner、证书 SAN 与指纹、
代理出口，以及客户端链路。

## 只把 Trojan password 放进剪贴板

以下命令让 secret 从服务器 stdout 直接进入 macOS `pbcopy`，终端不打印正文：

```bash
ssh aiyun 'sudo cat /etc/trojan-certman-v3/secrets/trojan-password' | pbcopy
```

执行前确认 SSH target 和远端文件是预期节点；执行后按剪贴板敏感信息处理。

## 生成 Trojan URI

URI 中的 password 必须 URL encode。用 stdin 传值，避免进入 argv：

```bash
DOMAIN=introspect.example.com
NODE_NAME=aiyun3
ssh aiyun3 'sudo cat /etc/trojan-certman-v3/secrets/trojan-password' \
  | python3 -c '
import sys, urllib.parse
password = sys.stdin.read().rstrip("\n")
domain = sys.argv[1]
name = sys.argv[2]
encoded_password = urllib.parse.quote(password, safe="")
print(f"trojan://{encoded_password}@{domain}:443?security=tls&sni={domain}#{urllib.parse.quote(name)}")
' "$DOMAIN" "$NODE_NAME" \
  | pbcopy
```

命令只把最终 URI 放进剪贴板，不应写入 shell history、日志或仓库。

## 生成最小 Mihomo YAML

先创建权限为 `0600` 的临时文件，再从 stdin 读取 password。下例不启用 TUN：

```bash
CONFIG_FILE="$(mktemp -t trojan-node.XXXXXX.yaml)"
chmod 0600 "$CONFIG_FILE"
DOMAIN=introspect.example.com
ADDRESS=203.0.113.10
NODE_NAME=aiyun3

ssh aiyun3 'sudo cat /etc/trojan-certman-v3/secrets/trojan-password' \
  | python3 -c '
import json, pathlib, sys
password = sys.stdin.read().rstrip("\n")
path = pathlib.Path(sys.argv[1])
address, domain, name = sys.argv[2:]
path.write_text(f"""mixed-port: 0
mode: rule
proxies:
  - name: {json.dumps(name)}
    type: trojan
    server: {json.dumps(address)}
    port: 443
    password: {json.dumps(password)}
    sni: {json.dumps(domain)}
    skip-cert-verify: false
    udp: true
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [{json.dumps(name)}]
rules:
  - MATCH,GLOBAL
""", encoding="utf-8")
' "$CONFIG_FILE" "$ADDRESS" "$DOMAIN" "$NODE_NAME"
```

测试完立即清理该临时配置；其中包含 secret。

## 改配置前检查与受控重启

不要直接修改 `/etc/xray/config.json` 后盲目 restart。先做精确备份和语法检查：

```bash
sudo cp -a /etc/xray/config.json "/etc/xray/config.json.$(date +%Y%m%d-%H%M%S).bak"
sudo /usr/local/bin/xray run -test -config /etc/xray/config.json
sudo systemctl restart xray
sudo systemctl is-active xray
sudo systemctl show xray -p MainPID -p NRestarts --no-pager
sudo ss -lntp 'sport = :443'
```

若启动或线上 TLS 失败，恢复刚才的精确备份并再次验证。不要用 `systemctl reset-failed`
掩盖根因。

## 证书续签与 timer

```bash
sudo /usr/local/sbin/trojan-certman status
sudo /usr/local/sbin/trojan-certman renew
sudo systemctl list-timers 'trojan-certman-*' --all --no-pager
sudo journalctl -u trojan-certman-renew.service -n 100 --no-pager
```

`renew` 是正常周期检查，不强制续签。证书切换必须同时通过 SAN、cert/key 匹配、Xray 启动
和线上指纹校验；失败由 certman 回滚到上一证书版本。

## 常见故障分层

先区分层级，不要把所有问题都归因于 Xray：

```bash
# Mac：DNS、TCP、TLS
dig +short introspect.example.com A
nc -vz introspect.example.com 443
openssl s_client -connect introspect.example.com:443 \
  -servername introspect.example.com </dev/null

# 服务器：服务、监听、队列、日志
sudo systemctl status xray --no-pager
sudo ss -lntp 'sport = :443'
sudo /usr/local/sbin/trojan-certman snapshot
sudo journalctl -u xray -n 100 --no-pager
```

- DNS 错：先修唯一 A 记录并等待传播。
- TCP 不通：检查云防火墙、安全组、路由和本机 firewall。
- TLS 错：核对 SNI、SAN、证书期限与线上/磁盘指纹。
- Trojan 认证错：核对客户端 password，不要把值打印到终端。
- 代理可用但 GCP SSH 失败：单独检查 GCP known-host、目标 `:50245` 与 SSH 层。

## 服务器重装后的 SSH host key

重装会改变 host key。不要先运行 `ssh-keygen -R` 再盲信新 key。先从云厂商控制台读取
服务器本机 ED25519 公钥指纹：

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

在独立可信通道核对后，才精确移除旧 alias 并人工建立新信任：

```bash
ssh-keygen -R aiyun3
ssh aiyun3 true
ssh-keygen -F aiyun3
```

`trojan-node node add` 与后续 SSH 都要求 alias 恰好存在一个 ED25519 条目；缺失、重复或
算法不符会停止，不会替用户作信任决定。

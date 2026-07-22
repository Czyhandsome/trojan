# Historical prompt — chg-20260722-0953-cgb

Source: verbatim user implementation request.

# 将自动续期、换机切流和邮件告警固化到 Czyhandsome/trojan

## Summary

- 第一版只做“运维安装层”：重写现有 `install-with-certman.sh`，不修改 Go 管理程序、不接手缺失 `web/templates` 的构建链。
- 保留上游 `install.sh`；新脚本固定使用 Jrohy v2.15.3，分别校验 amd64、arm64 的 SHA-256，避免静默下载变化。
- 新主机采用单命令引导式安装：初始化空 Trojan、签发 Cloudflare DNS-01 证书、安装自动续期与邮件告警，最后才切换 `introspect.czyhandsome.ink` 的 A 记录。
- 第一版不备份或迁移 MariaDB 用户数据。
- 不定期运行 `trojan tls`：该命令源码会使用 `--force` 强制签发并采用 standalone 验证，不适合作为周期任务。[Jrohy 实现](https://github.com/Jrohy/trojan/blob/master/trojan/install.go)

## Interfaces and Implementation

- 将 `install-with-certman.sh` 重写为自包含脚本，并安装为 `/usr/local/sbin/trojan-certman`，提供：
  - `install`：新主机引导式安装。
  - `adopt`：接管现有主机的续期和告警，不重装 Trojan、不切 DNS、不强制重签。
  - `status`：显示 DNS、磁盘/线上证书、服务、timer 和最近结果，不输出秘密。
  - `renew`：正常续期检查，禁止隐式 `--force`。
  - `test-email`：经确认后向 `caoziyu@hidream.ai` 发送测试邮件。
  - `dns-rollback`：恢复安装前保存的 A 记录。
  - `uninstall-automation`：只移除 certman 定时器、告警和配置，不删除 Trojan、证书或数据库。

- 新主机安装顺序固定为：
  1. 仅支持 Ubuntu 22.04/24.04、systemd、amd64/arm64 和公网 IPv4；其他环境直接失败。
  2. 静默读取 Cloudflare token 和 SMTP 密码；非秘密参数写入 `/etc/trojan-certman/config`，秘密文件为 root:root、`0600`，不得进入命令行、日志或 Git。
  3. 下载并校验上游 v2.15.3：amd64 `3acd0b...b98c`，arm64 `b8a8a4...4f59`。
  4. 使用仅限 `czyhandsome.ink` Zone 的 Cloudflare DNS Edit token 签发 DNS-01 证书；通过 `acme.sh --install-cert` 复制到稳定的 `/etc/trojan/tls/`，配置成功续期后重启 `trojan.service`。[acme.sh 官方安装证书约定](https://github.com/acmesh-official/acme.sh#3-install-the-certificate-to-apachenginx)
  5. 启动上游 Trojan 首次交互初始化；初始化完成后用原子 JSON 更新确保 `ssl.cert`、`ssl.key`、`ssl.sni` 指向受管路径。
  6. 配置 `msmtp`：`smtp.qiye.aliyun.com:465`、隐式 TLS、用户名和 From 均为 `caoziyu@hidream.ai`。阿里邮箱官方也指定 465 为 SSL 端口；密码使用三方客户端安全密码。[阿里邮箱 SMTP 配置](https://help.aliyun.com/document_detail/36576.html)
  7. 验证本机 443、证书 SAN、私钥匹配、服务状态和测试邮件；全部通过后才更新精确的 `introspect.czyhandsome.ink` A 记录，强制 `proxied=false`，等待 Cloudflare 权威 DNS 返回新 IP。
  8. 保存旧 A 记录用于显式回滚；不得修改同 Zone 的其他记录。

- 自动续期使用 `trojan-certman-renew.service` 与每日 timer，带随机延迟、`Persistent=true` 和进程锁：
  - 新机器的 DNS-01 续期不停止 80/443 服务。
  - `adopt` 当前 aiyun 时保留现有 standalone 证书，不立即强制重签；仅在证书进入 31 天窗口时临时停止 `trojan-web`，并通过 trap 保证失败后也恢复。
  - 续期后检查磁盘证书、线上证书指纹、至少 14 天有效期，以及 `trojan`/`trojan-web` 状态；证书变化后重启真正持有 443 的 `trojan.service`。
  - 失败触发邮件；持续失败每日最多一封，恢复后发送一次恢复通知。邮件只包含主机、域名、证书期限和失败阶段，不附可能含敏感信息的完整 ACME 日志。

## Repository and Test Changes

- 修改 `install-with-certman.sh`、README 和新增 shell CI/Bats 测试；保持上游 Go 文件与原 `install.sh` 不变，减少未来同步冲突。
- CI 执行 `bash -n`、ShellCheck 和 mocked Bats，覆盖：
  - 架构选择及固定 checksum。
  - 首装、重复执行和 `adopt` 幂等性。
  - DNS 记录不存在、重复、API 失败、权威解析超时及 rollback。
  - ACME 未到期、成功续期、失败续期，以及 standalone 模式恢复 80 端口服务。
  - 证书 SAN、期限、密钥匹配、磁盘/线上指纹不一致。
  - SMTP 465/TLS 配置、From 与用户名一致、密码文件权限和日志脱敏。
  - `uninstall-automation` 不触碰 Trojan、MariaDB 和证书。
- aiyun 验收使用 `adopt`：
  - 不改变当前 DNS，不重装服务，不强制签发新证书。
  - 当前证书应继续保持线上/磁盘指纹一致，2026-10-19 到期。
  - 手动运行一次 `renew` 应因未到期而安全跳过；timer 可见，邮件测试到达指定邮箱。
- 真正换机时才验收完整 `install`：本机服务和证书先通过，再切 Cloudflare A 记录，最后从外部确认新 IP 上的 443 证书。

## Assumptions and Boundaries

- `czyhandsome.ink` 继续由 Cloudflare 权威 DNS 托管；第一版只管理 `introspect.czyhandsome.ink` 的单个 IPv4 A 记录，不创建 AAAA。
- 当前 fork 没有 Release，源码也缺少 Web 模板，故不发布 fork 自有 Go 二进制。
- 第一版不迁移用户、配额、数据库、Web 管理状态，也不配置异地备份。
- 上游 v2.15.3 发布于 2023 年；固定版本解决的是可重复安装，不代表该老旧代理栈已完成安全现代化。
- SMTP 密码和 Cloudflare token 由你在目标主机终端静默输入；实现和测试中不读取 Symphony/Infisical 的现有秘密。

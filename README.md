# trojan
![](https://img.shields.io/github/v/release/Jrohy/trojan.svg) 
![](https://img.shields.io/docker/pulls/jrohy/trojan.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jrohy/trojan)](https://goreportcard.com/report/github.com/Jrohy/trojan)
[![Downloads](https://img.shields.io/github/downloads/Jrohy/trojan/total.svg)](https://img.shields.io/github/downloads/Jrohy/trojan/total.svg)
[![License](https://img.shields.io/badge/license-GPL%20V3-blue.svg?longCache=true)](https://www.gnu.org/licenses/gpl-3.0.en.html)


trojan多用户管理部署程序

## Czyhandsome fork：证书自动续期与换机安装

本 fork 在不修改上游 Go 管理程序的前提下，提供一个独立的运维安装层：

- 固定并校验 Jrohy `v2.15.3` 的 amd64/arm64 管理程序；
- 新主机使用 Cloudflare DNS-01 申请证书，本地验证通过后才切换指定 A 记录；
- 通过 systemd 每日检查续期，并验证磁盘证书、线上证书和服务状态；
- 续期失败通过阿里企业邮箱 SMTP 发送限频告警；
- 可接管已有安装，不重装 Trojan、不修改 DNS、不强制重新签发证书。

> 这解决的是可重复安装和证书运维；固定在 2023 年发布的 `v2.15.3`，不等于完成了代理栈的安全现代化。

### 支持范围

- Ubuntu 22.04 / 24.04，systemd；
- `x86_64` / `aarch64`；
- 一个公网 IPv4 A 记录，Cloudflare DNS-only；
- 首次 Trojan、MariaDB 和首用户初始化仍使用上游的交互式流程；
- 不迁移或备份旧主机的用户数据库。

### 新主机引导式安装

建议先下载并查看脚本，再以 root 执行：

```bash
curl -fsSLo /tmp/install-with-certman.sh \
  https://raw.githubusercontent.com/Czyhandsome/trojan/master/install-with-certman.sh
less /tmp/install-with-certman.sh
sudo bash /tmp/install-with-certman.sh install
```

脚本会静默读取 Cloudflare token 和 SMTP 三方客户端安全密码。秘密只写入 root 可读的
`/etc/trojan-certman/secrets/`，不会写入仓库或命令参数。Cloudflare token 应仅授权
`czyhandsome.ink` 的 `Zone:Read` 与 `DNS:Edit`。

安装顺序是：签发 DNS-01 证书 → 完成上游交互初始化 → 验证本机 443 和测试邮件 → 最后更新
`introspect.czyhandsome.ink`。切流前的 A 记录会保存下来，可显式回滚。

### 接管现有主机

```bash
sudo bash /tmp/install-with-certman.sh adopt
sudo trojan-certman status
sudo trojan-certman renew
```

`adopt` 从现有 `/usr/local/etc/trojan/config.json` 读取域名和证书路径，只安装 timer 与告警。
若现有证书是 standalone 模式，仅在进入 31 天续期窗口后临时停止 80 端口上的
`trojan-web`；无论续期成功或失败都会恢复该服务。

### 运维命令

```text
trojan-certman status
trojan-certman renew
trojan-certman test-email
trojan-certman dns-rollback
trojan-certman uninstall-automation
```

`renew` 永远不会隐式添加 `--force`。`uninstall-automation` 只删除 certman 的 timer、告警、
配置和凭据，不删除 Trojan、MariaDB 或证书。

## 功能
- 在线web页面和命令行两种方式管理trojan多用户
- 启动 / 停止 / 重启 trojan 服务端
- 支持流量统计和流量限制
- 命令行模式管理, 支持命令补全
- 集成acme.sh证书申请
- 生成客户端配置文件
- 在线实时查看trojan日志
- 在线trojan和trojan-go随时切换
- 支持trojan://分享链接和二维码分享(仅限web页面)
- 支持转化为clash订阅地址并导入到[clash_for_windows](https://github.com/Fndroid/clash_for_windows_pkg/releases)(仅限web页面)
- 限制用户使用期限

## 安装方式
*trojan使用请提前准备好服务器可用的域名*  

###  a. 一键脚本安装
```
#安装/更新
source <(curl -sL https://git.io/trojan-install)

#卸载
source <(curl -sL https://git.io/trojan-install) --remove

```
安装完后输入'trojan'可进入管理程序   
浏览器访问 https://域名 可在线web页面管理trojan用户  
前端页面源码地址: [trojan-web](https://github.com/Jrohy/trojan-web)

### b. docker运行
1. 安装mysql  

因为mariadb内存使用比mysql至少减少一半, 所以推荐使用mariadb数据库
```
docker run --name trojan-mariadb --restart=always -p 3306:3306 -v /home/mariadb:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=trojan -e MYSQL_ROOT_HOST=% -e MYSQL_DATABASE=trojan -d mariadb:10.2
```
端口和root密码以及持久化目录都可以改成其他的

2. 安装trojan
```
docker run -it -d --name trojan --net=host --restart=always --privileged jrohy/trojan init
```
运行完后进入容器 `docker exec -it trojan bash`, 然后输入'trojan'即可进行初始化安装   

启动web服务: `systemctl start trojan-web`   

设置自启动: `systemctl enable trojan-web`

更新管理程序: `source <(curl -sL https://git.io/trojan-install)`

## 运行截图
![avatar](asset/1.png)
![avatar](asset/2.png)

## 命令行
```
Usage:
  trojan [flags]
  trojan [command]

Available Commands:
  add           添加用户
  clean         清空指定用户流量
  completion    自动命令补全(支持bash和zsh)
  del           删除用户
  help          Help about any command
  info          用户信息列表
  log           查看trojan日志
  port          修改trojan端口
  restart       重启trojan
  start         启动trojan
  status        查看trojan状态
  stop          停止trojan
  tls           证书安装
  update        更新trojan
  updateWeb     更新trojan管理程序
  version       显示版本号
  import [path] 导入sql文件
  export [path] 导出sql文件
  web           以web方式启动

Flags:
  -h, --help   help for trojan
```

## 注意
安装完trojan后强烈建议开启BBR等加速: [one_click_script](https://github.com/jinwyp/one_click_script)  

## Thanks
感谢JetBrains提供的免费GoLand  
[![avatar](asset/jetbrains.svg)](https://jb.gg/OpenSource)

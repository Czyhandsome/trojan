mode: rule
log-level: warning
ipv6: false
profile:
  store-selected: true
proxies:
  # @trojan-node:proxies
proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      # @trojan-node:group-members
rules:
  - DOMAIN-SUFFIX,qq.com,DIRECT
  - DOMAIN-SUFFIX,qqmail.com,DIRECT
  - DOMAIN-SUFFIX,qqurl.com,DIRECT
  - DOMAIN-SUFFIX,foxmail.com,DIRECT
  - DOMAIN-SUFFIX,idqqimg.com,DIRECT
  - DOMAIN-SUFFIX,gtimg.com,DIRECT
  - GEOSITE,private,DIRECT
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,CN,DIRECT
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,节点选择

# 黑名单分享目录

这里存放搜集的黑名单文件。格式要求：**每行一个 IP 或 CIDR 段**，`#` 开头为注释行。

## 使用方式

在装有 PotLite 的服务器上下载并启用（下载为 `potlite.bans<数字>` 即被自动整合，无需任何配置）：

```bash
curl -sSL https://raw.githubusercontent.com/zcrv5/potlite/main/blacklists/potlite.bans2 -o /root/potlite.bans2
```

- 默认 1 分钟（`interval.bans`）内自动生效，条目随后并入 `potlite.bans` 主文件（不覆盖、不重复）；
- 源文件会一直保留、每个落盘周期自动重读（去重幂等，更新文件后新增条目自动吸收）；
- 已整合的条目会沉淀进主文件——删除本文件**不会**撤销已生效的封禁，移除请对具体 IP 执行 `potlite -unban`。

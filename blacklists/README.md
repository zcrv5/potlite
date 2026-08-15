# 黑名单分享目录

这里存放搜集的黑名单文件。格式要求：**每行一个 IP 或 CIDR 段**，`#` 开头为注释行。

## 使用方式

在装有 PotLite 的服务器上下载并启用（下载为 `potlite.bans<数字>` 即被自动整合，无需任何配置）：

```bash
curl -sSL https://raw.githubusercontent.com/zcrv5/potlite/main/blacklists/<文件名> -o /root/potlite.bans2
```

- 默认 1 分钟（`interval.bans`）内自动生效；
- 条目随后并入 `potlite.bans` 主文件（不覆盖、不重复）；
- 想移除时直接删除该文件并 `systemctl restart potlite`，或对具体 IP 用 `potlite -unban`。

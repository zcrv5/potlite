# 黑名单分享目录

这里存放搜集的黑名单文件。格式要求：**每行一个 IP 或 CIDR 段**，`#` 开头为注释行。

## 使用方式

在装有 PotLite 的服务器上下载为 `potlite.bans` + 任意后缀（如 `potlite.bans2`），默认 1 分钟（`interval.bans`）内自动生效，无需任何配置：

```bash
curl -sSL https://gitee.com/zcrv5/potlite/raw/master/blacklists/potlite.bans2 -o /root/potlite.bans2
```

**黑名单组模式**（无 `#整合` 标记，即本目录文件的默认用法）：

- 文件存在 → 封禁文件内的 IP；
- 修改文件 → 只封禁改后内容（被删掉的 IP 自动解除）；
- 删除文件 → 对应的封禁全部解除；
- 条目不写入 `potlite.bans` 主文件（主名单不受影响）。

**一次性整合模式**：文件首行含 `#整合` 时，条目并入主名单（只增不减）且源文件自动删除——适合"下载一次、永久加入"的场景。

# 轻蜜罐 PotLite

蜜罐端口一经访问即全 IP 永封的 Go 单二进制工具。零依赖、一键运行。

***

## 使用说明

### 一键安装启动

```bash
mkdir -p /root/potlite && curl -sSL https://github.com/zcrv5/potlite/releases/latest/download/potlite-linux-amd64 -o /root/potlite/potlite && chmod +x /root/potlite/potlite && /root/potlite/potlite install
```

执行后自动完成：下载最新版到/root/potlite/、安装为系统服务、开机自启、任意目录可直接使用 `potlite` 命令。

> **安装前必读**
>
> 1. 如果是阿里云/腾讯云之类的云服务器，需要在云控制台内的安全组放行蜜罐端口的TCP入站，默认20个端口（22,21,23,25,110,135,139,143,445,1433,3306,3389,5432,5900,6379,8080,8888,9200,11211,27017），可在配置中自定义。不放行则扫描流量进不来，蜜罐收不到"客人"；
> 2. 确认逃生通道可用：误封自己的 IP 后 SSH 也进不来（全端口封禁），只能通过云厂商 VNC/OrcaTerm 控制台登录解封；
> 3. 需要 root 权限（操作内核防火墙）。

### 分步安装

```bash
# 1. 创建程序目录
mkdir -p /root/potlite

# 2. 下载二进制程序
curl -sSL https://github.com/zcrv5/potlite/releases/latest/download/potlite-linux-amd64 -o /root/potlite/potlite

# 3. 赋予执行权限
chmod +x /root/potlite/potlite

# 4. 安装（自动生成配置、安装为系统服务、创建软链、设置开机自启）
/root/potlite/potlite install

# 5. 卸载程序（卸载只撤销服务与软链、清除内核封禁；最后输出全部数据文件路径，由你自行决定是否删除。）
/root/potlite/potlite uninstall
```


***

## 常用命令

### 内置命令

| 命令                          | 说明           |
| --------------------------- | ------------ |
| `potlite -ban 1.2.3.4`      | 手动封禁指定 IP    |
| `potlite -unban 1.2.3.4`    | 解除封禁         |
| `potlite -allow 1.2.3.4`    | 加入白名单        |
| `potlite -disallow 1.2.3.4` | 移出白名单        |
| `potlite -bancount`         | 查看当前封禁 IP 数量 |
| `potlite -potport`          | 查看正在监听的端口    |
| `potlite status`            | 查看运行状态汇总     |

### systemctl 命令

| 命令                          | 说明                        |
| --------------------------- | ------------------------- |
| `systemctl status potlite`  | 查看状态（含监听端口、封禁数、累计拒绝、白名单数） |
| `systemctl reload potlite`  | 修改配置后热重载（服务不中断）           |
| `systemctl restart potlite` | 重启服务                      |
| `systemctl stop potlite`    | 停止服务                      |

***

## 说明

### 配置

配置文件在程序所在目录的 `potlite.config`（默认路径为/root/potlite/potlite.config，首次运行自动生成，含中文注释）。修改后执行 `systemctl reload potlite` 生效。

| 字段              | 默认              | 说明                                  |
| --------------- | --------------- | ----------------------------------- |
| `ports`         | 20 个常见端口        | 蜜罐监听端口（逗号分隔）                        |
| `interval.bans` | 1               | 封禁名单记录间隔（分钟）                        |
| `log.level`     | 0               | CSV日志等级 0=不记录 1=记录                  |
| `interval.log`  | 10              | 日志记录间隔（分钟）                          |
| `ddns.domains`  | 空               | DDNS 白名单域名（逗号分隔）                    |
| `interval.ddns` | 120             | DDNS 域名解析间隔（分钟）                     |
| `allow.static`  | 127.0.0.1/8,::1 | 静态白名单                               |
| `data.dir`      | auto            | 数据目录（auto = /root 可写则 /root，否则程序目录） |
| `debug.log`     | 0               | 排障日志开关                              |

### 数据文件

| 文件                  | 说明                                                  |
| ------------------- | --------------------------------------------------- |
| `potlite.bans`      | 封禁名单（每行一个 IP/段；按 `interval.bans` 间隔时间增量落盘，服务器重启后据此恢复封禁） |
| `potlite.whitelist` | 白名单文件（仅在有 DDNS 解析结果或手动放行时生成）                        |
| `potlite.log.csv`   | CSV 日志（`log.level=1` 时启用）                           |
| `potlite.debug.log` | 排障日志（`debug.log=1` 时启用）                             |

### 日志

`log.level=1` 时，CSV 每行记录一条封禁：

```
IP,被拒总数,首次拒绝时间,最新拒绝时间
```

### 白名单

白名单共四个来源，命中任一即永不封禁：

1. 内置 127.0.0.1（永远生效，不写入文件）；
2. 本机接口 IP（自动识别，防止服务器本机自测误封）；
3. 静态配置（`allow.static`）；
4. DDNS 域名（按 `interval.ddns` 周期解析，IPv4 精确匹配、IPv6 按 /64 整段放行；每轮解析**全量替换**上轮结果，手动添加的条目不受影响）。

### 外部黑名单

可以把搜集到的黑名单放到数据目录下，命名为 `potlite.bans<数字>`（如 `potlite.bans2`、`potlite.bans10086`），程序会自动整合进封禁名单（不覆盖、不重复）：

- 文件格式：每行一个 IP 或 CIDR 段，`#` 开头为注释行；
- 整合时机：启动时 + 每个 `interval.bans` 周期（默认 1 分钟）；
- 程序自身产物（`potlite.bans.bak`、`potlite.bans.corrupt.*`）不会被误读。

例如下载搜集的黑名单并启用：

```bash
curl -sSL <黑名单文件地址> -o /root/potlite.bans2
```

1 分钟内自动生效，条目随后并入 `potlite.bans` 主文件。

***

## 特性

- **连接即永封**：任何 IP 触碰任一蜜罐端口，该 IP 的全部访问被内核防火墙永久拒绝（SYN 阶段即封，nmap/masscan 半开扫描无法绕过）；
- **全端口全协议封禁**：触发后该 IP 对服务器的 TCP/UDP/ICMP 一切流量均被拒绝；
- **IPv6 按 /64 段封禁**：封禁整个网段而非单地址；
- **白名单多来源**：内置 127.0.0.1 + 本机接口 IP 自动放行 + 静态配置 + DDNS 域名；
- **持久化**：封禁名单增量落盘、服务器重启自动恢复（`potlite.bans` 只增不减、永不覆盖丢失）；
- **外部黑名单整合**：数据目录放入 `potlite.bans<数字>`（如 `potlite.bans2`）文件即自动整合进封禁名单（不覆盖、不重复）；
- **日志分级**：`0` = 不记录（默认）；`1` = CSV 记录（IP、被拒总数、首次/最新拒绝时间）；
- **systemd 集成**：一键装服务、实时状态显示、SIGHUP 热重载、崩溃自愈。

***

## 常见问题

**我误连蜜罐端口被封了怎么办？**

封禁是整个 IP 全端口拒绝（包括 SSH）。通过云厂商 VNC/OrcaTerm 控制台登录后执行 `potlite -unban <你的IP>`。若你的出口 IP 解析自 DDNS 域名，下一轮解析会把你加入白名单（白名单在规则链最前放行，访问即恢复）。

**怎么看谁被封了？**

`potlite -bancount` 看数量；`cat potlite.bans` 看名单。

**卸载会删除数据吗？**

不会。`potlite uninstall` 输出全部数据文件路径后由你自行决定删除。

***

## 兼容性

内核 ≥ 5.4（2020 年后全部主流 Linux）：Ubuntu 20.04+、Debian 11+、Rocky/AlmaLinux 9+、Alpine 3.19+、openEuler 22.03+ 等。内核 4.x（CentOS 8、Ubuntu 18.04 等）自动降级适配；内核 < 4.1（CentOS 6/7 等）不支持。

***

## 从源码构建

需要 Go 1.22+：

```bash
go build -ldflags="-s -w" -o potlite .
```

***

## License

MIT

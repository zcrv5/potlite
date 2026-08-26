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

### 校验下载（可选）

每次发布都附带官方校验文件，可验证下载的二进制未被篡改：

```bash
curl -sSL https://github.com/zcrv5/potlite/releases/latest/download/checksums.txt -o /tmp/checksums.txt
cd /root/potlite && grep potlite-linux-amd64 /tmp/checksums.txt | sha256sum -c -
# 输出 "potlite: OK" 即校验通过
```


***

## 常用命令

### 内置命令

**安装与管理**

| 命令 | 说明 |
| --- | --- |
| `potlite install` | 一键安装为系统服务 |
| `potlite uninstall` | 卸载（停服、清内核封禁、列出全部产物文件） |
| `potlite update` | 检查并自动升级到最新版本 |
| `potlite reload` | 重载配置 |
| `potlite restart` | 重启服务 |
| `potlite help` | 显示命令说明 |

**信息查询**

| 命令 | 说明 |
| --- | --- |
| `potlite info` | 查看运行信息（推荐使用） |
| `potlite port` | 查看监听端口 |
| `potlite bancount` | 当前封禁 IP 数量 |
| `potlite stat [N]` | 本次启动拒绝次数 Top N 排行（默认前 10） |
| `potlite stats [N]` | 总计拒绝次数 Top N 排行（保存日志时才有；无日志时等同本次启动） |

**IP操作**

| 命令 | 说明 |
| --- | --- |
| `potlite ban <IP>` | 封禁 IP |
| `potlite unban <IP>` | 解封 IP |
| `potlite allow <IP[/段]>` | 加入白名单 |
| `potlite disallow <IP[/段]>` | 移出白名单 |

> 所有查看类命令（`info`/`stat`/`stats`/`bancount`）支持 `--json` 输出，方便脚本集成。

### systemctl 命令

| 命令                          | 说明                        |
| --------------------------- | ------------------------- |
| `systemctl status potlite` | 查看状态（含监听端口和封禁 IP 数量；完整详情推荐使用 `potlite info`） |
| `potlite reload` | 修改配置后热重载（服务不中断）           |
| `systemctl restart potlite` | 重启服务                      |
| `systemctl stop potlite`    | 停止服务                      |

### 真实运行输出

安装正确时，你会看到类似输出（这就是 potlite 正常工作的样子）：

```bash
$ potlite info
PotLite 轻蜜罐 信息
  当前版本:  0.3.2
  运行状态:  active
  已监听端口:  21-23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8888, 9200, 11211, 27017
  封禁 IP 数: 2618
  本次启动拒绝次数: 0
  总计拒绝次数: 3145
  白名单条目: 4
  日志开关:  开
  debug日志开关: 关
  数据目录:  /root
  配置:      /root/potlite/potlite.config

$ potlite stat 5
205.210.31.170 拒绝次数200
45.156.129.95 拒绝次数183
66.148.126.142 拒绝次数77
170.155.12.20 拒绝次数55
223.96.213.162 拒绝次数31
```

***

## 说明

### 配置

配置文件在程序所在目录的 `potlite.config`（默认路径为/root/potlite/potlite.config，首次运行自动生成，含中文注释）。修改后执行 `potlite reload` 生效。

| 字段              | 默认              | 说明                                  |
| --------------- | --------------- | ----------------------------------- |
| `ports`         | 20 个常见端口        | 蜜罐监听端口（逗号分隔）                        |
| `ban.days`      | 0               | 封禁时间（天）：0=永久封禁；>0 到期自动解封，支持小数（0.15=3小时36分）。自动封禁进入 potlite.bans 后参与滑动：到期时间=最后一次触发（新封禁/封禁期内再次访问/重启重载）+ban.days；黑名单组（在线黑名单/独立列表文件）不参与到期，永久封禁 |
| `interval.bans` | 1               | 封禁名单记录间隔（分钟）                        |
| `log.level`     | 0               | CSV日志等级 0=不记录 1=记录                  |
| `interval.log`  | 10              | 日志记录间隔（分钟）                          |
| `ddns.domains`  | 空               | DDNS 白名单域名（逗号分隔）                    |
| `interval.ddns` | 120             | DDNS 域名解析间隔（分钟）                     |
| `allow.static`  | 127.0.0.1/8,::1 | 静态白名单                               |
| `data.dir`      | auto            | 数据目录（auto = /root 可写则 /root，否则程序目录） |
| `debug.log` | 0 | 排障日志开关 |
| `firehol.level1` | 0 | FireHOL level1 在线黑名单（基础黑名单，误封率极低，推荐） |
| `firehol.webserver` | 0 | FireHOL webserver 在线黑名单（服务器有 web 服务时推荐） |
| `firehol.ipsum3` | 0 | FireHOL ipsum_3 在线黑名单（被 3 个以上名单共识收录，质量高） |

另有三个程序自动维护的字段（`latest.version` 最新版本、`total.rejected` 总计拒绝次数、`total.rejected.base` 计数基数），无需手动修改。

FireHOL 说明：置 1 即启用，程序每天 0 点自动从 FireHOL 官方源（iplists.firehol.org）下载对应名单（如 `firehol.level1=1` 下载 level1 并保存为 `potlite.bans.firehol.level1`），随即自动生效；下载失败自动保留上一份，不影响其它功能。

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

把黑名单文件放到数据目录（默认 `/root/`），命名为 `potlite.bans` + 任意后缀（如 `potlite.bans2`、`potlite.bans10086`、`potlite.bans国内`），程序每个 `interval.bans` 周期（默认 1 分钟）自动侦测并处理。文件格式：每行一个 IP 或 CIDR 段，`#` 开头为注释行。两种模式：

**一次性整合模式**：文件**首行**含 `#整合`——条目合并进主名单（`potlite.bans`，只增不减），完成后**源文件自动删除**：

```
#整合
1.2.3.4
5.6.7.0/24
```

**黑名单组模式**（默认）：无 `#整合` 标记——文件即真相源，条目不写入主文件：

- 文件存在 → 封禁文件内的 IP（启动时和文件变化时生效）；
- 修改文件 → 只封禁改后内容（被删掉的 IP 自动解除）；
- 删除文件 → 该文件对应的封禁全部解除；
- 文件未变化时跳过读取，无额外开销。

例如下载 GitHub 上的共享黑名单启用：

```bash
curl -sSL https://raw.githubusercontent.com/zcrv5/potlite/main/blacklists/potlite.bans2 -o /root/potlite.bans2
```

1 分钟内自动生效。程序自身产物（`potlite.bans.bak`、`potlite.bans.corrupt.*`）不会被误读。

***

## 特性

- **连接即永封**：任何 IP 触碰任一蜜罐端口，该 IP 的全部访问被内核防火墙永久拒绝（SYN 阶段即封，nmap/masscan 半开扫描无法绕过）；
- **全端口全协议封禁**：触发后该 IP 对服务器的 TCP/UDP/ICMP 一切流量均被拒绝；
- **IPv6 按 /64 段封禁**：封禁整个网段而非单地址；
- **白名单多来源**：内置 127.0.0.1 + 本机接口 IP 自动放行 + 静态配置 + DDNS 域名；
- **持久化**：封禁名单增量落盘、服务器重启自动恢复（`potlite.bans` 只增不减、永不覆盖丢失）；
- **外部黑名单**：数据目录放入 `potlite.bans` + 任意后缀的文件即生效——`#整合` 首行 = 一次性并入主名单（源文件自动删除）；无标记 = 黑名单组（文件为真相源，删改实时生效、删除文件即全部解除）；
- **日志分级**：`0` = 不记录（默认）；`1` = CSV 记录（IP、被拒总数、首次/最新拒绝时间）；
- **systemd 集成**：一键装服务、实时状态显示、SIGHUP 热重载、崩溃自愈。

***

## 常见问题

**我误连蜜罐端口被封了怎么办？**

封禁是整个 IP 全端口拒绝（包括 SSH）。通过云厂商 VNC/OrcaTerm 控制台登录后执行 `potlite unban <你的IP>`。若你的出口 IP 解析自 DDNS 域名，下一轮解析会把你加入白名单（白名单在规则链最前放行，访问即恢复）。

**怎么看谁被封了？**

`potlite bancount` 看数量；`cat potlite.bans` 看名单。

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

// PotLite（轻蜜罐）：多端口蜜罐 + 连接即全 IP 永久封禁。
// 单二进制两种形态：serve（常驻服务）与 CLI 管理命令，共用同一份名单/防火墙逻辑。
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zcrv5/potlite/internal/banlist"
	"github.com/zcrv5/potlite/internal/config"
	"github.com/zcrv5/potlite/internal/csvlog"
	"github.com/zcrv5/potlite/internal/ddns"
	"github.com/zcrv5/potlite/internal/honeypot"
	"github.com/zcrv5/potlite/internal/install"
	"github.com/zcrv5/potlite/internal/nftfw"
	"github.com/zcrv5/potlite/internal/notify"
	"github.com/zcrv5/potlite/internal/paths"
	"github.com/zcrv5/potlite/internal/whitelist"
)

// version 构建时由 ldflags 注入（-X main.version=vX.Y.Z）；源码构建为 "dev"。
var version = "dev"

// failedPorts 服务进程内绑定失败的端口（STATUS 栏显示用）。
var failedPorts atomic.Value // []int

var defaultPorts = []int{22, 21, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8888, 9200, 11211, 27017}

// 运行态配置（SIGHUP 热更新）
var curCfg atomic.Pointer[config.Config]

func main() {
	// panic 兜底：崩溃时输出简洁错误，不留 core、不泄内部细节
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "potlite: 程序异常退出: %v\n", r)
			os.Exit(1)
		}
	}()
	// 统一版本号格式（goreleaser 注入的是 "v0.2.2"，比较与显示均不带 v）
	version = strings.TrimPrefix(version, "v")
	if len(os.Args) == 1 {
		usage()
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root 权限，请使用 sudo potlite ...")
		os.Exit(1)
	}
	arg := strings.TrimPrefix(os.Args[1], "-")
	switch arg {
	case "serve": // 隐藏命令（systemd 服务内部使用），不在用法说明展示
		serve()
	case "install":
		must(install.DoInstall())
	case "uninstall":
		must(install.DoUninstall())
	case "info":
		infoCmd(hasJSON())
	case "reload":
		out, err := runOut("systemctl", "reload", "potlite")
		if err != nil {
			fmt.Fprintf(os.Stderr, "potlite: 重载失败: %s\n", strings.TrimSpace(out))
			os.Exit(1)
		}
		fmt.Println("配置已重载")
	case "restart":
		out, err := runOut("systemctl", "restart", "potlite")
		if err != nil {
			fmt.Fprintf(os.Stderr, "potlite: 重启失败: %s\n", strings.TrimSpace(out))
			os.Exit(1)
		}
		fmt.Println("服务已重启")
	case "stat":
		statCmd(hasJSON())
	case "stats":
		statsCmd(hasJSON())
	case "update":
		updateCmd()
	case "ban", "unban", "allow", "disallow":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		manage(arg, os.Args[2])
	case "bancount":
		bancount(hasJSON())
	case "port":
		portCmd()
	case "help", "h":
		usage()
		os.Exit(0)
	default:
		usage()
		os.Exit(2)
	}
}

// hasJSON 检查命令行是否带 --json。
func hasJSON() bool {
	for _, a := range os.Args {
		if a == "--json" {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprintln(os.Stderr, `PotLite 轻蜜罐 使用方法：

  安装与管理
    potlite install              一键安装为系统服务
    potlite uninstall            卸载（停服、清内核封禁、列出全部产物文件）
    potlite update               检查并自动升级到最新版本
    potlite reload               重载配置
    potlite restart              重启服务

  信息查询
    potlite info                 查看运行信息（推荐使用）
    potlite port                 查看监听端口
    potlite bancount             当前封禁 IP 数量
    potlite stat [N]             本次启动拒绝次数 Top N 排行（默认前 10）
    potlite stats [N]            总计拒绝次数 Top N 排行（保存日志时才有；无日志时等同本次启动）

  IP操作
    potlite ban <IP>             封禁 IP
    potlite unban <IP>           解封 IP
    potlite allow <IP[/段]>          加入白名单
    potlite disallow <IP[/段]>       移出白名单`)
}

// ---------- update ----------

// updateCmd 检查 GitHub 最新版本并自动下载替换升级。
func updateCmd() {
	exe, err := os.Executable()
	must(err)
	latest, err := latestVersion()
	if err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 查询最新版本失败:", err)
		os.Exit(1)
	}
	if latest == "" || latest == version {
		fmt.Printf("已是最新版本（%s）\n", version)
		return
	}
	fmt.Printf("发现新版本 v%s（当前 %s），正在下载…\n", latest, version)
	base := fmt.Sprintf("https://github.com/zcrv5/potlite/releases/download/v%s", latest)
	// 1) 先取官方 checksums.txt 提取本架构哈希
	wantHash := ""
	csResp, err := http.Get(base + "/checksums.txt")
	if err == nil {
		if csBody, rerr := io.ReadAll(io.LimitReader(csResp.Body, 1<<20)); rerr == nil {
			target := fmt.Sprintf("potlite-linux-%s", runtime.GOARCH)
			for _, line := range strings.Split(string(csBody), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[1] == target {
					wantHash = fields[0]
					break
				}
			}
		}
		csResp.Body.Close()
	}
	if wantHash == "" {
		fmt.Fprintln(os.Stderr, "potlite: 无法获取校验信息，升级中止（不信任未校验的下载）")
		os.Exit(1)
	}
	// 2) 下载二进制并校验 sha256
	url := base + fmt.Sprintf("/potlite-linux-%s", runtime.GOARCH)
	tmp := exe + ".new"
	if err := downloadFile(url, tmp); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 下载失败:", err)
		os.Remove(tmp)
		os.Exit(1)
	}
	got, err := sha256File(tmp)
	if err != nil || got != wantHash {
		fmt.Fprintln(os.Stderr, "potlite: 校验失败（文件与官方发布不一致），升级中止")
		os.Remove(tmp)
		os.Exit(1)
	}
	_ = os.Chmod(tmp, 0755)
	if err := os.Rename(tmp, exe); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 替换失败:", err)
		os.Remove(tmp)
		os.Exit(1)
	}
	// 若以系统服务运行则自动重启，无需手动操作
	if out, err := runOut("systemctl", "is-active", "potlite"); err == nil && strings.TrimSpace(out) == "active" {
		fmt.Printf("已升级到 v%s，正在重启服务…\n", latest)
		if _, err := runOut("systemctl", "restart", "potlite"); err != nil {
			fmt.Fprintln(os.Stderr, "potlite: 自动重启失败，请手动执行 systemctl restart potlite")
			os.Exit(0)
		}
		fmt.Printf("已升级到 v%s 并重启服务完成\n", latest)
		return
	}
	fmt.Printf("已升级到 v%s。若以服务运行，请执行 systemctl restart potlite 生效\n", latest)
}

// latestVersion 查询 GitHub 最新 release 版本号（不带 v 前缀）。
func latestVersion() (string, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/zcrv5/potlite/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", err
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// sha256File 计算文件 SHA-256（十六进制小写）。
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// downloadFile 下载文件到目标路径。
func downloadFile(url, dst string) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// newBanlist 创建封禁名单（备份文件放程序所在目录，用于自动回滚）。
func newBanlist(dir string) *banlist.List {
	bak, err := paths.BansBakFile()
	if err != nil {
		bak = ""
	}
	return banlist.New(paths.BansFile(dir), bak)
}

// banDuration 封禁时间（天）→ 持续时间；0 或负值返回 0（永久封禁）。
func banDuration(days float64) time.Duration {
	return time.Duration(days * 24 * float64(time.Hour))
}

// compactPorts 把端口列表压缩显示（连续段折叠：22, 80, 10000-20000）。
func compactPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	var parts []string
	start, prev := sorted[0], sorted[0]
	flush := func() {
		if start == prev {
			parts = append(parts, fmt.Sprint(start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", start, prev))
		}
	}
	for _, p := range sorted[1:] {
		if p == prev+1 {
			prev = p
			continue
		}
		flush()
		start, prev = p, p
	}
	flush()
	return strings.Join(parts, ", ")
}

// ---------- serve ----------

func serve() {
	// 端口段可能达数万：提高文件描述符上限（默认 1024 不够）
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err == nil && lim.Cur < lim.Max {
		lim.Cur = lim.Max
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root 权限，请使用 sudo potlite serve")
		os.Exit(1)
	}
	cfg, cfgPath, invalidKeys, err := loadCfg()
	must(err)
	if len(invalidKeys) > 0 {
		fmt.Fprintf(os.Stderr, "potlite: 警告: 配置中存在失效设置项（已按默认值运行）: %s\n", strings.Join(invalidKeys, ", "))
	}
	curCfg.Store(cfg)
	dir, err := paths.DataDir(cfg)
	must(err)

	// 单实例锁（flock，进程崩溃自动释放）
	lockPath, err := paths.LockFile()
	must(err)
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	must(err)
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 已有实例在运行（锁文件被占用）")
		os.Exit(1)
	}

	// systemd 通知（非 systemd 环境自动降级）
	nt := notify.New()

	// 防火墙：建表/集合/规则（log group 始终挂载，级别只影响程序侧订阅）
	fw, err := nftfw.New()
	must(err)
	defer fw.Close()
	must(fw.Setup(cfg.Ports))
	if err := fw.SyncObPorts(cfg.OutboundPorts); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 出站放行端口同步失败:", err)
	}

	// 封禁名单：加载 + 重放（读取失败时保留原文件并警告后继续，不阻塞启动）
	bl := newBanlist(dir)
	if err := bl.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 警告:", err)
	}
	// 重启/重新导入：所有自动封禁按 ban.days 重新计时（滑动窗口从此刻起算）；
	// 明确永久条目（#整合 导入等）与黑名单组不受影响
	bl.ResetExpires(cfg.BanDays)
	must(fw.ReplayBans(bl.Snapshot()))
	// FireHOL 在线黑名单：先下载再扫描（保证启动即收录）
	syncFirehol(cfg, dir)
	// 外部黑名单：一次性整合（#整合 文件）/ 黑名单组加载 → 内核同步
	if needBan, _, err := bl.ScanMerge(dir); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 外部名单扫描失败:", err)
	} else {
		for _, p := range needBan {
			_ = fw.BanPrefix(p)
		}
		if len(needBan) > 0 {
			fmt.Printf("potlite: 外部名单已加载 %d 个条目\n", len(needBan))
		}
	}

	// 白名单：内置 + 本机 IP + 配置静态 + 文件，全量重放进内核
	wlItems := buildWhitelist(cfg, dir)
	must(fw.ReplayWhitelist(wlItems))
	wlSet := make(map[netip.Prefix]struct{}, len(wlItems))
	for _, p := range wlItems {
		wlSet[p] = struct{}{}
	}

	// CSV 日志（级别 1：IP、被拒总数、首次/最新拒绝时间；数据源为内核 counter dump）
	cl := csvlog.New(paths.CSVFile(dir), cfg.LogLevel)
	if err := cl.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: CSV 日志恢复失败:", err)
	}

	// 蜜罐监听（accept 兜底）；hp 变量可被 SIGHUP 重建
	banFn := func(ip netip.Addr) error {
		if err := fw.Ban(ip); err != nil {
			return err
		}
		// 封禁时间（ban.days）：0=永久；>0 记到期时间，由周期任务自动解封
		if d := curCfg.Load().BanDays; d > 0 {
			bl.AddExpire(ip, time.Now().Add(banDuration(d)))
		} else {
			bl.Add(ip)
		}
		return nil
	}
	var hp *honeypot.Server
	startHP := func() []int {
		if hp != nil {
			hp.Close()
		}
		hp = honeypot.New(curCfg.Load().Ports,
			func(ip netip.Addr) bool { return inWhitelist(ip, wlSet) },
			banFn, nil)
		return hp.Start()
	}
	failed := startHP()
	failedPorts.Store(failed)
	if len(failed) > 0 {
		fmt.Printf("potlite: 有 %d 个端口绑定失败（见上方警告），其余端口已正常监听\n", len(failed))
	}

	// 周期任务：同步内核动态封禁（dynset 产生）→ bans 合并落盘 + pending6 搬运
	// 间隔动态读取（SIGHUP 改 interval.bans 后下一轮生效）
	// 滑动窗口：被封 IP 内核元素计数快照（检测"封禁期内再次访问"→ 重置封禁时间）
	banSeen := make(map[string]uint64)
	go func() {
		for {
			time.Sleep(time.Duration(curCfg.Load().IntervalBans) * time.Minute)
			// 1) 外部黑名单：一次性整合（#整合 文件并入主名单）/ 黑名单组 diff 同步 → 内核封禁与解封。
			//    放在内核同步之前，保证 groups 状态最新（组 IP 过滤与 HasMain 保护用）。
			needBan, needUnban, err := bl.ScanMerge(dir)
			if err != nil {
				fmt.Fprintln(os.Stderr, "potlite: 外部名单扫描失败:", err)
			}
			for _, p := range needBan {
				_ = fw.BanPrefix(p)
			}
			for _, p := range needUnban {
				if !bl.HasMain(p.Addr()) {
					_ = fw.UnbanPrefix(p)
				}
			}
			// 1.5) 并入文件状态（CLI 进程 ban/unban 写入的最新到期/永久记录），
			//      保证到期判定（2.5）用最新 expires，避免 CLI 重封的新到期被旧值提前解封
			bl.SyncFile()
			// 2) 内核动态封禁（dynset 产生）同步进主名单——组 IP 除外（组由文件管理，不进主文件）
			if ips, err := fw.ListBanned4(); err == nil {
				for _, a := range ips {
					if !bl.InGroup(a) {
						bl.Add(a)
					}
				}
			}
			if ips, err := fw.ListBanned6(); err == nil {
				for _, a := range ips {
					if !bl.InGroup(a) {
						bl.Add(a)
					}
				}
			}
			// 2.4) 滑动窗口：被封 IP 封禁期内再次访问（内核集合元素计数增长）→ 封禁时间重置。
			//      "再次访问"判定：被封后新 SYN 命中封禁集合即计数（全端口命中计数）。
			//      v4 键 = IP；v6 键 = /64 段（与 ListBannedCounters 格式一致）。
			if d := curCfg.Load().BanDays; d > 0 {
				counters := fw.ListBannedCounters()
				now := time.Now()
				for _, a := range bl.ActiveExpires() {
					key := a.String()
					if a.Is6() {
						key = netip.PrefixFrom(a, 64).Masked().String()
					}
					cur := counters[key]
					if last, ok := banSeen[key]; ok && cur > last {
						bl.AddExpire(a, now.Add(banDuration(d)))
						fmt.Printf("potlite: %s 封禁期内再次访问，封禁时间已重置\n", a)
					}
					banSeen[key] = cur
				}
			}
			// 2.5) 到期解封（ban.days>0 的封禁到期后自动解封）：
			//      批量解内核（避免逐条 netlink 往返）+ 一次性批量落盘（避免逐条原子写）
			if expired := bl.Expired(time.Now()); len(expired) > 0 {
				if err := fw.UnbanMany(expired); err != nil {
					// 批量失败（可能个别元素已不存在）→ 逐条兜底
					fmt.Fprintf(os.Stderr, "potlite: 批量到期解封失败，逐条兜底: %v\n", err)
					for _, a := range expired {
						_ = fw.Unban(a) // 已删除元素的报错忽略
					}
				}
				for _, a := range expired {
					bl.Remove(a)
					fmt.Printf("potlite: %s 封禁到期已自动解封\n", a)
				}
				if err := bl.SaveRemoveMany(expired); err != nil {
					// 落盘失败：回滚内存（下轮重试），避免文件残留导致重启后复活
					fmt.Fprintf(os.Stderr, "potlite: %d 条到期解封落盘失败: %v\n", len(expired), err)
					d := curCfg.Load().BanDays
					for _, a := range expired {
						if d > 0 {
							bl.AddExpire(a, time.Now().Add(banDuration(d)))
						} else {
							bl.Add(a)
						}
					}
				}
			}
			// 3) bans 合并落盘
			if err := bl.SaveMerge(); err != nil {
				fmt.Fprintln(os.Stderr, "potlite: 落盘失败:", err)
			}
			fw.MovePending6()
		}
	}()

	// DDNS 周期任务：解析域名 → whitelist 全量替换 → 内核/内存对齐（启动即同步一次）
	go func() {
		syncDdns := func() {
			c := curCfg.Load()
			if len(c.DdnsDomains) == 0 {
				return
			}
			prefixes, ok := ddns.Resolve(c.DdnsDomains)
			if !ok {
				fmt.Fprintln(os.Stderr, "potlite: DDNS 解析全部失败，本轮跳过")
				return
			}
			wf := whitelist.New(paths.WhitelistFile(dir))
			if err := wf.ReplaceDdns(prefixes); err != nil {
				fmt.Fprintln(os.Stderr, "potlite: DDNS 白名单更新失败:", err)
				return
			}
			refreshWhitelist(c, dir, fw, &wlSet)
			dlogf(dir, "DDNS 白名单更新：%d 个条目", len(prefixes))
			fmt.Printf("potlite: DDNS 白名单已更新（%d 个条目）\n", len(prefixes))
		}
		syncDdns()
		for {
			time.Sleep(time.Duration(curCfg.Load().IntervalDdns) * time.Minute)
			syncDdns()
		}
	}()

	// CSV 周期落盘（interval.log）：级别 2 先拉取内核计数
	go func() {
		for {
			time.Sleep(time.Duration(curCfg.Load().IntervalLog) * time.Minute)
			c := curCfg.Load()
			cl.SetLevel(c.LogLevel)
			if cl.Level() >= 1 {
				cl.SetCounters(fw.ListBannedCounters())
			}
		if err := cl.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "potlite: CSV 落盘失败:", err)
		}
	}
	}()

	// 出站自动白名单：每 60 秒扫描 /proc/net/tcp，把"本机主动 TCP 连出"的远端 IP
	// 写入白名单集合。过期由程序维护：普通远端按 outbound.minutes、黑名单内远端固定 10 分钟，
	// 超时未再出现即从集合移除（每轮全量重写）。
	go func() {
		lastSeen := make(map[netip.Addr]time.Time)
		isBlack := make(map[netip.Addr]bool)
		for {
			time.Sleep(60 * time.Second)
			c := curCfg.Load()
			if !c.OutboundAllow {
				_ = fw.SyncOutbound(true, nil, nil)
				continue
			}
			v4, v6, b4, b6 := outboundPeers(bl)
			now := time.Now()
			mark := func(addrs []netip.Addr, black bool) {
				for _, a := range addrs {
					lastSeen[a] = now
					isBlack[a] = black
				}
			}
			mark(v4, false)
			mark(v6, false)
			mark(b4, true)
			mark(b6, true)
			// 过滤未超时条目
			var keep4, keep6 []netip.Addr
			for a, t := range lastSeen {
				limit := time.Duration(c.OutboundMinutes) * time.Minute
				if isBlack[a] {
					limit = time.Duration(c.OutboundBlackMinutes) * time.Minute
				}
				if now.Sub(t) > limit {
					delete(lastSeen, a)
					delete(isBlack, a)
					continue
				}
				if a.Is4() {
					keep4 = append(keep4, a)
				} else {
					keep6 = append(keep6, a)
				}
			}
			if err := fw.SyncOutbound(len(c.OutboundPorts) == 0, keep4, keep6); err != nil {
				fmt.Fprintln(os.Stderr, "potlite: 出站白名单同步失败:", err)
			}
			fmt.Printf("potlite: 出站白名单已刷新（普通 %d、黑名单内 %d）\n",
				len(v4)+len(v6), len(b4)+len(b6))
		}
	}()

	// systemd 状态刷新（10 秒：STATUS 单行 + WATCHDOG）
	go func() {
		for {
			c := curCfg.Load()
			// 绑定失败端口（无失败则不显示该前缀）
			prefix := ""
			if v := failedPorts.Load(); v != nil {
				if fps := v.([]int); len(fps) > 0 {
					prefix = "绑定失败端口: " + compactPorts(fps) + " | "
				}
			}
			nt.Status([]string{
				prefix + fmt.Sprintf("监听端口: %s | 封禁 IP 数: %d", compactPorts(c.Ports), bl.Len()),
			})
			nt.Watchdog()
			time.Sleep(10 * time.Second)
		}
	}()

	// 每天 0 点检查一次新版本（结果写回配置 latest.version，供 info 显示）+ FireHOL 黑名单同步
	checkLatest(cfgPath)
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 1, 0, now.Location())
			time.Sleep(next.Sub(now))
			checkLatest(cfgPath)
			syncFirehol(curCfg.Load(), dir)
		}
	}()

	// 拒绝计数滚动：totalSaved = 存档累计、totalBase = 存档时对应的内核实时值。
	// 每次启动表重建后内核计数器归零：滚动基数必须同步归零并写回 config，
	// 否则 CLI 的"总计 = 存档 + (实时 - 基数)"会因基数残留而算错。
	var totalSaved atomic.Uint64
	var totalBase atomic.Uint64
	totalSaved.Store(cfg.TotalRejected)
	totalBase.Store(0)
	if _, err := config.WriteBack(cfgPath, map[string]string{"total.rejected.base": "0"}); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 拒绝计数基数重置失败:", err)
	}
	rollTotal := func() {
		cur := fw.TotalRejected()
		saved := totalSaved.Load() + (cur - totalBase.Load())
		totalSaved.Store(saved)
		totalBase.Store(cur)
		if _, err := config.WriteBack(cfgPath, map[string]string{
			"total.rejected":      strconv.FormatUint(saved, 10),
			"total.rejected.base": strconv.FormatUint(cur, 10),
		}); err != nil {
			fmt.Fprintln(os.Stderr, "potlite: 拒绝计数存档失败:", err)
		}
	}
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			rollTotal()
		}
	}()

	// 信号处理
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sig {
			switch s {
			case syscall.SIGTERM, syscall.SIGINT:
				fmt.Println("potlite: 正在退出（最后一次落盘）…")
				dlogf(dir, "服务停止（%v）", s)
				nt.Stopping()
				rollTotal()
				bl.SaveMerge()
				hp.Close()
				os.Exit(0)
			case syscall.SIGHUP:
				reload(cfgPath, dir, fw, bl, &wlSet, startHP, cl)
			}
		}
	}()

	nt.Ready()
	dlogf(dir, "服务启动：配置=%s 端口=%d 级别=%d", cfgPath, len(cfg.Ports), cfg.LogLevel)
	fmt.Printf("PotLite 轻蜜罐已启动：配置 %s，监听 %d 个端口，数据目录 %s\n",
		cfgPath, len(cfg.Ports)-len(failed), dir)
	select {}
}

// reload SIGHUP 热重载：重读配置 → 端口集合更新 → 蜜罐重绑 → 白名单对齐 → 日志级别切换。
func reload(cfgPath, dir string, fw *nftfw.FW, bl *banlist.List,
	wlSet *map[netip.Prefix]struct{}, startHP func() []int, cl *csvlog.Log) {
	newCfg, invalidKeys, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 重载失败（配置读取错误）:", err)
		return
	}
	if len(invalidKeys) > 0 {
		fmt.Fprintf(os.Stderr, "potlite: 警告: 配置中存在失效设置项（已按默认值运行）: %s\n", strings.Join(invalidKeys, ", "))
	}
	curCfg.Store(newCfg)
	fmt.Println("potlite: 配置已热重载")

	if err := fw.SyncPorts(newCfg.Ports); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 端口同步失败:", err)
	}
	_ = fw.SyncObPorts(newCfg.OutboundPorts)
	failed := startHP()
	failedPorts.Store(failed)
	if len(failed) > 0 {
		fmt.Printf("potlite: %d 个端口绑定失败，其余端口已正常监听\n", len(failed))
	}
	refreshWhitelist(newCfg, dir, fw, wlSet)
	// FireHOL 开关可能已变：立即同步（下载/清理），新文件由下一周期 ScanMerge 收录
	syncFirehol(newCfg, dir)
	// 日志级别热切换
	cl.SetLevel(newCfg.LogLevel)
	dlogf(dir, "配置热重载：端口=%d 级别=%d", len(newCfg.Ports), newCfg.LogLevel)
}

// totalRejected 从内核 counter 求和累计被拒包数。
func totalRejected(fw *nftfw.FW) uint64 {
	return fw.TotalRejected()
}

// debug 日志（debug.log=1 时写 potlite.debug.log）。
var (
	dlogFile *os.File
	dlogMu   sync.Mutex
)

// sanitize S1 日志注入防护：外部输入进入日志前剥离控制字符（换行/制表符保留空格语义）。
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func dlogf(dir, format string, args ...interface{}) {
	c := curCfg.Load()
	if c == nil || !c.DebugLog {
		return
	}
	for i := range args {
		if s, ok := args[i].(string); ok {
			args[i] = sanitize(s)
		}
	}
	dlogMu.Lock()
	defer dlogMu.Unlock()
	if dlogFile == nil {
		f, err := os.OpenFile(paths.DebugLogFile(dir), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		dlogFile = f
	}
	fmt.Fprintf(dlogFile, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// refreshWhitelist 重算白名单 → 内核全量对齐 → 更新内存集合。
func refreshWhitelist(cfg *config.Config, dir string, fw *nftfw.FW, wlSet *map[netip.Prefix]struct{}) {
	items := buildWhitelist(cfg, dir)
	if err := fw.ReplaceWhitelist(items); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 白名单对齐失败:", err)
	}
	newSet := make(map[netip.Prefix]struct{}, len(items))
	for _, p := range items {
		newSet[p] = struct{}{}
	}
	*wlSet = newSet
}

// buildWhitelist 合并全部白名单来源（内置 127.0.0.1/8 + 本机接口 IP + 配置静态 + 文件 ddns/manual）。
func buildWhitelist(cfg *config.Config, dir string) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		p = p.Masked()
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	add(netip.MustParsePrefix("127.0.0.1/8"))
	add(netip.MustParsePrefix("::1/128"))
	for _, a := range localIPs() {
		add(netip.PrefixFrom(a, a.BitLen()))
	}
	for _, s := range cfg.AllowStatic {
		if p, err := netip.ParsePrefix(s); err == nil {
			add(p)
		} else if ip, err := netip.ParseAddr(s); err == nil {
			add(netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	wf := whitelist.New(paths.WhitelistFile(dir))
	if items, err := wf.Load(); err == nil {
		for _, it := range items {
			add(it.Prefix)
		}
	}
	return out
}

func inWhitelist(ip netip.Addr, set map[netip.Prefix]struct{}) bool {
	for p := range set {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func localIPs() []netip.Addr {
	var out []netip.Addr
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().IsValid() {
				out = append(out, p.Addr())
			}
		}
	}
	return out
}

// ---------- CLI 管理命令（内核 + 文件同步，与服务进程同一份逻辑） ----------

func manage(cmd, arg string) {
	cfg, _, _, err := loadCfg()
	must(err)
	dir, err := paths.DataDir(cfg)
	must(err)

	fw, err := nftfw.New()
	must(err)
	defer fw.Close()
	must(fw.Attach())

	bl := newBanlist(dir)
	wf := whitelist.New(paths.WhitelistFile(dir))

	switch cmd {
	case "ban":
		ip := mustIP(arg)
		must(fw.Ban(ip))
		// 封禁时间（ban.days）：0=永久；>0 记到期时间，由周期任务自动解封
		if d := cfg.BanDays; d > 0 {
			bl.AddExpire(ip, time.Now().Add(banDuration(d)))
		} else {
			bl.Add(ip)
		}
		must(bl.SaveMerge())
		fmt.Printf("已封禁 %s\n", ip)
	case "unban":
		ip := mustIP(arg)
		must(fw.Unban(ip))
		bl.Remove(ip)
		must(bl.SaveRemove(ip))
		fmt.Printf("已解封 %s\n", ip)
	case "allow":
		p := mustPrefix(arg)
		must(fw.Allow(p))
		must(wf.AddManual(p))
		fmt.Printf("已加入白名单 %s\n", p)
	case "disallow":
		p := mustPrefix(arg)
		must(fw.Disallow(p))
		must(wf.RemoveManual(p))
		fmt.Printf("已移出白名单 %s\n", p)
	}
}

func bancount(jsonOut bool) {
	cfg, _, _, err := loadCfg()
	must(err)
	dir, err := paths.DataDir(cfg)
	must(err)
	bl := newBanlist(dir)
	must(bl.Load())
	n := bl.Len()
	if fw2, err := nftfw.New(); err == nil {
		if err := fw2.Attach(); err == nil {
			n = fw2.BannedCount()
		}
		fw2.Close()
	}
	if jsonOut {
		printJSON(map[string]any{"banned": n})
		return
	}
	fmt.Printf("当前封禁 IP 数量：%d\n", n)
}

// portCmd 查看监听端口（与 info 的端口部分一致：已监听 + 失败时的绑定失败端口）。
func portCmd() {
	cfg, _, _, err := loadCfg()
	must(err)
	ok := listeningPorts()
	var okList, failList []int
	for _, p := range cfg.Ports {
		if ok[p] {
			okList = append(okList, p)
		} else {
			failList = append(failList, p)
		}
	}
	fmt.Printf("已监听端口:  %s\n", compactPorts(okList))
	if len(failList) > 0 {
		fmt.Printf("绑定失败端口: %s\n", compactPorts(failList))
	}
}

// infoCmd 运行信息汇总（数据目录在配置上方；存在失效设置项时在配置行下方列出）。
func infoCmd(jsonOut bool) {
	cfg, cfgPath, invalid, err := loadCfg()
	if err != nil {
		if jsonOut {
			printJSON(map[string]any{"error": err.Error()})
			return
		}
		fmt.Printf("PotLite 轻蜜罐 信息\n")
		fmt.Printf("  运行状态: 配置读取失败: %v\n", err)
		return
	}
	dir, err := paths.DataDir(cfg)
	if err != nil {
		if jsonOut {
			printJSON(map[string]any{"error": err.Error()})
			return
		}
		fmt.Printf("  数据目录计算失败: %v\n", err)
		return
	}
	bl := newBanlist(dir)
	bl.Load()
	wf := whitelist.New(paths.WhitelistFile(dir))
	items, _ := wf.Load()

	// 实际监听检测：配置端口 vs ss 查询到的 potlite 实际监听端口
	ok := listeningPorts()
	var okList, failList []int
	for _, p := range cfg.Ports {
		if ok[p] {
			okList = append(okList, p)
		} else {
			failList = append(failList, p)
		}
	}
	var curRej, totalRej uint64
	bannedN := 0
	if fw2, err := nftfw.New(); err == nil {
		if err := fw2.Attach(); err == nil {
			curRej = fw2.TotalRejected()
			bannedN = fw2.BannedCount()
		}
		fw2.Close()
	}

	if jsonOut {
		printJSON(map[string]any{
			"version":          versionLine(cfg),
			"service":          serviceState(),
			"listening_ports":  okList,
			"failed_ports":     failList,
			"banned":           bannedN,
			"rejected_current": curRej,
			"rejected_total":   totalRej,
			"whitelist":        len(items),
			"log_enabled":      cfg.LogLevel >= 1,
			"debug_log":        cfg.DebugLog,
			"data_dir":         dir,
			"config":           cfgPath,
			"invalid_keys":     invalid,
		})
		return
	}

	fmt.Println("PotLite 轻蜜罐 信息")
	fmt.Printf("  当前版本:  %s\n", versionLine(cfg))
	fmt.Printf("  运行状态:  %s\n", serviceState())
	fmt.Printf("  已监听端口:  %s\n", compactPorts(okList))
	if len(failList) > 0 {
		fmt.Printf("  绑定失败端口: %s\n", compactPorts(failList))
	}
	fmt.Printf("  封禁 IP 数: %d\n", bannedN)
	fmt.Printf("  本次启动拒绝次数: %d\n", curRej)
	fmt.Printf("  总计拒绝次数: %d\n", totalRej)
	fmt.Printf("  白名单条目: %d\n", len(items))
	fmt.Printf("  日志开关:  %s\n", onoff(cfg.LogLevel >= 1))
	fmt.Printf("  debug日志开关: %s\n", onoff(cfg.DebugLog))
	fmt.Printf("  数据目录:  %s\n", dir)
	fmt.Printf("  配置:      %s\n", cfgPath)
	if len(invalid) > 0 {
		fmt.Printf("  失效设置项: %s\n", strings.Join(invalid, ", "))
	}
}

// statCmd 拒绝次数 Top N 排行（默认前 10；数据源为内核元素 counter）。
func statCmd(jsonOut bool) {
	n := 10
	if len(os.Args) >= 3 {
		if v, err := strconv.Atoi(os.Args[2]); err == nil && v > 0 {
			n = v
		}
	}
	fw, err := nftfw.New()
	if err != nil {
		if jsonOut {
			printJSON(map[string]any{"error": err.Error()})
			return
		}
		must(err)
	}
	defer fw.Close()
	if err := fw.Attach(); err != nil {
		if jsonOut {
			printJSON(map[string]any{"error": err.Error()})
			return
		}
		must(err)
	}
	counters := fw.ListBannedCounters()
	type item struct {
		IP     string `json:"ip"`
		Reject uint64 `json:"reject"`
	}
	list := make([]item, 0, len(counters))
	for ip, cnt := range counters {
		list = append(list, item{ip, cnt})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Reject > list[j].Reject })
	if len(list) > n {
		list = list[:n]
	}
	if jsonOut {
		printJSON(map[string]any{"top": list})
		return
	}
	if len(list) == 0 {
		fmt.Println("暂无封禁数据")
		return
	}
	for _, it := range list {
		fmt.Printf("%s 拒绝次数%d\n", it.IP, it.Reject)
	}
}

// statsCmd 总计拒绝次数 Top N 排行（默认前 10；数据源：CSV 日志的累计计数）。
// 无 CSV（日志开关关闭）时降级为内核 counter（等同本次启动的 stat）。
func statsCmd(jsonOut bool) {
	n := 10
	if len(os.Args) >= 3 {
		if v, err := strconv.Atoi(os.Args[2]); err == nil && v > 0 {
			n = v
		}
	}
	type item struct {
		IP     string `json:"ip"`
		Reject uint64 `json:"reject"`
	}
	outTop := func(list []item) {
		sort.Slice(list, func(i, j int) bool { return list[i].Reject > list[j].Reject })
		if len(list) > n {
			list = list[:n]
		}
		if jsonOut {
			printJSON(map[string]any{"top": list})
			return
		}
		if len(list) == 0 {
			fmt.Println("暂无数据")
			return
		}
		for _, it := range list {
			fmt.Printf("%s 拒绝次数%d\n", it.IP, it.Reject)
		}
	}

	cfg, _, _, err := loadCfg()
	if err != nil {
		if jsonOut {
			printJSON(map[string]any{"error": err.Error()})
			return
		}
		must(err)
	}
	dir, err := paths.DataDir(cfg)
	must(err)
	f, err := os.Open(paths.CSVFile(dir))
	if err != nil {
		// 无 CSV（日志开关关闭）：降级为内核 counter（等同本次启动）
		if fw2, err2 := nftfw.New(); err2 == nil {
			if err2 := fw2.Attach(); err2 == nil {
				var list []item
				for ip, cnt := range fw2.ListBannedCounters() {
					list = append(list, item{ip, cnt})
				}
				outTop(list)
			}
			fw2.Close()
			return
		}
		if jsonOut {
			printJSON(map[string]any{"error": err.Error()})
			return
		}
		must(err)
	}
	defer f.Close()
	var list []item
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ",")
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		list = append(list, item{fields[0], v})
	}
	outTop(list)
}

// printJSON 标准 JSON 单行输出。
func printJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "potlite:", err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}

// listeningPorts 通过 ss 查询 potlite 进程实际监听的 TCP 端口。
func listeningPorts() map[int]bool {
	out, err := runOut("ss", "-tlnp")
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`:(\d+)\s+.*potlite`)
	m := make(map[int]bool)
	for _, line := range strings.Split(out, "\n") {
		if ms := re.FindStringSubmatch(line); ms != nil {
			if p, err := strconv.Atoi(ms[1]); err == nil {
				m[p] = true
			}
		}
	}
	return m
}

// versionLine 当前版本；配置中 latest.version（服务每天 0 点维护）不同时
// 显示"当前（最新版 X）"形式。status 查询不访问网络。
func versionLine(cfg *config.Config) string {
	if cfg.LatestVersion == "" || cfg.LatestVersion == version {
		return version
	}
	return fmt.Sprintf("%s（最新版 %s）", version, cfg.LatestVersion)
}

// checkLatest 查询 GitHub 最新版并写回配置文件（latest.version 字段）。
// 查询失败或已是最新时同样写入（保持字段存在）；发现新版本时打日志提醒。
func checkLatest(cfgPath string) {
	latest, err := latestVersion()
	if err != nil || latest == "" {
		latest = version
	}
	if _, err := config.WriteBack(cfgPath, map[string]string{"latest.version": latest}); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 写入最新版本配置失败:", err)
	}
	if latest != version {
		fmt.Printf("potlite: 发现新版本 v%s（当前 %s），运行 potlite update 升级\n", latest, version)
	}
}

// ---------- FireHOL 在线黑名单 ----------

const fireholBase = "https://iplists.firehol.org/files/"

// fireholSources 配置开关 → 远端文件 → 本地文件名（黑名单组机制自动收录）。
var fireholSources = []struct {
	enabled func(*config.Config) bool
	remote  string
	local   string
}{
	{func(c *config.Config) bool { return c.FireholLevel1 }, "firehol_level1.netset", "potlite.bans.firehol.level1"},
	{func(c *config.Config) bool { return c.FireholWeb }, "firehol_webserver.netset", "potlite.bans.firehol.webserver"},
	{func(c *config.Config) bool { return c.FireholIpsum3 }, "ipsum_3.ipset", "potlite.bans.firehol.ipsum3"},
}

// syncFirehol 按配置下载/清理 FireHOL 黑名单（启动时 + 每天 0 点调用）。
// 下载 → 校验（大小下限 + 有效 IP 行）→ 原子替换；失败保留旧文件；未启用的项删除程序代管文件。
func syncFirehol(cfg *config.Config, dir string) {
	for _, src := range fireholSources {
		local := filepath.Join(dir, src.local)
		if !src.enabled(cfg) {
			_ = os.Remove(local)
			continue
		}
		tmp := local + ".tmp"
		if err := downloadFile(fireholBase+src.remote, tmp); err != nil {
			fmt.Fprintf(os.Stderr, "potlite: FireHOL %s 下载失败（保留旧文件）: %v\n", src.remote, err)
			_ = os.Remove(tmp)
			continue
		}
		// ipset 格式转换（create/add 命令行 → 纯 IP/CIDR 列表）
		if strings.HasSuffix(src.remote, ".ipset") {
			if err := convertIpset(tmp); err != nil {
				fmt.Fprintf(os.Stderr, "potlite: FireHOL %s 格式转换失败，保留旧文件\n", src.remote)
				_ = os.Remove(tmp)
				continue
			}
		}
		if !validBlocklist(tmp) {
			fmt.Fprintf(os.Stderr, "potlite: FireHOL %s 校验失败（文件异常），保留旧文件\n", src.remote)
			_ = os.Remove(tmp)
			continue
		}
		_ = os.Chmod(tmp, 0600)
		if err := os.Rename(tmp, local); err == nil {
			fmt.Printf("potlite: FireHOL 黑名单已更新：%s\n", src.remote)
		} else {
			_ = os.Remove(tmp)
		}
	}
}

// outboundPeers 扫描 /proc/net/tcp(+tcp6)，返回"本机主动 TCP 连出"的远端 IP：
// v4/v6 为普通远端（超时按配置），black4/black6 为落在黑名单内（任意黑名单：组或主名单）的远端
// （超时固定 10 分钟，避免误白长期放行）。
// 判别：ESTABLISHED + 本机为源（私网/回环地址）+ 本地 ephemeral 端口（≥32768）。
// 注意：7.x 内核无 /proc/net/nf_conntrack（procfs 接口已移除）；/proc/net/tcp 为 2.4 起稳定接口，全内核可用。
func outboundPeers(bl *banlist.List) ([]netip.Addr, []netip.Addr, []netip.Addr, []netip.Addr) {
	seen4 := make(map[netip.Addr]struct{})
	seen6 := make(map[netip.Addr]struct{})
	black4 := make(map[netip.Addr]struct{})
	black6 := make(map[netip.Addr]struct{})
	scan := func(path string, is6 bool) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // 表头
			}
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "01" {
				continue // 仅 ESTABLISHED
			}
			local := strings.Split(fields[1], ":")
			remote := strings.Split(fields[2], ":")
			if len(local) != 2 || len(remote) != 2 {
				continue
			}
			port, err := strconv.ParseInt(local[1], 16, 32)
			if err != nil || port < 32768 {
				continue // 非 ephemeral 端口 → 非本机出站客户端
			}
			lip := procIP(local[0], is6)
			rip := procIP(remote[0], is6)
			if !lip.IsPrivate() && !lip.IsLoopback() {
				continue // 本机地址非内网 → 非本机
			}
			inBlack := bl.InGroup(rip) || bl.HasMain(rip)
			if is6 {
				if inBlack {
					black6[rip] = struct{}{}
				} else {
					seen6[rip] = struct{}{}
				}
			} else {
				if inBlack {
					black4[rip] = struct{}{}
				} else {
					seen4[rip] = struct{}{}
				}
			}
		}
	}
	scan("/proc/net/tcp", false)
	scan("/proc/net/tcp6", true)
	toSlice := func(m map[netip.Addr]struct{}) []netip.Addr {
		out := make([]netip.Addr, 0, len(m))
		for a := range m {
			out = append(out, a)
		}
		return out
	}
	return toSlice(seen4), toSlice(seen6), toSlice(black4), toSlice(black6)
}

// procIP 解析 /proc/net/tcp 的十六进制 IP（IPv4 小端 4 字节 / IPv6 4 组小端 uint32）。
func procIP(hex string, is6 bool) netip.Addr {
	if !is6 {
		v, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			return netip.Addr{}
		}
		b := []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
		a, _ := netip.AddrFromSlice(b)
		return a
	}
	if len(hex) != 32 {
		return netip.Addr{}
	}
	var b [16]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(hex[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return netip.Addr{}
		}
		b[i*4] = byte(v)
		b[i*4+1] = byte(v >> 8)
		b[i*4+2] = byte(v >> 16)
		b[i*4+3] = byte(v >> 24)
	}
	a, _ := netip.AddrFromSlice(b[:])
	return a
}

// convertIpset 把 ipset 格式文件（create ... / add <name> <ip>）转换为纯 IP/CIDR 列表（原地覆盖）。
func convertIpset(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "create ") {
			continue
		}
		if strings.HasPrefix(line, "add ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				out = append(out, fields[2])
			}
			continue
		}
		out = append(out, line) // 兼容纯 IP/CIDR 行
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
}

// validBlocklist 校验下载的黑名单文件：大小下限 + 至少一行有效 IP/CIDR。
func validBlocklist(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() < 10*1024 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := netip.ParseAddr(line); err == nil {
			return true
		}
		if _, err := netip.ParsePrefix(line); err == nil {
			return true
		}
	}
	return false
}

// onoff 开关显示。
func onoff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

func serviceState() string {
	if out, err := runOut("systemctl", "is-active", "potlite"); err == nil {
		return strings.TrimSpace(out)
	}
	return "未知（非 systemd 环境）"
}

func runOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	return string(out), err
}

// ---------- 辅助 ----------

func loadCfg() (*config.Config, string, []string, error) {
	cfgPath, err := paths.ConfigPath()
	if err != nil {
		return nil, "", nil, err
	}
	cfg, invalid, err := config.Load(cfgPath)
	if err != nil {
		return nil, "", invalid, err
	}
	// S4：配置文件属主/权限校验（可被非 root 改写 = 白名单投毒风险）
	if st, err := os.Stat(cfgPath); err == nil {
		if st.Mode().Perm()&0o022 != 0 {
			fmt.Fprintln(os.Stderr, "potlite: 警告: 配置文件权限过宽（建议 0600），存在被改写风险")
		}
	}
	return cfg, cfgPath, invalid, nil
}

func mustIP(s string) netip.Addr {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "potlite: 无效 IP: %s\n", s)
		os.Exit(1)
	}
	return ip
}

func mustPrefix(s string) netip.Prefix {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "potlite: 无效 IP/段: %s\n", s)
		os.Exit(1)
	}
	return netip.PrefixFrom(ip, ip.BitLen())
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "potlite:", err)
		os.Exit(1)
	}
}

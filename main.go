// PotLite（轻蜜罐）：多端口蜜罐 + 连接即全 IP 永久封禁。
// 单二进制两种形态：serve（常驻服务）与 CLI 管理命令，共用同一份名单/防火墙逻辑。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
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
	// 统一版本号格式（goreleaser 注入的是 "v0.2.2"，比较与显示均不带 v）
	version = strings.TrimPrefix(version, "v")
	if len(os.Args) == 1 {
		serve()
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root 权限，请使用 sudo potlite ...")
		os.Exit(1)
	}
	arg := strings.TrimPrefix(os.Args[1], "-")
	switch arg {
	case "serve":
		serve()
	case "install":
		must(install.DoInstall())
	case "uninstall":
		must(install.DoUninstall())
	case "status":
		status()
	case "update":
		updateCmd()
	case "ban", "unban", "allow", "disallow":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		manage(arg, os.Args[2])
	case "bancount":
		bancount()
	case "potport":
		potport()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `PotLite（轻蜜罐）用法：
  potlite                  启动服务（无参数 = serve）
  potlite serve            启动服务（建立防火墙规则并常驻）
  potlite install          一键安装为系统服务
  potlite uninstall        卸载（停服、清内核封禁、列出全部产物文件）
  potlite status           查看运行状态
  potlite update           检查并自动升级到最新版本
  potlite ban <IP>         封禁 IP
  potlite unban <IP>       解封 IP
  potlite allow <IP[/段]>      加入白名单
  potlite disallow <IP[/段]>   移出白名单
  potlite bancount         当前封禁 IP 数量
  potlite potport          正在监听的端口`)
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
	url := fmt.Sprintf("https://github.com/zcrv5/potlite/releases/download/v%s/potlite-linux-%s", latest, runtime.GOARCH)
	tmp := exe + ".new"
	if err := downloadFile(url, tmp); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 下载失败:", err)
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

// ---------- serve ----------

func serve() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root 权限，请使用 sudo potlite serve")
		os.Exit(1)
	}
	cfg, cfgPath, err := loadCfg()
	must(err)
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

	// 封禁名单：加载 + 重放（读取失败时保留原文件并警告后继续，不阻塞启动）
	bl := newBanlist(dir)
	if err := bl.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 警告:", err)
	}
	must(fw.ReplayBans(bl.Snapshot()))
	// 外部黑名单：一次性整合（#整合 文件）/ 黑名单组加载 → 内核同步
	if needBan, _, err := bl.ScanMerge(dir); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 外部名单扫描失败:", err)
	} else {
		for _, a := range needBan {
			_ = fw.Ban(a)
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

	// 蜜罐监听（accept 兜底）；hp 变量可被 SIGHUP 重建
	banFn := func(ip netip.Addr) error {
		if err := fw.Ban(ip); err != nil {
			return err
		}
		bl.Add(ip)
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
	go func() {
		for {
			time.Sleep(time.Duration(curCfg.Load().IntervalBans) * time.Minute)
			// 1) 外部黑名单：一次性整合（#整合 文件并入主名单）/ 黑名单组 diff 同步 → 内核封禁与解封。
			//    放在内核同步之前，保证 groups 状态最新（组 IP 过滤与 HasMain 保护用）。
			needBan, needUnban, err := bl.ScanMerge(dir)
			if err != nil {
				fmt.Fprintln(os.Stderr, "potlite: 外部名单扫描失败:", err)
			}
			for _, a := range needBan {
				_ = fw.Ban(a)
			}
			for _, a := range needUnban {
				if !bl.HasMain(a) {
					_ = fw.Unban(a)
				}
			}
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

	// systemd 状态刷新（10 秒：STATUS 单行 + WATCHDOG）
	go func() {
		for {
			c := curCfg.Load()
			parts := make([]string, len(c.Ports))
			for i, p := range c.Ports {
				parts[i] = fmt.Sprint(p)
			}
			// 绑定失败端口（无失败则不显示该前缀）
			prefix := ""
			if v := failedPorts.Load(); v != nil {
				if fps := v.([]int); len(fps) > 0 {
					ps := make([]string, len(fps))
					for i, p := range fps {
						ps[i] = fmt.Sprint(p)
					}
					prefix = "绑定失败端口: " + strings.Join(ps, ", ") + " | "
				}
			}
			nt.Status([]string{
				prefix + fmt.Sprintf("监听端口: %s | 封禁 IP 数: %d", strings.Join(parts, ", "), bl.Len()),
			})
			nt.Watchdog()
			time.Sleep(10 * time.Second)
		}
	}()

	// 每天 0 点检查一次新版本（结果写回配置 latest.version，供 status 显示）
	checkLatest(cfgPath)
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 1, 0, now.Location())
			time.Sleep(next.Sub(now))
			checkLatest(cfgPath)
		}
	}()

	// 拒绝计数滚动：totalSaved = 存档累计、totalBase = 存档时对应的内核实时值。
	// 每次启动表重建后内核计数器归零：滚动基数必须同步归零并写回 config，
	// 否则 CLI 的"总计 = 存档 + (实时 - 基数)"会因基数残留而算错。
	var totalSaved atomic.Uint64
	var totalBase atomic.Uint64
	totalSaved.Store(cfg.TotalRejected)
	totalBase.Store(0)
	if err := config.UpdateKeys(cfgPath, map[string]string{"total.rejected.base": "0"}); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 拒绝计数基数重置失败:", err)
	}
	rollTotal := func() {
		cur := fw.TotalRejected()
		saved := totalSaved.Load() + (cur - totalBase.Load())
		totalSaved.Store(saved)
		totalBase.Store(cur)
		if err := config.UpdateKeys(cfgPath, map[string]string{
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
	newCfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 重载失败（配置读取错误）:", err)
		return
	}
	curCfg.Store(newCfg)
	fmt.Println("potlite: 配置已热重载")

	if err := fw.SyncPorts(newCfg.Ports); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 端口集合更新失败:", err)
	}
	failed := startHP()
	failedPorts.Store(failed)
	if len(failed) > 0 {
		fmt.Printf("potlite: %d 个端口绑定失败，其余端口已正常监听\n", len(failed))
	}
	refreshWhitelist(newCfg, dir, fw, wlSet)
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

func dlogf(dir, format string, args ...interface{}) {
	c := curCfg.Load()
	if c == nil || !c.DebugLog {
		return
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
	cfg, _, err := loadCfg()
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
		bl.Add(ip)
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

func bancount() {
	cfg, _, err := loadCfg()
	must(err)
	dir, err := paths.DataDir(cfg)
	must(err)
	bl := newBanlist(dir)
	must(bl.Load())
	fmt.Printf("当前封禁 IP 数量：%d\n", bl.Len())
}

func potport() {
	cfg, _, err := loadCfg()
	must(err)
	parts := make([]string, len(cfg.Ports))
	for i, p := range cfg.Ports {
		parts[i] = fmt.Sprint(p)
	}
	fmt.Printf("正在监听的端口：%s\n", strings.Join(parts, ", "))
}

// status 运行状态汇总。
func status() {
	cfg, cfgPath, err := loadCfg()
	if err != nil {
		fmt.Printf("PotLite 状态\n")
		fmt.Printf("  运行状态: 配置读取失败: %v\n", err)
		return
	}
	dir, err := paths.DataDir(cfg)
	if err != nil {
		fmt.Printf("  数据目录计算失败: %v\n", err)
		return
	}
	bl := newBanlist(dir)
	bl.Load()
	wf := whitelist.New(paths.WhitelistFile(dir))
	items, _ := wf.Load()

	fmt.Println("PotLite 轻蜜罐 状态")
	fmt.Printf("  当前版本:  %s\n", versionLine(cfg))
	fmt.Printf("  运行状态:  %s\n", serviceState())
	// 实际监听检测：配置端口 vs ss 查询到的 potlite 实际监听端口
	ok := listeningPorts()
	var okList, failList []string
	for _, p := range cfg.Ports {
		if ok[p] {
			okList = append(okList, strconv.Itoa(p))
		} else {
			failList = append(failList, strconv.Itoa(p))
		}
	}
	fmt.Printf("  已监听端口:  %s\n", strings.Join(okList, ", "))
	if len(failList) > 0 {
		fmt.Printf("  绑定失败端口: %s\n", strings.Join(failList, ", "))
	}
	fmt.Printf("  封禁 IP 数: %d\n", bl.Len())
	if fw2, err := nftfw.New(); err == nil {
		if err := fw2.Attach(); err == nil {
			cur := fw2.TotalRejected()
			fmt.Printf("  本次启动拒绝次数: %d\n", cur)
			fmt.Printf("  总计拒绝次数: %d\n", cfg.TotalRejected+(cur-cfg.TotalRejectedBase))
		}
		fw2.Close()
	}
	fmt.Printf("  白名单条目: %d\n", len(items))
	fmt.Printf("  日志开关:  %s\n", onoff(cfg.LogLevel >= 1))
	fmt.Printf("  debug日志开关: %s\n", onoff(cfg.DebugLog))
	fmt.Printf("  配置:      %s\n", cfgPath)
	fmt.Printf("  数据目录:  %s\n", dir)
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
	if err := config.UpdateKeys(cfgPath, map[string]string{"latest.version": latest}); err != nil {
		fmt.Fprintln(os.Stderr, "potlite: 写入最新版本配置失败:", err)
	}
	if latest != version {
		fmt.Printf("potlite: 发现新版本 v%s（当前 %s），运行 potlite update 升级\n", latest, version)
	}
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

func loadCfg() (*config.Config, string, error) {
	cfgPath, err := paths.ConfigPath()
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, "", err
	}
	return cfg, cfgPath, nil
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

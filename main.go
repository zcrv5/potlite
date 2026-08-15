// PotLite（轻蜜罐）：多端口蜜罐 + 连接即全 IP 永久封禁。
// 单二进制两种形态：serve（常驻服务）与 CLI 管理命令，共用同一份名单/防火墙逻辑。
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
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

var defaultPorts = []int{22, 21, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8888, 9200, 11211, 27017}

// 运行态配置（SIGHUP 热更新）
var curCfg atomic.Pointer[config.Config]

func main() {
	if len(os.Args) == 1 {
		serve()
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root 权限，请使用 sudo potlite ...")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "serve":
		serve()
	case "install":
		must(install.DoInstall())
	case "uninstall":
		must(install.DoUninstall())
	case "status":
		status()
	case "-ban", "-unban", "-allow", "-disallow":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		manage(os.Args[1], os.Args[2])
	case "-bancount":
		bancount()
	case "-potport":
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
  potlite -ban <IP>        封禁 IP
  potlite -unban <IP>      解封 IP
  potlite -allow <IP[/段]>     加入白名单
  potlite -disallow <IP[/段]>  移出白名单
  potlite -bancount        当前封禁 IP 数量
  potlite -potport         正在监听的端口`)
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
	lock, err := os.OpenFile(paths.LockFile(dir), os.O_CREATE|os.O_RDWR, 0600)
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
	bl := banlist.New(paths.BansFile(dir))
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
	if len(failed) > 0 {
		fmt.Printf("potlite: 有 %d 个端口绑定失败（见上方警告），其余照常工作\n", len(failed))
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
			nt.Status(fmt.Sprintf("监听端口: %s | 封禁 IP 数: %d | 累计拒绝次数: %d | 白名单条目数: %d",
				strings.Join(parts, ", "), bl.Len(), totalRejected(fw), len(wlSet)))
			nt.Watchdog()
			time.Sleep(10 * time.Second)
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
	if len(failed) > 0 {
		fmt.Printf("potlite: %d 个端口绑定失败，其余照常\n", len(failed))
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

	bl := banlist.New(paths.BansFile(dir))
	wf := whitelist.New(paths.WhitelistFile(dir))

	switch cmd {
	case "-ban":
		ip := mustIP(arg)
		must(fw.Ban(ip))
		bl.Add(ip)
		must(bl.SaveMerge())
		fmt.Printf("已封禁 %s\n", ip)
	case "-unban":
		ip := mustIP(arg)
		must(fw.Unban(ip))
		bl.Remove(ip)
		must(bl.SaveRemove(ip))
		fmt.Printf("已解封 %s\n", ip)
	case "-allow":
		p := mustPrefix(arg)
		must(fw.Allow(p))
		must(wf.AddManual(p))
		fmt.Printf("已加入白名单 %s\n", p)
	case "-disallow":
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
	bl := banlist.New(paths.BansFile(dir))
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
		fmt.Printf("  服务: 配置读取失败: %v\n", err)
		return
	}
	dir, err := paths.DataDir(cfg)
	if err != nil {
		fmt.Printf("  数据目录计算失败: %v\n", err)
		return
	}
	bl := banlist.New(paths.BansFile(dir))
	bl.Load()
	wf := whitelist.New(paths.WhitelistFile(dir))
	items, _ := wf.Load()

	fmt.Println("PotLite 状态")
	fmt.Printf("  服务:      %s\n", serviceState())
	parts := make([]string, len(cfg.Ports))
	for i, p := range cfg.Ports {
		parts[i] = fmt.Sprint(p)
	}
	fmt.Printf("  监听端口:  %s\n", strings.Join(parts, ", "))
	fmt.Printf("  封禁 IP 数: %d\n", bl.Len())
	fmt.Printf("  白名单条目: %d\n", len(items))
	fmt.Printf("  日志级别:  %d\n", cfg.LogLevel)
	fmt.Printf("  配置:      %s\n", cfgPath)
	fmt.Printf("  数据目录:  %s\n", dir)
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

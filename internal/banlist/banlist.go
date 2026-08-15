// Package banlist 管理封禁名单：内存名单 + potlite.bans 增量合并落盘。
//
// 保存协议（需求共识 7.0）：
//   - 落盘 = 读文件 → 与内存合并去重 → 原子写回（写前轮换 potlite.bans.bak）
//   - 文件永远只增不减（除非 Unban 显式删除），用户手动加的条目同样被保留
//   - Unban = 读文件 → 过滤该 IP → 原子写回（防合并复活）
//   - 启动读失败：原文件改名 potlite.bans.corrupt.<时间戳> 保留，绝不覆盖
package banlist

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// List 封禁名单（内存 map + 文件路径）。
type List struct {
	mu     sync.Mutex
	path   string
	ips    map[netip.Addr]struct{} // 主名单（落盘 potlite.bans）
	groups map[string]*group       // 外部黑名单组（文件是真相源，不落盘主文件）
}

// group 一个黑名单组的当前状态（mtime+size 用于变化侦测，未变化跳过读取）。
type group struct {
	ips   map[netip.Addr]struct{}
	mtime time.Time
	size  int64
}

// New 创建名单（不加载）。
func New(path string) *List {
	return &List{path: path, ips: make(map[netip.Addr]struct{}), groups: make(map[string]*group)}
}

// Load 从文件加载名单到内存。文件不存在则空名单；读取失败按 corrupt 保护处理。
func (l *List) Load() error {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return l.preserveCorrupt(err)
	}
	defer f.Close()

	l.mu.Lock()
	defer l.mu.Unlock()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			l.ips[a] = struct{}{}
		} else if p, err := netip.ParsePrefix(line); err == nil {
			// 段（v6 /64）以段内第一个地址记录；v4 段同样以起始地址记录
			l.ips[p.Addr()] = struct{}{}
		}
		// 无法解析的行静默跳过
	}
	if err := sc.Err(); err != nil {
		return l.preserveCorrupt(err)
	}
	return nil
}

// Add 内存加入。返回是否新增（false = 已存在）。
func (l *List) Add(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.ips[ip]; ok {
		return false
	}
	l.ips[ip] = struct{}{}
	return true
}

// Remove 内存移除。
func (l *List) Remove(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ips, ip)
}

// Has 是否存在。
func (l *List) Has(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.ips[ip]
	return ok
}

// Len 当前生效封禁总数（主名单 + 各黑名单组）。
func (l *List) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.ips)
	for _, g := range l.groups {
		n += len(g.ips)
	}
	return n
}

// HasMain 主名单是否包含该地址（组条目 unban 的保护：主名单有的不能被组删除解除）。
func (l *List) HasMain(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.ips[ip]
	return ok
}

// InGroup 该地址是否属于某个黑名单组（组 IP 由文件管理，不进入主名单/主文件）。
func (l *List) InGroup(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range l.groups {
		if _, ok := g.ips[ip]; ok {
			return true
		}
	}
	return false
}

// Snapshot 当前名单副本（排序）。
func (l *List) Snapshot() []netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]netip.Addr, 0, len(l.ips))
	for a := range l.ips {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// isExternal 外部黑名单文件的匹配规则：文件名以 potlite.bans 开头且带任意后缀
// （如 potlite.bans2、potlite.bans.Aa、potlite.bans国内 等）；
// 排除程序自身产物（.bak/.corrupt.*/.tmp）与主文件本身（无后缀）。
func isExternal(name string) bool {
	if !strings.HasPrefix(name, "potlite.bans") || name == "potlite.bans" {
		return false
	}
	suffix := name[len("potlite.bans"):]
	switch {
	case suffix == ".bak", suffix == ".tmp", strings.HasPrefix(suffix, ".corrupt."):
		return false
	}
	return true
}

// readExternal 读外部文件：返回条目集合与是否为"#整合"一次性导入模式（首行含 #整合）。
// 行解析失败静默跳过；# 注释行跳过。
func readExternal(fp string) (map[netip.Addr]struct{}, bool, error) {
	f, err := os.Open(fp)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	ips := make(map[netip.Addr]struct{})
	first := true
	integrate := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.Contains(line, "#整合") {
				integrate = true
				continue
			}
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			ips[a] = struct{}{}
		} else if p, err := netip.ParsePrefix(line); err == nil {
			ips[p.Addr()] = struct{}{}
		}
	}
	return ips, integrate, sc.Err()
}

// ScanMerge 扫描数据目录中的外部黑名单文件，返回需要内核封禁/解封的地址（由调用方执行）：
//   - mtime+size 未变化的文件跳过（省掉无谓读取）；
//   - 首行含"#整合"的文件：条目并入主名单并删除源文件（一次性导入）；
//   - 其余文件作为黑名单组：文件为真相源——新增条目进 needBan、被删条目进 needUnban；
//   - 组文件被删除：该组全部条目进 needUnban（解除封禁）。
func (l *List) ScanMerge(dir string) (needBan, needUnban []netip.Addr, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[string]bool)

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, e := range entries {
		if e.IsDir() || !isExternal(e.Name()) {
			continue
		}
		seen[e.Name()] = true
		fp := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		// mtime+size 缓存：未变化跳过
		if g, ok := l.groups[e.Name()]; ok && g.mtime.Equal(info.ModTime()) && g.size == info.Size() {
			continue
		}
		ips, integrate, err := readExternal(fp)
		if err != nil {
			continue // 读失败容忍（如文件正在被写入）
		}
		if integrate {
			// 一次性整合进主名单（由周期落盘写入 potlite.bans），完成后删除源文件
			for a := range ips {
				if _, dup := l.ips[a]; !dup {
					l.ips[a] = struct{}{}
					needBan = append(needBan, a)
				}
			}
			delete(l.groups, e.Name())
			_ = os.Remove(fp)
			continue
		}
		// 黑名单组：diff 新旧集合
		var old map[netip.Addr]struct{}
		if g, ok := l.groups[e.Name()]; ok {
			old = g.ips
		}
		for a := range ips {
			if _, existed := old[a]; !existed {
				needBan = append(needBan, a)
			}
		}
		for a := range old {
			if _, still := ips[a]; !still {
				needUnban = append(needUnban, a)
			}
		}
		l.groups[e.Name()] = &group{ips: ips, mtime: info.ModTime(), size: info.Size()}
	}
	// 组文件被删除：该组全部解除
	for name, g := range l.groups {
		if !seen[name] {
			for a := range g.ips {
				needUnban = append(needUnban, a)
			}
			delete(l.groups, name)
		}
	}
	return needBan, needUnban, nil
}

// SaveMerge 增量合并落盘：文件 ∪ 内存，去重后原子写回。
func (l *List) SaveMerge() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	merged := make(map[netip.Addr]struct{}, len(l.ips)+64)
	// 先读文件
	if f, err := os.Open(l.path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if a, err := netip.ParseAddr(line); err == nil {
				merged[a] = struct{}{}
			} else if p, err := netip.ParsePrefix(line); err == nil {
				merged[p.Addr()] = struct{}{}
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("读取名单文件失败: %w", err)
	}
	// 合并内存
	for a := range l.ips {
		merged[a] = struct{}{}
	}
	return l.atomicWrite(merged)
}

// SaveRemove 落盘前先过滤掉指定 IP（Unban 防复活）。
func (l *List) SaveRemove(ip netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	keep := make(map[netip.Addr]struct{}, len(l.ips)+64)
	if f, err := os.Open(l.path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if a, err := netip.ParseAddr(line); err == nil {
				keep[a] = struct{}{}
			} else if p, err := netip.ParsePrefix(line); err == nil {
				keep[p.Addr()] = struct{}{}
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("读取名单文件失败: %w", err)
	}
	delete(keep, ip)
	return l.atomicWrite(keep)
}

// atomicWrite 原子写回：轮换 .bak → 写临时文件 → rename。
func (l *List) atomicWrite(ips map[netip.Addr]struct{}) error {
	lines := make([]string, 0, len(ips))
	for a := range ips {
		lines = append(lines, a.String())
	}
	sort.Strings(lines)

	// 轮换 .bak
	if _, err := os.Stat(l.path); err == nil {
		_ = os.Rename(l.path, l.path+".bak")
	}
	tmp := l.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("写临时文件失败: %w", err)
	}
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, l.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换名单文件失败: %w", err)
	}
	return nil
}

// preserveCorrupt 启动读失败保护：原文件改名保留，绝不覆盖。
func (l *List) preserveCorrupt(err error) error {
	corrupt := fmt.Sprintf("%s.corrupt.%s", l.path, time.Now().Format("20060102-150405"))
	if _, rerr := os.Stat(l.path); rerr == nil {
		_ = os.Rename(l.path, corrupt)
	}
	return fmt.Errorf("名单文件读取失败（原文件已保留为 %s）: %w", filepath.Base(corrupt), err)
}

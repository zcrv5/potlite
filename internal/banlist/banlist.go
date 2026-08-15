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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// List 封禁名单（内存 map + 文件路径）。
type List struct {
	mu   sync.Mutex
	path string
	ips  map[netip.Addr]struct{} // v4 单 IP / v6 地址（段在文件中按 /64 记）
}

// New 创建名单（不加载）。
func New(path string) *List {
	return &List{path: path, ips: make(map[netip.Addr]struct{})}
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

// Add 内存加入。
func (l *List) Add(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ips[ip] = struct{}{}
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

// Len 数量。
func (l *List) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ips)
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

// externalRe 外部补充名单文件的匹配规则：potlite.bans 及 potlite.bans<数字>
// （如 potlite.bans2、potlite.bans10086）。程序自身产物（.bak/.corrupt./.tmp）不匹配。
var externalRe = regexp.MustCompile(`^potlite\.bans\d*$`)

// ScanMerge 扫描数据目录中全部外部名单文件，解析后合并进内存名单（去重）。
// 返回新增条目数。单个文件读取失败/行解析失败均容忍跳过。
// 外部文件支持 # 注释行（搜集的黑名单常带注释）。
func (l *List) ScanMerge(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && externalRe.MatchString(e.Name()) {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	before := len(l.ips)
	for _, fp := range files {
		f, err := os.Open(fp)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if a, err := netip.ParseAddr(line); err == nil {
				l.ips[a] = struct{}{}
			} else if p, err := netip.ParsePrefix(line); err == nil {
				l.ips[p.Addr()] = struct{}{}
			}
		}
		f.Close()
	}
	return len(l.ips) - before, nil
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

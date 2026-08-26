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
	"strconv"
	"strings"
	"sync"
	"time"
)

// List 封禁名单（内存 map + 文件路径）。
type List struct {
	mu      sync.Mutex
	path    string
	bakPath string // 备份文件路径（程序所在目录；空则禁用回滚）
	ips     map[netip.Addr]struct{}  // 主名单（落盘 potlite.bans）
	expires map[netip.Addr]time.Time // 封禁到期时间（零值 = 无到期/永久；到期由周期任务解封）
	dirty   map[netip.Addr]struct{}  // 本轮新增/变更（SaveMerge 写回依据：文件已删的条目不复活）
	groups  map[string]*group        // 外部黑名单组（文件是真相源，不落盘主文件）
}

// group 一个黑名单组的当前状态（mtime+size 用于变化侦测，未变化跳过读取）。
// entries 以 Prefix 存储（单 IP = /32 或 /128），支持 CIDR 段与包含匹配。
type group struct {
	entries map[netip.Prefix]struct{}
	mtime   time.Time
	size    int64
}

// New 创建名单（不加载）。bakPath 为备份文件路径（放程序所在目录，可自动回滚）。
func New(path, bakPath string) *List {
	return &List{path: path, bakPath: bakPath, ips: make(map[netip.Addr]struct{}), expires: make(map[netip.Addr]time.Time), dirty: make(map[netip.Addr]struct{}), groups: make(map[string]*group)}
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
		if a, exp, ok := parseEntry(line); ok {
			l.ips[a] = struct{}{}
			if !exp.IsZero() {
				l.expires[a] = exp
			}
		}
		// 无法解析的行静默跳过
	}
	if err := sc.Err(); err != nil {
		return l.preserveCorrupt(err)
	}
	// 自动回滚：主文件条目数不足备份的 1/3 → 判定损坏 → 用备份恢复后重新加载
	if l.bakPath != "" {
		if bakN, err := countEntries(l.bakPath); err == nil && len(l.ips)*3 < bakN {
			fmt.Fprintf(os.Stderr, "potlite: 警告: 名单条目异常（%d 条 < 备份 %d 条的 1/3），自动用备份回滚\n", len(l.ips), bakN)
			if data, err := os.ReadFile(l.bakPath); err == nil {
				if err := os.WriteFile(l.path, data, 0600); err == nil {
					l.ips = make(map[netip.Addr]struct{})
					l.expires = make(map[netip.Addr]time.Time)
					if f2, err := os.Open(l.path); err == nil {
						sc2 := bufio.NewScanner(f2)
						sc2.Buffer(make([]byte, 64*1024), 1024*1024)
						for sc2.Scan() {
							line := sc2.Text()
							if line == "" {
								continue
							}
							if a, exp, ok := parseEntry(line); ok {
								l.ips[a] = struct{}{}
								if !exp.IsZero() {
									l.expires[a] = exp
								}
							}
						}
						f2.Close()
					}
				}
			}
		}
	}
	return nil
}

// parseEntry 解析名单行：
//   - "IP"：自动封禁（无明确到期，重启时按 ban.days 重新计时）
//   - "IP 到期unix秒"：明确到期时间（到期自动解封）
// 旧版 "IP 0"（曾经的永久标记）按自动封禁处理。段（v6 /64）以段内第一个地址记录。
func parseEntry(line string) (netip.Addr, time.Time, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return netip.Addr{}, time.Time{}, false
	}
	var exp time.Time
	if sp := strings.IndexByte(line, ' '); sp > 0 {
		if ts, err := strconv.ParseInt(line[sp+1:], 10, 64); err == nil {
			line = line[:sp]
			if ts > 0 {
				exp = time.Unix(ts, 0)
			}
			// ts<=0（含旧版 "IP 0"）→ 无到期（自动封禁）
		} else {
			return netip.Addr{}, time.Time{}, false // 带无法识别的后缀 → 无效行
		}
	}
	if a, err := netip.ParseAddr(line); err == nil {
		return a, exp, true
	}
	if p, err := netip.ParsePrefix(line); err == nil {
		return p.Addr(), exp, true
	}
	return netip.Addr{}, time.Time{}, false
}

// countEntries 解析名单文件返回条目数（无法解析的行静默跳过）。
func countEntries(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, ok := parseEntry(line); ok {
			n++
		}
	}
	return n, sc.Err()
}

// Add 内存加入（永久封禁）。返回是否新增（false = 已存在）。
func (l *List) Add(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.ips[ip]; ok {
		return false
	}
	l.ips[ip] = struct{}{}
	delete(l.expires, ip) // 永久语义，清除可能的到期记录
	l.dirty[ip] = struct{}{}
	return true
}

// AddExpire 内存加入并设置到期时间（到期后由周期任务解封）。
// at 为零值等价永久封禁（清除到期记录）。
func (l *List) AddExpire(ip netip.Addr, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ips[ip] = struct{}{}
	if at.IsZero() {
		delete(l.expires, ip)
	} else {
		l.expires[ip] = at
	}
	l.dirty[ip] = struct{}{}
}

// Expired 返回已到期（now 之后不再有效）的封禁地址列表（排序）。
func (l *List) Expired(now time.Time) []netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []netip.Addr
	for a, exp := range l.expires {
		if !exp.IsZero() && now.After(exp) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Remove 内存移除。
func (l *List) Remove(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ips, ip)
	delete(l.expires, ip)
	delete(l.dirty, ip)
}

// ResetExpires 重启/重新导入时重置所有自动封禁的到期时间（滑动窗口重新计时）；
// days<=0 时全部恢复永久，并同步文件清除残留的旧到期行
// （否则下轮 SaveMerge 读文件并入会把到期恢复，永久化永远写不回文件）。
func (l *List) ResetExpires(days float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	needSync := false
	for a := range l.ips {
		if days > 0 {
			l.expires[a] = now.Add(time.Duration(days * 24 * float64(time.Hour)))
			l.dirty[a] = struct{}{}
		} else {
			delete(l.expires, a)
			needSync = true
		}
	}
	if needSync {
		merged := make(map[netip.Addr]time.Time, len(l.ips))
		for a := range l.ips {
			if exp, ok := l.expires[a]; ok {
				merged[a] = exp
			} else {
				merged[a] = time.Time{}
			}
		}
		_ = l.atomicWrite(merged)
	}
}

// ActiveExpires 返回所有带到期时间的条目（滑动窗口"再次访问重置"检测用，排序）。
func (l *List) ActiveExpires() []netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []netip.Addr
	for a, exp := range l.expires {
		if !exp.IsZero() {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
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
		n += len(g.entries)
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
// 支持 CIDR 段包含匹配（如组内含 0.0.0.0/8，则 0.1.2.3 属于该组）。
func (l *List) InGroup(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range l.groups {
		for p := range g.entries {
			if p.Contains(ip) {
				return true
			}
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

// readExternal 读外部文件：返回条目集合（Prefix 形式，单 IP = /32 或 /128）与是否为"#整合"一次性导入模式。
// 行解析失败静默跳过；# 注释行跳过。
func readExternal(fp string) (map[netip.Prefix]struct{}, bool, error) {
	f, err := os.Open(fp)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	entries := make(map[netip.Prefix]struct{})
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
			entries[netip.PrefixFrom(a, a.BitLen())] = struct{}{}
		} else if p, err := netip.ParsePrefix(line); err == nil {
			entries[p.Masked()] = struct{}{}
		}
	}
	return entries, integrate, sc.Err()
}

// ScanMerge 扫描数据目录中的外部黑名单文件，返回需要内核封禁/解封的地址（由调用方执行）：
//   - mtime+size 未变化的文件跳过（省掉无谓读取）；
//   - 首行含"#整合"的文件：条目并入主名单并删除源文件（一次性导入）；
//   - 其余文件作为黑名单组：文件为真相源——新增条目进 needBan、被删条目进 needUnban；
//   - 组文件被删除：该组全部条目进 needUnban（解除封禁）。
func (l *List) ScanMerge(dir string) (needBan, needUnban []netip.Prefix, err error) {
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
		cur, integrate, err := readExternal(fp)
		if err != nil {
			continue // 读失败容忍（如文件正在被写入）
		}
		if integrate {
			// 一次性整合进主名单（由周期落盘写入 potlite.bans），完成后删除源文件。
			// 整合后即普通自动条目：参与到期滑动（重启重置/再次访问重置/到期解封）。
			for p := range cur {
				if _, dup := l.ips[p.Addr()]; !dup {
					l.ips[p.Addr()] = struct{}{}
					delete(l.expires, p.Addr())
					l.dirty[p.Addr()] = struct{}{}
					needBan = append(needBan, p)
				}
			}
			delete(l.groups, e.Name())
			_ = os.Remove(fp)
			continue
		}
		// 黑名单组：diff 新旧集合（Prefix 对比）
		var old map[netip.Prefix]struct{}
		if g, ok := l.groups[e.Name()]; ok {
			old = g.entries
		}
		for p := range cur {
			if _, existed := old[p]; !existed {
				needBan = append(needBan, p)
			}
		}
		for p := range old {
			if _, still := cur[p]; !still {
				needUnban = append(needUnban, p)
			}
		}
		l.groups[e.Name()] = &group{entries: cur, mtime: info.ModTime(), size: info.Size()}
	}
	// 组文件被删除：该组全部解除
	for name, g := range l.groups {
		if !seen[name] {
			for p := range g.entries {
				needUnban = append(needUnban, p)
			}
			delete(l.groups, name)
		}
	}
	return needBan, needUnban, nil
}

// SyncFile 把文件中的到期记录并入内存（CLI 进程 potlite ban/unban 写入的最新状态）。
// 单向往内存合并（不删除、不写回）；到期时间取"更晚"（内存已有更新值如滑动重置时不覆盖）；
// 必须在到期判定（Expired）之前调用，否则 CLI 重新封禁的新到期在并入前会被内存旧值提前解封。
func (l *List) SyncFile() {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if a, exp, ok := parseEntry(line); ok {
			if !exp.IsZero() {
				l.ips[a] = struct{}{}
				if cur, ok := l.expires[a]; !ok || exp.After(cur) {
					l.expires[a] = exp
				}
			}
		}
	}
}

// SaveMerge 增量合并落盘：文件 ∪ 内存，去重后原子写回。
// 行格式："IP"（自动）/ "IP 到期unix秒"。
// 文件中的到期记录（CLI 进程 potlite ban 等写入）并入内存，保证服务进程感知。
// 合并仅写回"本轮新增/变更（dirty）或文件已有"的条目——CLI unban 显式删除的条目不复活。
func (l *List) SaveMerge() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	merged := make(map[netip.Addr]time.Time, len(l.ips)+64)
	fileSeen := make(map[netip.Addr]struct{}, len(l.ips)+64)
	// 先读文件
	if f, err := os.Open(l.path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if a, exp, ok := parseEntry(line); ok {
				fileSeen[a] = struct{}{}
				merged[a] = exp
				if !exp.IsZero() {
					// 并入内存（CLI 写入的到期条目服务进程才能自动解封）；
					// 取更晚到期：内存已有更新值（如滑动重置）时不被文件旧值覆盖
					if _, inMem := l.ips[a]; !inMem {
						l.ips[a] = struct{}{}
					}
					if cur, ok := l.expires[a]; !ok || exp.After(cur) {
						l.expires[a] = exp
					}
				}
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("读取名单文件失败: %w", err)
	}
	// 合并内存：仅写回"本轮新增/变更（dirty）或文件已有"的条目
	for a := range l.ips {
		_, dirty := l.dirty[a]
		_, inFile := fileSeen[a]
		if exp, ok := l.expires[a]; ok {
			if dirty || inFile {
				merged[a] = exp
			}
			continue
		}
		if dirty || inFile {
			merged[a] = time.Time{}
		}
	}
	if err := l.atomicWrite(merged); err != nil {
		return err
	}
	// 写回成功：清除脏标记（下轮起以文件状态为准）
	l.dirty = make(map[netip.Addr]struct{})
	return nil
}

// SaveRemove 落盘前先过滤掉指定 IP（Unban 防复活），其余行（含到期）原样保留。
func (l *List) SaveRemove(ip netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	keep := make(map[netip.Addr]time.Time, len(l.ips)+64)
	if f, err := os.Open(l.path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if a, exp, ok := parseEntry(line); ok {
				keep[a] = exp
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("读取名单文件失败: %w", err)
	}
	delete(keep, ip)
	return l.atomicWrite(keep)
}

// SaveRemoveMany 落盘前一次性过滤掉多个 IP（批量解封用，避免逐条全文件原子写卡死）。
func (l *List) SaveRemoveMany(ips []netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	drop := make(map[netip.Addr]struct{}, len(ips))
	for _, a := range ips {
		drop[a] = struct{}{}
	}
	keep := make(map[netip.Addr]time.Time, len(l.ips)+64)
	if f, err := os.Open(l.path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if a, exp, ok := parseEntry(line); ok {
				if _, d := drop[a]; !d {
					keep[a] = exp
				}
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("读取名单文件失败: %w", err)
	}
	return l.atomicWrite(keep)
}

// atomicWrite 原子写回：写临时文件 → rename；成功后同步 .bak = 新文件
// （避免"解封后文件合法变小"被回滚保护误判为损坏而回滚出已解封的 IP）。
func (l *List) atomicWrite(ips map[netip.Addr]time.Time) error {
	lines := make([]string, 0, len(ips))
	for a, exp := range ips {
		if exp.IsZero() {
			lines = append(lines, a.String())
		} else {
			lines = append(lines, fmt.Sprintf("%s %d", a, exp.Unix()))
		}
	}
	sort.Strings(lines)

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
	// 写成功后同步 .bak（备份放程序所在目录）
	if l.bakPath != "" {
		if data, err := os.ReadFile(l.path); err == nil {
			_ = os.WriteFile(l.bakPath, data, 0600)
		}
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

// Package whitelist 管理白名单文件 potlite.whitelist。
//
// 文件格式（每行一条，来源 + 空格 + IP/段）：
//
//	ddns   121.207.44.113
//	ddns   240e:379:4472:c600::/64
//	manual 8.8.8.8
//
// 语义（需求共识）：
//   - 内置白名单 127.0.0.1 永远生效且不写文件；
//   - DDNS 解析成功后**全量替换** ddns 来源条目（旧删新写），manual 条目不受影响；
//   - 解析全失败跳过本轮（保留旧条目，防误封自己）；
//   - 仅在需要时读写（启动/DDNS 周期/allow 操作），无周期落盘。
package whitelist

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Item 一条白名单记录。
type Item struct {
	Source string // "ddns" 或 "manual"
	Prefix netip.Prefix
}

// File 白名单文件管理。
type File struct {
	path string
}

func New(path string) *File { return &File{path: path} }

// Load 读取全部条目。
func (w *File) Load() ([]Item, error) {
	f, err := os.Open(w.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var items []Item
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		src, addr := fields[0], fields[1]
		if src != "ddns" && src != "manual" {
			continue
		}
		var p netip.Prefix
		if p, err = netip.ParsePrefix(addr); err != nil {
			if ip, err2 := netip.ParseAddr(addr); err2 == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			} else {
				continue
			}
		}
		items = append(items, Item{Source: src, Prefix: p.Masked()})
	}
	return items, sc.Err()
}

// ReplaceDdns DDNS 全量替换：保留 manual 条目，删除全部 ddns 条目，写入新解析结果。
// 若文件不存在且新结果为空 → 不创建文件（返回 nil）。
func (w *File) ReplaceDdns(newDdns []netip.Prefix) error {
	items, err := w.Load()
	if err != nil {
		return err
	}
	var manual []netip.Prefix
	for _, it := range items {
		if it.Source == "manual" {
			manual = append(manual, it.Prefix)
		}
	}
	if len(manual) == 0 && len(newDdns) == 0 {
		// 动态白名单全部清空 → 删除文件
		_ = os.Remove(w.path)
		return nil
	}
	return w.write(manual, newDdns)
}

// AddManual 手动加白名单。
func (w *File) AddManual(p netip.Prefix) error {
	items, err := w.Load()
	if err != nil {
		return err
	}
	var manual, ddns []netip.Prefix
	for _, it := range items {
		if it.Source == "manual" {
			manual = append(manual, it.Prefix)
		} else {
			ddns = append(ddns, it.Prefix)
		}
	}
	for _, m := range manual {
		if m == p {
			return nil // 已存在
		}
	}
	manual = append(manual, p)
	return w.write(manual, ddns)
}

// RemoveManual 手动移除白名单。
func (w *File) RemoveManual(p netip.Prefix) error {
	items, err := w.Load()
	if err != nil {
		return err
	}
	var manual, ddns []netip.Prefix
	for _, it := range items {
		if it.Source == "manual" {
			if it.Prefix != p {
				manual = append(manual, it.Prefix)
			}
		} else {
			ddns = append(ddns, it.Prefix)
		}
	}
	if len(manual) == 0 && len(ddns) == 0 {
		_ = os.Remove(w.path)
		return nil
	}
	return w.write(manual, ddns)
}

// write 原子写回（manual 在前，ddns 在后，各自排序去重）。
func (w *File) write(manual, ddns []netip.Prefix) error {
	sort.Slice(manual, func(i, j int) bool { return manual[i].String() < manual[j].String() })
	sort.Slice(ddns, func(i, j int) bool { return ddns[i].String() < ddns[j].String() })

	tmp := w.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("写白名单临时文件失败: %w", err)
	}
	for _, p := range manual {
		fmt.Fprintf(f, "manual %s\n", p)
	}
	for _, p := range ddns {
		fmt.Fprintf(f, "ddns %s\n", p)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, w.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换白名单文件失败: %w", err)
	}
	return nil
}

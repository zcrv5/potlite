// Package csvlog 实现分级 CSV 日志（log.level 0-1）。
//
// 级别 0：不记录；级别 1：每行 = IP, 被拒总数, 首次拒绝时间, 最新拒绝时间。
// 数据来源：内核 counter dump（周期拉取），内存表维护，按 interval.log 全量重写（原子写）。
package csvlog

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Rec 一条封禁记录。
type Rec struct {
	IP        string
	Rejected  uint64
	FirstTime time.Time
	LastTime  time.Time
}

// Log CSV 日志器。
type Log struct {
	mu      sync.Mutex
	level   int
	path    string
	records map[string]*Rec
}

// New 创建日志器。
func New(path string, level int) *Log {
	return &Log{path: path, level: level, records: make(map[string]*Rec)}
}

// SetLevel 热更新级别（SIGHUP）。
func (l *Log) SetLevel(level int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Level 当前级别。
func (l *Log) Level() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetCounters 更新 per-IP 被拒计数（内核 counter dump，周期调用）。
// 首次出现的 IP 创建记录（首次/最新时间 = 现在）；计数变化则刷新最新拒绝时间。
func (l *Log) SetCounters(counts map[string]uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for ip, n := range counts {
		if rec, ok := l.records[ip]; ok {
			if n != rec.Rejected {
				rec.Rejected = n
				rec.LastTime = now
			}
		} else {
			l.records[ip] = &Rec{IP: ip, Rejected: n, FirstTime: now, LastTime: now}
		}
	}
}

// Save 按级别全量重写 CSV（原子写）。
func (l *Log) Save() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.level < 1 || len(l.records) == 0 {
		return nil
	}
	ips := make([]string, 0, len(l.records))
	for ip := range l.records {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	tmp := l.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ts := func(t time.Time) string { return t.Format("2006-01-02 15:04:05") }
	for _, ip := range ips {
		rec := l.records[ip]
		line := fmt.Sprintf("%s,%s,%s,%s",
			rec.IP, strconv.FormatUint(rec.Rejected, 10), ts(rec.FirstTime), ts(rec.LastTime))
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
		return err
	}
	return nil
}

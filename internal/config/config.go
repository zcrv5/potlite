// Package config 实现 potlite.config 的解析与默认配置生成。
// 解析规则（对小白宽容）：等号前后空格无影响；空行跳过；行首 # 为注释；
// 键名大小写不敏感；未知键警告后忽略；兼容 CRLF；非法值回退默认并警告。
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config 全部配置项。
type Config struct {
	Ports        []int    // 蜜罐监听端口
	IntervalBans int      // bans 落盘间隔（分钟）
	IntervalLog  int      // CSV 落盘间隔（分钟）
	IntervalDdns int      // DDNS 解析间隔（分钟）
	LogLevel     int      // 日志级别 0-3
	DdnsDomains  []string // DDNS 白名单域名
	AllowStatic  []string // 静态白名单 IP/CIDR
	DataDir      string   // auto 或绝对路径
	DebugLog     bool     // debug 日志开关
}

var defaultPorts = []int{22, 21, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8888, 9200, 11211, 27017}

// Default 返回默认配置。
func Default() *Config {
	return &Config{
		Ports:        append([]int(nil), defaultPorts...),
		IntervalBans: 1,
		IntervalLog:  10,
		IntervalDdns: 120,
		LogLevel:     0,
		DdnsDomains:  []string{},
		AllowStatic:  []string{"127.0.0.1/8", "::1"},
		DataDir:      "auto",
		DebugLog:     false,
	}
}

// DefaultTemplate 生成默认配置文件时写入的完整内容（含中文注释）。
const DefaultTemplate = `# PotLite（轻蜜罐）配置文件
# 修改后执行 systemctl reload potlite 热重载生效

# 蜜罐监听端口（逗号分隔，可增删）
ports = 22,21,23,25,110,135,139,143,445,1433,3306,3389,5432,5900,6379,8080,8888,9200,11211,27017

# 封禁名单保存间隔（单位：分钟）
interval.bans = 1

# 日志级别：0=不记录 1=记录IP与触发端口 2=增加被拒总次数 3=增加端口明细
log.level = 0
# 日志保存间隔（单位：分钟）
interval.log = 10

# DDNS 白名单域名（逗号分隔，留空则只使用静态白名单）
ddns.domains = 
# 域名重新解析间隔（单位：分钟）
interval.ddns = 120

# 静态白名单 IP/CIDR（逗号分隔）
allow.static = 127.0.0.1/8,::1

# 数据目录：auto=自动（/root 可写则 /root，否则程序目录）；也可填写绝对路径
data.dir = auto

# debug 日志开关：0=不记录（默认） 1=记录程序运行细节（排障时开启）
debug.log = 0
`

// Load 读取配置文件；文件不存在时先生成默认配置再使用。
func Load(path string) (*Config, error) {
	cfg := Default()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		if werr := os.WriteFile(path, []byte(DefaultTemplate), 0600); werr != nil {
			return nil, fmt.Errorf("生成默认配置失败: %w", werr)
		}
		f, err = os.Open(path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 256*1024)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			warnf("忽略无法解析的配置行: %s", line)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		cfg.apply(key, val)
	}
	return cfg, sc.Err()
}

func (c *Config) apply(key, val string) {
	switch key {
	case "ports":
		if list, ok := parseIntList(val); ok && len(list) > 0 {
			c.Ports = list
		} else {
			warnf("ports 值无效，使用默认端口")
		}
	case "interval.bans":
		if v, ok := parseIntIn(val, 1, 1440); ok {
			c.IntervalBans = v
		} else {
			warnf("interval.bans 值无效（需 1-1440），使用默认 %d", c.IntervalBans)
		}
	case "interval.log":
		if v, ok := parseIntIn(val, 1, 1440); ok {
			c.IntervalLog = v
		} else {
			warnf("interval.log 值无效（需 1-1440），使用默认 %d", c.IntervalLog)
		}
	case "interval.ddns":
		if v, ok := parseIntIn(val, 1, 10080); ok {
			c.IntervalDdns = v
		} else {
			warnf("interval.ddns 值无效（需 1-10080），使用默认 %d", c.IntervalDdns)
		}
	case "log.level":
		if v, ok := parseIntIn(val, 0, 1); ok {
			c.LogLevel = v
		} else {
			warnf("log.level 值无效（需 0-1），使用默认 %d", c.LogLevel)
		}
	case "ddns.domains":
		c.DdnsDomains = splitList(val)
	case "allow.static":
		if list := splitList(val); len(list) > 0 {
			c.AllowStatic = list
		}
	case "data.dir":
		if val != "" {
			c.DataDir = val
		}
	case "debug.log":
		if v, ok := parseIntIn(val, 0, 1); ok {
			c.DebugLog = v == 1
		} else {
			warnf("debug.log 值无效（需 0 或 1），使用默认 0")
		}
	default:
		warnf("未知配置项 %q 已忽略", key)
	}
}

func splitList(val string) []string {
	var out []string
	for _, s := range strings.Split(val, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseIntList(val string) ([]int, bool) {
	parts := splitList(val)
	if len(parts) == 0 {
		return nil, false
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 1 || v > 65535 {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

func parseIntIn(val string, lo, hi int) (int, bool) {
	v, err := strconv.Atoi(val)
	if err != nil || v < lo || v > hi {
		return 0, false
	}
	return v, true
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "potlite: 警告: "+format+"\n", args...)
}

// Package config 实现 potlite.config 的解析、生成与模板同步。
// 解析规则（对小白宽容）：等号前后空格无影响；空行跳过；行首 # 为注释；
// 键名大小写不敏感；未知键警告后忽略；兼容 CRLF；非法值回退默认并警告。
//
// 配置文件按"设置块"组织：每块用 ########################## 上下包裹。
// 版本升级时以新模板为准重写（注释替换为最新、用户的变量值保留、
// 模板新增键自动补入、模板已移除的键列入失效清单并不再写回）。
package config

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Config 全部配置项。
type Config struct {
	Ports          []int     // 蜜罐监听端口
	BanDays        float64   // 封禁时间（天）：0=永久封禁；>0 到期自动解封，支持小数（0.15=3小时36分）
	IntervalBans   int       // bans 落盘间隔（分钟）
	IntervalLog    int      // CSV 落盘间隔（分钟）
	IntervalDdns   int      // DDNS 解析间隔（分钟）
	LogLevel       int      // 日志级别 0-1
	DdnsDomains    []string // DDNS 白名单域名
	AllowStatic    []string // 静态白名单 IP/CIDR
	DataDir        string   // auto 或绝对路径
	DebugLog       bool     // debug 日志开关
	FireholLevel1  bool     // FireHOL level1 黑名单
	FireholWeb     bool     // FireHOL webserver 黑名单
	FireholIpsum3  bool     // FireHOL ipsum_3 黑名单
	LatestVersion  string   // 程序自动维护：每天 0 点检查 GitHub 后写入的最新版本号
	TotalRejected     uint64 // 总计拒绝次数（历史累计）
	TotalRejectedBase uint64 // 最近存档时对应的本次启动内核实时值（滚动基数）
	OutboundAllow       bool  // 出站自动白名单开关（默认开）
	OutboundPorts       []int // 放行端口（空 = 全部端口）
	OutboundMinutes     int   // 普通远端时效分钟（默认 240）
	OutboundBlackMinutes int  // 黑名单内远端时效分钟（默认 10）
}

var defaultPorts = []int{22, 21, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8888, 9200, 11211, 27017}

// Default 返回默认配置。
func Default() *Config {
	return &Config{
		Ports:        append([]int(nil), defaultPorts...),
		BanDays:      0,
		IntervalBans: 1,
		IntervalLog:  10,
		IntervalDdns: 120,
		LogLevel:     0,
		DdnsDomains:  []string{},
		AllowStatic:  []string{"127.0.0.1/8", "::1"},
		DataDir:      "auto",
		DebugLog:     false,
		OutboundAllow:       true,
		OutboundPorts:       nil,
		OutboundMinutes:     240,
		OutboundBlackMinutes: 10,
	}
}

// DefaultTemplate 完整配置模板（按设置块组织，含中文注释）。
// 版本升级时程序以本模板为准重写配置文件（保留用户值）。
const DefaultTemplate = `# PotLite 轻蜜罐配置文件
# 修改后执行 potlite reload 热重载生效

##########################
# 蜜罐监听端口(逗号分隔)。支持端口段(如 100-300,500-300)与排除(如 -80 , -80--90)
# 默认20个端口为 22,21,23,25,110,135,139,143,445,1433,3306,3389,5432,5900,6379,8080,8888,9200,11211,27017
ports = 22,21,23,25,110,135,139,143,445,1433,3306,3389,5432,5900,6379,8080,8888,9200,11211,27017
##########################

##########################
# 封禁时间(单位:天):0=永久封禁(默认);填写数字则到期自动解封,支持小数
# 例:7=封禁7天;0.15=封禁3小时36分
ban.days = 0
##########################

##########################
# 封禁名单(potlite.bans)保存间隔(单位:分钟)
interval.bans = 1
##########################

##########################
# 日志开关:0=不记录(默认值) 1=记录(保存为potlite.log.csv,内容为:IP、拒绝次数、首次封禁时间、最近封禁时间)
log.level = 0
# 日志保存间隔(单位:分钟)
interval.log = 10
# debug日志开关:0=不记录(默认) 1=记录程序运行细节(排障时开启)
debug.log = 0
##########################

##########################
# DDNS 白名单域名(逗号分隔,留空则只使用静态白名单)
ddns.domains = 
# 域名重新解析间隔(单位:分钟)
interval.ddns = 120
##########################

##########################
# 静态白名单 IP/CIDR(逗号分隔)
allow.static = 127.0.0.1/8,::1
##########################

##########################
# 数据目录:auto=自动(/root 可写则 /root,否则程序目录)；也可填写绝对路径
data.dir = auto
##########################

##########################
#来自于FireHOL的在线黑名单,根据需求使用,0=不启用(默认),1=启用,每日0点自动更新。
#level1,基础黑名单,误封率低,推荐使用。
firehol.level1 = 0
#当服务器有web服务时推荐
firehol.webserver = 0
#被超过3个黑名单列表均收录的IP地址,黑名单质量高
firehol.ipsum3 = 0
##########################

##########################
# 出站自动白名单：服务器主动连接过的远端 IP,在时效内对其放行指定端口（不填则为全部端口）的新连接
outbound.allow = 1
# 放行端口（仅对自动白名单内 IP 生效）
outbound.ports = 
# 出站自动白名单时效（分钟）
outbound.minutes = 240
# 当远端IP处于黑名单时，自动白名单失效（分钟,避免误白长期放行）
outbound.black.minutes = 10
##########################

##########################
# 系统使用字段,请勿手工修改
latest.version = 
total.rejected = 0
total.rejected.base = 0
##########################
`

// Load 读取配置文件；文件不存在时先生成默认配置再使用。
// 返回的 invalidKeys 为"旧配置中存在但当前版本已不支持"的键列表（程序按默认值运行）。
func Load(path string) (*Config, []string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if werr := os.WriteFile(path, []byte(DefaultTemplate), 0600); werr != nil {
			return nil, nil, fmt.Errorf("生成默认配置失败: %w", werr)
		}
		return Default(), nil, nil
	}
	// 以模板为准重写（保留用户值），得到失效键清单
	invalid, err := WriteBack(path, nil)
	if err != nil {
		return nil, nil, err
	}
	cfg := Default()
	f, err := os.Open(path)
	if err != nil {
		return nil, invalid, err
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
	return cfg, invalid, sc.Err()
}

// WriteBack 以模板为准重写配置文件：注释替换为最新、用户的变量值保留、
// 模板新增键自动补入、模板已移除的键列入失效清单（不再写回）。
// kvs 为额外要写入的值（程序自动维护字段用）。返回失效键列表。
func WriteBack(path string, kvs map[string]string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	userVals := extractKeyValues(string(data))
	tmplKeys := extractKeyValues(DefaultTemplate)
	// 失效键：现有文件有、模板没有
	var invalid []string
	for k := range userVals {
		if _, ok := tmplKeys[k]; !ok {
			invalid = append(invalid, k)
		}
	}
	sort.Strings(invalid)
	// 合并额外值
	for k, v := range kvs {
		userVals[k] = v
	}
	// 模板重写 + 回填用户值
	out := DefaultTemplate
	for k, v := range userVals {
		if _, ok := tmplKeys[k]; !ok {
			continue // 失效键不写回
		}
		out = replaceKeyValue(out, k, v)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(out), 0600); err != nil {
		return invalid, err
	}
	return invalid, os.Rename(tmp, path)
}

// extractKeyValues 从文本中提取所有"键 = 值"（非注释行，键名小写）。
func extractKeyValues(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		eq := strings.Index(trimmed, "=")
		if eq <= 0 || strings.HasPrefix(trimmed, "#") {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(trimmed[:eq]))
		out[k] = strings.TrimSpace(trimmed[eq+1:])
	}
	return out
}

// replaceKeyValue 在文本中把指定键的值行替换为 "键 = 值"（保持缩进）。
func replaceKeyValue(text, key, val string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		eq := strings.Index(trimmed, "=")
		if eq <= 0 || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.ToLower(strings.TrimSpace(trimmed[:eq])) == key {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + key + " = " + val
			break
		}
	}
	return strings.Join(lines, "\n")
}

func (c *Config) apply(key, val string) {
	switch key {
	case "ports":
		if inc, exc, ok := parsePortRanges(val); ok {
			list := expandPorts(inc, exc)
			if len(list) > 0 {
				c.Ports = list
			} else {
				warnf("ports 展开后为空，使用默认端口")
			}
		} else {
			warnf("ports 值无效，使用默认端口")
		}
	case "ban.days":
		if v, ok := parseFloatIn(val, 0, 36500); ok {
			c.BanDays = v
		} else {
			warnf("ban.days 值无效（需 0-36500 天），使用默认 0（永久封禁）")
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
	case "firehol.level1":
		c.FireholLevel1 = val == "1"
	case "firehol.webserver":
		c.FireholWeb = val == "1"
	case "firehol.ipsum3":
		c.FireholIpsum3 = val == "1"
	case "latest.version":
		if val != "" {
			c.LatestVersion = val
		}
	case "total.rejected":
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			c.TotalRejected = v
		}
	case "total.rejected.base":
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			c.TotalRejectedBase = v
		}
	case "outbound.allow":
		if v, ok := parseIntIn(val, 0, 1); ok {
			c.OutboundAllow = v == 1
		} else {
			warnf("outbound.allow 值无效（需 0 或 1），使用默认 0")
		}
	case "outbound.ports":
		if val == "" {
			c.OutboundPorts = nil // 空 = 放行全部端口
			return
		}
		if inc, exc, ok := parsePortRanges(val); ok && len(exc) == 0 {
			if list := expandPorts(inc, nil); len(list) > 0 {
				c.OutboundPorts = list
			} else {
				warnf("outbound.ports 值无效，使用默认（全部端口）")
			}
		} else {
			warnf("outbound.ports 值无效，使用默认（全部端口）")
		}
	case "outbound.hours": // 旧键（小时），兼容转换
		if v, ok := parseIntIn(val, 1, 30); ok {
			c.OutboundMinutes = v * 60
		} else {
			warnf("outbound.hours 值无效，使用默认 240")
		}
	case "outbound.minutes":
		if v, ok := parseIntIn(val, 1, 43200); ok {
			c.OutboundMinutes = v
		} else {
			warnf("outbound.minutes 值无效（需 1-43200），使用默认 %d", c.OutboundMinutes)
		}
	case "outbound.black.minutes":
		if v, ok := parseIntIn(val, 1, 43200); ok {
			c.OutboundBlackMinutes = v
		} else {
			warnf("outbound.black.minutes 值无效（需 1-43200），使用默认 %d", c.OutboundBlackMinutes)
		}
	default:
		warnf("未知配置项 %q 已忽略", key)
	}
}

func splitList(val string) []string {
	val = strings.ReplaceAll(val, "，", ",") // 中文逗号兼容
	var out []string
	for _, s := range strings.Split(val, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// portRange 端口段（单端口即 lo==hi）。
type portRange struct{ lo, hi int }

// parsePortRanges 解析逗号分隔的端口配置：
//   - 单端口：22
//   - 段：10000-20000（反向 20000-10000 等价，自动归一化）
//   - 排除：以负号开头，如 -11111--11114（排除 11111~11114；反向写法等价）
//
// 返回（包含段, 排除段, 是否有效）。
func parsePortRanges(val string) ([]portRange, []portRange, bool) {
	var inc, exc []portRange
	for _, item := range splitList(val) {
		exclude := false
		if strings.HasPrefix(item, "-") {
			exclude = true
			item = item[1:]
		}
		// 规范化连续横杠：-11111--11114 去掉前缀负号后为 11111--11114 → 11111-11114
		for strings.Contains(item, "--") {
			item = strings.ReplaceAll(item, "--", "-")
		}
		var r portRange
		if strings.Contains(item, "-") {
			parts := strings.SplitN(item, "-", 2)
			a, err1 := strconv.Atoi(parts[0])
			b, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil || a < 1 || b < 1 || a > 65535 || b > 65535 {
				return nil, nil, false
			}
			r.lo, r.hi = min(a, b), max(a, b) // 反向归一化
		} else {
			v, err := strconv.Atoi(item)
			if err != nil || v < 1 || v > 65535 {
				return nil, nil, false
			}
			r.lo, r.hi = v, v
		}
		if exclude {
			exc = append(exc, r)
		} else {
			inc = append(inc, r)
		}
	}
	return inc, exc, len(inc) > 0
}

// expandPorts 展开包含段为端口列表并剔除排除段（排除不存在的端口静默忽略）。
func expandPorts(inc, exc []portRange) []int {
	var out []int
	for _, r := range inc {
		for p := r.lo; p <= r.hi; p++ {
			out = append(out, p)
		}
	}
	if len(exc) == 0 {
		return out
	}
	exSet := make(map[int]struct{})
	for _, r := range exc {
		for p := r.lo; p <= r.hi; p++ {
			exSet[p] = struct{}{}
		}
	}
	filtered := out[:0]
	for _, p := range out {
		if _, ok := exSet[p]; !ok {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func parseIntIn(val string, lo, hi int) (int, bool) {
	v, err := strconv.Atoi(val)
	if err != nil || v < lo || v > hi {
		return 0, false
	}
	return v, true
}

// parseFloatIn 解析小数配置值（ban.days 等），越界返回 false。
func parseFloatIn(val string, lo, hi float64) (float64, bool) {
	v, err := strconv.ParseFloat(val, 64)
	if err != nil || v < lo || v > hi {
		return 0, false
	}
	return v, true
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "potlite: 警告: "+format+"\n", args...)
}

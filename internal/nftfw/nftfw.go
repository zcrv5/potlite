// Package nftfw 封装 nftables 操作：表/集合/规则链的创建与元素维护。
//
// 表结构：inet potlite（与 fail2ban 的 f2b-table、云镜 ip filter 完全隔离）。
// 规则链顺序（蜜罐端口流量）：白名单 accept → 已封静默 drop → 新 SYN dynset 封禁 → 全端口静默 drop（黑洞）。
//
// 实测确立的内核限制（7.1.5，设计依据）：
//   - dynset（规则内动态添加）**不支持 interval 集合**（EOPNOTSUPP），支持 counter 集合；
//   - 因此：banned4/pending6 用 counter（无 interval）承接 dynset；
//     banned6（interval+counter）只接受手动写入（IPv6 /64 段），pending6 周期搬运升级为段。
package nftfw

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	tableName = "potlite"
	chainName = "input"
	setPorts  = "ports"
	setWl4    = "whitelist4"
	setWl6    = "whitelist6"
	setBan4   = "banned4"  // counter，无 interval：dynset v4 目标 + 全端口静默 drop
	setBan4Nets = "banned4nets" // interval + counter：v4 段封禁（FireHOL 等 CIDR 名单），全端口静默 drop
	setObPorts = "ob_ports"     // inet_service：出站自动白名单放行的新连接端口（空 = 全端口模式）
	setObOk    = "ob_ok"        // ipv4：出站自动白名单（端口限定模式）
	setObOk6   = "ob_ok6"       // ipv6：同上
	setObAll   = "ob_all"       // ipv4：出站自动白名单（全端口模式，ports 为空时）
	setObAll6  = "ob_all6"      // ipv6：同上
	setBan6   = "banned6"  // interval + counter：IPv6 /64 段主集合（手动写入）
	setPend6  = "pending6" // counter，无 interval：dynset v6 目标，周期搬运进 banned6
)

// FW 是 nftables 防火墙封装。
type FW struct {
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
	ports *nftables.Set
	wl4   *nftables.Set
	wl6   *nftables.Set
	ban4  *nftables.Set
	ban4Nets *nftables.Set
	ban6  *nftables.Set
	pend6 *nftables.Set
	obPorts *nftables.Set
	obOk  *nftables.Set
	obOk6 *nftables.Set
	obAll *nftables.Set
	obAll6 *nftables.Set
}

// New 建立 nftables 连接。
func New() (*FW, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("连接 nftables 失败: %w", err)
	}
	return &FW{conn: conn, table: &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}}, nil
}

// Attach 挂接已存在的防火墙结构（CLI 管理命令用；serve 用 Setup 建表）。
// 表不存在时返回友好错误。
func (f *FW) Attach() error {
	tables, err := f.conn.ListTables()
	if err != nil {
		return fmt.Errorf("列出 nftables 表失败: %w", err)
	}
	found := false
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyINet {
			f.table = t
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("未找到防火墙表 %s：请先运行 potlite serve 启动服务", tableName)
	}
	chains, err := f.conn.ListChains()
	if err != nil {
		return fmt.Errorf("列出链失败: %w", err)
	}
	for _, c := range chains {
		if c.Table.Name == tableName && c.Name == chainName {
			f.chain = c
		}
	}
	sets, err := f.conn.GetSets(f.table)
	if err != nil {
		return fmt.Errorf("列出集合失败: %w", err)
	}
	for _, s := range sets {
		switch s.Name {
		case setPorts:
			f.ports = s
		case setWl4:
			f.wl4 = s
		case setWl6:
			f.wl6 = s
		case setBan4:
			f.ban4 = s
		case setBan4Nets:
			f.ban4Nets = s
		case setBan6:
			f.ban6 = s
		case setPend6:
			f.pend6 = s
		case setObPorts:
			f.obPorts = s
		case setObOk:
			f.obOk = s
		case setObOk6:
			f.obOk6 = s
		case setObAll:
			f.obAll = s
		case setObAll6:
			f.obAll6 = s
		}
	}
	if f.wl4 == nil || f.wl6 == nil || f.ban4 == nil || f.ban4Nets == nil || f.ban6 == nil || f.pend6 == nil {
		return fmt.Errorf("防火墙集合不完整，请重新运行 potlite serve")
	}
	return nil
}

// Setup 全量（重）建防火墙结构：删旧表、建表/集合/链、写入端口与 10 条规则。
// Setup 全量重建防火墙（表/集合/链/规则）。
// 幂等：重复调用等价于重建。
func (f *FW) Setup(ports []int) error {
	f.conn.DelTable(f.table)
	f.conn.Flush()
	f.conn.AddTable(f.table)

	f.ports = &nftables.Set{Table: f.table, Name: setPorts, KeyType: nftables.TypeInetService}
	f.wl4 = &nftables.Set{Table: f.table, Name: setWl4, KeyType: nftables.TypeIPAddr, Interval: true}
	f.wl6 = &nftables.Set{Table: f.table, Name: setWl6, KeyType: nftables.TypeIP6Addr, Interval: true}
	f.ban4 = &nftables.Set{Table: f.table, Name: setBan4, KeyType: nftables.TypeIPAddr, Counter: true}
	f.ban4Nets = &nftables.Set{Table: f.table, Name: setBan4Nets, KeyType: nftables.TypeIPAddr, Interval: true, Counter: true}
	f.ban6 = &nftables.Set{Table: f.table, Name: setBan6, KeyType: nftables.TypeIP6Addr, Interval: true, Counter: true}
	f.pend6 = &nftables.Set{Table: f.table, Name: setPend6, KeyType: nftables.TypeIP6Addr, Counter: true}
	f.obPorts = &nftables.Set{Table: f.table, Name: setObPorts, KeyType: nftables.TypeInetService}
	f.obOk = &nftables.Set{Table: f.table, Name: setObOk, KeyType: nftables.TypeIPAddr}
	f.obOk6 = &nftables.Set{Table: f.table, Name: setObOk6, KeyType: nftables.TypeIP6Addr}
	f.obAll = &nftables.Set{Table: f.table, Name: setObAll, KeyType: nftables.TypeIPAddr}
	f.obAll6 = &nftables.Set{Table: f.table, Name: setObAll6, KeyType: nftables.TypeIP6Addr}
	for _, s := range []*nftables.Set{f.ports, f.wl4, f.wl6, f.ban4, f.ban4Nets, f.ban6, f.pend6, f.obPorts, f.obOk, f.obOk6, f.obAll, f.obAll6} {
		if err := f.conn.AddSet(s, nil); err != nil {
			return fmt.Errorf("创建集合 %s 失败: %w", s.Name, err)
		}
	}

	f.chain = &nftables.Chain{
		Table:    f.table,
		Name:     chainName,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityRef(0),
	}
	f.chain = f.conn.AddChain(f.chain)

	// 端口元素（inet_service，2 字节大端）
	els := make([]nftables.SetElement, 0, len(ports))
	for _, p := range ports {
		els = append(els, nftables.SetElement{Key: []byte{byte(p >> 8), byte(p & 0xff)}})
	}
	if err := f.conn.SetAddElements(f.ports, els); err != nil {
		return fmt.Errorf("写入端口失败: %w", err)
	}

	// 规则（established 回程放行最前，出站自动白名单其后）
	f.addRule(f.ruleEstablished())
	f.addRule(f.ruleObAccept(false))
	f.addRule(f.ruleObAccept(true))
	f.addRule(f.ruleObAcceptAll(false))
	f.addRule(f.ruleObAcceptAll(true))
	f.addRule(f.ruleWhitelist(false))
	f.addRule(f.ruleWhitelist(true))
	f.addRule(f.ruleBannedDrop(false, setBan4))
	f.addRule(f.ruleBannedDrop(true, setPend6))
	f.addRule(f.ruleBannedDrop(true, setBan6))
	f.addRule(f.ruleDynsetBan(false, setBan4))
	f.addRule(f.ruleDynsetBan(true, setPend6))
	f.addRule(f.ruleAllDrop(false, setBan4))
	f.addRule(f.ruleAllDrop(false, setBan4Nets))
	f.addRule(f.ruleAllDrop(true, setPend6))
	f.addRule(f.ruleAllDrop(true, setBan6))
	return f.conn.Flush()
}

// Ban 封禁 IP：IPv4 写单 IP 进 banned4；IPv6 取 /64 段写 banned6（双端点表示）。
// BanPrefix 封禁一个前缀段（v4 任意段 / v6 任意段），带计数器。
// v4 段进 banned4nets（interval），v6 段进 banned6。
func (f *FW) BanPrefix(p netip.Prefix) error {
	p = p.Masked()
	if p.Addr().Is4() {
		if err := f.conn.SetAddElements(f.ban4Nets, prefixElems(p)); err != nil {
			return err
		}
		return f.conn.Flush()
	}
	if err := f.conn.SetAddElements(f.ban6, prefixElems(p)); err != nil {
		return err
	}
	return f.conn.Flush()
}

// UnbanPrefix 解除一个前缀段的封禁。
func (f *FW) UnbanPrefix(p netip.Prefix) error {
	p = p.Masked()
	if p.Addr().Is4() {
		if err := f.conn.SetDeleteElements(f.ban4Nets, prefixElems(p)); err != nil {
			return err
		}
		return f.conn.Flush()
	}
	if err := f.conn.SetDeleteElements(f.ban6, prefixElems(p)); err != nil {
		return err
	}
	return f.conn.Flush()
}

// BanPrefixMany 批量封禁前缀段（外部黑名单组 diff 用，避免逐条 netlink 往返）：
// v4 段进 banned4nets，v6 段进 banned6。
// 关键处理：① 按段去重（名单间相同段）；② 排序后做区间合并——重叠/相邻区间合并为
// 最大区间（interval 集合为半开区间 [start,end) 语义，任意区间用双端点编码写入，
// 合并后覆盖完整、无重叠、段数最少，不会因 EEXIST 毁批）；③ 分批写入。
func (f *FW) BanPrefixMany(prefixes []netip.Prefix) error {
	var v4pfx, v6pfx []netip.Prefix
	seen := make(map[string]struct{}, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		if _, dup := seen[p.String()]; dup {
			continue
		}
		seen[p.String()] = struct{}{}
		if p.Addr().Is4() {
			v4pfx = append(v4pfx, p)
		} else {
			v6pfx = append(v6pfx, p)
		}
	}
	// 排序 + 区间合并：返回合并后的 [start, end) 区间对（半开区间终点 = 最后地址+1）
	type span struct{ start, end netip.Addr }
	merge := func(pfx []netip.Prefix) []span {
		sort.Slice(pfx, func(i, j int) bool { return pfx[i].Addr().Less(pfx[j].Addr()) })
		var out []span
		var curStart, curEnd netip.Addr
		for _, p := range pfx {
			start := p.Addr()
			end := prefixLast(p).Next()
			if !end.IsValid() {
				end = prefixLast(p)
			}
			if !curEnd.IsValid() {
				curStart, curEnd = start, end
				continue
			}
			if start.Less(curEnd) || start == curEnd {
				// 重叠或相邻 → 合并（终点取更大）
				if curEnd.Less(end) {
					curEnd = end
				}
				continue
			}
			out = append(out, span{curStart, curEnd})
			curStart, curEnd = start, end
		}
		if curEnd.IsValid() {
			out = append(out, span{curStart, curEnd})
		}
		return out
	}
	// 区间 → interval 集合双端点元素
	spanElems := func(s span) []nftables.SetElement {
		return []nftables.SetElement{
			{Key: append([]byte(nil), s.start.AsSlice()...)},
			{Key: append([]byte(nil), s.end.AsSlice()...), IntervalEnd: true},
		}
	}
	var els4, els6 []nftables.SetElement
	for _, s := range merge(v4pfx) {
		els4 = append(els4, spanElems(s)...)
	}
	for _, s := range merge(v6pfx) {
		els6 = append(els6, spanElems(s)...)
	}
	const batchElems = 250
	write := func(set *nftables.Set, els []nftables.SetElement) error {
		for i := 0; i < len(els); i += batchElems {
			end := i + batchElems
			if end > len(els) {
				end = len(els)
			}
			if err := f.conn.SetAddElements(set, els[i:end]); err != nil {
				// 兜底：批量意外失败时逐条写入，重复/冲突元素静默丢弃
				for _, el := range els[i:end] {
					_ = f.conn.SetAddElements(set, []nftables.SetElement{el})
					_ = f.conn.Flush()
				}
				continue
			}
			if err := f.conn.Flush(); err != nil {
				for _, el := range els[i:end] {
					_ = f.conn.SetAddElements(set, []nftables.SetElement{el})
					_ = f.conn.Flush()
				}
			}
		}
		return nil
	}
	if len(els4) > 0 {
		if err := write(f.ban4Nets, els4); err != nil {
			return err
		}
	}
	if len(els6) > 0 {
		if err := write(f.ban6, els6); err != nil {
			return err
		}
	}
	return nil
}

// UnbanPrefixMany 批量解除前缀段封禁（外部黑名单组 diff 用）。按段去重；
// 失败批退化为逐条删除（不存在的元素静默忽略）。
func (f *FW) UnbanPrefixMany(prefixes []netip.Prefix) error {
	var els4, els6 []nftables.SetElement
	seen := make(map[string]struct{}, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		if _, dup := seen[p.String()]; dup {
			continue
		}
		seen[p.String()] = struct{}{}
		if p.Addr().Is4() {
			els4 = append(els4, prefixElems(p)...)
		} else {
			els6 = append(els6, prefixElems(p)...)
		}
	}
	const batchElems = 250
	del := func(set *nftables.Set, els []nftables.SetElement) error {
		for i := 0; i < len(els); i += batchElems {
			end := i + batchElems
			if end > len(els) {
				end = len(els)
			}
			if err := f.conn.SetDeleteElements(set, els[i:end]); err != nil {
				for _, el := range els[i:end] {
					_ = f.conn.SetDeleteElements(set, []nftables.SetElement{el})
					_ = f.conn.Flush()
				}
				continue
			}
			if err := f.conn.Flush(); err != nil {
				for _, el := range els[i:end] {
					_ = f.conn.SetDeleteElements(set, []nftables.SetElement{el})
					_ = f.conn.Flush()
				}
			}
		}
		return nil
	}
	if len(els4) > 0 {
		if err := del(f.ban4Nets, els4); err != nil {
			return err
		}
	}
	if len(els6) > 0 {
		if err := del(f.ban6, els6); err != nil {
			return err
		}
	}
	return nil
}

func (f *FW) Ban(ip netip.Addr) error {
	if ip.Is4() {
		if err := f.conn.SetAddElements(f.ban4, []nftables.SetElement{{Key: ip.AsSlice()}}); err != nil {
			return err
		}
		return f.conn.Flush()
	}
	p := netip.PrefixFrom(ip, 64).Masked()
	if err := f.conn.SetAddElements(f.ban6, prefixElems(p)); err != nil {
		return err
	}
	return f.conn.Flush()
}

// Unban 解封。
func (f *FW) Unban(ip netip.Addr) error {
	if ip.Is4() {
		if err := f.conn.SetDeleteElements(f.ban4, []nftables.SetElement{{Key: ip.AsSlice()}}); err != nil {
			return err
		}
		return f.conn.Flush()
	}
	p := netip.PrefixFrom(ip, 64).Masked()
	if err := f.conn.SetDeleteElements(f.ban6, prefixElems(p)); err != nil {
		return err
	}
	return f.conn.Flush()
}

// UnbanMany 批量解封（到期解封用，避免逐条 netlink 往返卡住周期）。
// 分批删除（单条消息长度限制同 ReplayBans）；v6 段按 /64 折叠去重。
// 调用方注意：元素已不存在的删除会报错（逐条兜底或忽略错误）。
func (f *FW) UnbanMany(ips []netip.Addr) error {
	var els4 []nftables.SetElement
	seen6 := make(map[string]struct{})
	var els6 []nftables.SetElement
	for _, ip := range ips {
		if ip.Is4() {
			els4 = append(els4, nftables.SetElement{Key: ip.AsSlice()})
			continue
		}
		p := netip.PrefixFrom(ip, 64).Masked()
		if _, dup := seen6[p.String()]; dup {
			continue
		}
		seen6[p.String()] = struct{}{}
		els6 = append(els6, prefixElems(p)...)
	}
	const batchElems = 250
	del := func(set *nftables.Set, els []nftables.SetElement) error {
		for i := 0; i < len(els); i += batchElems {
			end := i + batchElems
			if end > len(els) {
				end = len(els)
			}
			if err := f.conn.SetDeleteElements(set, els[i:end]); err != nil {
				return err
			}
			if err := f.conn.Flush(); err != nil {
				return err
			}
		}
		return nil
	}
	if len(els4) > 0 {
		if err := del(f.ban4, els4); err != nil {
			return err
		}
	}
	if len(els6) > 0 {
		if err := del(f.ban6, els6); err != nil {
			return err
		}
	}
	return nil
}

// MovePending6 搬运：把 pending6 中的动态封禁（单地址）升级为 /64 段写入 banned6 并清除。
// 周期任务调用（interval.bans）。
func (f *FW) MovePending6() (int, error) {
	els, err := f.conn.GetSetElements(f.pend6)
	if err != nil {
		return 0, fmt.Errorf("读取 pending6 失败: %w", err)
	}
	moved := 0
	for _, el := range els {
		addr, ok := netip.AddrFromSlice(el.Key)
		if !ok || addr.Is4() {
			continue
		}
		p := netip.PrefixFrom(addr, 64).Masked()
		if err := f.conn.SetAddElements(f.ban6, prefixElems(p)); err != nil {
			continue // 已存在等错误容忍
		}
		if err := f.conn.SetDeleteElements(f.pend6, []nftables.SetElement{{Key: el.Key}}); err != nil {
			continue
		}
		moved++
	}
	if moved > 0 {
		f.conn.Flush()
	}
	return moved, nil
}

// Allow 加入白名单（v4 单 IP/CIDR；v6 段）。
func (f *FW) Allow(p netip.Prefix) error {
	p = p.Masked()
	if p.Addr().Is4() {
		if err := f.conn.SetAddElements(f.wl4, prefixElems(p)); err != nil {
			return err
		}
		return f.conn.Flush()
	}
	if err := f.conn.SetAddElements(f.wl6, prefixElems(p)); err != nil {
		return err
	}
	return f.conn.Flush()
}

// Disallow 移出白名单。
func (f *FW) Disallow(p netip.Prefix) error {
	p = p.Masked()
	if p.Addr().Is4() {
		if err := f.conn.SetDeleteElements(f.wl4, prefixElems(p)); err != nil {
			return err
		}
		return f.conn.Flush()
	}
	if err := f.conn.SetDeleteElements(f.wl6, prefixElems(p)); err != nil {
		return err
	}
	return f.conn.Flush()
}

// ReplayBans 启动重放：批量写入封禁名单（Setup 之后调用；v6 段进 banned6）。
// 分批写入：SetAddElements 会把全部元素编入单条 netlink 消息，条目多时
// 超出内核消息长度上限（sendmsg: message too long，启动即失败），
// 故按批发送（每批独立 Flush）；v6 段先按 /64 折叠去重，避免跨批重复元素报错。
func (f *FW) ReplayBans(bans []netip.Addr) error {
	if len(bans) == 0 {
		return nil
	}
	var els4 []nftables.SetElement
	seen6 := make(map[string]struct{})
	var els6 []nftables.SetElement
	for _, ip := range bans {
		if ip.Is4() {
			els4 = append(els4, nftables.SetElement{Key: ip.AsSlice()})
			continue
		}
		p := netip.PrefixFrom(ip, 64).Masked()
		if _, dup := seen6[p.String()]; dup {
			continue
		}
		seen6[p.String()] = struct{}{}
		els6 = append(els6, prefixElems(p)...)
	}
	const batchElems = 250 // 每批元素数（单消息 ~10KB，远低于内核上限）
	write := func(set *nftables.Set, els []nftables.SetElement) error {
		for i := 0; i < len(els); i += batchElems {
			end := i + batchElems
			if end > len(els) {
				end = len(els)
			}
			if err := f.conn.SetAddElements(set, els[i:end]); err != nil {
				return err
			}
			if err := f.conn.Flush(); err != nil {
				return err
			}
		}
		return nil
	}
	if len(els4) > 0 {
		if err := write(f.ban4, els4); err != nil {
			return fmt.Errorf("重放 v4 封禁失败: %w", err)
		}
	}
	if len(els6) > 0 {
		if err := write(f.ban6, els6); err != nil {
			return fmt.Errorf("重放 v6 封禁失败: %w", err)
		}
	}
	return nil
}

// ReplayWhitelist 白名单重放（Setup 之后调用，全量）。
func (f *FW) ReplayWhitelist(items []netip.Prefix) error {
	var els4, els6 []nftables.SetElement
	for _, p := range items {
		p = p.Masked()
		if p.Addr().Is4() {
			els4 = append(els4, prefixElems(p)...)
		} else {
			els6 = append(els6, prefixElems(p)...)
		}
	}
	if len(els4) > 0 {
		if err := f.conn.SetAddElements(f.wl4, els4); err != nil {
			return fmt.Errorf("重放 v4 白名单失败: %w", err)
		}
	}
	if len(els6) > 0 {
		if err := f.conn.SetAddElements(f.wl6, els6); err != nil {
			return fmt.Errorf("重放 v6 白名单失败: %w", err)
		}
	}
	return f.conn.Flush()
}

// RemoveTable 删除 potlite 表（uninstall 用，清空全部封禁）。
func (f *FW) RemoveTable() {
	f.conn.DelTable(f.table)
	f.conn.Flush()
}

// SyncPorts 热更新蜜罐端口集合（SIGHUP 重载用）：清空后写入新端口。
func (f *FW) SyncPorts(ports []int) error {
	els, err := f.conn.GetSetElements(f.ports)
	if err == nil && len(els) > 0 {
		f.conn.SetDeleteElements(f.ports, els)
	}
	newEls := make([]nftables.SetElement, 0, len(ports))
	for _, p := range ports {
		newEls = append(newEls, nftables.SetElement{Key: []byte{byte(p >> 8), byte(p & 0xff)}})
	}
	if err := f.conn.SetAddElements(f.ports, newEls); err != nil {
		return err
	}
	return f.conn.Flush()
}

// ReplaceWhitelist 白名单全量对齐（SIGHUP/DDNS 用）：清空两个集合后全量写入。
func (f *FW) ReplaceWhitelist(items []netip.Prefix) error {
	// 清空：FlushSet（DELSETELEM 不带元素 = 清空整个集合，避免逐元素删除的编码匹配问题）
	f.conn.FlushSet(f.wl4)
	f.conn.FlushSet(f.wl6)
	var els4, els6 []nftables.SetElement
	for _, p := range items {
		p = p.Masked()
		if p.Addr().Is4() {
			els4 = append(els4, prefixElems(p)...)
		} else {
			els6 = append(els6, prefixElems(p)...)
		}
	}
	if len(els4) > 0 {
		if err := f.conn.SetAddElements(f.wl4, els4); err != nil {
			return err
		}
	}
	if len(els6) > 0 {
		if err := f.conn.SetAddElements(f.wl6, els6); err != nil {
			return err
		}
	}
	return f.conn.Flush()
}

// TotalRejected 累计被拒包数（三个封禁集合的元素 counter 求和）。
func (f *FW) TotalRejected() uint64 {
	var total uint64
	for _, set := range []*nftables.Set{f.ban4, f.ban6, f.pend6} {
		els, err := f.conn.GetSetElements(set)
		if err != nil {
			continue
		}
		for _, el := range els {
			if el.Counter != nil {
				total += el.Counter.Packets
			}
		}
	}
	return total
}

// ListBannedCounters 返回 per-IP 被拒包计数（级别 2 用）。
// 键：v4 单 IP；v6 段为 /64 段首（与 ListBanned6 语义一致）。
func (f *FW) ListBannedCounters() map[string]uint64 {
	out := make(map[string]uint64)
	for _, set := range []*nftables.Set{f.ban4, f.ban6, f.pend6} {
		els, err := f.conn.GetSetElements(set)
		if err != nil {
			continue
		}
		for _, el := range els {
			if el.Counter == nil {
				continue
			}
			a, ok := netip.AddrFromSlice(el.Key)
			if !ok {
				continue
			}
			key := a.String()
			if a.Is6() {
				key = netip.PrefixFrom(a, 64).Masked().String()
			}
			out[key] += el.Counter.Packets
		}
	}
	return out
}

// BannedCount 当前内核封禁条目总数（banned4 单 IP + banned4nets 段 + banned6 段）。
func (f *FW) BannedCount() int {
	n := 0
	for _, set := range []*nftables.Set{f.ban4, f.ban4Nets, f.ban6} {
		if els, err := f.conn.GetSetElements(set); err == nil {
			n += len(els)
		}
	}
	return n
}

// ListBanned4 列出当前 banned4（单 IP）+ banned4nets（段起点）中的全部地址。
func (f *FW) ListBanned4() ([]netip.Addr, error) {
	els, err := f.conn.GetSetElements(f.ban4)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(els))
	for _, el := range els {
		if a, ok := netip.AddrFromSlice(el.Key); ok {
			out = append(out, a)
		}
	}
	// banned4nets：段元素（双端点），取起点地址（InGroup 含段匹配，组段不进主名单）
	if elsN, err := f.conn.GetSetElements(f.ban4Nets); err == nil {
		for _, el := range elsN {
			if el.IntervalEnd {
				continue
			}
			if a, ok := netip.AddrFromSlice(el.Key); ok {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// ListBanned6 列出 banned6 中的段（返回各段起始地址）。
func (f *FW) ListBanned6() ([]netip.Addr, error) {
	els, err := f.conn.GetSetElements(f.ban6)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, el := range els {
		if el.IntervalEnd {
			continue // 跳过终点元素（双端点表示）
		}
		if a, ok := netip.AddrFromSlice(el.Key); ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// SyncObPorts 同步出站自动白名单的放行端口集合（启动/重载时调用）。
func (f *FW) SyncObPorts(ports []int) error {
	f.conn.FlushSet(f.obPorts)
	if len(ports) == 0 {
		return f.conn.Flush()
	}
	els := make([]nftables.SetElement, 0, len(ports))
	for _, p := range ports {
		els = append(els, nftables.SetElement{Key: []byte{byte(p >> 8), byte(p & 0xff)}})
	}
	if err := f.conn.SetAddElements(f.obPorts, els); err != nil {
		return err
	}
	return f.conn.Flush()
}

// SyncOutbound 全量刷新出站自动白名单集合（过期判定由调用方维护：只写"应保留"的远端）。
// allPorts=true 时远端进入全端口模式集合（ob_all），否则进端口限定集合（ob_ok）；另一模式集合同步清空。
func (f *FW) SyncOutbound(allPorts bool, v4, v6 []netip.Addr) error {
	okSet, ok6 := f.obOk, f.obOk6
	other, other6 := f.obAll, f.obAll6
	if allPorts {
		okSet, ok6 = f.obAll, f.obAll6
		other, other6 = f.obOk, f.obOk6
	}
	write := func(set *nftables.Set, ips []netip.Addr) error {
		f.conn.FlushSet(set)
		if len(ips) == 0 {
			return nil
		}
		els := make([]nftables.SetElement, 0, len(ips))
		for _, a := range ips {
			els = append(els, nftables.SetElement{Key: a.AsSlice()})
		}
		return f.conn.SetAddElements(set, els)
	}
	if err := write(okSet, v4); err != nil {
		return err
	}
	if err := write(ok6, v6); err != nil {
		return err
	}
	f.conn.FlushSet(other)
	f.conn.FlushSet(other6)
	return f.conn.Flush()
}

// Close 关闭连接。
func (f *FW) Close() error {
	if f.conn != nil {
		return f.conn.CloseLasting()
	}
	return nil
}

// ---------- 内部实现 ----------

func (f *FW) addRule(r *nftables.Rule) {
	f.conn.AddRule(r)
}

// matchTCPPortsAndNew 返回规则前缀：meta l4proto tcp + tcp dport @ports + ct state new。
// 编码细节经 spike 实测校准（ct 掩码后 cmp neq 0x00000000，勿写成 0x08）。
func matchTCPPortsAndNew() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Lookup{SourceRegister: 1, SetName: setPorts},
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{0x08, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

// matchTCPDportSet 匹配"tcp dport @指定集合"（不含 ct 状态条件）。
func matchTCPDportSet(setName string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Lookup{SourceRegister: 1, SetName: setName},
	}
}

// ruleEstablished 规则 0：已建立连接的回程流量放行（conntrack 标准正典）。
// state & (ESTABLISHED|RELATED) != 0 → accept。
func (f *FW) ruleEstablished() *nftables.Rule {
	return &nftables.Rule{Table: f.table, Chain: f.chain, Exprs: []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{0x06, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
}

// ruleObAccept 出站自动白名单：白名单 IP 对放行端口集合的新连接 accept。
func (f *FW) ruleObAccept(isV6 bool) *nftables.Rule {
	setName := setObOk
	if isV6 {
		setName = setObOk6
	}
	exprs := matchTCPDportSet(setObPorts)
	exprs = append(exprs, matchSaddr(isV6)...)
	exprs = append(exprs,
		&expr.Lookup{SourceRegister: 1, SetName: setName},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	return &nftables.Rule{Table: f.table, Chain: f.chain, Exprs: exprs}
}

// ruleObAcceptAll 出站自动白名单（全端口模式，outbound.ports 为空时）：白名单 IP 的 TCP 新连接全端口 accept。
func (f *FW) ruleObAcceptAll(isV6 bool) *nftables.Rule {
	setName := setObAll
	if isV6 {
		setName = setObAll6
	}
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
	}
	exprs = append(exprs, matchSaddr(isV6)...)
	exprs = append(exprs,
		&expr.Lookup{SourceRegister: 1, SetName: setName},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	return &nftables.Rule{Table: f.table, Chain: f.chain, Exprs: exprs}
}

// matchSaddr 返回 nfproto 限定 + saddr 加载（inet 表必须限定协议族）。
func matchSaddr(isV6 bool) []expr.Any {
	if isV6 {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
		}
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
	}
}

func wlName(isV6 bool) string {
	if isV6 {
		return setWl6
	}
	return setWl4
}

// 规则 1/2：白名单 accept。
func (f *FW) ruleWhitelist(isV6 bool) *nftables.Rule {
	exprs := matchTCPPortsAndNew()
	exprs = append(exprs, matchSaddr(isV6)...)
	exprs = append(exprs,
		&expr.Lookup{SourceRegister: 1, SetName: wlName(isV6)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	return &nftables.Rule{Table: f.table, Chain: f.chain, Exprs: exprs}
}

// 规则 3-5：已封 IP 的后续 SYN 静默丢弃（setName 指定封禁集合）。
func (f *FW) ruleBannedDrop(isV6 bool, setName string) *nftables.Rule {
	exprs := matchTCPPortsAndNew()
	exprs = append(exprs, matchSaddr(isV6)...)
	exprs = append(exprs,
		&expr.Lookup{SourceRegister: 1, SetName: setName},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
	return &nftables.Rule{Table: f.table, Chain: f.chain, Exprs: exprs}
}

// 规则 6/7：新 IP 首个 SYN → dynset 封禁 + 丢弃。
// （NFLOG 已随日志分级简化移除，不再挂 log group）
func (f *FW) ruleDynsetBan(isV6 bool, setName string) *nftables.Rule {
	exprs := matchTCPPortsAndNew()
	exprs = append(exprs, matchSaddr(isV6)...)
	exprs = append(exprs,
		&expr.Dynset{SrcRegKey: 1, SetName: setName, Operation: unix.NFT_DYNSET_OP_ADD},
	)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	return &nftables.Rule{Table: f.table, Chain: f.chain, Exprs: exprs}
}

// 规则 8-10：被封 IP 的其余全部流量静默丢弃（全端口全协议，黑洞式无响应）。
// 对外表现：封禁 IP 的任何连接/探测（TCP/UDP/ICMP）均无任何回应。
func (f *FW) ruleAllDrop(isV6 bool, setName string) *nftables.Rule {
	exprs := matchSaddr(isV6)
	exprs = append(exprs,
		&expr.Lookup{SourceRegister: 1, SetName: setName},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
	return &nftables.Rule{Table: f.table, Chain: f.chain, Exprs: exprs}
}

// prefixElems 把 Prefix 编码为 interval 集合元素（双端点表示法，3.13+ 全内核通用）。
// 实测确立（7.1.5）：interval 集合是**半开区间 [start, end)** 语义——
// 终点元素的 Key 是"区间外的第一个地址"，即终点 = 区间末地址 + 1；
// 若终点元素与起点重合（空区间）会被内核忽略，导致元素变成开区间。
// （Key+KeyEnd 单消息区间在 7.1.5 上实测 EINVAL，不可用。）
func prefixElems(p netip.Prefix) []nftables.SetElement {
	first := p.Addr().AsSlice()
	end := prefixLast(p).Next()
	if !end.IsValid() {
		// 极端边界（区间到地址空间末尾），退化为末地址本身
		end = prefixLast(p)
	}
	last := end.AsSlice()
	return []nftables.SetElement{
		{Key: append([]byte(nil), first...)},
		{Key: append([]byte(nil), last...), IntervalEnd: true},
	}
}

// prefixLast 返回前缀内最后一个地址。
func prefixLast(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		a := p.Addr().As4()
		bits := p.Bits()
		for i := bits / 8; i < 4; i++ {
			a[i] = 0xff
		}
		if rem := bits % 8; rem != 0 {
			a[bits/8] |= 0xff >> rem
		}
		return netip.AddrFrom4(a)
	}
	a := p.Addr().As16()
	bits := p.Bits()
	for i := bits / 8; i < 16; i++ {
		a[i] = 0xff
	}
	if rem := bits % 8; rem != 0 {
		a[bits/8] |= 0xff >> rem
	}
	return netip.AddrFrom16(a)
}

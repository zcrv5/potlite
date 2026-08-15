// Package ddns 实现 DDNS 域名解析：IPv4 精确、IPv6 自动取 /64 段。
package ddns

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Resolve 解析域名列表，返回去重后的白名单前缀（IPv4 /32、IPv6 /64 段）。
// 至少一个域名解析成功则 ok=true；全部失败 ok=false（调用方应跳过本轮，防误封）。
func Resolve(domains []string) ([]netip.Prefix, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := &net.Resolver{}

	seen := make(map[netip.Prefix]struct{})
	var out []netip.Prefix
	ok := false
	for _, d := range domains {
		ips, err := r.LookupNetIP(ctx, "ip", d)
		if err != nil {
			continue
		}
		ok = true
		for _, ip := range ips {
			var p netip.Prefix
			if ip.Is4() {
				p = netip.PrefixFrom(ip, 32)
			} else {
				p = netip.PrefixFrom(ip, 64).Masked()
			}
			if _, exists := seen[p]; !exists {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out, ok
}

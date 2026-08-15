// Package honeypot 实现蜜罐 TCP 监听池与 accept 兜底判定。
//
// 主封禁路径在内核规则层（SYN 即封）；本模块是兜底：
// 完成握手的连接（白名单 IP 或规则层异常漏网）到达时，程序侧判定并幂等补封。
package honeypot

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Handler 连接事件回调（CSV 记录用，M4 接入；可为 nil）。
type Handler interface {
	OnConnect(src netip.Addr, port int, whitelisted bool)
	OnBan(src netip.Addr, port int)
}

// Server 蜜罐监听器。
type Server struct {
	ports     []int
	whitelist func(netip.Addr) bool  // 白名单判定（上层注入）
	ban       func(netip.Addr) error // 封禁执行（上层注入，幂等）
	handler   Handler
	maxConns  chan struct{}
	listeners []net.Listener
	wg        sync.WaitGroup
}

// New 创建蜜罐服务器。
func New(ports []int, wl func(netip.Addr) bool, ban func(netip.Addr) error, h Handler) *Server {
	return &Server{
		ports:     ports,
		whitelist: wl,
		ban:       ban,
		handler:   h,
		maxConns:  make(chan struct{}, 64),
	}
}

// Start 启动监听（双栈）；绑定失败的端口跳过并返回失败列表（由上层给出醒目警告）。
func (s *Server) Start() []int {
	var failed []int
	for _, p := range s.ports {
		ln4, err := net.Listen("tcp4", fmt.Sprintf(":%d", p))
		if err != nil {
			failed = append(failed, p)
			fmt.Printf("potlite: 警告: 端口 %d 绑定失败（可能被真实服务占用，攻击者将直达该服务而非蜜罐）\n", p)
			continue
		}
		s.listeners = append(s.listeners, ln4)
		if ln6, err := net.Listen("tcp6", fmt.Sprintf(":%d", p)); err == nil {
			s.listeners = append(s.listeners, ln6)
		}
	}
	for _, ln := range s.listeners {
		s.wg.Add(1)
		go s.serve(ln)
	}
	return failed
}

// Close 停止所有监听。
func (s *Server) Close() {
	for _, ln := range s.listeners {
		ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) serve(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.maxConns <- struct{}{}
		go func(c net.Conn) {
			defer func() { <-s.maxConns }()
			s.handle(c)
		}(conn)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	var src netip.Addr
	var srcPort int
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		if ap, ok := netip.AddrFromSlice(ta.IP); ok {
			src = ap
			srcPort = ta.Port
		}
	}
	if !src.IsValid() {
		return
	}
	wl := s.whitelist(src)
	if s.handler != nil {
		s.handler.OnConnect(src, srcPort, wl)
	}
	if !wl {
		// 兜底封禁（幂等）
		if s.ban != nil {
			_ = s.ban(src)
		}
		if s.handler != nil {
			s.handler.OnBan(src, srcPort)
		}
	}
	// 挂 1 秒断开（拖住扫描器）
	time.Sleep(time.Second)
}

// Package notify 实现 sd_notify 协议（零依赖）：向 systemd 报告就绪/状态/健康。
// 非 systemd 环境（/run/systemd/notify 不存在）自动降级为静默。
package notify

import (
	"net"
	"strings"
	"sync"
)

const socketPath = "/run/systemd/notify"

// Notifier sd_notify 客户端。
type Notifier struct {
	mu   sync.Mutex
	conn *net.UnixConn
	ok   bool
}

// New 创建通知器；连接失败（非 systemd 环境）返回降级实例。
func New() *Notifier {
	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return &Notifier{ok: false}
	}
	return &Notifier{ok: true, conn: conn}
}

// Enabled 是否可用。
func (n *Notifier) Enabled() bool { return n.ok }

// Ready 通知服务就绪（Type=notify 必须）。
func (n *Notifier) Ready() { n.send("READY=1") }

// Status 更新多行状态（systemctl status 的 Status 段；10 秒级刷新）。
// 备注：M2 曾因一次不严谨的实验结论改为单行拼接，本轮重新验证 systemd 对
// STATUS 值内换行的支持——sd_notify 手册允许换行，此前实验被周期刷新覆盖导致误判。
func (n *Notifier) Status(lines []string) {
	n.send("STATUS=" + strings.Join(lines, "\n"))
}

// Watchdog 健康保活（周期必须小于 WatchdogSec）。
func (n *Notifier) Watchdog() { n.send("WATCHDOG=1") }

// Stopping 通知即将停止。
func (n *Notifier) Stopping() { n.send("STOPPING=1") }

func (n *Notifier) send(payload string) {
	if !n.ok {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, _ = n.conn.Write([]byte(payload + "\n"))
}

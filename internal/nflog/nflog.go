// Package nflog 订阅内核 NFLOG 组播（蜜罐被拒包的旁路通知）并解析包头。
// 自研实现：组播接收（JoinGroup）+ 配置消息（设置 NFLOG 实例 copy mode = COPY_PACKET，否则内核默认只发元数据无包内容）。
//
// 规则链保证（设计文档 7 章）：log group 1（snaplen 128）挂在"新 IP 首条 SYN"与"全端口 drop"规则上，
// 程序按级别决定如何使用事件：级别 1/2 只取新 IP 的首条（触发端口），级别 3 全量聚合端口明细。
package nflog

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	// 两个"组"概念（实测理清）：
	// - nflogGroup：NFLOG 实例组 = nft 规则 `log group N` 的 N，BIND 配置消息用它（须与规则一致）
	// - netlinkGroup：netlink 组播组 = NFNLGRP_NFLOG(9) + N - 1，JoinGroup 订阅用它
	nflogGroup      = 1
	netlinkGroup    = 9
	nfUlaPayload    = 9  // NFULA_PAYLOAD
	nfnlSubSysUlog  = 4  // NFNL_SUBSYS_ULOG
	nfUlnlMsgConfig = 1  // NFULNL_MSG_CONFIG
	nfUlACfgCmd     = 1  // NFULA_CFG_CMD
	nfUlACfgMode    = 2  // NFULA_CFG_MODE

	nfUlnlCfgCmdPfUnbind = 4 // NFULNL_CFG_CMD_PF_UNBIND
	nfUlnlCfgCmdPfBind   = 3 // NFULNL_CFG_CMD_PF_BIND
	nfUlnlCfgCmdUnbind   = 2 // NFULNL_CFG_CMD_UNBIND
	nfUlnlCfgCmdBind     = 1 // NFULNL_CFG_CMD_BIND
	nfUlnlCopyPacket     = 2 // NFULNL_COPY_PACKET
)

// Event 一条被拒包事件。
type Event struct {
	SrcIP   netip.Addr // 源 IP
	DstPort int        // 目的端口（蜜罐端口）
}

// Subscriber NFLOG 订阅器。
type Subscriber struct {
	conn *netlink.Conn
}

// Subscribe 订阅 log group 1 并持续回调（内部 goroutine）。
func Subscribe(handler func(Event)) (*Subscriber, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{DisableNSLockThread: true})
	if err != nil {
		return nil, fmt.Errorf("打开 netlink 失败: %w", err)
	}
	if err := conn.JoinGroup(netlinkGroup); err != nil {
		conn.Close()
		return nil, fmt.Errorf("加入 NFLOG 组播失败: %w", err)
	}
	if err := configure(conn); err != nil {
		fmt.Println("nflog: 配置 copy mode 失败（payload 可能缺失）:", err)
	}
	s := &Subscriber{conn: conn}
	go s.loop(handler)
	return s, nil
}

// configure 发送 NFLOG 配置序列（照抄 libnetfilter_log/go-nflog 的 BIND + COPY_PACKET 流程）。
func configure(conn *netlink.Conn) error {
	var seq uint32
	cfg := func(oseq uint32, resid uint16, attrs []netlink.Attribute) (uint32, error) {
		cmd, err := netlink.MarshalAttributes(attrs)
		if err != nil {
			return 0, err
		}
		data := make([]byte, 4) // nfgenmsg: family + version + res_id(大端)
		data[0] = unix.AF_UNSPEC
		data[1] = unix.NFNETLINK_V0
		binary.BigEndian.PutUint16(data[2:4], resid)
		data = append(data, cmd...)
		req := netlink.Message{
			Header: netlink.Header{
				Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
				Flags:    netlink.Request | netlink.Acknowledge,
				Sequence: oseq,
			},
			Data: data,
		}
		replies, err := conn.Execute(req)
		if err != nil {
			return 0, err
		}
		if len(replies) > 0 {
			return replies[0].Header.Sequence, nil
		}
		return 0, nil
	}

	if s, err := cfg(0, 0, []netlink.Attribute{{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind}}}); err != nil {
		return err
	} else {
		seq = s
	}
	if _, err := cfg(seq, 0, []netlink.Attribute{{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfBind}}}); err != nil {
		return err
	}
	if _, err := cfg(seq, 0, []netlink.Attribute{{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}}}); err != nil {
		return err
	}
	if _, err := cfg(seq, nflogGroup, []netlink.Attribute{{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}}}); err != nil {
		return err
	}
	mode := make([]byte, 0, 8)
	mode = binary.BigEndian.AppendUint32(mode, 8192) // 缓冲区大小（4 字节大端）
	mode = append(mode, nfUlnlCopyPacket, 0x0)      // copy mode + 填充
	if _, err := cfg(seq, nflogGroup, []netlink.Attribute{{Type: nfUlACfgMode, Data: mode}}); err != nil {
		return err
	}
	return nil
}

// Close 关闭订阅。
func (s *Subscriber) Close() error {
	return s.conn.Close()
}

func (s *Subscriber) loop(handler func(Event)) {
	var count uint64
	for {
		msgs, err := s.conn.Receive()
		if err != nil {
			fmt.Println("nflog: 接收循环退出:", err)
			return
		}
		for _, m := range msgs {
			count++
			if count <= 3 {
				fmt.Printf("nflog: 收到消息 #%d len=%d\n", count, len(m.Data))
			}
			if ev, ok := parseNflogMsg(m.Data); ok {
				handler(ev)
			}
		}
	}
}

// parseNflogMsg 解析 nfgenmsg(4) + 属性 TLV，提取 NFULA_PAYLOAD。
// 注意：mdlayher/netlink 的 Message.Data 已剥离 nlmsghdr；nla 头为主机字节序（小端）。
func parseNflogMsg(data []byte) (Event, bool) {
	if len(data) < 8 {
		return Event{}, false
	}
	off := 4 // 跳过 nfgenmsg
	for off+4 <= len(data) {
		alen := int(binary.NativeEndian.Uint16(data[off : off+2]))
		atype := binary.NativeEndian.Uint16(data[off+2 : off+4])
		if alen < 4 || off+alen > len(data) {
			break
		}
		if atype == nfUlaPayload {
			return Parse(data[off+4 : off+alen])
		}
		off += (alen + 3) &^ 3
	}
	return Event{}, false
}

// Parse 从原始 IP 包解析（源 IP、目的端口）。仅 TCP。
func Parse(b []byte) (Event, bool) {
	if len(b) < 20 {
		return Event{}, false
	}
	switch b[0] >> 4 {
	case 4: // IPv4
		ihl := int(b[0]&0x0f) * 4
		if len(b) < ihl+4 || b[9] != 6 {
			return Event{}, false
		}
		var s4 [4]byte
		copy(s4[:], b[12:16])
		return Event{
			SrcIP:   netip.AddrFrom4(s4),
			DstPort: int(binary.BigEndian.Uint16(b[ihl+2 : ihl+4])),
		}, true
	case 6: // IPv6（无扩展头假设：蜜罐 SYN 场景）
		if len(b) < 60 || b[6] != 6 {
			return Event{}, false
		}
		var s16 [16]byte
		copy(s16[:], b[8:24])
		return Event{
			SrcIP:   netip.AddrFrom16(s16),
			DstPort: int(binary.BigEndian.Uint16(b[42:44])),
		}, true
	}
	return Event{}, false
}

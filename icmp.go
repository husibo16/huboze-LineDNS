package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var icmpSeq atomic.Uint32

// icmpPing sends one ICMP echo and waits for the reply. It uses unprivileged
// ICMP datagram sockets (net.ipv4.ping_group_range), so the container needs
// no capabilities; raw sockets are tried as a fallback.
func icmpPing(target string, v6 bool, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	family := "ip4"
	if v6 {
		family = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, family, target)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("无法解析 %s：%v", target, err)
	}
	ip := ips[0]

	var (
		conn    *icmp.PacketConn
		proto   int
		reqType icmp.Type
		repType icmp.Type
		dgram   = true
	)
	if v6 {
		proto, reqType, repType = 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
		conn, err = icmp.ListenPacket("udp6", "::")
		if err != nil {
			dgram = false
			conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		}
	} else {
		proto, reqType, repType = 1, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
		conn, err = icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			dgram = false
			conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		}
	}
	if err != nil {
		return fmt.Errorf("无法创建 ICMP 套接字（宿主机 net.ipv4.ping_group_range 未包含容器用户）：%v", err)
	}
	defer conn.Close()

	seq := int(icmpSeq.Add(1) & 0xffff)
	payload := []byte(fmt.Sprintf("huboze-%d", time.Now().UnixNano()))
	msg := icmp.Message{Type: reqType, Body: &icmp.Echo{ID: seq, Seq: seq, Data: payload}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	var dst net.Addr = &net.IPAddr{IP: ip}
	if dgram {
		dst = &net.UDPAddr{IP: ip}
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.WriteTo(b, dst); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return errors.New("超时无响应")
			}
			return err
		}
		rm, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || rm.Type != repType {
			continue
		}
		if echo, ok := rm.Body.(*icmp.Echo); ok && echo.Seq == seq && bytes.Equal(echo.Data, payload) {
			return nil
		}
	}
}

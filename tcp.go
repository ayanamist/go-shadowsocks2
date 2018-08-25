package main

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/internal/fakedns"
	"github.com/shadowsocks/go-shadowsocks2/internal/stat"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type NoDelaySetter interface {
	SetNoDelay(noDelay bool) error
}

// Create a SOCKS server listening on addr and proxy to server.
func socksLocal(localAddr string, dial func(string, string) (net.Conn, error)) {
	tcpLocal(localAddr, dial, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// Listen on addr and proxy to server to reach target from getAddr.
func tcpLocal(localAddr string, proxyDial func(string, string) (net.Conn, error), getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", localAddr)
	if err != nil {
		logf("failed to listen on %s: %v", localAddr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			tcpConn := c.(*net.TCPConn)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
			tcpConn.SetNoDelay(true)
			tgt, err := getAddr(c)
			if err != nil {
				logf("failed to get target address: %v", err)
				return
			}
			tgt = fakedns.TryReplaceIP2Dom(tgt)
			remote := tgt.String()

			directConnect := false
			if ip := tgt.IP().To4(); ip != nil && fakedns.ShouldDirectConnect(fakedns.FromNetIP(ip)) {
				directConnect = true
			}

			var rc io.ReadWriteCloser
			var dialFunc func(string, string) (net.Conn, error)
			var proxyType string
			if directConnect {
				dialFunc = dialer.Dial
				proxyType = "direct"
			} else {
				dialFunc = proxyDial
				proxyType = "proxy"
			}
			rc, err = dialFunc("tcp4", remote)
			if err != nil {
				logf("failed to dial %v: %v", remote, err)
				return
			}
			if tcpConn, ok := rc.(NoDelaySetter); ok {
				tcpConn.SetNoDelay(true)
			}
			logf("%s %s <-> %s", proxyType, c.RemoteAddr(), tgt)
			defer rc.Close()

			if !directConnect {
				rc = stat.Wrap(rc)
			}
			_, _, err = relay(rc, c)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func relay(left, right io.ReadWriteCloser) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		err = ignoreClosedErr(err)
		right.Close()
		left.Close()
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	err = ignoreClosedErr(err)
	right.Close()
	left.Close()
	rs := <-ch

	if err == nil {
		err = rs.Err
	}

	// http2 response.Body的Close和net.Conn不同，提前Close会导致数据流断开，进而上层读取时异常，只能这样绕过
	type ReaderCloser interface {
		CloseRead() error
	}
	if c, ok := left.(ReaderCloser); ok {
		c.CloseRead()
	}
	if c, ok := right.(ReaderCloser); ok {
		c.CloseRead()
	}

	return n, rs.N, err
}

func ignoreClosedErr(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}

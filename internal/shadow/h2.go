package shadow

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/http2"
)

func WrapH2(proxyServer, user, pass string, dialFunc func(string, string) (net.Conn, error)) func(string, string) (net.Conn, error) {
	nextProtos := []string{"h2"}
	tr := &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := dialFunc("tcp", proxyServer)
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
			}
			return tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         nextProtos,
			}), nil
		},
	}
	var auth string
	if len(user)+len(pass) > 0 {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	return func(_, realServer string) (net.Conn, error) {
		pr, pw := io.Pipe()
		req, err := http.NewRequest(http.MethodConnect, fmt.Sprintf("https://%s/", realServer), pr)
		if err != nil {
			pr.Close()
			return nil, errors.Wrap(err, "http.NewRequest")
		}
		req.ContentLength = -1
		if auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			pr.Close()
			return nil, errors.Wrap(err, "RoundTrip")
		}
		if resp.StatusCode != http.StatusOK {
			pr.Close()
			resp.Body.Close()
			return nil, errors.Errorf("tunnel failed %s", resp.Status)
		}
		return &PipeReadWriteCloser{resp.Body, pw}, nil
	}
}

type PipeReadWriteCloser struct {
	pr io.ReadCloser
	pw io.WriteCloser
}

func (p *PipeReadWriteCloser) LocalAddr() net.Addr {
	return &net.IPAddr{}
}

func (p *PipeReadWriteCloser) RemoteAddr() net.Addr {
	return &net.IPAddr{}
}

func (p *PipeReadWriteCloser) SetDeadline(t time.Time) error {
	return nil
}

func (p *PipeReadWriteCloser) SetReadDeadline(t time.Time) error {
	return nil
}

func (p *PipeReadWriteCloser) SetWriteDeadline(t time.Time) error {
	return nil
}

func (p *PipeReadWriteCloser) Close() error {
	p.pw.Close()
	return nil
}

func (p *PipeReadWriteCloser) CloseRead() error {
	p.pr.Close()
	return nil
}

func (p *PipeReadWriteCloser) Read(b []byte) (n int, err error) {
	return p.pr.Read(b)
}

func (p *PipeReadWriteCloser) Write(b []byte) (n int, err error) {
	return p.pw.Write(b)
}

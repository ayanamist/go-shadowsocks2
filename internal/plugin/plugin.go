package plugin

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	logf = log.Printf
)

func LoggerFunc(f func(f string, v ...interface{})) {
	logf = f
}

type SsPlugin struct {
	cmd  string
	opts string

	remoteServer string
	remotePort   int

	localPort int
}

func NewSsPlugin(cmd, opts string, remoteServer string, remotePort int) *SsPlugin {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen 127.0.0.1:0 error: %v", err)
	}
	defer l.Close()
	addr := l.Addr().String()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("extract port from %s error: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("parse port %s error: %v", portStr, err)
	}
	return &SsPlugin{
		cmd:          cmd,
		opts:         opts,
		remoteServer: remoteServer,
		remotePort:   remotePort,
		localPort:    port,
	}
}

func (p *SsPlugin) HostPort() string {
	return fmt.Sprintf("127.0.0.1:%d", p.localPort)
}

func (p *SsPlugin) Start() {
	// https://shadowsocks.org/en/spec/Plugin.html
	fields := strings.Fields(p.cmd)
	for {
		cmd := exec.Command(fields[0], fields[1:]...)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("SS_REMOTE_HOST=%s", p.remoteServer),
			fmt.Sprintf("SS_REMOTE_PORT=%d", p.remotePort),
			"SS_LOCAL_HOST=127.0.0.1",
			fmt.Sprintf("SS_LOCAL_PORT=%d", p.localPort),
			fmt.Sprintf("SS_PLUGIN_OPTIONS=%s", p.opts),
		)
		pr, _ := cmd.StdoutPipe()
		go func() {
			scanner := bufio.NewScanner(pr)
			for scanner.Scan() {
				logf("plugin stdout: %s", scanner.Text())
			}
			pr.Close()
		}()
		cmd.Stderr = cmd.Stdout
		start := time.Now()
		logf("plugin run: %v", cmd.Run())
		delta := time.Now().Sub(start)
		if delta < time.Second {
			if delta < 0 {
				delta = 0
			}
			time.Sleep(time.Second - delta)
		}
	}
}

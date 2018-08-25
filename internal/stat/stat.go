package stat

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"path"
	"sync/atomic"
	"time"
)

var (
	logf = log.Printf

	tx, rx uint64

	statPath string

	externalDir string
)

func SetLoggerFunc(f func(f string, v ...interface{})) {
	logf = f
}

func SetPath(f string) {
	statPath = f
}

func SetExternalDir(d string) {
	externalDir = d
}

func incrTx(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&tx, uint64(n))
}

func incrRx(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&rx, uint64(n))
}

func Start() {
	go start()
}

func start() {
	if _, err := os.Stat(path.Join(externalDir, "no_stat")); err == nil {
		logf("no_stat detected, disable stat report")
		return
	}
	var (
		oldTx, oldRx, newTx, newRx uint64
	)
	writeBuf := make([]byte, 16)
	readBuf := make([]byte, 1)
	for t := time.NewTicker(time.Second); ; <-t.C {
		func() {
			newTx, newRx = atomic.LoadUint64(&tx), atomic.LoadUint64(&rx)
			if oldRx == newTx && oldRx == newRx {
				return
			}
			conn, err := net.DialTimeout("unix", statPath, time.Second)
			if err != nil {
				logf("dial %s: %v", statPath, err)
				return
			}
			defer conn.Close()
			binary.LittleEndian.PutUint64(writeBuf, newTx)
			binary.LittleEndian.PutUint64(writeBuf[8:], newRx)
			if _, err := conn.Write(writeBuf); err != nil {
				logf("send %s: %v", statPath, err)
				return
			}
			if _, err := conn.Read(readBuf); err != nil && err != io.EOF {
				logf("recv %s: %v", statPath, err)
			}
			oldTx, oldRx = newTx, newRx
		}()
	}
}

type countedReadWriteCloser struct {
	io.ReadWriteCloser
}

func (r *countedReadWriteCloser) Write(b []byte) (n int, err error) {
	n, err = r.ReadWriteCloser.Write(b)
	incrTx(n)
	return
}

func (r *countedReadWriteCloser) Read(b []byte) (n int, err error) {
	n, err = r.ReadWriteCloser.Read(b)
	incrRx(n)
	return
}

func Wrap(r io.ReadWriteCloser) io.ReadWriteCloser {
	return &countedReadWriteCloser{r}
}

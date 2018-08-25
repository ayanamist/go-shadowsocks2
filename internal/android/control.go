package android

import (
	"syscall"

	"github.com/pkg/errors"
)

const (
	protectPath = "protect_path"
)

func DialerControl(_, _ string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		err = protectFd(int(fd))
	})
	return errors.Wrap(err, "protect_path")
}

// +build linux

package stdio

import "syscall"

func RedirectStream(src, dst uintptr) {
	syscall.Dup3(int(src), int(dst), 0)
}

package fakedns

import (
	"encoding/binary"
	"net"
)

type IPv4 uint32

func (i IPv4) toNetIP() net.IP {
	buf := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}

func (i IPv4) String() string {
	if i == 0 {
		return "<nil>"
	}
	return i.toNetIP().String()
}

func FromNetIP(ip net.IP) IPv4 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return IPv4(binary.BigEndian.Uint32(ip))
}

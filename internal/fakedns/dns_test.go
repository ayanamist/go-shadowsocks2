package fakedns

import (
	"net"
	"testing"
)

func BenchmarkIPRange(b *testing.B) {
	SetAclListPath("data/bypass-lan-china.acl")
	readAclList()
	buildAllHostsIPs()
	const (
		positiveIPStr = "101.37.183.171"
		negativeIPStr = "104.244.42.1"
	)
	positiveIP := FromNetIP(net.ParseIP(positiveIPStr))
	if positiveIP == 0 {
		b.Fatalf("%s want to be an IP but not", positiveIPStr)
	}
	negativeIP := FromNetIP(net.ParseIP(negativeIPStr))
	if negativeIP == 0 {
		b.Fatalf("%s want to be an IP but not", positiveIPStr)
	}

	for i := 0; i < b.N; i++ {
		if !ShouldDirectConnect(positiveIP) {
			b.Fatalf("%s want direct but not", positiveIP)
		}
		if ShouldDirectConnect(negativeIP) {
			b.Fatalf("%s want proxy but not", negativeIP)
		}
	}
}

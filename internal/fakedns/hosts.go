// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// copy from net/hosts.go with some modifications.

package fakedns

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// hosts contains known host entries.
var hosts struct {
	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byName *sync.Map // map[string][]IPv4

	allIPs      atomic.Value // map[string]struct{}
	allIPsMutex sync.Mutex
}

var hostsPaths = []string{"/etc/hosts"}

func init() {
	hosts.byName = new(sync.Map)
}

func SetHostsPath(paths []string) {
	hostsPaths = paths
}

func readHosts() {
	for _, path := range hostsPaths {
		if err := readHostsFromFile(path); err != nil && !os.IsNotExist(err) {
			logf("readHosts from %s error: %v", path, err)
		}
	}
	buildAllHostsIPs()
	cnt := 0
	hosts.byName.Range(func(key, value interface{}) bool {
		cnt++
		return true
	})
	logf("readHosts %d items", cnt)
}

func readHostsFromFile(path string) error {
	hs := hosts.byName

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			// Discard comments.
			line = line[0:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ip := FromNetIP(net.ParseIP(f[0]))
		if ip == 0 {
			continue
		}
		for i := 1; i < len(f); i++ {
			key := normalizeDomainName(f[i])
			if val, ok := hs.Load(key); ok {
				tmp := val.([]IPv4)
				hs.Store(key, append(tmp, ip))
			} else {
				hs.Store(key, []IPv4{ip})
			}
		}
	}
	// Update the data cache.
	return nil
}

func updateHosts(domain string, ips []IPv4) {
	key := normalizeDomainName(domain)
	hosts.byName.Store(key, ips)
	buildAllHostsIPs()
}

// lookupStaticHost looks up the addresses for the given host from /etc/hosts.
func lookupStaticHost(host string) []IPv4 {
	if val, ok := hosts.byName.Load(normalizeDomainName(host)); ok {
		ips := val.([]IPv4)
		ipsCp := make([]IPv4, len(ips))
		copy(ipsCp, ips)
		return ipsCp
	}
	return nil
}

func buildAllHostsIPs() {
	hosts.allIPsMutex.Lock()
	defer hosts.allIPsMutex.Unlock()

	set := make(map[IPv4]struct{})
	hosts.byName.Range(func(key, value interface{}) bool {
		for _, ip := range value.([]IPv4) {
			set[ip] = struct{}{}
		}
		return true
	})
	hosts.allIPs.Store(set)
}

func normalizeDomainName(host string) string {
	lowerHost := []byte(host)
	lowerASCIIBytes(lowerHost)
	return absDomainName(lowerHost)
}

func absDomainName(b []byte) string {
	hasDots := false
	for _, x := range b {
		if x == '.' {
			hasDots = true
			break
		}
	}
	if hasDots && b[len(b)-1] != '.' {
		b = append(b, '.')
	}
	return string(b)
}

func lowerASCIIBytes(x []byte) {
	for i, b := range x {
		if 'A' <= b && b <= 'Z' {
			x[i] += 'a' - 'A'
		}
	}
}

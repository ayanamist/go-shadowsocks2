package fakedns

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emirpasic/gods/trees/avltree"
	"github.com/miekg/dns"
	"github.com/pkg/errors"

	"github.com/shadowsocks/go-shadowsocks2/internal/android"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const (
	dnsTimeout = 9 * time.Second
)

var (
	directLookupId uint32

	logf = log.Printf

	bindAddr string

	chinaDNS []string

	probeDNS      []string
	probeDNSMutex = &sync.RWMutex{}

	mappingByIP     = make(map[IPv4]string)
	mappingByDomain = make(map[string]IPv4)
	mappingMutex    = &sync.RWMutex{}

	customRules []customRule

	fakeDnsIp4 = FromNetIP(net.ParseIP("11.0.0.0"))

	baseDir string

	cacheFile *os.File

	aclListPath string
	// map[IPv4]IPv4
	aclRanges = avltree.NewWith(func(a, b interface{}) int {
		aa := a.(IPv4)
		bb := b.(IPv4)
		if aa >= bb {
			return int(aa - bb)
		} else {
			return -1
		}
	})

	dialer = &net.Dialer{
		Timeout: dnsTimeout,
		Control: android.DialerControl,
	}
)

const (
	directDnsQuery = "0"
	fakeDnsQuery   = "1"
)

func SetLoggerFunc(f func(f string, v ...interface{})) {
	logf = f
}

func SetBaseDir(dir string) {
	baseDir = dir
}

func SetAclListPath(p string) {
	aclListPath = p
}

func SetChnDns(s string) {
	parts := strings.Split(s, ",")
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if _, _, err := net.SplitHostPort(p); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "missing port in address") {
				parts[i] = p + ":53"
			} else {
				log.Fatalf("invalid dns: %v", p)
			}
		}
	}
	chinaDNS = parts
}

func SetLocalPort(p int) {
	bindAddr = fmt.Sprintf("127.0.0.1:%d", p)
}

type dnsError struct {
	rcode int
}

func (e *dnsError) Error() string {
	return fmt.Sprintf("dns error with rcode=%s", dns.RcodeToString[e.rcode])
}

type customRule interface {
	MatchProxy(domain string) bool
}

type domainCustomRule struct {
	domain string
}

func (d *domainCustomRule) MatchProxy(domain string) bool {
	domain = strings.ToLower(domain)
	return d.domain == domain || strings.HasSuffix(domain, d.domain)
}

type regexpCustomRule struct {
	exp *regexp.Regexp
}

func (r *regexpCustomRule) MatchProxy(domain string) bool {
	return r.exp.MatchString(strings.ToLower(domain))
}

func Start() {
	if len(chinaDNS) == 0 {
		log.Fatal("remote dns not specified")
	} else {
		log.Printf("remote dns: %v", chinaDNS)
	}

	readHosts()
	readCache()
	readAclList()
	readCustomRules()

	if err := refreshProbeDnsSrv(); err != nil {
		log.Fatalf("refreshProbeDnsSrv: %v", err)
	}
	srv := dns.Server{
		Addr:    fmt.Sprintf(bindAddr),
		Net:     "udp4",
		Handler: dns.HandlerFunc(dnsHandler),
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("dns listen: %v", err)
		}
	}()
}

func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	for i := range r.Question {
		q := r.Question[i]
		r1 := *r
		r2 := &r1
		r2.Question = []dns.Question{q}
		if q.Qtype == dns.TypeA {
			dnsTypeAHandler(w, r2, q)
		} else if q.Qtype == dns.TypeAAAA {
			m := new(dns.Msg)
			m.SetRcode(r2, dns.RcodeSuccess)
			m.Authoritative = true
			m.Question = []dns.Question{q}
			m.Answer = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: q.Qtype,
						Ttl:    3600,
						Class:  dns.ClassINET,
					},
					Ns:      "nstld.verisign-grs.com",
					Mbox:    "a.gtld-servers.net",
					Serial:  1800,
					Refresh: 1800,
					Retry:   900,
					Expire:  604800,
					Minttl:  3600,
				},
			}
			_ = w.WriteMsg(m)
		} else {
			resp, err := directQueryWithMsg(r2, chinaDNS)
			if err != nil {
				dns.HandleFailed(w, r2)
			} else {
				_ = w.WriteMsg(resp)
			}
		}
	}
}

func dnsTypeAHandler(w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	qName := q.Name
	logf("dns query: %s", q.Name)
	if q.Qtype == dns.TypeA {
		if staticIps := lookupStaticHost(qName); len(staticIps) > 0 {
			logf("domain %s found in hosts: %v", qName, staticIps)
			respMsg := fakeRespDnsMsg(r, staticIps)
			_ = w.WriteMsg(respMsg)
			return
		}
	}
	r.Question = []dns.Question{q}
	respMsg := func() *dns.Msg {
		if q.Qtype == dns.TypeA && qName != "" && qName[len(qName)-1] == '.' && strings.Count(qName, ".") == 1 {
			return fakeRespDnsMsg(r, nil)
		}

		for _, rule := range customRules {
			if rule.MatchProxy(q.Name) {
				logf("matched rule %#v: %s", rule, q.Name)
				return fakeRespDnsMsg(r, []IPv4{insertFakeDnsRecord(qName)})
			}
		}

		shouldProbe := q.Qtype == dns.TypeA

		var fakeIp IPv4
		mappingMutex.RLock()
		fakeIp, ok := mappingByDomain[qName]
		mappingMutex.RUnlock()
		logf("mapping %s -> %v, %s", qName, ok, fakeIp)
		if ok {
			if fakeIp > 0 {
				return fakeRespDnsMsg(r, []IPv4{fakeIp})
			} else {
				shouldProbe = false
			}
		}
		probeCh := make(chan IPv4, 1)
		if shouldProbe {
			go func() {
				defer close(probeCh)
				probeDNSMutex.RLock()
				localProbeDNS := probeDNS
				probeDNSMutex.RUnlock()
				resp, err := directQueryWithMsg(r, localProbeDNS)
				if err != nil {
					return
				}
				if resp.Rcode == dns.RcodeSuccess {
					logf("domain %s polluted", qName)
					probeCh <- insertFakeDnsRecord(qName)
				}
			}()
		} else {
			close(probeCh)
		}
		realCh := make(chan *dns.Msg, 1)
		go func() {
			defer close(realCh)
			resp, err := directQueryWithMsg(r, chinaDNS)
			if err == nil {
				realCh <- resp
			} else {
				realCh <- nil
			}
		}()
		var respMsg *dns.Msg
		select {
		case fakeIp := <-probeCh:
			if fakeIp > 0 {
				return fakeRespDnsMsg(r, []IPv4{fakeIp})
			} else {
				respMsg = <-realCh
			}
		case respMsg = <-realCh:
			if shouldProbe {
				fakeIp := <-probeCh
				if fakeIp > 0 {
					return fakeRespDnsMsg(r, []IPv4{fakeIp})
				}
			}
		}
		if respMsg == nil {
			respMsg = failedDnsMsg(r)
		} else {
			if respMsg.Rcode == dns.RcodeServerFailure {
				logf("domain %s server failure", qName)
				return fakeRespDnsMsg(r, []IPv4{insertFakeDnsRecord(qName)})
			}
		}
		if respMsg.Rcode == dns.RcodeSuccess && q.Qtype == dns.TypeA {
			var chnAnswers []dns.RR
			var chnACnt int
			for _, answer := range respMsg.Answer {
				answer.Header().Ttl = 3600
				if dnsA, ok := answer.(*dns.A); ok {
					if ShouldDirectConnect(FromNetIP(dnsA.A)) {
						chnAnswers = append(chnAnswers, dnsA)
						chnACnt++
					}
				} else {
					chnAnswers = append(chnAnswers, answer)
				}
			}
			if chnACnt == 0 {
				if shouldProbe {
					logf("domain %s has no chn ips, fake it", qName)
					respMsg = fakeRespDnsMsg(r, []IPv4{insertFakeDnsRecord(qName)})
				} else {
					logf("WARN %s has no chn ips and need probe again.", qName)
				}
			} else {
				respMsg.Answer = chnAnswers
				if shouldProbe {
					insertDirectRecord(qName)
				}
			}
		}
		return respMsg
	}()
	_ = w.WriteMsg(respMsg)
}

func readCache() {
	cachePath := filepath.Join(baseDir, "fakedns.cache")
	var err error
	cacheFile, err = os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatalf("open %s: %v", cachePath, err)
	}
	scanner := bufio.NewScanner(cacheFile)
	cnt := 0
	for scanner.Scan() {
		var (
			fakeState string
			domain    string
		)
		line := scanner.Text()
		splitted := strings.Split(line, " ")
		switch len(splitted) {
		case 1:
			domain, fakeState = line, fakeDnsQuery
		case 2:
			domain, fakeState = splitted[0], splitted[1]
		default:
		}
		if domain == "" {
			continue
		}
		switch fakeState {
		case directDnsQuery:
			mappingByDomain[domain] = 0
		case fakeDnsQuery:
			ip := newFakeIp()
			logf("fakeDns loaded: %s -> %s", domain, ip.String())
			mappingByIP[ip] = domain
			mappingByDomain[domain] = ip
		default:
			logf("invalid state: %s", line)
		}
		cnt++
	}
	logf("loaded %s %d items, err: %v", cachePath, cnt, scanner.Err())
}

func readCustomRules() {
	filename := filepath.Join(filepath.Dir(aclListPath), "custom-rules.acl")
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("open %s error, ignore: %v", filename, err)
		return
	}
	defer file.Close()

	var domainPrefixes = []string{
		`(^|\.)`,
		`^(.*\.)?`,
		`(?:^|\.)`,
	}
	const domainSuffix = `$`

	var proxyList bool
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		line := strings.Trim(scanner.Text(), " ")
		if line == "" {
			continue
		}
		if line[0] == '[' {
			if line == "[proxy_list]" {
				proxyList = true
			} else {
				proxyList = false
			}
			continue
		}
		if !proxyList {
			continue
		}
		if strings.HasSuffix(line, domainSuffix) {
			for _, p := range domainPrefixes {
				if strings.HasPrefix(line, p) {
					line = line[len(p) : len(line)-len(domainSuffix)]
					break
				}
			}
			line = strings.Replace(line, `\.`, ".", -1)
			customRules = append(customRules, &domainCustomRule{normalizeDomainName(line)})
		} else {
			exp, err := regexp.Compile(line)
			if err != nil {
				log.Printf("invalid regexp %s error: %v", line, err)
			} else {
				customRules = append(customRules, &regexpCustomRule{exp})
			}
		}
	}
}

func readAclList() {
	defer func() {
		logf("loaded %s %d items", aclListPath, aclRanges.Size())
	}()

	if aclListPath == "" {
		return
	}

	file, err := os.Open(aclListPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var bypassList bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), " ")
		if line == "" {
			continue
		}
		if line[0] == '[' {
			if line == "[bypass_list]" {
				bypassList = true
			} else {
				bypassList = false
			}
			continue
		}
		if !bypassList {
			continue
		}
		ip, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		start := ip.Mask(ipnet.Mask)
		ones, bits := ipnet.Mask.Size()
		size := 1 << (bits - ones)
		end := net.IP(make([]byte, net.IPv4len))
		binary.BigEndian.PutUint32(end, binary.BigEndian.Uint32(start)+uint32(size)-1)
		aclRanges.Put(FromNetIP(start), FromNetIP(end))
	}
}

func ShouldDirectConnect(ip IPv4) bool {
	if ip == 0 {
		return true
	}
	_, ok := hosts.allIPs.Load().(map[IPv4]struct{})[ip]
	if ok {
		return true
	}
	floor, _ := aclRanges.Floor(ip)
	if floor == nil {
		return false
	}
	return ip <= floor.Value.(IPv4)
}

func insertDirectRecord(domain string) {
	mappingMutex.Lock()
	_, ok := mappingByDomain[domain]
	if !ok {
		mappingByDomain[domain] = 0
		_, _ = fmt.Fprintln(cacheFile, domain, directDnsQuery)
	}
	mappingMutex.Unlock()
	if !ok {
		logf("fakeDns bypass: %s", domain)
	}
}

func insertFakeDnsRecord(domain string) (ip IPv4) {
	mappingMutex.Lock()
	ip, ok := mappingByDomain[domain]
	if ip == 0 {
		ok = false
	}
	if !ok {
		ip = newFakeIp()
		mappingByIP[ip] = domain
		mappingByDomain[domain] = ip
		_, _ = fmt.Fprintln(cacheFile, domain, fakeDnsQuery)
	}
	mappingMutex.Unlock()
	logf("fakeDns exist %v: %s -> %s", ok, domain, ip.String())
	return ip
}

func newFakeIp() IPv4 {
	return IPv4(atomic.AddUint32((*uint32)(&fakeDnsIp4), 1))
}

func TryReplaceIP2Dom(orig socks.Addr) socks.Addr {
	ip := orig.IP().To4()
	port := orig.Port()
	if ip == nil || port == "" {
		return orig
	}
	mappingMutex.RLock()
	domain := mappingByIP[FromNetIP(ip)]
	mappingMutex.RUnlock()
	if domain == "" {
		return orig
	}
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	addr := socks.ParseAddr(net.JoinHostPort(domain, port))
	if addr == nil {
		return orig
	}
	logf("fakeDns replace: %s -> %s", orig, addr)
	return addr
}

func failedDnsMsg(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func fakeRespDnsMsg(r *dns.Msg, ips []IPv4) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.CheckingDisabled = true
	q := r.Question[0]
	m.Question = []dns.Question{q}
	rrs := make([]dns.RR, len(ips))
	for i, ip := range ips {
		rrs[i] = &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: q.Qtype,
				Ttl:    3600,
				Class:  dns.ClassINET,
			},
			A: ip.toNetIP(),
		}
	}
	m.Answer = rrs
	return m
}

func directLookup(domain string, dnsSrv []string) ([]IPv4, error) {
	if domain[len(domain)-1] != '.' {
		domain += "."
	}
	if staticIps := lookupStaticHost(domain); len(staticIps) > 0 {
		return staticIps, nil
	}
	logf("direct lookup %s @%v", domain, dnsSrv)
	m := new(dns.Msg)
	m.Id = uint16(atomic.AddUint32(&directLookupId, 1))
	m.Opcode = dns.OpcodeQuery
	m.CheckingDisabled = true
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{
			Name:   domain,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}
	resp, err := directQueryWithMsg(m, dnsSrv)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, &dnsError{resp.Rcode}
	}
	var ips []IPv4
	for _, answer := range resp.Answer {
		if dnsA, ok := answer.(*dns.A); ok {
			if v := FromNetIP(dnsA.A); v != 0 {
				ips = append(ips, v)
			}
		}
	}
	return ips, nil
}

func directQueryWithMsg(req *dns.Msg, dnsSrvs []string) (*dns.Msg, error) {
	if len(dnsSrvs) == 0 {
		return nil, errors.New("no dns server")
	}
	type respWithErr struct {
		resp *dns.Msg
		err  error
	}
	ctx, cancel := context.WithCancel(context.Background())
	respCh := make(chan respWithErr, len(dnsSrvs))
	for i, dnsSrv := range dnsSrvs {
		go func(i int, dnsSrv string) {
			time.Sleep(time.Duration(i) * time.Second)
			select {
			case <-ctx.Done():
				return
			default:
			}
			resp, err := func() (*dns.Msg, error) {
				var err error
				co := new(dns.Conn)
				if co.Conn, err = dialer.Dial("udp4", dnsSrv); err != nil {
					return nil, err
				}
				defer co.Close()
				_ = co.SetWriteDeadline(time.Now().Add(dnsTimeout))
				if err = co.WriteMsg(req); err != nil {
					return nil, err
				}
				_ = co.SetReadDeadline(time.Now().Add(dnsTimeout))
				return co.ReadMsg()

			}()
			respCh <- respWithErr{resp, err}
		}(i, dnsSrv)
	}
	var (
		r     respWithErr
		lastR *respWithErr
	)
	for i := 0; i < len(dnsSrvs); i++ {
		r = <-respCh
		if lastR == nil {
			lastR = &r
		}
		if r.err == nil && r.resp.Rcode != dns.RcodeServerFailure {
			lastR = &r
			cancel()
			break
		}
	}
	if lastR == nil {
		lastR = &respWithErr{err: errors.New("unexpected dns query error")}
	}
	return lastR.resp, lastR.err
}

func refreshProbeDnsSrv() error {
	nsCachePath := filepath.Join(baseDir, "fakedns.ns")

	fetchRemote := func() error {
		const probeSrvCap = 2
		var (
			probeDnsSrvCh = make(chan string, probeSrvCap)

			probeSrvCnt uint32

			wg = &sync.WaitGroup{}

			probeTLDs = []string{"hk", "kr", "jp"}
		)

		for _, probeTLD := range probeTLDs {
			wg.Add(1)
			go func(probeTLD string) {
				defer wg.Done()
				m := new(dns.Msg)
				m.Id = uint16(atomic.AddUint32(&directLookupId, 1))
				m.Opcode = dns.OpcodeQuery
				m.CheckingDisabled = true
				m.RecursionDesired = true
				m.Question = []dns.Question{
					{
						Name:   probeTLD + ".",
						Qtype:  dns.TypeNS,
						Qclass: dns.ClassINET,
					},
				}
				resp, err := directQueryWithMsg(m, chinaDNS)
				if err != nil {
					logf("query NS %s error: %v", probeTLD, err)
					return
				}
				if resp.Rcode != dns.RcodeSuccess {
					logf("query NS %s, rcode=%v", probeTLD, dns.RcodeToString[resp.Rcode])
					return
				}
				var probeNameServers []string
				for _, answer := range resp.Answer {
					if ns, ok := answer.(*dns.NS); ok {
						probeNameServers = append(probeNameServers, ns.Ns)
					}
				}
				if len(probeNameServers) == 0 {
					logf("query NS %s but got none", probeTLD)
					return
				}
				logf("query NS %s: %v", probeTLD, probeNameServers)

				for _, s := range probeNameServers {
					wg.Add(1)
					go func(s string) {
						defer wg.Done()
						if atomic.LoadUint32(&probeSrvCnt) > probeSrvCap {
							return
						}
						ips, err := directLookup(s, chinaDNS)
						if err != nil {
							logf("lookup %s: %v", s, err)
							return
						}
						for _, ip := range ips {
							wg.Add(1)
							go func(ip IPv4) {
								defer wg.Done()
								if atomic.LoadUint32(&probeSrvCnt) > probeSrvCap {
									return
								}
								srvStr := ip.String() + ":53"
								_, err := directLookup("www.baidu.com", []string{srvStr})
								logf("probe server %s return: %v", ip, err)
								if err != nil {
									if _, ok := err.(*dnsError); ok {
										if atomic.AddUint32(&probeSrvCnt, 1) <= probeSrvCap {
											probeDnsSrvCh <- srvStr
										}
									}
								}
							}(ip)
							time.Sleep(20 * time.Millisecond)
						}
					}(s)
					time.Sleep(20 * time.Millisecond)
				}
			}(probeTLD)
		}

		wgCh := make(chan struct{})
		go func() {
			wg.Wait()
			close(wgCh)
		}()
		ips := make([]string, 0, probeSrvCap)
		for i := 0; i < probeSrvCap; i++ {
			var ip string
			select {
			case ip = <-probeDnsSrvCh:
			case <-wgCh:
				select {
				case ip = <-probeDnsSrvCh:
				default:
					i = probeSrvCap
				}
			}
			if len(ip) > 0 {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 {
			logf("probe dns empty, discard and keep old: %v", probeDNS)
			return nil
		}
		logf("probe dns: %v", ips)
		changed := false
		probeDNSMutex.Lock()
		if len(probeDNS) != len(ips) {
			changed = true
		} else {
			for _, a := range probeDNS {
				found := false
				for _, b := range ips {
					if a == b {
						found = true
						break
					}
				}
				if !found {
					changed = true
					break
				}
			}
		}
		if changed {
			probeDNS = ips
		}
		probeDNSMutex.Unlock()
		if changed {
			_ = ioutil.WriteFile(nsCachePath, []byte(strings.Join(ips, "\n")), 0600)
		}
		return nil
	}

	var ips []string
	nsBytes, _ := ioutil.ReadFile(nsCachePath)
	nsStr := string(nsBytes)
	for _, s := range strings.Split(nsStr, "\n") {
		if host, port, err := net.SplitHostPort(s); err == nil {
			if net.ParseIP(host) != nil {
				if _, err := strconv.Atoi(port); err == nil {
					ips = append(ips, s)
				}
			}
		}
	}
	var err error
	if len(ips) > 0 {
		probeDNSMutex.Lock()
		probeDNS = ips
		probeDNSMutex.Unlock()
		logf("probe name server load from cache: %v", ips)
	} else {
		err = fetchRemote()
	}
	go func() {
		if info, err := os.Stat(nsCachePath); err == nil {
			delta := time.Now().Sub(info.ModTime())
			if delta < 0 {
				delta = 0
			}
			delta = time.Hour - delta
			if delta > 0 {
				time.Sleep(delta)
			}
		}
		for {
			logf("fetchRemote: %v", fetchRemote())
			time.Sleep(time.Hour)
		}
	}()
	return err
}
func AlwaysDirectLookup(domain string) {
	if len(domain) == 0 {
		return
	}
	if net.ParseIP(domain) != nil {
		return
	}
	domain = normalizeDomainName(domain)
	go func(domain string) {
		for interval := time.NewTicker(4 * time.Hour); ; <-interval.C {
			if ips, err := directLookup(domain, chinaDNS); err != nil {
				logf("direct lookup %s @%v error: %v", domain, chinaDNS, err)
			} else {
				updateHosts(domain, ips)
				logf("updateHosts %s -> %v", domain, ips)
			}
		}
	}(domain)
	logf("always direct lookup domain: %s", domain)
}

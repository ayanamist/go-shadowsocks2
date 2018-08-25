package shadow

import (
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

func Test_h2Shadow(t *testing.T) {
	dialer = &net.Dialer{
		Timeout: 5 * time.Second,
	}
	h2ProxyTest := os.Getenv("H2_PROXY_TEST")
	u, err := url.ParseRequestURI(h2ProxyTest)
	if err != nil {
		t.Fatalf("invalid H2_PROXY_TEST: %v", err)
	}
	var (
		user, pass string
	)
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	dialFunc := WrapH2(u.Host, user, pass)
	tr := &http.Transport{
		Dial: dialFunc,
	}
	sema := make(chan struct{}, 5)
	empty := struct{}{}
	wg := &sync.WaitGroup{}
	n := 100
	req, _ := http.NewRequest(http.MethodGet, "https://api.twitter.com/", nil)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sema <- empty
			defer func() {
				<-sema
			}()

			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Errorf("roundtrip: %v", err)
				return
			}
			if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
				t.Errorf("read body: %v", err)
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
}

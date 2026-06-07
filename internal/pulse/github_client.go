package pulse

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var githubHostIPs = map[string]string{
	"github.com":                           "140.82.116.3",
	"objects.githubusercontent.com":        "185.199.108.133",
	"raw.githubusercontent.com":            "185.199.108.133",
	"release-assets.githubusercontent.com": "185.199.108.133",
}

func githubHTTPClient(hostname, ip string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "",
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				port := "443"
				if _, requestedPort, err := net.SplitHostPort(addr); err == nil && requestedPort != "" {
					port = requestedPort
				}
				return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
		Timeout: 30 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func resolveGithubHost(hostname string) (string, error) {
	if ip := githubHostIPs[strings.ToLower(hostname)]; ip != "" {
		return ip, nil
	}
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", hostname, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].String(), nil
	}
	return "", fmt.Errorf("resolve %s: no address", hostname)
}

func isGithubDownloadHost(hostname string) bool {
	host := strings.ToLower(hostname)
	return host == "github.com" || strings.HasSuffix(host, ".github.com") || strings.HasSuffix(host, ".githubusercontent.com")
}

func (a *App) githubRequest(method, target string, body io.Reader, headers map[string]string) (*http.Response, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("missing host in %s", target)
	}
	ip, err := resolveGithubHost(hostname)
	if err != nil {
		return nil, err
	}
	requestURL := *parsed
	requestURL.Host = ip
	if port := parsed.Port(); port != "" {
		requestURL.Host = net.JoinHostPort(ip, port)
	}
	req, err := http.NewRequest(method, requestURL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Host = parsed.Host
	req.Header.Set("Host", parsed.Host)
	req.Header.Set("User-Agent", subscriptionUserAgent)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := githubHTTPClient(hostname, ip).Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", target, err)
	}
	if location := resp.Header.Get("Location"); location != "" {
		_ = resp.Body.Close()
		next, err := parsed.Parse(location)
		if err != nil {
			return nil, err
		}
		a.appendLog("info", "github download redirect: "+next.String())
		return a.githubRequest(method, next.String(), body, headers)
	}
	return resp, nil
}

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

var githubHostIPs = map[string][]string{
	"github.com": {
		"140.82.116.3",
		"140.82.114.4",
	},
	"objects.githubusercontent.com": {
		"185.199.108.133",
		"185.199.109.133",
		"185.199.110.133",
		"185.199.111.133",
	},
	"raw.githubusercontent.com": {
		"185.199.108.133",
		"185.199.109.133",
		"185.199.110.133",
		"185.199.111.133",
	},
	"release-assets.githubusercontent.com": {
		"185.199.108.133",
		"185.199.109.133",
		"185.199.110.133",
		"185.199.111.133",
	},
	"api.github.com": {
		"140.82.112.5",
		"140.82.113.5",
		"140.82.114.5",
		"140.82.116.6",
	},
}

func githubHTTPClient(hostname, ip string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         hostname,
			},
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if ip == "" {
					return (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, network, addr)
				}
				port := "443"
				if _, requestedPort, err := net.SplitHostPort(addr); err == nil && requestedPort != "" {
					port = requestedPort
				}
				return (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func resolveGithubHostCandidates(hostname string) ([]string, error) {
	candidates := append([]string(nil), githubHostIPs[strings.ToLower(hostname)]...)
	seen := make(map[string]bool, len(candidates)+1)
	out := make([]string, 0, len(candidates)+1)
	for _, ip := range candidates {
		if ip != "" && !seen[ip] {
			out = append(out, ip)
			seen[ip] = true
		}
	}
	ips, err := net.LookupIP(hostname)
	if err != nil {
		if len(out) > 0 {
			return append(out, ""), nil
		}
		return nil, fmt.Errorf("resolve %s: %w", hostname, err)
	}
	for _, ip := range ips {
		value := ip.String()
		if v4 := ip.To4(); v4 != nil {
			value = v4.String()
		}
		if !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	out = append(out, "")
	return out, nil
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
	ips, err := resolveGithubHostCandidates(hostname)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		requestURL := *parsed
		if ip != "" {
			requestURL.Host = ip
			if port := parsed.Port(); port != "" {
				requestURL.Host = net.JoinHostPort(ip, port)
			}
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
			lastErr = err
			targetHost := hostname
			if ip != "" {
				targetHost = ip
			}
			a.appendLog("warn", fmt.Sprintf("github download attempt failed host=%s via=%s error=%s", hostname, targetHost, err.Error()))
			continue
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
	if lastErr != nil {
		return nil, fmt.Errorf("request %s: %w", target, lastErr)
	}
	return nil, fmt.Errorf("request %s: no github download candidates", target)
}

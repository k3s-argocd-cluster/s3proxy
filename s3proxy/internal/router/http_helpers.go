package router

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
)

// getMetadataHeaders parses user-defined metadata headers from request headers.
func getMetadataHeaders(header http.Header) map[string]string {
	result := map[string]string{}

	for key := range header {
		key = strings.ToLower(key)
		if strings.HasPrefix(key, "x-amz-meta-") {
			name := strings.TrimPrefix(key, "x-amz-meta-")
			result[name] = strings.Join(header.Values(key), ",")
		}
	}

	return result
}

func parseRetentionTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

// repackage modifies an incoming request so it can be safely forwarded to upstream S3.
func repackage(r *http.Request) (*http.Request, error) {
	req := r.Clone(r.Context())
	req.URL.RawPath = ""
	req.RequestURI = ""

	host, err := config.GetHostConfig()
	if err != nil {
		return nil, fmt.Errorf("getting host config: %w", err)
	}

	endpoint, err := parseEndpointHost(host)
	if err != nil {
		return nil, err
	}

	req.Host = endpoint.Host
	req.URL.Host = endpoint.Host
	req.URL.Scheme = endpoint.Scheme

	headersToRemove := []string{
		"X-Real-Ip",
		"X-Forwarded-Scheme",
		"X-Forwarded-Proto",
		"X-Scheme",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-For",
	}
	for _, header := range headersToRemove {
		req.Header.Del(header)
	}

	return req, nil
}

type endpointHost struct {
	Scheme string
	Host   string
}

func parseEndpointHost(raw string) (endpointHost, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return endpointHost{}, fmt.Errorf("host cannot be empty")
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return endpointHost{}, fmt.Errorf("parsing host endpoint: %w", err)
		}
		if parsed.Host == "" {
			return endpointHost{}, fmt.Errorf("host endpoint is missing host")
		}
		return endpointHost{Scheme: parsed.Scheme, Host: parsed.Host}, nil
	}
	return endpointHost{Scheme: "https", Host: raw}, nil
}

// validateContentMD5 checks if the content-md5 header matches the body.
func validateContentMD5(contentMD5 string, body []byte) error {
	if contentMD5 == "" {
		return nil
	}

	expected, err := base64.StdEncoding.DecodeString(contentMD5)
	if err != nil {
		return fmt.Errorf("decoding base64: %w", err)
	}

	if len(expected) != 16 {
		return fmt.Errorf("content-md5 must be 16 bytes long, got %d bytes", len(expected))
	}

	// #nosec G401
	actual := md5.Sum(body)
	if !bytes.Equal(actual[:], expected) {
		return fmt.Errorf("content-md5 mismatch, header is %x, body is %x", expected, actual)
	}

	return nil
}

// match reports whether path matches pattern, and if it matches,
// assigns any capture groups to the *string vars.
func match(path string, pattern *regexp.Regexp, vars ...*string) bool {
	matches := pattern.FindStringSubmatch(path)
	if len(matches) <= 0 {
		return false
	}

	for i, capture := range matches[1:] {
		*vars[i] = capture
	}
	return true
}

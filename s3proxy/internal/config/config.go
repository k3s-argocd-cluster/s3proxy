package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
)

var k = koanf.New(".")

func LoadConfig() error {
	// Load environment variables with the `S3PROXY_` prefix and replace `_` with `.`
	return k.Load(env.Provider("S3PROXY_", ".", func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, "_", "."))
	}), nil)
}

func GetHostConfig() (string, error) {
	// Ensure loading was successful before calling Get
	if !k.Exists("s3proxy.host") {
		return "", errors.New("unable to get 'S3PROXY_HOST' env var")
	}
	return k.String("s3proxy.host"), nil
}

func GetKMSStaticKey() (string, error) {
	if !k.Exists("s3proxy.kms.static.key") {
		return "", errors.New("unable to get 'S3PROXY_KMS_STATIC_KEY' env var")
	}
	value := strings.TrimSpace(k.String("s3proxy.kms.static.key"))
	if value == "" {
		return "", fmt.Errorf("'S3PROXY_KMS_STATIC_KEY' cannot be empty")
	}
	return value, nil
}

func GetThrottlingRequestsMax() int {
	return k.Int("s3proxy.throttling.requestsmax")
}

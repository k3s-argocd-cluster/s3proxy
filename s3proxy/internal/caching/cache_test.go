package caching

import (
	"net/http"
	"net/http/httptest"
	"testing"

	logger "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestGetFromCache_PrefixEquivalentToDirectPath(t *testing.T) {
	t.Parallel()

	log := logger.New()
	log.SetLevel(logger.PanicLevel)
	cache := NewCacheWithStore(&memoryStore{}, log)

	path := "/bucket/some/path/to/file"
	headers := http.Header{"Content-Type": []string{"application/octet-stream"}}
	body := []byte("payload")
	element := CacheElement{Header: &headers, Body: &body, StatusCode: http.StatusOK}
	cache.SaveToCache("seed", ActionGet, path, element)

	req := httptest.NewRequest(http.MethodGet, "http://example.local/bucket?prefix=/some/path/to/file", nil)
	result, err := cache.GetFromCache("lookup", req)

	require.NoError(t, err)
	require.True(t, result.CachingDesired)
	require.Equal(t, path, result.Path)
	require.True(t, result.ElementFound)
	require.Equal(t, element, result.Element)
}

func TestGetFromCache_PrefixWithoutLeadingSlash_ShouldMatchDirectPath(t *testing.T) {
	t.Parallel()

	log := logger.New()
	log.SetLevel(logger.PanicLevel)
	cache := NewCacheWithStore(&memoryStore{}, log)

	path := "/bucket/some/path/to/file"
	headers := http.Header{"Content-Type": []string{"application/octet-stream"}}
	body := []byte("payload")
	element := CacheElement{Header: &headers, Body: &body, StatusCode: http.StatusOK}
	cache.SaveToCache("seed", ActionGet, path, element)

	req := httptest.NewRequest(http.MethodGet, "http://example.local/bucket?prefix=some/path/to/file", nil)
	result, err := cache.GetFromCache("lookup", req)

	require.NoError(t, err)
	require.True(t, result.CachingDesired)
	require.Equal(t, path, result.Path)
	require.True(t, result.ElementFound)
	require.Equal(t, element, result.Element)
}

func TestGetFromCache_PrefixWithEncodedPlus_ShouldNotDecodeTwice(t *testing.T) {
	t.Parallel()

	log := logger.New()
	log.SetLevel(logger.PanicLevel)
	cache := NewCacheWithStore(&memoryStore{}, log)

	path := "/bucket/some/path+to/file"
	headers := http.Header{"Content-Type": []string{"application/octet-stream"}}
	body := []byte("payload")
	element := CacheElement{Header: &headers, Body: &body, StatusCode: http.StatusOK}
	cache.SaveToCache("seed", ActionGet, path, element)

	req := httptest.NewRequest(http.MethodGet, "http://example.local/bucket?prefix=some/path%2Bto/file", nil)
	result, err := cache.GetFromCache("lookup", req)

	require.NoError(t, err)
	require.True(t, result.CachingDesired)
	require.Equal(t, path, result.Path)
	require.True(t, result.ElementFound)
	require.Equal(t, element, result.Element)
}

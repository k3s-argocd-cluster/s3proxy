/*
Copyright (c) slig2008 2026

SPDX-License-Identifier: AGPL-3.0-only
*/
/*
Package cache implements caching for repetitive s3 GET and HEAD requests
*/
package cache

import (
	"net/http"
	"net/url"
	"strings"
)

type Action string

const (
	Head Action = "HEAD"
	Get  Action = "GET"
)

type CacheElement struct {
	Header     http.Header
	Body       []byte
	StatusCode int
}

// Store is an interface describing methods to persist data.
type Cache interface {
	GetFromCache(req *http.Request) (bool, *string, *CacheElement, error)
	Store(action Action, path string, element *CacheElement)
	RemoveFromCache(path string)
}

type DefaultCache struct {
	store Store
}

func NewCache(cacheType string) (*Cache, error) {
	c := new(DefaultCache)
	c.store = NewStore(cacheType)
	var result Cache = c
	return &result, nil
}

func (c DefaultCache) GetFromCache(req *http.Request) (bool, *string, *CacheElement, error) {
	path := req.URL.Path
	prefix := req.URL.Query().Get("prefix")
	if prefix != "" {
		decoded, err := url.QueryUnescape(prefix)
		if err != nil {
			return true, nil, nil, err
		}
		path += decoded
	}

	path = adjustPath(path)

	if req.Method == http.MethodDelete || req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut {
		c.RemoveFromCache(path)
	}

	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false, nil, nil, nil
	}

	return true, &path, c.store.Get(Action(req.Method), path), nil
}

func (c DefaultCache) Store(action Action, path string, element *CacheElement) {
	c.store.Set(action, adjustPath(path), element)
}

func (c DefaultCache) RemoveFromCache(path string) {
	path = adjustPath(path)

	// remove any caches for the element itself
	c.store.ClearElements(path)

	// try to go one level up and remove any caches for the parent as well
	last := strings.LastIndex(path, "/")
	if last > 0 {
		c.store.ClearElements(path[0:last])
	}
}

func adjustPath(path string) string {
	if strings.HasSuffix(path, "/") {
		return path[0 : len(path)-1]
	}

	return path
}

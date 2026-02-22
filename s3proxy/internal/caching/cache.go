/*
Copyright (c) slig2008 2026

SPDX-License-Identifier: AGPL-3.0-only
*/
/*
package caching implements caching for repetitive s3 GET and HEAD requests
*/
package caching

import (
	"net/http"
	"net/url"
	"strings"

	logger "github.com/sirupsen/logrus"
)

type Action string

const (
	ActionHead Action = "HEAD"
	ActionGet  Action = "GET"
)

type CacheElement struct {
	Header     *http.Header
	Body       *[]byte
	StatusCode int
}

type CacheGetResult struct {
	Desired      bool
	Path         string
	ElementFound bool
	Element      CacheElement
}

// Store is an interface describing methods to persist data.
type Cache interface {
	GetFromCache(requestID string, req *http.Request) (CacheGetResult, error)
	Store(requestID string, action Action, path string, element CacheElement)
	RemoveFromCache(requestID string, path string)
}

type defaultCache struct {
	store store
	log   *logger.Logger
}

func NewCache(cacheType string, log *logger.Logger) Cache {
	return defaultCache{
		store: newStore(cacheType, log),
		log:   log,
	}
}

func (c defaultCache) GetFromCache(requestID string, req *http.Request) (CacheGetResult, error) {
	path := req.URL.Path
	prefix := req.URL.Query().Get("prefix")
	if prefix != "" {
		decoded, err := url.QueryUnescape(prefix)
		if err != nil {
			return CacheGetResult{}, err
		}
		path += decoded
	}

	path = adjustPath(path)
	log := c.log.WithFields(logger.Fields{
		"requestID":    requestID,
		"originalPath": req.URL.Path,
		"path":         path,
		"method":       req.Method,
	})

	if req.Method == http.MethodDelete || req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut {
		c.removeFromCacheInternal(log, path)
	}

	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		log.Debug("not a method for caching")
		return CacheGetResult{}, nil
	}

	element, found := c.store.Get(Action(req.Method), path)

	log = log.WithField("found", found)
	if found {
		log = log.WithFields(logger.Fields{
			"header":     *element.Header,
			"body":       string(*element.Body),
			"statusCode": element.StatusCode,
		})
	}
	log.Trace("return from cache")

	return CacheGetResult{
		Desired:      true,
		Path:         path,
		ElementFound: found,
		Element:      element,
	}, nil
}

func (c defaultCache) Store(requestID string, action Action, path string, element CacheElement) {
	if c.log.Level == logger.TraceLevel {
		c.log.WithFields(logger.Fields{
			"requestID":  requestID,
			"action":     action,
			"path":       path,
			"header":     *element.Header,
			"body":       string(*element.Body),
			"statusCode": element.StatusCode,
		}).Trace("store element to cache")
	} else {
		c.log.WithFields(logger.Fields{
			"requestID": requestID,
			"action":    action,
			"path":      path,
		}).Debug("store element to cache")
	}
	c.store.Set(action, adjustPath(path), element)
}

func (c defaultCache) RemoveFromCache(requestID string, path string) {
	path = adjustPath(path)
	c.removeFromCacheInternal(c.log.WithField("requestID", requestID).WithField("path", path), path)
}

func (c defaultCache) removeFromCacheInternal(log *logger.Entry, path string) {
	// remove any caches for the element itself
	log.Debug("remove element")
	c.store.ClearElements(path)

	// try to go one level up and remove any caches for the parent as well
	last := strings.LastIndex(path, "/")
	if last > 0 {
		parent := path[0:last]
		log.WithField("parent", parent).Debug("remove parent")
		c.store.ClearElements(parent)
	}
}

func adjustPath(path string) string {
	if strings.HasSuffix(path, "/") {
		return path[0 : len(path)-1]
	}

	return path
}

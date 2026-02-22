/*
Copyright (c) slig2008 2026

SPDX-License-Identifier: AGPL-3.0-only
*/
/*
package caching implements caching for repetitive s3 GET and HEAD requests
*/
package caching

import (
	logger "github.com/sirupsen/logrus"
)

// Store is an interface describing methods to persist data.
type store interface {
	Get(action Action, path string) (CacheElement, bool)
	Set(action Action, path string, element CacheElement)
	ClearElements(path string)
}

func newStore(storeType string, _ *logger.Logger) store {
	if storeType == "none" {
		return noStore{}
	}

	return memoryStore{
		elements: make(map[string]map[Action]CacheElement),
	}
}

type memoryStore struct {
	elements map[string]map[Action]CacheElement
}

func (c memoryStore) Get(action Action, path string) (CacheElement, bool) {
	pathElements, ok := c.elements[path]
	if ok {
		result, ok := pathElements[action]
		if ok {
			return result, true
		}
	}

	return CacheElement{}, false
}

func (c memoryStore) Set(action Action, path string, element CacheElement) {
	pathElements, ok := c.elements[path]
	if !ok {
		pathElements = make(map[Action]CacheElement)
		c.elements[path] = pathElements
	}
	pathElements[action] = element
}

func (c memoryStore) ClearElements(path string) {
	delete(c.elements, path)
}

type noStore struct {
}

func (c noStore) Get(_ Action, _ string) (CacheElement, bool) {
	return CacheElement{}, false
}

func (c noStore) Set(_ Action, _ string, _ CacheElement) {
}

func (c noStore) ClearElements(_ string) {
}

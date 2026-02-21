/*
Copyright (c) slig2008 2026

SPDX-License-Identifier: AGPL-3.0-only
*/
/*
Package cache implements caching for repetitive s3 GET and HEAD requests
*/
package cache

// Store is an interface describing methods to persist data.
type Store interface {
	Get(action Action, path string) *CacheElement
	Set(action Action, path string, element *CacheElement)
	ClearElements(path string)
}

func NewStore(storeType string) Store {
	if storeType == "none" {
		c := new(NoStore)
		var result Store = c
		return result
	}

	c := new(MemoryStore)
	c.elements = make(map[string]map[Action]*CacheElement)
	var result Store = c
	return result
}

type MemoryStore struct {
	elements map[string]map[Action]*CacheElement
}

func (c MemoryStore) Get(action Action, path string) *CacheElement {
	pathElements, ok := c.elements[path]
	if ok {
		result, ok := pathElements[action]
		if ok {
			return result
		}
	}

	return nil
}

func (c MemoryStore) Set(action Action, path string, element *CacheElement) {
	pathElements, ok := c.elements[path]
	if !ok {
		pathElements = make(map[Action]*CacheElement)
		c.elements[path] = pathElements
	}
	pathElements[action] = element
}

func (c MemoryStore) ClearElements(path string) {
	delete(c.elements, path)
}

type NoStore struct {
}

func (c NoStore) Get(action Action, path string) *CacheElement {
	return nil
}

func (c NoStore) Set(action Action, path string, element *CacheElement) {
}

func (c NoStore) ClearElements(path string) {
}

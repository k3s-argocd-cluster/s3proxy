/*
Copyright (c) slig2008 2026

SPDX-License-Identifier: AGPL-3.0-only
*/
/*
package caching implements caching for repetitive s3 GET and HEAD requests
*/
package caching

import (
	"errors"
	"sync"

	logger "github.com/sirupsen/logrus"
)

// Store is an interface describing methods to persist data.
type CacheStore interface {
	Get(action Action, path string) (CacheElement, bool, error)
	Set(action Action, path string, element CacheElement)
	ClearElements(path string)
}

func newStore(storeType string, _ *logger.Logger) CacheStore {
	if storeType == "none" {
		return &noStore{}
	}

	return &memoryStore{}
}

type memoryStore struct {
	elements sync.Map
}

func (c *memoryStore) Get(action Action, path string) (CacheElement, bool, error) {
	if raw, ok := c.elements.Load(path + "::" + string(action)); ok {
		if raw == nil {
			return CacheElement{}, true, errors.New("no cache element")
		}

		element, ok := raw.(CacheElement)
		if !ok {
			return element, true, errors.New("invalid cache element")
		}

		return element, true, nil
	}

	return CacheElement{}, false, nil
}

func (c *memoryStore) Set(action Action, path string, element CacheElement) {
	c.elements.Store(path+"::"+string(action), element)
}

func (c *memoryStore) ClearElements(path string) {
	actions := [2]Action{ActionHead, ActionGet}
	for _, action := range actions {
		c.elements.Delete(path + "::" + string(action))
	}
}

type noStore struct {
}

func (c *noStore) Get(_ Action, _ string) (CacheElement, bool, error) {
	return CacheElement{}, false, nil
}

func (c *noStore) Set(_ Action, _ string, _ CacheElement) {
}

func (c *noStore) ClearElements(_ string) {
}

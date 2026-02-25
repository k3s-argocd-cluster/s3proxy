package caching

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	store := newStore("none", nil)
	require.IsType(t, &noStore{}, store, "expected noStore for type none")

	store = newStore("memory", nil)
	require.IsType(t, &memoryStore{}, store, "exptected memoryStore for type memory")
}

func TestInitialGet(t *testing.T) {
	storesUnderTest := [2]struct {
		name  string
		store CacheStore
	}{
		{name: "NoStore", store: &noStore{}},
		{name: "MemoryStore", store: &memoryStore{}},
	}

	for _, test := range storesUnderTest {
		t.Run(test.name, func(t *testing.T) {
			actions := [2]Action{ActionHead, ActionGet}
			for _, action := range actions {
				result, found, err := test.store.Get(action, "/test-path/")
				require.NoError(t, err, "expected no error when getting from empty store for %s", action)
				require.False(t, found, "expected no element being found from empty store for %s", action)
				require.Equal(t, CacheElement{}, result, "expected element to be default for %s", action)
			}
		})
	}
}

func TestSetGet(t *testing.T) {
	actionsUnderTest := [2]struct {
		action      Action
		succeedWith []Action
		failWith    []Action
	}{
		{action: ActionGet, succeedWith: []Action{ActionGet}, failWith: []Action{ActionHead}},
		{action: ActionHead, succeedWith: []Action{ActionHead}, failWith: []Action{ActionGet}},
	}

	for _, aut := range actionsUnderTest {
		storesUnderTest := []struct {
			name          string
			store         CacheStore
			found         bool
			emptyExpected bool
		}{
			{name: "NoStore", store: &noStore{}, found: false, emptyExpected: true},
			{name: "MemoryStore", store: &memoryStore{}, found: true, emptyExpected: false},
		}

		for _, toBeStored := range []CacheElement{{StatusCode: 123}, {StatusCode: 234}, {Header: &http.Header{}}} {
			for _, test := range storesUnderTest {
				t.Run(fmt.Sprintf("%s-%s", test.name, aut.action), func(t *testing.T) {
					require.NotEqual(t, CacheElement{}, toBeStored, "expected element to be stored not be empty")

					test.store.Set(aut.action, "/test-path/", toBeStored)

					for _, action := range aut.succeedWith {
						result, found, err := test.store.Get(action, "/test-path/")
						require.NoError(t, err, "expected no error when getting element just stored for %s", action)
						if test.found {
							require.True(t, found, "expected element being found for %s", action)
						} else {
							require.False(t, found, "expected element not being found for %s", action)
						}
						var expected CacheElement
						if test.emptyExpected {
							expected = CacheElement{}
						} else {
							expected = toBeStored
						}
						require.Equal(t, expected, result, "wrong element for %s", action)
					}

					for _, action := range aut.failWith {
						result, found, err := test.store.Get(action, "/test-path/")
						require.NoError(t, err, "expected no error when getting element for %s", action)
						require.False(t, found, "expected element not being found for %s", action)
						require.Equal(t, CacheElement{}, result, "expected element to be default for %s", action)
					}

					for _, unknownPath := range []string{"/test-path-1/", "/test-path/1/", "1/test-path/", "/1/test-path/", "/test-path", "test-path/", "test-path"} {
						result, found, err := test.store.Get(aut.action, unknownPath)
						require.NoError(t, err, "expected no error when getting element with unknown path %s", unknownPath)
						require.False(t, found, "expected element not being found with unknown path %s", unknownPath)
						require.Equal(t, CacheElement{}, result, "expected element to be default with unknown path %s", unknownPath)
					}
				})
			}
		}
	}
}

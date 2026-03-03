package router

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	logger "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestIsUnwantedGetEndpoint(t *testing.T) {
	cases := []url.Values{
		{"acl": {""}},
		{"attributes": {""}},
		{"legal-hold": {""}},
		{"retention": {""}},
		{"tagging": {""}},
		{"torrent": {""}},
		{"uploadId": {"1"}},
	}

	for _, q := range cases {
		require.True(t, isUnwantedGetEndpoint(q))
	}
	require.False(t, isUnwantedGetEndpoint(url.Values{}))
}

func TestIsUnwantedPutEndpoint(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		query  url.Values
	}{
		{name: "copy source", header: http.Header{"X-Amz-Copy-Source": []string{"/a/b"}}, query: url.Values{}},
		{name: "upload part", header: http.Header{}, query: url.Values{"partNumber": {"1"}, "uploadId": {"u"}}},
		{name: "tagging", header: http.Header{}, query: url.Values{"tagging": {""}}},
		{name: "legal hold", header: http.Header{}, query: url.Values{"legal-hold": {""}}},
		{name: "object lock", header: http.Header{}, query: url.Values{"object-lock": {""}}},
		{name: "retention", header: http.Header{}, query: url.Values{"retention": {""}}},
		{name: "public access block", header: http.Header{}, query: url.Values{"publicAccessBlock": {""}}},
		{name: "acl", header: http.Header{}, query: url.Values{"acl": {""}}},
	}

	for _, c := range cases {
		require.True(t, isUnwantedPutEndpoint(c.header, c.query), c.name)
	}
	require.False(t, isUnwantedPutEndpoint(http.Header{}, url.Values{}))
}

func TestGetMultipartHandlerAlwaysBlocks(t *testing.T) {
	r := Router{log: logger.New()}

	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploads", nil)
	h := r.getMultipartHandler(req)
	require.NotNil(t, h)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotImplemented, w.Result().StatusCode)
}

func TestIsTaggingAttempt(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		header string
		want   bool
	}{
		{name: "put with tagging header", method: http.MethodPut, target: "/bucket/key", header: "k=v", want: true},
		{name: "put with tagging query", method: http.MethodPut, target: "/bucket/key?tagging", want: true},
		{name: "get with tagging query", method: http.MethodGet, target: "/bucket/key?tagging", want: false},
		{name: "put without tagging", method: http.MethodPut, target: "/bucket/key", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.header != "" {
				req.Header.Set("x-amz-tagging", tt.header)
			}
			require.Equal(t, tt.want, isTaggingAttempt(req))
		})
	}
}

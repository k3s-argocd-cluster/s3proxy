package router

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreparePutBodyForUpload_NoDigest_StreamsAndCounts(t *testing.T) {
	req := httptest.NewRequest("PUT", "/bucket/key", strings.NewReader("hello world"))
	body, cleanup, sizeFn, mismatch, err := preparePutBodyForUpload(req)
	require.NoError(t, err)
	require.Nil(t, mismatch)
	defer cleanup()

	n, err := io.Copy(io.Discard, body)
	require.NoError(t, err)
	require.Equal(t, int64(11), n)
	require.Equal(t, int64(11), sizeFn())
}

func TestPreparePutBodyForUpload_WithDigestAndMD5_ValidatesAndCounts(t *testing.T) {
	payload := []byte("payload")
	sha := fmt.Sprintf("%x", sha256.Sum256(payload))
	md5sum := md5.Sum(payload) // #nosec G401
	md5b64 := base64.StdEncoding.EncodeToString(md5sum[:])

	req := httptest.NewRequest("PUT", "/bucket/key", strings.NewReader(string(payload)))
	req.Header.Set("x-amz-content-sha256", sha)
	req.Header.Set("content-md5", md5b64)

	body, cleanup, sizeFn, mismatch, err := preparePutBodyForUpload(req)
	require.NoError(t, err)
	require.Nil(t, mismatch)
	defer cleanup()

	n, err := io.Copy(io.Discard, body)
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), n)
	require.Equal(t, int64(len(payload)), sizeFn())
}

func TestPreparePutBodyForUpload_DigestMismatch(t *testing.T) {
	req := httptest.NewRequest("PUT", "/bucket/key", strings.NewReader("payload"))
	req.Header.Set("x-amz-content-sha256", "deadbeef")

	body, cleanup, _, mismatch, err := preparePutBodyForUpload(req)
	require.NoError(t, err)
	require.Nil(t, body)
	require.NotNil(t, mismatch)
	if cleanup != nil {
		cleanup()
	}
}
